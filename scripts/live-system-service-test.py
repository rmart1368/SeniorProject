"""Disposable Linux CI host only: verify actual system services and crash recovery."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen

SPEC = importlib.util.spec_from_file_location("system_installer", Path(__file__).with_name("install-linux.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def wait_for(check, message, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise RuntimeError(message)


def active(name):
    return command("systemctl", "is-active", "--quiet", name, check=False).returncode == 0


def pid(name):
    return int(command("systemctl", "show", "-p", "MainPID", "--value", name).stdout.strip() or "0")


def alerts(name):
    output = command("journalctl", "-u", name, "--no-pager", "-o", "cat").stdout
    rows = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and "rule_id" in row:
            rows.append(row)
    return rows


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Requires root on a disposable Linux systemd test host")
    binary = Path(sys.argv[1]).resolve(strict=True)
    units = [INSTALLER.UNIT_DIR / name for name in [*INSTALLER.SERVICES, "chompedr.target"]]
    if any(p.exists() or p.is_symlink() for p in [INSTALLER.BINARY_PATH, INSTALLER.CLI_PATH, Path("/var/lib/chomp-edr"), *units]):
        raise RuntimeError("Refusing to overwrite an existing system installation or checkpoint")
    if INSTALLER.DASHBOARD_UNIT.exists() or INSTALLER.DASHBOARD_UNIT.is_symlink() or INSTALLER.DASHBOARD_DIR.exists():
        raise RuntimeError("Refusing to overwrite an existing dashboard installation")
    written = []
    dashboard_written = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    def dashboard():
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/snapshot", timeout=3) as response:
                return json.load(response)
        except (OSError, ValueError):
            return {}
    child = None
    with tempfile.TemporaryDirectory(prefix="chomp-system-live-", dir="/tmp") as folder:
        folder = Path(folder)
        watched = folder / "watched"
        watched.write_text("baseline")
        executable = folder / "demo-sleep"
        shutil.copy2(shutil.which("sleep"), executable)
        try:
            written = INSTALLER.install(binary, [str(watched)], port=port)
            # Restrict the response integration rule to this disposable child executable.
            custom_rules = folder / "response-rules.yaml"
            custom_rules.write_text("version: 1\nrules:\n  - id: CHOMP-PROC-001\n    name: Disposable process response\n    severity: medium\n    detection:\n      all:\n        - field: process.executable\n          op: equals\n          value: " + json.dumps(str(executable)) + "\n    response:\n      - action: terminate_process\n        target:\n          pid_field: process.pid\n          start_time_field: process.start_ticks\n        mode: approval_required\n")
            process_unit = INSTALLER.UNIT_DIR / "chompedr-processes.service"
            process_unit.write_text(process_unit.read_text().replace("watch-processes --include-existing", "watch-processes --include-existing --rules " + str(custom_rules)))
            preserved = folder / "preserved.conf"
            preserved.write_text("trusted configuration")
            preserve_rules = folder / "preserve.yaml"
            preserve_yaml = ("version: 1\nrules:\n  - id: CONFIG-LIVE\n    name: Preserve live test config\n    severity: high\n    enabled: true\n    detection:\n      all:\n        - field: event.type\n          op: exists\n    response:\n      - action: preserve_file\n        target: {path: " + str(preserved) + "}\n        mode: automatic\n")
            preserve_rules.write_text(preserve_yaml)
            response_unit = INSTALLER.UNIT_DIR / "chompedr-response.service"
            response_unit.write_text(response_unit.read_text().replace("worker.py follow", "worker.py --preserve-rules " + str(preserve_rules) + " follow"))
            command("systemd-sysusers", str(INSTALLER.SYSUSERS_PATH))
            command("systemctl", "daemon-reload")
            command("systemctl", "enable", "--now", "chompedr.target")
            command("systemctl", "is-enabled", "chompedr.target")
            command("systemctl", "enable", "--now", "chompedr-dashboard.service")
            wait_for(lambda: all(active(name) for name in INSTALLER.SERVICES), "Collectors did not start")
            # Wait for both polling baselines before changing the test host.
            def baseline(name):
                return "Baseline ready" in command("journalctl", "-u", name, "--no-pager", "-o", "cat").stdout
            wait_for(lambda: baseline("chompedr-files") and baseline("chompedr-processes"), "Missing baselines")
            watched.write_text("modified test configuration")
            wait_for(lambda: any(a["rule_id"] == "CHOMP-FILE-001" and
                                a["event"]["file"]["path"] == str(watched)
                                for a in alerts("chompedr-files")), "Missing file alert")
            child = subprocess.Popen([str(executable), "120"])
            wait_for(lambda: any(a["rule_id"] == "CHOMP-PROC-001" and
                                a["event"]["process"]["pid"] == child.pid
                                for a in alerts("chompedr-processes")), "Missing process alert")
            def dashboard_has_alerts():
                snapshot = dashboard()
                rows = snapshot.get("alerts", [])
                ids = {row["rule_id"] for row in rows}
                return ("CHOMP-FILE-001" in ids and "CHOMP-PROC-001" in ids and
                        (snapshot.get("rules") or {}).get("source") == "embedded" and
                        not snapshot.get("errors"))
            try:
                wait_for(dashboard_has_alerts, "Dashboard could not read real alerts, services or rules")
            except RuntimeError:
                print("Dashboard snapshot:", json.dumps(dashboard(), indent=2), flush=True)
                print(command("journalctl", "-u", "chompedr-dashboard", "--no-pager", "-n", "60").stdout, flush=True)
                print(command("systemctl", "status", "chompedr-dashboard", "dbus", check=False).stdout, flush=True)
                print(command("journalctl", "-u", "dbus", "--no-pager", "-n", "30").stdout, flush=True)
                raise
            response_cli = str(INSTALLER.CLI_PATH)
            def pending():
                rows = json.loads(command(response_cli, "responses", "list").stdout)
                return next((row for row in rows if row["status"] == "pending" and
                             (row.get("target") or {}).get("pid") == child.pid), None)
            wait_for(lambda: pending() is not None, "Response was not queued for approval")
            if child.poll() is not None:
                raise RuntimeError("Approval-required action executed before approval")
            token = command(response_cli, "responses", "dashboard-token").stdout.strip()
            origin = f"http://127.0.0.1:{port}"
            decision = Request(origin + "/api/responses/" + pending()["id"] + "/approve",
                               headers={"Origin": origin, "Authorization": "Bearer " + token}, method="POST")
            with urlopen(decision, timeout=5) as result:
                if json.load(result).get("status") != "queued":
                    raise RuntimeError("Dashboard approval did not queue action")
            wait_for(lambda: child.poll() is not None, "Approved process termination did not execute")
            if child.returncode != -15:
                raise RuntimeError("Expected SIGTERM after response approval")
            def guards():
                return [r for r in json.loads(command(response_cli, "responses", "list").stdout)
                        if r["rule_id"] == "CONFIG-LIVE"]
            wait_for(lambda: any(r["status"] == "active" for r in guards()), "Preservation did not activate")
            preserved.write_text("unauthorized update")
            wait_for(lambda: preserved.read_text() == "trusted configuration", "Preservation did not restore file")
            preserve_rules.write_text(preserve_yaml.replace("enabled: true", "enabled: false"))
            wait_for(lambda: all(r["status"] == "disabled" for r in guards()), "Preservation did not disable")
            preserved.write_text("legitimate update")
            preserve_rules.write_text(preserve_yaml)
            wait_for(lambda: any(r["status"] == "active" for r in guards()), "Preservation did not re-enable")
            preserved.write_text("second unauthorized update")
            wait_for(lambda: preserved.read_text() == "legitimate update", "Preservation did not use refreshed baseline")
            dashboard_uid = command("ps", "-o", "uid=", "-p", str(pid("chompedr-dashboard"))).stdout.strip()
            if not dashboard_uid or dashboard_uid == "0":
                raise RuntimeError("Dashboard did not run as an unprivileged user")
            for name in [*INSTALLER.SERVICES, "chompedr-dashboard.service"]:
                previous = pid(name)
                if previous <= 0:
                    raise RuntimeError(f"No main PID for {name}")
                command("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", name)
                wait_for(lambda: active(name) and pid(name) > 0 and pid(name) != previous,
                         f"Crash recovery failed: {name}")
            command("systemctl", "stop", "chompedr.target")
            wait_for(lambda: not any(active(name) for name in INSTALLER.SERVICES), "Target did not stop collectors")
            print("PASS: collectors, real dashboard feeds, approved process response, unprivileged web user, crash restarts and target stop")
        finally:
            command("systemctl", "disable", "--now", "chompedr-dashboard.service", check=False)
            for path in dashboard_written:
                path.unlink(missing_ok=True)
            if written:
                shutil.rmtree(INSTALLER.DASHBOARD_DIR, ignore_errors=True)
            command("systemctl", "disable", "--now", "chompedr.target", check=False)
            for name in INSTALLER.SERVICES:
                command("systemctl", "stop", name, check=False)
            if child is not None and child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            for path in written:
                path.unlink(missing_ok=True)
            if written:
                shutil.rmtree("/var/lib/chomp-edr", ignore_errors=True)
            command("systemctl", "daemon-reload", check=False)
            command("systemctl", "reset-failed", check=False)


if __name__ == "__main__":
    main()
