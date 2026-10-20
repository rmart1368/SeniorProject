"""Read-only, loopback dashboard for Chomp's Linux system services. Python 3.9+."""
import argparse
import copy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

COLLECTORS = ("chompedr-ssh.service", "chompedr-processes.service", "chompedr-files.service")
WEB_UNIT = "chompedr-dashboard.service"
LIMIT = 500
MAX_OUTPUT = 8 * 1024 * 1024
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def run_command(args, timeout=10):
    """Fixed argument arrays only; bound output and lifetime without invoking a shell."""
    deadline = time.monotonic() + timeout
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C")) as process:
        buffers = {"out": bytearray(), "err": bytearray()}
        total = 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "out")
                selector.register(process.stderr, selectors.EVENT_READ, "err")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError("Command timed out: " + args[0])
                    for key, _ in selector.select(min(remaining, 0.25)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_OUTPUT:
                            raise RuntimeError("Command output exceeded 8 MiB: " + args[0])
                        buffers[key.data].extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if code:
                detail = buffers["err"].decode("utf-8", "replace").strip()[:600]
                raise RuntimeError(args[0] + " failed: " + (detail or str(code)))
            if args[0].endswith("/journalctl") and buffers["err"]:
                raise RuntimeError("journalctl diagnostics: " + buffers["err"].decode("utf-8", "replace").strip()[:600])
            return buffers["out"].decode("utf-8", "replace")
        except BaseException:
            process.kill()
            process.wait()
            raise


def journal_args(lines, alerts_only=False):
    args = ["/usr/bin/journalctl", "--no-pager", "--all", "--output=json",
            "--since=-24h", "--lines=" + str(lines),
            "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,MESSAGE"]
    for unit in COLLECTORS:
        args += ["--unit", unit]
    if alerts_only:
        # Filter before --lines so collector diagnostics cannot crowd out alerts.
        args += ["--grep", r'^\{.*"rule_id"\s*:']
    return args


def parse_journal(text):
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if isinstance(row, dict) and row.get("_SYSTEMD_UNIT") in COLLECTORS:
            records.append(row)
    # --grep with --lines implies reverse ordering on systemd. Normalize both feeds.
    return sorted(records, key=lambda row: int(row.get("__REALTIME_TIMESTAMP", "0")), reverse=True)


def alert_rows(records):
    alerts = []
    seen = set()
    for record in records:
        message = record.get("MESSAGE")
        if not isinstance(message, str):
            continue
        try:
            alert = json.loads(message)
        except ValueError:
            continue
        if not isinstance(alert, dict) or not isinstance(alert.get("rule_id"), str):
            continue
        if not isinstance(alert.get("event"), dict):
            continue
        # Dedupe only repeated journal records. Preserve genuine repeated observations.
        cursor = record.get("__CURSOR")
        if isinstance(cursor, str) and cursor in seen:
            continue
        if isinstance(cursor, str):
            seen.add(cursor)
        alert = dict(alert)
        alert["collector_unit"] = record["_SYSTEMD_UNIT"]
        alert["journal_cursor"] = cursor
        alert["observed_at_us"] = record.get("__REALTIME_TIMESTAMP")
        alerts.append(alert)
    return alerts


def service_rows(text):
    rows = []
    for block in text.strip().split("\n\n"):
        values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if values.get("Id") in (*COLLECTORS, WEB_UNIT):
            rows.append(values)
    return rows


class Snapshot:
    """One background reader; HTTP requests never spawn commands or select file paths."""
    def __init__(self, binary, runner=run_command):
        self.binary = str(binary)
        self.runner = runner
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.data = {
            "host": socket.gethostname(), "updated_at": None, "loading": True,
            "alerts": [], "services": [], "rules": None, "logs": [],
            "errors": [], "sources": {},
            "window": {"hours": 24, "alert_limit": LIMIT, "log_limit": 100},
        }

    def refresh(self):
        previous = self.read()
        data = copy.deepcopy(previous)
        data["errors"] = []
        operations = {
            "alerts": lambda: alert_rows(parse_journal(self.runner(journal_args(LIMIT, True)))),
            "services": lambda: service_rows(self.runner([
                "/usr/bin/systemctl", "show", "--no-pager",
                "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,ExecMainStatus,ActiveEnterTimestamp,ExecStart,FragmentPath",
                *COLLECTORS, WEB_UNIT])),
            "rules": lambda: json.loads(self.runner([self.binary, "export-rules"])),
            "logs": lambda: parse_journal(self.runner(journal_args(100))),
        }
        for name, operation in operations.items():
            try:
                value = operation()
                if name == "rules" and (not isinstance(value, dict) or
                                       value.get("source") != "embedded" or
                                       not isinstance(value.get("files"), list)):
                    raise ValueError("Executable returned an invalid embedded-rule inventory")
                data[name] = value
                data["sources"][name] = {"ok": True, "updated_at": utc_now()}
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                data["errors"].append({"source": name, "message": str(error)[:700]})
                data["sources"][name] = {
                    "ok": False,
                    "updated_at": previous["sources"].get(name, {}).get("updated_at"),
                }
        data["loading"] = False
        data["updated_at"] = utc_now()
        with self.lock:
            self.data = data

    def read(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def follow(self):
        while not self.stop.is_set():
            self.refresh()
            self.stop.wait(5)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, snapshot, asset_dir=None):
        self.snapshot = snapshot
        self.asset_dir = Path(asset_dir or Path(__file__).parent / "web")
        super().__init__(address, Handler)
        self.allowed_hosts = {"127.0.0.1", "localhost"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ChompDashboard"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def send_body(self, code, data, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Loopback plus Host/Origin checks prevent DNS rebinding and cross-site reads.
        authority = self.headers.get("Host", "").lower()
        origin = self.headers.get("Origin")
        host, separator, port = authority.rpartition(":")
        trusted_host = (separator and host in self.server.allowed_hosts and port.isdecimal()
                        and 1 <= int(port) <= 65535)
        # An SSH tunnel may use a different local port from the VM listening port.
        if (not trusted_host or
            (origin is not None and origin != "http://" + authority) or
                self.headers.get("Sec-Fetch-Site") == "cross-site"):
            self.send_body(403, b"Forbidden", "text/plain")
            return
        path = urlsplit(self.path).path
        if path == "/api/snapshot":
            self.send_body(200, json.dumps(self.server.snapshot.read()).encode(), "application/json")
        elif path in ASSETS:
            name, content_type = ASSETS[path]
            try:
                content = (self.server.asset_dir / name).read_bytes()
            except OSError:
                self.send_body(503, b"Dashboard assets unavailable", "text/plain")
                return
            self.send_body(200, content, content_type)
        else:
            self.send_body(404, b"Not found", "text/plain")

    def do_POST(self):
        self.send_body(405, b"Read-only dashboard", "text/plain")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def log_message(self, format_string, *args):
        # No request strings or untrusted URLs in service logs.
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("/usr/local/lib/chomp-edr/chompedr"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    binary = args.binary.resolve(strict=True)
    snapshot = Snapshot(binary)
    server = DashboardServer(("127.0.0.1", args.port), snapshot)
    reader = threading.Thread(target=snapshot.follow, daemon=True)
    reader.start()
    print("Chomp dashboard listening at http://127.0.0.1:" + str(args.port), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        snapshot.stop.set()
        server.server_close()
        reader.join(timeout=45)


if __name__ == "__main__":
    main()
