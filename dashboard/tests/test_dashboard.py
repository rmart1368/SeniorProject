"""HTTP and journal adapter checks; all data comes from explicit test fixtures."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


WEB = module("dashboard", ROOT / "dashboard/server.py")
INSTALLER = module("dashboard_installer", ROOT / "scripts/install-dashboard-linux.py")
ALERT = {"rule_id": "CHOMP-SSH-001", "rule_name": "<script>alert(1)</script>",
         "severity": "high", "event": {"timestamp": "2026-10-20T12:00:00Z", "host": "lab"}}


def record(cursor="one", message=None):
    return {"__CURSOR": cursor, "__REALTIME_TIMESTAMP": str(1792497600000000 + (1 if cursor == "two" else 0)),
            "_SYSTEMD_UNIT": "chompedr-ssh.service", "MESSAGE": json.dumps(ALERT) if message is None else message}


class AdapterTests(unittest.TestCase):
    def test_journal_filters_units_and_preserves_real_repeats(self):
        rows = [record(), record(), record("two"), record("log", "collector started"),
                dict(record("other"), _SYSTEMD_UNIT="other.service")]
        parsed = WEB.parse_journal("\n".join(json.dumps(r) for r in rows))
        alerts = WEB.alert_rows(parsed)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["journal_cursor"], "two")
        self.assertEqual(alerts[0]["rule_name"], ALERT["rule_name"])

    def test_both_journal_orderings_produce_newest_first(self):
        for rows in [[record(), record("two")], [record("two"), record()]]:
            parsed = WEB.parse_journal("\n".join(json.dumps(row) for row in rows))
            self.assertEqual(WEB.alert_rows(parsed)[0]["journal_cursor"], "two")

    def test_invalid_alert_payloads_are_not_displayed_as_detections(self):
        for message in ["not json", "[]", '{"rule_id":3}', '{"rule_id":"x","event":null}']:
            self.assertEqual(WEB.alert_rows([record(message=message)]), [])

    def test_journal_query_is_bounded_and_filters_before_line_limit(self):
        args = WEB.journal_args(500, True)
        self.assertIn("--since=-24h", args)
        self.assertIn("--lines=500", args)
        self.assertIn("--grep", args)
        self.assertIn("--all", args)
        for unit in WEB.COLLECTORS:
            self.assertIn(unit, args)

    def test_refresh_retains_cached_data_and_reports_failures(self):
        failing = False

        def runner(args):
            if failing:
                raise RuntimeError("journal permission denied")
            if "export-rules" in args:
                return json.dumps({"source": "embedded", "version": "0.1.0", "files": []})
            if "show" in args:
                return "Id=chompedr-ssh.service\nActiveState=active\nMainPID=42\n"
            return json.dumps(record())

        snapshot = WEB.Snapshot("/installed/chompedr", runner)
        snapshot.refresh()
        first = snapshot.read()
        self.assertEqual(first["alerts"][0]["rule_id"], "CHOMP-SSH-001")
        self.assertTrue(first["sources"]["alerts"]["ok"])
        failing = True
        snapshot.refresh()
        cached = snapshot.read()
        self.assertEqual(cached["alerts"], first["alerts"])
        self.assertFalse(cached["sources"]["alerts"]["ok"])
        self.assertEqual(cached["sources"]["alerts"]["updated_at"], first["sources"]["alerts"]["updated_at"])
        self.assertEqual(len(cached["errors"]), 4)

    def test_command_timeout_and_output_limit(self):
        with self.assertRaises(RuntimeError):
            WEB.run_command([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
        with self.assertRaises(RuntimeError):
            WEB.run_command([sys.executable, "-c", "import sys; sys.stdout.write('x' * (9 * 1024 * 1024))"])
        self.assertEqual(WEB.run_command([sys.executable, "-c", "print('ok')"]).strip(), "ok")


class HttpTests(unittest.TestCase):
    def setUp(self):
        snapshot = WEB.Snapshot("/unused", lambda _: "")
        snapshot.data["alerts"] = [ALERT]
        self.server = WEB.DashboardServer(("127.0.0.1", 0), snapshot)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, path="/", headers=None, method="GET"):
        return urlopen(Request(self.url + path, headers=headers or {}, method=method), timeout=3)

    def test_page_and_api_security_headers(self):
        with self.request() as response:
            self.assertIn(b"Alert activity", response.read())
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
        with self.request("/api/snapshot") as response:
            self.assertEqual(json.load(response)["alerts"][0]["rule_id"], "CHOMP-SSH-001")
        for asset in ["/app.js", "/style.css"]:
            with self.request(asset) as response:
                self.assertEqual(response.status, 200)

    def test_forwarded_local_port_is_allowed(self):
        with self.request("/api/snapshot", {"Host": "127.0.0.1:9000", "Origin": "http://127.0.0.1:9000"}) as response:
            self.assertEqual(response.status, 200)

    def test_origin_host_and_write_rejection(self):
        for headers in [{"Host": "attacker.example"},
                        {"Origin": "https://attacker.example"},
                        {"Sec-Fetch-Site": "cross-site"}]:
            with self.assertRaises(HTTPError) as raised:
                self.request("/api/snapshot", headers)
            self.assertEqual(raised.exception.code, 403)
            raised.exception.close()
        with self.assertRaises(HTTPError) as raised:
            self.request("/api/snapshot", method="POST")
        self.assertEqual(raised.exception.code, 405)
        raised.exception.close()

    def test_arbitrary_paths_are_not_served(self):
        for path in ["/server.py", "/../server.py", "/%2e%2e/server.py", "/api/run"]:
            with self.assertRaises(HTTPError) as raised:
                self.request(path)
            self.assertEqual(raised.exception.code, 404)
            raised.exception.close()


class InstallationTests(unittest.TestCase):
    def test_stage_and_replace_without_activation(self):
        with tempfile.TemporaryDirectory(prefix="chomp-dashboard-") as folder:
            root = Path(folder)
            written = INSTALLER.install(destdir=root)
            self.assertEqual(len(written), 5)
            assets = root / INSTALLER.DESTINATION.relative_to("/")
            self.assertEqual(assets.stat().st_mode & 0o777, 0o755)
            self.assertEqual((assets / "web").stat().st_mode & 0o777, 0o755)
            unit = root / INSTALLER.UNIT.relative_to("/")
            content = unit.read_text()
            for expected in ["DynamicUser=yes", "SupplementaryGroups=systemd-journal",
                             "ProtectSystem=strict", "Restart=always", "--port 8765"]:
                self.assertIn(expected, content)
            self.assertFalse((unit.parent / "multi-user.target.wants").exists())
            with self.assertRaises(ValueError):
                INSTALLER.install(destdir=root)
            INSTALLER.install(port=9000, replace=True, destdir=root)
            self.assertIn("--port 9000", unit.read_text())
            self.assertFalse(list(root.rglob(".chomp-system-*")))

    def test_invalid_port_leaves_no_installation(self):
        with tempfile.TemporaryDirectory() as folder:
            for port in [80, 0, 65536]:
                with self.assertRaises(ValueError):
                    INSTALLER.install(port=port, destdir=folder)
            self.assertFalse(list(Path(folder).iterdir()))


if __name__ == "__main__":
    unittest.main()
