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



class ResponseControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = module('response_worker_for_web', ROOT / 'response/worker.py')
        self.control = module('response_control_for_web', ROOT / 'response/control.py')
        self.state = self.root / 'state'
        queue = self.worker.Queue(self.state)
        response = {'action': 'block_ip', 'target': {'field': 'source.ip'}, 'mode': 'approval_required'}
        for cursor in ('first', 'second'):
            queue.ingest({'_SYSTEMD_UNIT': self.worker.UNITS[0], '__CURSOR': cursor,
                          'MESSAGE': json.dumps({'rule_id': 'web-test', 'event': {'source': {'ip': '192.0.2.4'}}, 'response': [response]})})
        self.ids = [r['id'] for r in queue.rows()]
        queue.db.close()
        self.token = self.control.management_token(self.state)
        self.socket = self.root / 'runtime/control.sock'
        self.broker = self.control.ControlServer(self.socket, lambda: self.worker.Queue(self.state), self.token)
        self.broker_thread = threading.Thread(target=self.broker.serve_forever, daemon=True)
        self.broker_thread.start()
        self.snapshot = WEB.Snapshot('/unused', response_socket=self.socket)
        self.snapshot.data['responses'] = WEB.response_control(self.socket, {'command': 'overview'})
        self.server = WEB.DashboardServer(('127.0.0.1', 0), self.snapshot)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_address[1])
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.broker.shutdown()
        self.broker.server_close()
        self.broker_thread.join(timeout=3)

    def decide(self, decision='approve', index=0, token=None, origin=None):
        headers = {'Authorization': 'Bearer ' + (self.token if token is None else token),
                   'Origin': self.url if origin is None else origin}
        return urlopen(Request(self.url + '/api/responses/' + self.ids[index] + '/' + decision,
                               headers=headers, method='POST'), timeout=3)

    def test_snapshot_lists_targets_modes_and_audit_without_token(self):
        with urlopen(self.url + '/api/snapshot', timeout=3) as response:
            raw = response.read()
            data = json.loads(raw)
        self.assertNotIn(self.token.encode(), raw)
        self.assertEqual(data['responses']['pending_count'], 2)
        row = data['responses']['requests'][0]
        self.assertEqual(row['target']['ip'], '192.0.2.4')
        self.assertEqual(row['response']['mode'], 'approval_required')
        self.assertEqual(len(data['responses']['audit']), 2)

    def test_browser_approval_and_rejection_persist_without_executing_in_web_server(self):
        with self.decide() as response:
            self.assertEqual(json.load(response)['status'], 'queued')
        with self.decide('reject', 1) as response:
            self.assertEqual(json.load(response)['status'], 'rejected')
        overview = WEB.response_control(self.socket, {'command': 'overview'})
        self.assertEqual({r['status'] for r in overview['requests']}, {'queued', 'rejected'})
        self.assertEqual(overview['pending_count'], 0)
        self.assertEqual(len(overview['audit']), 4)
        with self.assertRaises(HTTPError) as raised:
            self.decide()
        self.assertEqual(raised.exception.code, 409)
        raised.exception.close()

    def test_invalid_token_and_cross_origin_cannot_approve(self):
        for kwargs in [{'token': 'x' * 43}, {'token': ''}, {'origin': 'http://attacker.example'}, {'origin': ''}]:
            with self.assertRaises(HTTPError) as raised:
                self.decide(**kwargs)
            self.assertEqual(raised.exception.code, 403)
            raised.exception.close()
        self.assertEqual(WEB.response_control(self.socket, {'command': 'overview'})['pending_count'], 2)

    def test_authenticated_pause_resume_rebaselines_preservation(self):
        preserve = module('preserve_for_web', ROOT / 'response/preserve.py')
        target = self.root / 'config.txt'
        target.write_text('trusted')
        queue = self.worker.Queue(self.state, executor=lambda response, target, state, key:
                                  preserve.activate(state, key, target['path'], refresh=target.get('refresh_baseline', False)))
        self.addCleanup(queue.db.close)
        rule = {'id': 'preserve-web', 'name': 'Preserve web test', 'severity': 'high', 'enabled': True,
                'response': [{'action': 'preserve_file', 'target': {'path': str(target)}, 'mode': 'automatic'}]}
        manager = preserve.Manager(queue, '/unused', '/unused', loader=lambda: [rule])
        manager.tick()
        queue.run_one()
        self.ids.append(queue.rows()[-1]['id'])
        with self.decide('pause', 2) as result:
            self.assertEqual(json.load(result)['status'], 'paused')
        target.write_text('legitimate')
        manager.tick()
        self.assertEqual(target.read_text(), 'legitimate')
        with self.decide('resume', 2) as result:
            self.assertEqual(json.load(result)['status'], 'queued')
        queue.run_one()
        target.write_text('malicious')
        manager.tick()
        self.assertEqual(target.read_text(), 'legitimate')

    def test_socket_peer_authorization_and_unavailable_service(self):
        self.broker.allowed_uids = set()
        with self.assertRaises(WEB.ControlError):
            WEB.response_control(self.socket, {'command': 'overview'})
        self.snapshot.response_socket = self.root / 'missing.sock'
        with self.assertRaises(HTTPError) as raised:
            self.decide()
        self.assertEqual(raised.exception.code, 503)
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
