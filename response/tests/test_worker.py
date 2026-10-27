import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('responses', Path(__file__).resolve().parents[1] / 'worker.py')
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)


def record(response, event=None, cursor='cursor-1'):
    return {'_SYSTEMD_UNIT': W.UNITS[0], '__CURSOR': cursor, 'MESSAGE': json.dumps({
        'rule_id': 'test', 'event': event or {'source': {'ip': '192.0.2.1'}}, 'response': [response]})}


def response(action='block_ip', mode='approval_required'):
    return {'action': action, 'target': {'field': 'source.ip'}, 'mode': mode, 'duration': '15m'}


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state'
        self.calls = []
        self.q = W.Queue(self.state, lambda *args: self.calls.append(args) or 'done')
        self.addCleanup(self.q.db.close)

    def status(self):
        return self.q.rows()[0]['status']

    def test_approval_rejection_and_automatic(self):
        self.q.ingest(record(response()))
        self.assertFalse(self.q.run_one())
        self.assertEqual(self.status(), 'pending')
        key = self.q.rows()[0]['id']
        self.q.decide(key, True)
        self.assertTrue(self.q.run_one())
        self.assertEqual(self.status(), 'succeeded')
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(ValueError):
            self.q.decide(key, True)
        self.q.ingest(record(response(), cursor='cursor-2'))
        self.q.decide(self.q.rows()[1]['id'], False)
        self.assertFalse(self.q.run_one())
        self.assertEqual(self.q.rows()[1]['status'], 'rejected')
        self.q.ingest(record(response(mode='automatic'), cursor='cursor-3'))
        self.assertTrue(self.q.run_one())
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([r['status'] for r in self.q.rows(True)][:4], ['pending', 'queued', 'executing', 'succeeded'])

    def test_dry_run_replay_restart_and_untrusted_units(self):
        self.q.ingest(record(response(mode='dry_run')))
        self.assertFalse(self.q.run_one())
        self.assertEqual(self.status(), 'dry_run')
        other = W.Queue(self.state, self.q.executor)
        self.addCleanup(other.db.close)
        other.ingest(record(response(mode='dry_run')))
        self.assertEqual(len(other.rows()), 1)
        forged = record(response(mode='automatic'), cursor='evil')
        forged['_SYSTEMD_UNIT'] = 'untrusted.service'
        other.ingest(forged)
        self.assertEqual(len(other.rows()), 1)
        self.assertFalse(other.run_one())
        self.assertEqual(self.calls, [])

    def test_failed_and_interrupted_requests_never_retry(self):
        self.q.ingest(record(response(mode='automatic')))
        self.q.executor = lambda *args: (_ for _ in ()).throw(ValueError('failed operation'))
        self.q.run_one()
        self.assertEqual(self.status(), 'failed')
        self.q.ingest(record(response(mode='automatic')))
        self.assertFalse(self.q.run_one())
        self.q.ingest(record(response(mode='automatic'), cursor='second'))
        with self.q.db:
            self.q.transition(self.q.rows()[1]['id'], 'executing', 'simulated crash')
        self.assertFalse(self.q.run_one())

    def test_bad_mode_missing_target_and_unsupported_fail(self):
        for index, item in enumerate([response(mode='typo'), response(action='isolate_host'),
                                      dict(response(), target={'field': 'missing'})]):
            self.q.ingest(record(item, cursor=str(index)))
        self.assertTrue(all(row['status'] == 'failed' for row in self.q.rows()))
        self.assertFalse(self.q.run_one())

    def test_two_workers_cannot_claim_the_same_request(self):
        self.q.ingest(record(response(mode='automatic')))
        other = W.Queue(self.state, self.q.executor)
        self.addCleanup(other.db.close)
        self.assertTrue(other.run_one())
        self.assertFalse(self.q.run_one())
        self.assertEqual(len(self.calls), 1)


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)

    def file_request(self, action):
        file = self.root / 'target'
        file.write_text('disposable test content')
        info = file.stat()
        event = {'file': {'path': str(file), 'after': {'inode': info.st_ino, 'device': info.st_dev,
                 'size': info.st_size, 'modified_seconds': info.st_mtime_ns // 1000000000,
                 'modified_nanoseconds': info.st_mtime_ns % 1000000000}}}
        request = {'action': action, 'target': {'field': 'file.path'}, 'mode': 'approval_required'}
        return file, request, event

    def test_real_delete_requires_approval_and_quarantine_retains_contents(self):
        file, request, event = self.file_request('delete_file')
        queue = W.Queue(self.state)
        self.addCleanup(queue.db.close)
        queue.ingest(record(request, event))
        self.assertFalse(queue.run_one())
        self.assertTrue(file.exists())
        queue.decide(queue.rows()[0]['id'], True)
        self.assertTrue(queue.run_one())
        self.assertFalse(file.exists())
        self.assertEqual(queue.rows()[0]['status'], 'succeeded')
        file, request, event = self.file_request('quarantine_file')
        target = W.resolve(request, event)
        W.execute(request, target, self.state, 'quarantine-test')
        self.assertFalse(file.exists())
        self.assertEqual((self.state / 'quarantine/quarantine-test').read_text(), 'disposable test content')

    def test_automatic_file_deletion_and_approval_revalidates_target(self):
        file, request, event = self.file_request('delete_file')
        request['mode'] = 'automatic'
        queue = W.Queue(self.state)
        self.addCleanup(queue.db.close)
        queue.ingest(record(request, event))
        self.assertTrue(queue.run_one())
        self.assertFalse(file.exists())
        self.assertEqual(queue.rows()[0]['status'], 'succeeded')
        file, request, event = self.file_request('delete_file')
        queue.ingest(record(request, event, cursor='later'))
        key = queue.rows()[1]['id']
        file.write_text('replacement after request')
        queue.decide(key, True)
        queue.run_one()
        self.assertEqual(queue.rows()[1]['status'], 'failed')
        self.assertEqual(file.read_text(), 'replacement after request')

    def test_suspend_real_child_and_resume_manually(self):
        child = subprocess.Popen(['sleep', '30'])
        try:
            ticks = int(Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
            request = {'action': 'suspend_process', 'target': {'pid_field': 'process.pid', 'start_time_field': 'process.start_ticks'}}
            target = W.resolve(request, {'process': {'pid': child.pid, 'start_ticks': ticks}})
            W.execute(request, target, self.state, 'suspend')
            _, status = os.waitpid(child.pid, os.WUNTRACED)
            self.assertTrue(os.WIFSTOPPED(status))
            self.assertEqual(os.WSTOPSIG(status), signal.SIGSTOP)
        finally:
            child.send_signal(signal.SIGCONT)
            child.terminate()
            child.wait(timeout=5)

    def test_changed_file_and_symlinks_are_rejected(self):
        file, request, event = self.file_request('delete_file')
        target = W.resolve(request, event)
        file.write_text('changed after approval was requested')
        with self.assertRaises(ValueError):
            W.execute(request, target, self.state, 'changed')
        self.assertTrue(file.exists())
        file.unlink()
        file.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            W.resolve(request, event)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            W.file_parent(str(alias / 'target'))

    def test_real_process_identity_and_signal(self):
        child = subprocess.Popen(['sleep', '30'])
        try:
            ticks = int(Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
            request = {'action': 'terminate_process', 'target': {'pid_field': 'process.pid', 'start_time_field': 'process.start_ticks'}}
            target = W.resolve(request, {'process': {'pid': child.pid, 'start_ticks': ticks}})
            with self.assertRaises(ValueError):
                W.execute(request, dict(target, start_ticks=ticks + 1), self.state, 'wrong')
            self.assertIsNone(child.poll())
            W.execute(request, target, self.state, 'right')
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_firewall_uses_fixed_arguments_and_duration(self):
        item = response(mode='automatic')
        target = W.resolve(item, {'source': {'ip': '192.0.2.1'}})
        with patch.object(W.subprocess, 'run') as run:
            W.execute(item, target, self.state, 'block')
        args = run.call_args.args[0]
        self.assertEqual(args[0], '/usr/bin/firewall-cmd')
        self.assertIn('--timeout=900', args)
        self.assertIn('source address="192.0.2.1"', args[1])
        with self.assertRaises(ValueError):
            W.resolve(item, {'source': {'ip': '127.0.0.1'}})
        with self.assertRaises(ValueError):
            W.resolve(item, {'source': {'ip': '192.0.2.1; whoami'}})


if __name__ == '__main__':
    unittest.main()
