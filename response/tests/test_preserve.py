import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'response'))
import preserve as P
import worker as W


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'config'
        self.target.mkdir()
        (self.target / 'app.conf').write_text('trusted=yes\n')
        (self.target / 'nested').mkdir()
        (self.target / 'nested/other.conf').write_bytes(b'original\x00')
        self.q = W.Queue(self.root / 'state')
        self.addCleanup(self.q.db.close)
        self.rule = {'id': 'PRESERVE-TEST', 'name': 'Config preservation', 'severity': 'high', 'enabled': True,
                     'response': [{'action': 'preserve_file', 'target': {'path': str(self.target)}, 'mode': 'automatic'}]}
        self.rules = [self.rule]
        self.manager = P.Manager(self.q, '/unused', '/unused', loader=lambda: self.rules)

    def activate(self):
        self.manager.tick()
        self.q.run_one()
        self.assertEqual(self.q.rows()[-1]['status'], 'active')

    def test_recursive_content_additions_deletions_permissions_and_alerts(self):
        expected = P.snapshot(str(self.target))
        self.activate()
        (self.target / 'app.conf').write_text('attacker=yes')
        (self.target / 'app.conf').chmod(0o600)
        (self.target / 'nested/other.conf').unlink()
        (self.target / 'extra').mkdir()
        (self.target / 'extra/new').write_text('new')
        with patch('builtins.print') as output:
            self.manager.tick()
        alert = json.loads(output.call_args.args[0])
        self.assertEqual(alert['rule_id'], self.rule['id'])
        self.assertGreater(alert['preservation']['changed_count'], 0)
        self.assertEqual(P.snapshot(str(self.target)), expected)
        self.assertEqual(self.q.rows(True)[-1]['status'], 'restored')
        # Reads do not trigger changes/restoration.
        (self.target / 'app.conf').read_text()
        count = len(self.q.rows(True))
        self.manager.tick()
        self.assertEqual(len(self.q.rows(True)), count)

    def test_disable_edit_reenable_recaptures_but_restart_keeps_baseline(self):
        self.activate()
        self.rule['enabled'] = False
        self.manager.tick()
        self.assertEqual(self.q.rows()[0]['status'], 'disabled')
        (self.target / 'app.conf').write_text('legitimate update')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'legitimate update')
        self.rule['enabled'] = True
        self.activate()
        (self.target / 'app.conf').write_text('attacker again')
        restarted = P.Manager(self.q, '/unused', '/unused', loader=lambda: self.rules)
        restarted.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'legitimate update')

    def test_single_file_removed_and_replaced_by_symlink(self):
        self.rule['response'][0]['target']['path'] = str(self.target / 'app.conf')
        self.activate()
        (self.target / 'app.conf').unlink()
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')
        outside = self.root / 'outside'
        outside.write_text('must remain unchanged')
        (self.target / 'app.conf').unlink()
        (self.target / 'app.conf').symlink_to(outside)
        self.manager.tick()
        self.assertFalse((self.target / 'app.conf').is_symlink())
        self.assertEqual(outside.read_text(), 'must remain unchanged')

    def test_directory_removed_and_baseline_file_replaced_with_directory(self):
        self.activate()
        import shutil
        shutil.rmtree(self.target)
        self.manager.tick()
        self.assertEqual((self.target / 'nested/other.conf').read_bytes(), b'original\x00')
        (self.target / 'app.conf').unlink()
        (self.target / 'app.conf').mkdir()
        (self.target / 'app.conf/new').write_text('bad')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')

    def test_approval_before_activation_and_cancellation_when_disabled(self):
        self.rule['response'][0]['mode'] = 'approval_required'
        self.manager.tick()
        self.assertFalse(self.q.run_one())
        self.assertEqual(self.q.rows()[0]['status'], 'pending')
        self.q.decide(self.q.rows()[0]['id'], True)
        self.q.run_one()
        self.assertEqual(self.q.rows()[0]['status'], 'active')
        self.rule['enabled'] = False
        self.manager.tick()
        self.rule['enabled'] = True
        self.manager.tick()
        pending = self.q.rows()[-1]['id']
        self.rule['enabled'] = False
        self.manager.tick()
        with self.assertRaises(ValueError):
            self.q.decide(pending, True)

    def test_dry_run_never_restores(self):
        self.rule['response'][0]['mode'] = 'dry_run'
        self.activate()
        (self.target / 'app.conf').write_text('changed')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'changed')
        self.assertEqual(self.q.rows(True)[-1]['status'], 'dry_run')

    def test_reject_baseline_symlinks_overlapping_targets_and_state(self):
        (self.target / 'link').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            P.snapshot(str(self.target))
        (self.target / 'link').unlink()
        other = dict(self.rule, id='other')
        self.rules.append(other)
        with self.assertRaises(ValueError):
            self.manager.tick()
        with self.assertRaises(ValueError):
            P.activate(self.q.state, 'test', str(self.root))

    def test_extended_attributes_restore(self):
        file = self.target / 'app.conf'
        os.setxattr(file, 'user.chomp-test', b'trusted')
        self.activate()
        os.setxattr(file, 'user.chomp-test', b'changed')
        self.manager.tick()
        self.assertEqual(os.getxattr(file, 'user.chomp-test'), b'trusted')

    def test_pause_resume_captures_new_contents(self):
        self.activate()
        request_id = self.q.rows()[0]['id']
        self.q.preservation_state(request_id, False)
        (self.target / 'app.conf').write_text('maintenance')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'maintenance')
        self.q.preservation_state(request_id, True)
        self.manager.tick()
        self.q.run_one()
        self.assertEqual(self.q.rows()[0]['status'], 'active')
        (self.target / 'app.conf').write_text('attack')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'maintenance')

    def test_invalid_reload_keeps_protection_after_restart(self):
        self.activate()
        def invalid():
            raise ValueError('invalid rule YAML')
        restarted = P.Manager(self.q, '/unused', '/unused', loader=invalid)
        (self.target / 'app.conf').write_text('attack during malformed edit')
        restarted.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')

    def test_restore_does_not_rewrite_unchanged_files(self):
        self.activate()
        unchanged = (self.target / 'nested/other.conf').stat().st_ino
        (self.target / 'app.conf').write_text('attack')
        self.manager.tick()
        self.assertEqual((self.target / 'nested/other.conf').stat().st_ino, unchanged)


    def test_oversized_modified_file_is_restored(self):
        self.activate()
        (self.target / 'app.conf').write_bytes(b'X' * 256)
        with patch.object(P, 'MAX_BYTES', 128):
            self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')

    def test_actual_yaml_loader_and_live_enabled_reload(self):
        binary = ROOT / 'target/debug/chompedr'
        if not binary.is_file():
            self.skipTest('Build Rust CLI before running loader integration')
        source = self.root / 'preserve.yaml'
        yaml = ('version: 1\nrules:\n  - id: LOAD-TEST\n    name: Live preservation\n    severity: high\n    enabled: true\n    detection:\n      all:\n        - field: event.type\n          op: equals\n          value: file_metadata_changed\n    response:\n      - action: preserve_file\n        mode: automatic\n        target: {path: ' + str(self.target) + '}\n')
        source.write_text(yaml)
        manager = P.Manager(self.q, source, binary)
        manager.tick()
        self.q.run_one()
        (self.target / 'app.conf').write_text('attacker')
        manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')
        source.write_text(yaml.replace('enabled: true', 'enabled: false'))
        manager.tick()
        self.assertEqual(self.q.rows()[-1]['status'], 'disabled')
        (self.target / 'app.conf').write_text('approved edit')
        source.write_text(yaml)
        manager.tick()
        self.q.run_one()
        (self.target / 'app.conf').write_text('attack again')
        manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'approved edit')


    def test_overlapping_reload_does_not_stop_existing_guard(self):
        self.activate()
        self.rules.append(dict(self.rule, id='overlapping'))
        (self.target / 'app.conf').write_text('attack during invalid reload')
        self.manager.tick()
        self.assertEqual((self.target / 'app.conf').read_text(), 'trusted=yes\n')
        self.assertEqual(len(self.q.rows()), 1)
        self.assertEqual(self.q.rows()[0]['status'], 'active')


if __name__ == '__main__':
    unittest.main()
