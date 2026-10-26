"""Exercise installation in disposable user directories; never start a service."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve(strict=True)
INSTALLER = Path(__file__).with_name("install-linux.py")
VERIFY = shutil.which("systemd-analyze")


class Installation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chomp install ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.prefix = self.home / ".local"
        self.config = self.root / "config"
        self.state = self.root / "state"
        trap = self.root / "trap"
        trap.mkdir()
        fake = trap / "systemctl"
        fake.write_text('#!/bin/sh\necho invoked > "$HOME/systemctl-called"\nexit 99\n')
        fake.chmod(0o755)
        self.env = dict(os.environ, HOME=str(self.home), XDG_CONFIG_HOME=str(self.config),
                        XDG_STATE_HOME=str(self.state), PATH=str(trap) + os.pathsep + os.environ["PATH"])

    def install(self, *args):
        return subprocess.run([sys.executable, str(INSTALLER), "--binary", str(BINARY), *args],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_binary_install_and_no_service_side_effects(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = self.prefix / "bin/chompedr"
        self.assertEqual(binary.read_bytes(), BINARY.read_bytes())
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        result = subprocess.run([str(binary), "monitor", "--status"], env=self.env,
                                capture_output=True, text=True, timeout=10, check=True)
        self.assertFalse(json.loads(result.stdout)["saved_progress"])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse((self.home / "systemctl-called").exists())

    def test_cli_available_in_new_bash_and_profile_update_is_idempotent(self):
        profile = self.home / ".bashrc"
        profile.write_text("# existing user settings\n")
        self.assertEqual(self.install().returncode, 0)
        for name in (".profile", ".bashrc"):
            self.assertIn("# ChompEDR command path", (self.home / name).read_text())
        result = subprocess.run(["bash", "--noprofile", "--rcfile", str(profile),
                                 "-ic", "chompedr --version"], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("chompedr ", result.stdout)
        before = profile.read_bytes()
        self.assertEqual(self.install("--replace").returncode, 0)
        self.assertEqual(profile.read_bytes(), before)
        self.assertTrue(profile.read_text().startswith("# existing user settings"))

    def test_service_unit_valid_with_spaces_and_stays_disabled(self):
        result = self.install("--service")
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = self.config / "systemd/user/chompedr.service"
        text = unit.read_text()
        self.assertIn('ExecStart="' + str(self.prefix / "bin/chompedr") + '" monitor', text)
        self.assertIn('"' + str(self.state / "chomp-edr/ssh") + '"', text)
        self.assertIn("Restart=no", text)
        self.assertFalse((unit.parent / "default.target.wants").exists())
        self.assertFalse((self.home / "systemctl-called").exists())
        self.assertIsNotNone(VERIFY, "CI must have systemd-analyze for unit validation")
        verified = subprocess.run([VERIFY, "verify", str(unit)], capture_output=True, text=True, timeout=30)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_upgrade_requires_explicit_replace_and_preserves_state(self):
        self.assertEqual(self.install("--service").returncode, 0)
        self.state.mkdir()
        sentinel = self.state / "existing-checkpoint"
        sentinel.write_text("preserve me")
        rejected = self.install("--service")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("--replace", rejected.stderr)
        self.assertEqual(self.install("--service", "--replace").returncode, 0)
        self.assertEqual(sentinel.read_text(), "preserve me")
        self.assertFalse(list(self.root.rglob(".chomp-install-*")))

    def test_invalid_paths_fail_before_installation(self):
        for args in [("--prefix", "relative"), ("--prefix", str(self.root / "bad%prefix"), "--service")]:
            result = self.install(*args)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "bad%prefix").exists())
        self.assertFalse(self.prefix.exists())

    def test_replace_does_not_follow_destination_symlinks(self):
        target = self.root / "unrelated"
        target.write_text("preserve me")
        destination = self.prefix / "bin/chompedr"
        destination.parent.mkdir(parents=True)
        destination.symlink_to(target)
        result = self.install("--replace")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()
