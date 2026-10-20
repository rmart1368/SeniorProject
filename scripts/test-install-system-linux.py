"""Stage the system installation without root or running service-control commands."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve(strict=True)
SPEC = importlib.util.spec_from_file_location("system_installer", Path(__file__).with_name("install-system-linux.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class SystemInstallation(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="chomp-system-test-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)

    def install(self, paths=None, replace=False):
        return INSTALLER.install(BINARY, paths or INSTALLER.DEFAULT_PATHS, self.root, replace)

    def test_staging_and_unit_validation(self):
        written = self.install(["/tmp/example with spaces", "/etc/passwd"])
        self.assertEqual(len(written), 5)
        binary = self.root / INSTALLER.BINARY_PATH.relative_to("/")
        self.assertEqual(binary.read_bytes(), BINARY.read_bytes())
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        directory = self.root / INSTALLER.UNIT_DIR.relative_to("/")
        for name in INSTALLER.SERVICES:
            text = (directory / name).read_text()
            self.assertIn("Restart=always", text)
            self.assertIn("RestartSec=10s", text)
            self.assertIn("StartLimitIntervalSec=0", text)
            self.assertIn("PartOf=chompedr.target", text)
        self.assertIn('--path "/tmp/example with spaces"', (directory / "chompedr-files.service").read_text())
        self.assertIn("WantedBy=multi-user.target", (directory / "chompedr.target").read_text())
        self.assertFalse((directory / "multi-user.target.wants").exists())
        self.assertFalse((self.root / "var/lib/chomp-edr").exists())
        # Validate staged units using the staged executable, without activation.
        verify_dir = self.root / "verify"
        verify_dir.mkdir()
        for name in [*INSTALLER.SERVICES, "chompedr.target"]:
            text = (directory / name).read_text().replace(str(INSTALLER.BINARY_PATH), str(binary))
            (verify_dir / name).write_text(text)
        verify = shutil.which("systemd-analyze")
        self.assertIsNotNone(verify)
        result = subprocess.run([verify, "verify", *map(str, verify_dir.iterdir())],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_paths_fail_before_writing(self):
        for path in ["relative", "/tmp/../etc", "/tmp/x%y", "/tmp/x$y", '/tmp/x"y', "/tmp/x\\y", "/tmp/x\ny"]:
            with self.assertRaises(ValueError, msg=path):
                self.install([path])
        self.assertFalse((self.root / "usr").exists())
        with self.assertRaises(ValueError):
            INSTALLER.units(["/tmp/" + str(i) for i in range(65)])

    def test_upgrade_preserves_checkpoint_and_requires_replace(self):
        self.install()
        state = self.root / "var/lib/chomp-edr/ssh"
        state.mkdir(parents=True)
        (state / "snapshot.json").write_text("existing state")
        with self.assertRaises(ValueError):
            self.install()
        self.install(replace=True)
        self.assertEqual((state / "snapshot.json").read_text(), "existing state")
        self.assertFalse(list(self.root.rglob(".chomp-system-*")))

    def test_symlink_parent_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "usr").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.install(replace=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_invalid_binary_is_rejected(self):
        fake = self.root / "fake"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        with self.assertRaises(ValueError):
            INSTALLER.install(fake, INSTALLER.DEFAULT_PATHS, self.root)


if __name__ == "__main__":
    unittest.main()
