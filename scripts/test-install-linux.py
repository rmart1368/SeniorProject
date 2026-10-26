"""Stage the system installation without root or running service-control commands."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BINARY = Path(sys.argv.pop(1)).resolve(strict=True)
SPEC = importlib.util.spec_from_file_location("system_installer", Path(__file__).with_name("install-linux.py"))
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
        self.assertEqual(len(written), 11)
        binary = self.root / INSTALLER.BINARY_PATH.relative_to("/")
        self.assertEqual(binary.read_bytes(), BINARY.read_bytes())
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        launcher = self.root / INSTALLER.CLI_PATH.relative_to("/")
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
        # Verify argument forwarding through the PATH launcher against the same binary.
        local_launcher = self.root / "launcher"
        local_launcher.write_text(launcher.read_text().replace(str(INSTALLER.BINARY_PATH), str(binary)))
        local_launcher.chmod(0o755)
        result = subprocess.run([str(local_launcher), "--version"],
                                capture_output=True, text=True, check=True)
        direct = subprocess.run([str(binary), "--version"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, direct.stdout)
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
        for name in [*INSTALLER.SERVICES, "chompedr.target", "chompedr-dashboard.service"]:
            text = (directory / name).read_text().replace(str(INSTALLER.BINARY_PATH), str(binary))
            (verify_dir / name).write_text(text)
        verify = shutil.which("systemd-analyze")
        self.assertIsNotNone(verify)
        result = subprocess.run([verify, "verify", *map(str, verify_dir.iterdir())],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dashboard_installed_and_invalid_port_is_preflighted(self):
        for port in (80, 0, 65536):
            with self.assertRaises(ValueError):
                INSTALLER.install(BINARY, destdir=self.root, port=port)
            self.assertFalse((self.root / "usr").exists())
        written = INSTALLER.install(BINARY, destdir=self.root, port=9000)
        self.assertEqual(len(written), 11)
        assets = self.root / INSTALLER.DASHBOARD_DIR.relative_to("/")
        self.assertEqual((assets / "web").stat().st_mode & 0o777, 0o755)
        self.assertTrue((assets / "server.py").is_file())
        unit = self.root / INSTALLER.DASHBOARD_UNIT.relative_to("/")
        for expected in ("DynamicUser=yes", "SupplementaryGroups=systemd-journal",
                         "ProtectSystem=strict", "--port 9000"):
            self.assertIn(expected, unit.read_text())
        with self.assertRaises(ValueError):
            INSTALLER.install(BINARY, destdir=self.root)
        INSTALLER.install(BINARY, destdir=self.root, replace=True)
        self.assertIn("--port 8765", unit.read_text())

    def test_dashboard_conflict_does_not_write_collector_binary(self):
        conflict = self.root / INSTALLER.DASHBOARD_UNIT.relative_to("/")
        conflict.parent.mkdir(parents=True)
        conflict.write_text("keep this")
        with self.assertRaises(ValueError):
            self.install()
        self.assertFalse((self.root / INSTALLER.BINARY_PATH.relative_to("/")).exists())
        self.assertEqual(conflict.read_text(), "keep this")

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

    def test_default_install_builds_as_user_then_requests_sudo(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            if args[0] == "cargo":
                binary = checkout / "target/release/chompedr"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(BINARY.read_bytes())
            return subprocess.CompletedProcess(args, 0)
        with patch.object(INSTALLER, "ROOT", checkout), patch.object(INSTALLER.os, "geteuid", return_value=1000):
            with patch.object(INSTALLER.shutil, "which", side_effect=lambda name: name):
                with patch.object(INSTALLER.subprocess, "run", side_effect=command):
                    with patch.object(INSTALLER, "migrate_user_install") as migrate:
                        with patch.object(sys, "argv", ["install-linux.py", "--replace"]):
                            INSTALLER.main()
        self.assertEqual(calls[0][0:4], ["cargo", "build", "--release", "--locked"])
        self.assertEqual(calls[1][0:2], ["sudo", "python3"])
        self.assertIn("--binary", calls[1])
        self.assertIn("--replace", calls[1])
        migrate.assert_called_once()

    def test_failed_build_never_requests_sudo(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        with patch.object(INSTALLER, "ROOT", checkout), patch.object(INSTALLER.os, "geteuid", return_value=1000):
            with patch.object(INSTALLER.shutil, "which", return_value="cargo"):
                with patch.object(INSTALLER.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")) as run:
                    with patch.object(sys, "argv", ["install-linux.py"]):
                        with self.assertRaises(subprocess.CalledProcessError):
                            INSTALLER.main()
        self.assertEqual(run.call_count, 1)

    def test_staging_main_never_builds_or_controls_services(self):
        with patch.object(INSTALLER.subprocess, "run") as run:
            with patch.object(sys, "argv", ["install-linux.py", "--binary", str(BINARY),
                                           "--destdir", str(self.root)]):
                INSTALLER.main()
        run.assert_not_called()
        self.assertTrue((self.root / INSTALLER.CLI_PATH.relative_to("/")).is_file())

    def test_invalid_binary_is_rejected(self):
        fake = self.root / "fake"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        with self.assertRaises(ValueError):
            INSTALLER.install(fake, INSTALLER.DEFAULT_PATHS, self.root)


if __name__ == "__main__":
    unittest.main()
