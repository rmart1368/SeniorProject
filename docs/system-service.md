# Always-on Linux services

This installation runs SSH detection, process observation and selected-file monitoring as three systemd services grouped under `chompedr.target`. Once enabled, they start at boot, survive logout, and retry unexpected exits every ten seconds. An explicit stop stays stopped until started again or the next boot. Disable the target to prevent boot startup.

Requirements: Linux with systemd and journald, Python 3, and a native Chomp binary built for the target architecture. Run the build as your regular user. System installation requires sudo. The services run as root so they can read the system SSH journal and observe host process/file metadata; this gives the Chomp executable privileged access. Install only a trusted local build. Monitoring remains subject to namespaces, /proc restrictions and polling gaps.

## Build, install, enable

From the repository root:

```sh
cargo build --release --locked
sudo python3 scripts/install-system-linux.py
sudo systemctl daemon-reload
sudo systemctl enable --now chompedr.target
sudo systemctl status chompedr-ssh chompedr-processes chompedr-files
```

If the old user SSH service is running, stop and disable it first as your regular user:

```sh
systemctl --user disable --now chompedr.service
```

Skip that command if the user service was never installed. The system installer writes files but does not run systemctl, enable services, change journal permissions, or alter the existing user installation.

The default watched paths are /etc/passwd, /etc/shadow, /etc/group and /etc/gshadow. Supply repeated absolute paths to replace this selection:

```sh
sudo python3 scripts/install-system-linux.py --watch-path /etc/passwd --watch-path /absolute/path/to/demo
```

Select at most 64 files or directories. Directories are recursive. Paths containing control characters, parent components or systemd expansion/escape syntax are rejected. Stop the target and add --replace to change an existing installation. The installer copies the binary to /usr/local/lib/chomp-edr/chompedr and writes four units into /etc/systemd/system. It rejects existing destinations unless --replace is supplied, and refuses symlink destinations or parent directories.

For an extracted Linux package, add `--binary ./chompedr`. For staging without root or activation, use `--destdir /absolute/staging-directory`; generated unit paths still describe the final installed system.

## Web dashboard

The [read-only web dashboard](dashboard.md) displays the collectors' alerts, embedded rule sources, service status and diagnostics. Its separate unprivileged service listens on localhost and can be reached through an SSH tunnel. Rebuild/reinstall the updated binary before installing the dashboard.

## Logs and control

```sh
sudo journalctl -u chompedr-ssh -u chompedr-processes -u chompedr-files -f -o cat
sudo systemctl restart chompedr.target
sudo systemctl stop chompedr.target
sudo systemctl start chompedr.target
sudo systemctl disable --now chompedr.target
```

Check each service, not just the target: an active target does not establish that every collector is healthy. Alerts are JSON Lines in the journal alongside collector diagnostics. Journal retention and persistence use the host journald configuration; this installer does not promise durable alert storage across reboots.

The process service includes already-running processes after every restart. This can repeat review alerts. File monitoring creates a fresh baseline after every restart and does not detect changes made while stopped. Its default rules report metadata changes, not file contents or the responsible process. PrivateTmp is disabled so the collectors see the host /tmp and /var/tmp.

The SSH service keeps a separate root-owned checkpoint at /var/lib/chomp-edr/ssh, created under systemd StateDirectory with private permissions. Inspect it using:

```sh
sudo /usr/local/lib/chomp-edr/chompedr monitor --status --checkpoint /var/lib/chomp-edr/ssh
```

Restarting does not repair unsupported SSH records, unavailable journal cursors, changed rule identities, or backward event timestamps. Those errors can repeatedly stop the SSH collector while the other collectors continue. Inspect its journal and follow the [checkpoint recovery guide](ssh-demo.md#restart-recovery-journal-json-only); do not delete checkpoint data to hide an error. Automatic restarts also do not detect a hung process. This is supervision of the existing collectors, not a guarantee of uninterrupted detection.

## Verify recovery and boot startup

On your test VM, confirm that all three services report active. Then kill one collector and check that systemd replaces its main PID after about ten seconds:

```sh
sudo systemctl show chompedr-processes -p MainPID -p NRestarts
sudo systemctl kill --kill-whom=main --signal=SIGKILL chompedr-processes
# Wait about ten seconds, then inspect again:
sudo systemctl show chompedr-processes -p MainPID -p NRestarts
sudo systemctl is-active chompedr-ssh chompedr-processes chompedr-files
sudo systemctl is-enabled chompedr.target
```

Reboot the VM when convenient and check all three service statuses again without manually starting them. Repeat a harmless file/process demo to verify collection after reboot. Boot enablement does not prove that SSH activity is present in the journal.

## Upgrade and remove

Build the new binary, stop the target, replace files, reload and restart:

```sh
cargo build --release --locked
sudo systemctl stop chompedr.target
sudo python3 scripts/install-system-linux.py --replace
sudo systemctl daemon-reload
sudo systemctl start chompedr.target
```

Repeat custom --watch-path options during upgrade to retain that selection. Checkpoints are preserved. Rule changes can require the recovery procedure above. Each file is replaced atomically; an interrupted multi-file installation can be completed by rerunning with --replace.

To remove the services and binary while preserving checkpoints:

```sh
sudo systemctl disable --now chompedr.target
sudo rm /etc/systemd/system/chompedr.target /etc/systemd/system/chompedr-ssh.service /etc/systemd/system/chompedr-processes.service /etc/systemd/system/chompedr-files.service
sudo rm /usr/local/lib/chomp-edr/chompedr
sudo systemctl daemon-reload
```

## Tests

```sh
cargo build --locked
python3 scripts/test-install-system-linux.py target/debug/chompedr
# Only on a disposable Linux VM with systemd and no existing system Chomp installation:
sudo python3 scripts/live-system-service-test.py target/debug/chompedr
```

Staging tests cover generated-unit verification, path validation, permissions, explicit replacement and preserved checkpoints. The live test temporarily installs and enables the real units, checks file/process alerts, kills and verifies restart of each collector, checks grouped stopping, and removes its installation. It does not reboot the VM; reboot verification remains a manual target-host check.

References: [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
