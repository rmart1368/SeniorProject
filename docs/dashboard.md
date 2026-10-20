# Chomp web dashboard

The dashboard displays the local system collectors' alerts, embedded rules, status and diagnostics. It is served by the VM and refreshes approximately every five seconds. No Node, npm, pip or third-party web dependencies are required: Python 3.9+ serves the bundled HTML, CSS and JavaScript.

This version is read-only. Rules and service settings can be inspected but not edited in the browser. There are no host-response or process-control web endpoints.

## Update an existing service installation

The dashboard branch includes the existing always-on service setup. Fetch it even if your checkout was cloned with --single-branch:

```sh
git fetch origin codex/web-dashboard
git switch --create web-dashboard FETCH_HEAD
cargo build --release --locked
```

The updated executable adds export-rules so the dashboard can inspect its actual embedded defaults. Stop the collectors before replacing it. If you installed a previous dashboard, stop it before replacing its files too.

```sh
sudo systemctl stop chompedr.target
sudo python3 scripts/install-system-linux.py --replace
sudo python3 scripts/install-dashboard-linux.py
sudo systemctl daemon-reload
sudo systemctl start chompedr.target
sudo systemctl enable --now chompedr-dashboard.service
```

Repeat any custom --watch-path options on the system installer to preserve your watched-path selection; omitting them reinstates the default account-file paths. The collectors' SSH checkpoint is preserved. Restarting creates new process/file baselines and can repeat process review alerts.

For a fresh installation, omit --replace and use sudo systemctl enable --now chompedr.target to enable collector startup at boot. Dashboard startup is enabled separately. Neither installer activates services itself.

For a dashboard upgrade, first run sudo systemctl stop chompedr-dashboard, then install-dashboard-linux.py --replace, daemon-reload and start the dashboard again. --port 8765 selects the default port; ports 1024..65535 are supported. Repeat a custom port during upgrades.

## Open the website

Inside the VM, visit http://127.0.0.1:8765.

From your Windows desktop, open PowerShell and establish an SSH tunnel:

```powershell
ssh -N -L 8765:127.0.0.1:8765 YOUR_USER@VM_IP
```

Keep that terminal open, then visit http://127.0.0.1:8765 in your desktop browser. Replace YOUR_USER and VM_IP with your VM login details. For SSH on another port, add -p PORT to the SSH command. If local port 8765 is busy, forward 8766:127.0.0.1:8765 and open http://127.0.0.1:8766 instead.

The server binds only to 127.0.0.1. It does not open a firewall port or provide a public website. SSH provides authenticated remote access. There is no separate dashboard login; other local users on the VM can access the loopback endpoint. Do not proxy it publicly without adding authentication and TLS.

## Views and data meaning

- Alerts: latest 500 retained JSON alerts in the past 24 hours, newest first. Filter by severity/collector or search event fields. Select a rule name for full event JSON. Export downloads the currently filtered alerts.
- Detection rules: metadata and original YAML compiled into the installed executable, including disabled rules and synthetic starter examples. The inventory is independent of any neighboring YAML directory. Inspect custom rule overrides in the collector launch configuration; they are not loaded by this bundled-rule view.
- Collectors: ActiveState, SubState, main PID, restart count, last process exit status and ExecStart from systemd. An active process does not prove complete telemetry or a healthy detection pipeline.
- Diagnostics: the latest 100 retained collector journal records in the past 24 hours.

Counts describe the returned window, not lifetime totals or unique incidents. Replayed SSH alerts can share alert_id values; repeated process observations can also alert again. Only repeated instances of the same journal cursor are deduplicated.

Alerts are read directly from journald; the dashboard does not maintain another alert database. History and reboot persistence depend on the host journal configuration and retention. Diagnostic messages are filtered out before applying the 500-alert limit. Journal queries require systemd with journalctl --grep support (for example current Ubuntu).

The page displays unavailable-source errors and retains previous successful values with source timestamps (hover the snapshot time). A disconnected browser snapshot may be stale. Each source is sampled separately, so a refresh is not an atomic snapshot. Browser times use the viewer's local timezone. Initial reads may take several seconds.

The rule inventory describes the installed executable on disk. Restart collectors after replacing it so in-memory defaults match. If you override collector binaries, rules or unit names, this default dashboard configuration needs corresponding adaptation.

## Service and access

```sh
sudo systemctl status chompedr-dashboard
sudo journalctl -u chompedr-dashboard -n 50 --no-pager
sudo systemctl restart chompedr-dashboard
sudo systemctl disable --now chompedr-dashboard
```

Files live at /usr/local/lib/chomp-edr/dashboard and /etc/systemd/system/chompedr-dashboard.service. The web service uses a temporary unprivileged systemd identity with SupplementaryGroups=systemd-journal. That group permits reading the host journal, although the HTTP API only queries the three fixed Chomp collector units. The web process has no root service-management privileges. A strict read-only filesystem, Host/Origin checks and a same-origin content policy limit the local HTTP surface.

The dashboard starts independently of chompedr.target and remains available to report stopped collectors. Disable or stop the dashboard separately when desired.

For source-only testing without installation, run as a regular account that can read the collector journal:

```sh
python3 dashboard/server.py --binary target/release/chompedr
```

It still reads the installed system services' journal/status; synthetic replay scans from a shell do not automatically appear in that journal. The server does not accept arbitrary command execution, client-selected filesystem paths or writable API requests.

## Verify with real data

Run the harmless process demo while the collectors are active:

```sh
mkdir -p /tmp/chomp-dashboard-demo
cp /usr/bin/sleep /tmp/chomp-dashboard-demo/demo-sleep
/tmp/chomp-dashboard-demo/demo-sleep 15
```

The process should remain alive long enough for polling. A CHOMP-PROC-001 alert should appear after the next collection/dashboard refresh. Select it to inspect its executable path and PID. For file alerts, modify a disposable path explicitly selected with --watch-path. Do not change account files merely to test the website.

## Automated checks

```sh
cargo test --locked
node --check dashboard/web/app.js
python3 -m unittest discover -s dashboard/tests -p 'test_*.py'
```

Node is used only for the optional development syntax check. Rust tests verify the embedded export. Python tests cover HTTP routes, origin/Host rejection, write rejection, journal normalization/deduplication, bounded commands, stale-cache errors and staged installation.

On a disposable Linux VM with no system Chomp installation, sudo python3 scripts/live-system-service-test.py target/debug/chompedr additionally checks actual service alerts through the unprivileged dashboard, boot enablement and crash recovery. Do not run that installation test on your working competition VM.

These checks are wired into CI. Passing them and target-VM browser/reboot verification must be recorded separately; source inclusion does not mean the checks passed.

## Remove the dashboard

```sh
sudo systemctl disable --now chompedr-dashboard
sudo rm /etc/systemd/system/chompedr-dashboard.service
sudo rm -r /usr/local/lib/chomp-edr/dashboard
sudo systemctl daemon-reload
```

Collector services and SSH checkpoints remain installed.
