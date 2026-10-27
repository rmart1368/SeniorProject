# Chomp web dashboard

The dashboard displays the local system collectors' alerts, embedded rules, status and diagnostics. It is served by the VM and refreshes approximately every five seconds. No Node, npm, pip or third-party web dependencies are required: Python 3.9+ serves the bundled HTML, CSS and JavaScript.

The Responses tab shows requests, resolved targets, rule modes, results and audit history. Administrators can approve or reject pending actions. Rules and service settings remain viewable; rule editing and service start/stop controls are not included. See [responses and approvals](responses.md).

## Install or upgrade

The dashboard is included in the one Linux installation; no separate dashboard
installer is required. From the repository, run as your regular user:

```sh
bash scripts/install-dependencies-linux.sh
python3 scripts/install-linux.py
```

For an existing installation, run `python3 scripts/install-linux.py --replace`.
This builds the updated binary, replaces all components, and starts/enables both
collectors and dashboard. Repeat custom `--watch-path` and `--port` options on
upgrade. Use `--no-start` to install without activation.
See [Linux installation](linux-install.md) for details.

## Open the website

Inside the VM, visit http://127.0.0.1:8765.

From your Windows desktop, open PowerShell and establish an SSH tunnel:

```powershell
ssh -N -L 8765:127.0.0.1:8765 YOUR_USER@VM_IP
```

Keep that terminal open, then visit http://127.0.0.1:8765 in your desktop browser. Replace YOUR_USER and VM_IP with your VM login details. For SSH on another port, add -p PORT to the SSH command. If local port 8765 is busy, forward 8766:127.0.0.1:8765 and open http://127.0.0.1:8766 instead.

The server binds only to 127.0.0.1. It does not open a firewall port or provide a public website. SSH provides authenticated remote access. Other local users on the VM can read the loopback dashboard. Approve/reject operations require the administrator management token described below. Do not proxy it publicly without adding authentication and TLS.

## Response approvals

Open Responses to filter requests by status or search for an action, target, rule
or request ID. Select an action to inspect its full declaration and captured
target. The view shows the latest 500 requests and 500 audit entries, plus the
total pending count. Requests outside that window remain available through the CLI.

To authorize browser decisions, run on the VM:

```sh
sudo chompedr responses dashboard-token
```

Enter the result under **Authorize browser approvals**. The token stays in the
current page's password input and is never saved in browser storage, URLs, or
snapshots. Clear it when done. Active `preserve_file` guards also offer **Pause** and **Resume** for legitimate
maintenance; resume captures a new baseline. See [file preservation](preservation.md).
Approval asks for confirmation and queues the
captured action; the worker rechecks target identity before executing. Rejection
prevents execution. Automatic rules do not wait for browser approval. If a decision
times out, refresh its status before retrying.

The web server remains unprivileged. A private Unix socket permits only root and
the dashboard account to reach the response service. Decision requests also need
the management token and matching Host/Origin headers. The dashboard never gets
direct write access to the response database and does not execute actions itself.
The token is stored root-only at `/var/lib/chomp-edr/responses/dashboard-token`.
To rotate it, stop the response service, remove that token file as root, then
restart the response service. Browsers must enter the replacement token.

Upgrade using the normal installer with `--replace`; it installs both socket
control code and web assets. Existing installations need both services restarted.
If the response service is unavailable, the dashboard reports that source error,
retains cached history, and disables decision buttons. Full source-only testing
can pass `--response-socket /absolute/path/to/control.sock` to the dashboard and
`--socket /absolute/path/to/control.sock` to the worker's `follow` command.

## Views and data meaning

- Alerts: latest 500 retained JSON alerts in the past 24 hours, newest first. Filter by severity/collector or search event fields. Select a rule name for full event JSON. Export downloads the currently filtered alerts.
- Detection rules: metadata and original YAML compiled into the installed executable, including disabled rules and synthetic starter examples. The inventory is independent of any neighboring YAML directory. Inspect custom rule overrides in the collector launch configuration; they are not loaded by this bundled-rule view.
- Collectors: ActiveState, SubState, main PID, restart count, last process exit status and ExecStart from systemd. An active process does not prove complete telemetry or a healthy detection pipeline.
- Responses: targets, modes, status, approval/rejection controls and audit history.
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

Files live at /usr/local/lib/chomp-edr/dashboard and /etc/systemd/system/chompedr-dashboard.service. The web service uses a dedicated unprivileged system account with SupplementaryGroups=systemd-journal. That group permits reading the host journal, although the journal API only queries the fixed Chomp collector and response units. The web process has no root service-management privileges; response decisions pass through the worker's authenticated local socket. A strict read-only filesystem, Host/Origin checks and a same-origin content policy limit the local HTTP surface.

The dashboard starts independently of chompedr.target and remains available to report stopped collectors. Disable or stop the dashboard separately when desired.

For source-only testing without installation, run as a regular account that can read the collector journal:

```sh
python3 dashboard/server.py --binary target/release/chompedr
```

It still reads the installed system services' journal/status; synthetic replay scans from a shell do not automatically appear in that journal. The server does not accept arbitrary command execution or client-selected filesystem paths. Its write routes approve/reject existing requests and pause/resume preservation guards after authorization.

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

Node is used only for the optional development syntax check. Rust tests verify the embedded export. Python tests cover HTTP routes, origin/Host rejection, authenticated response decisions, rejection of unsupported writes, journal normalization/deduplication, bounded commands, stale-cache errors and staged installation.

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
