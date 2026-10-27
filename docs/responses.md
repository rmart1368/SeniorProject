# Linux responses and approvals

Manage detection and responses through the main `chompedr` command. The response
worker is an internal service in the same installation; `chompedr.target` starts
and stops the collectors and response worker together. The older
`chompedr-response` command remains available as a compatibility alias.

The installer now includes `chompedr-response.service` as part of `chompedr.target`.
It follows the three installed collectors' journal records, captures response
targets, and persists requests, decisions, results and journal progress in a
private SQLite database at `/var/lib/chomp-edr/responses/responses.sqlite3`.
There are no third-party Python dependencies. Python 3.9+ and Linux are required;
process signaling requires kernel/Python pidfd support.

## Rule control

Choose a mode independently for each response. No action, including deletion,
has a hardcoded approval requirement:

- `dry_run` (default): validate/capture the target and record the request without execution.
- `approval_required`: persist a pending request; execute only after an operator approves it.
- `automatic`: queue and execute without interactive approval.

For example, one rule can request automatic process termination and file deletion
that requires approval. Process actions use `process.pid` and `process.start_ticks`.
File actions currently require the file collector's `file.after` metadata; process
executable paths alone do not provide enough file identity evidence.

```yaml
version: 1
rules:
  - id: CUSTOM-FILE-001
    name: Selected file changed
    severity: high
    detection:
      all:
        - field: event.type
          op: equals
          value: file_metadata_changed
        - field: event.action
          op: equals
          value: changed
    response:
      - action: delete_file
        target:
          field: file.path
        mode: approval_required
```

Use this only with explicitly selected disposable paths while testing. Changing
`mode` to `automatic` permits automatic deletion. Bundled rules still have no
response declarations, so installing/upgrading alone does not enable destructive
responses. The rule creator controls whether an action needs approval.

The service reads installed collector output, not arbitrary stdin, shell scan
output, or dashboard requests. Configure custom collector rules using systemd
overrides, for example `sudo systemctl edit chompedr-files.service`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/lib/chomp-edr/chompedr watch-files --path /absolute/disposable/path --rules /etc/chomp-edr/custom-files.yaml
```

Keep rule files and their parent directories root-owned and not writable by
untrusted users: automatic rules authorize root-level actions. Then run
`sudo systemctl daemon-reload` and `sudo systemctl restart chompedr-files.service`.
Use analogous overrides for `watch-processes` or `monitor`; preserve the monitor's
checkpoint option. A changed monitor rule identity requires a new checkpoint.

## Review and approve

After installing/upgrading on a systemd Linux VM with the normal installer:

```sh
sudo chompedr responses list
sudo chompedr responses approve FULL_REQUEST_ID
sudo chompedr responses reject FULL_REQUEST_ID
sudo chompedr responses audit
sudo systemctl status chompedr-response.service
sudo journalctl -u chompedr-response.service --no-pager -n 50
```

`list` shows resolved targets, original declarations, status and failure details.
Approval changes `pending` to `queued`; the running service executes it shortly
afterward. Rejection is final. Only pending requests can be decided. Approval is
available through the administrative CLI and the dashboard Responses tab. Browser
decisions require the administrator token from `sudo chompedr responses dashboard-token`;
see [dashboard approval access](dashboard.md#response-approvals).
Run these commands as root for the installed queue. For isolated development,
use `python3 response/worker.py --state /absolute/private/directory list`.

## File preservation

`preserve_file` arms a standing guard from a configured rule source, restores
changes to a trusted baseline, and supports maintenance pause/resume in the CLI
and dashboard. It requires `target: {path: /absolute/file-or-directory}`.
See [preservation setup and maintenance](preservation.md).

## Executable actions

| Action | Behavior and requirements |
| --- | --- |
| `terminate_process` | Verify captured PID/start ticks and send SIGTERM through a pidfd; success means signal delivery, not guaranteed exit. |
| `suspend_process` | Verify identity and send SIGSTOP through a pidfd. Resume manually with SIGCONT after verifying identity. |
| `delete_file` | Verify event-time and queued file identity, atomically move into private quarantine, verify again, then unlink. |
| `quarantine_file` | Same checks, but retain the file under `responses/quarantine/REQUEST_ID`; original path is in the request record. Restore manually after review. |
| `preserve_file` | Capture a trusted baseline before changes; restore file/directory differences while active. |
| `block_ip` | Install a runtime firewalld source-address drop rule in its default zone; optional duration uses firewalld's timeout. |

IP blocking requires an existing running firewalld installation and
`/usr/bin/firewall-cmd`. The installer does not install, enable or replace the
host firewall. Test policy on the target VM; rich rules apply to the default
zone and do not promise to terminate established connections. Loopback,
unspecified and multicast IPs are rejected. Other addresses, including management
addresses, can be blocked if rules request them. Missing duration lasts until
firewall reload/reboot or manual removal. Expiration is managed by firewalld,
not the response worker.

File actions require a regular file with one hard link and matching
`file.after.inode`, `device`, `size`, and modification timestamp. Symlink targets
and symlink parent directories are rejected. Identity is checked again after
approval. Quarantine uses atomic rename on the same filesystem: a different
filesystem fails explicitly instead of falling back to copying and deletion.
A change detected after rename leaves the moved entry in quarantine for manual
investigation. A queued file target may become stale while awaiting approval;
that fails without retrying against a replacement file.

`notify`, `isolate_host` and `disable_account` remain schema-valid but have no
executor. They produce failed requests with an unsupported-action explanation.
The service does not execute arbitrary shell commands. Protected process IDs
include PID 1 and the response worker itself.

## Delivery, restarts and operational limits

Journal cursor and request insertion commit together. Requests deduplicate by
collector unit, alert ID (or journal cursor), response index and declaration.
Replaying the same alert does not repeat the same response. Separate alerts can
still request repeated actions; there is no cross-alert cooldown or rate limit.
Changing a response declaration creates a distinct request.

Execution claims are committed before side effects. If the worker stops during
an action, the request stays `executing` for manual investigation and is never
automatically retried. This prevents duplicate side effects but does not promise
exactly-once execution: a crash may leave the result uncertain. Failed actions
also stay failed. Rule edits do not revoke already queued or approved requests.
On first startup the worker reads the last 60 seconds; later starts resume from
the saved cursor. Journal retention gaps can prevent recovery and require operator
diagnosis. Queue/audit retention currently requires administrative management.

The worker runs as root to perform privileged responses; only trusted local
collector units are consumed. The approval database is owned by the service
account with a private state directory. Local root administrators can approve or
alter state. Browser decisions require a shared administrator management token, matching
Host/Origin headers, and the private control socket. Audit records distinguish
CLI and dashboard decisions; there are no individual browser user accounts.

## Validation

```sh
python3 -m unittest discover -s response/tests -p 'test_*.py'
python3 scripts/test-install-linux.py target/debug/chompedr
```

Tests cover approvals, rejection, dry-run, automatic dispatch, duplicate records,
restart persistence, execution claims, failure recording, real disposable-file
removal/quarantine, and real child-process termination with identity checks.
Firewall command construction is mocked; actual firewall behavior needs a
firewalld VM. The existing disposable systemd integration test also checks that a
real collector queues a pending process action and only terminates its harmless
child after approval. That integration test requires root and systemd; it cannot
run in the cloud development container.
