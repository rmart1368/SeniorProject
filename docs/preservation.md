# Preserve files and configuration directories

`preserve_file` is a standing guard. It captures a trusted baseline **before**
changes occur, then polls about once per second, emits alerts on differences, and
restores the baseline. It allows ordinary reads and does not block writes at the
kernel: other processes can briefly observe changed contents before restoration.
It does not distinguish malicious edits from legitimate ones; every difference
within its scope is treated as an unauthorized change while active.

## Configure a guard

Upgrade using `python3 scripts/install-linux.py --replace`. On the Linux systemd
host, create the root-owned file `/etc/chomp-edr/preserve.yaml` and its parent
folder. Keep both inaccessible for modification by untrusted users. For example:

```yaml
version: 1
rules:
  - id: CONFIG-PRESERVE-001
    name: Preserve application configuration
    severity: high
    enabled: true
    detection:
      all:
        - field: event.type
          op: equals
          value: file_metadata_changed
    response:
      - action: preserve_file
        target:
          path: /etc/my-application
        mode: automatic
```

`target.path` is a literal absolute path to an existing regular file or directory.
Directories include their descendants. It must not be `/`, contain `.`/`..` or
empty path components, overlap another guard, or overlap response state storage.
Choose the exact configuration file or directory to preserve.

The response service reloads this source live. No collector restart is required
when changing `enabled`. For a different source, override the response service's
ExecStart with `worker.py --preserve-rules /absolute/rules.yaml follow`, preserving
its normal Python/script path. The source can also be a rule directory supported
by the CLI. A missing source means no configured preservation guards.

Preservation declarations must be in this configured source: adding one only to
an alert-producing collector rule cannot recover a pre-attack baseline. The
`detection` block remains valid rule syntax, but preservation is armed from
`enabled` and `response`, not by waiting for a matching alert. While active it
alerts on all differences in the literal target, regardless of detection filters.

Modes apply to activation:

- `automatic`: capture the baseline and begin restoring.
- `approval_required`: wait for approval, then capture the current contents and
  begin restoring. Review/trust the contents before approving; there is no
  protection while activation is pending. Approval covers subsequent restores
  until the guard is paused or disabled.
- `dry_run`: capture a baseline and alert on changes without restoring anything.

Wait for `active` in the dashboard Responses view or `chompedr responses list`
before relying on a guard. An invalid/missing initial target produces a failed
activation, not a successful protection claim. Correct the problem and explicitly
disable/re-enable the rule to request a new activation.

## Legitimate maintenance

Use either workflow:

1. Set the rule's `enabled: false`, save it, and wait for `disabled` in Responses.
2. Make legitimate changes.
3. Set `enabled: true`; wait for activation (and approve it if required).
4. The updated contents become the new trusted baseline.

Or use the dashboard's authenticated **Pause** and **Resume** buttons, or:

```sh
sudo chompedr responses pause FULL_REQUEST_ID
# Make legitimate changes only after pause succeeds.
sudo chompedr responses resume FULL_REQUEST_ID
```

Pause is serialized against restoration so a successful pause acknowledgment
means an earlier restoration has finished. Resume queues a fresh capture; for
`approval_required` it waits for approval again. Wait for `active` after resume.
Pausing does not edit the YAML; it persists in the queue across service restarts.
A YAML disable/re-enable also releases the paused guard and creates a new one.
Keep the disabled/paused state until maintenance is complete; a disable/re-enable
that happens between polling cycles cannot be observed.

Ordinary service restarts reuse the existing baseline; they never silently trust
potentially modified files. Malformed YAML or overlapping-target reloads retain the last valid rules,
including after restart. Removing the configured rule or source releases its guard.
Changing a response's path or mode deliberately releases the old guard and queues
a new activation. Do not change mode merely to troubleshoot a suspected attack:
new activation trusts the contents present at that time.

## What is restored

For regular files/directories, the baseline includes file bytes, names/tree
structure, permissions, owner/group, modification timestamps and extended
attributes. Added entries are removed, missing entries are recreated, and changed
files are atomically replaced. Unchanged files keep their inode. Reads alone do
not count as changes; access timestamps, inode numbers and change timestamps are
not preserved. Replacing a file with an equivalent file is not an alert if all
preserved attributes and contents are equal. Already-open file descriptors can
still refer to the old inode after replacement.

Baselines containing symlinks, hard-linked files or special files are rejected.
A newly introduced symlink is removed/replaced without following it. Parent
symlinks and different-device filesystem boundaries are refused; use real parent
paths that remain present. Restoration may fail on permission, filesystem,
immutable-file or mount restrictions and records `preservation_error` in the audit
history. This is not protection against an attacker who can alter the root-owned
worker, its rules, or its baseline database.

Bounds are 10,000 baseline entries, 64 directory levels and 64 MiB total file
contents per guard. Choose small configuration trees. Restoration is per-file,
not a transaction covering the entire directory; a service reading several files
can see intermediate versions. Temporary files created inside the guard are also
removed. Concurrent writers can race restoration; alerts/audit results and target
VM testing are essential to assess behavior with the protected application.

Baselines are private files under `/var/lib/chomp-edr/responses/baselines`; they
contain configuration contents and must remain root-only. Disabled generations
are retained for investigation and currently need administrative retention
management. The dashboard exposes targets/status/audit metadata, not baseline
contents. Preservation alerts appear in Alerts and restoration results in the
Responses audit history. The response worker's journal is included in dashboard
diagnostics as well.

## Validation

Tests exercise recursive edits, additions/deletions, directory/file replacement,
permissions, extended attributes, symlink replacement without touching its target,
oversized changed files, read-only access, pause/edit/resume, YAML enabled reload,
approval before activation, dry-run, restart persistence and malformed reloads.
HTTP tests exercise authenticated pause/resume and real restoration of a disposable
file. Full service deployment on the target systemd VM remains a separate check.
