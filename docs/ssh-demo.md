# SSH detection demo

## Run it

From the repository root, build with `cargo build --release --locked`. Use `cargo run --` instead of `chompedr` if the installed executable has not been updated.

```sh
chompedr scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text
```

Expected alerts: one `CHOMP-SSH-001` alert on the fifth failure from `198.51.100.20`, and one `CHOMP-SSH-002` alert for a root login. The example uses documentation IP addresses and synthetic records, not captured production activity. One unrelated PAM line is skipped and counted on stderr. `--fail-on-alert` returns code 1 when alerts occur; errors return code 2.

## Linux input

Supported input is an OpenSSH log record with an explicit ISO date, numeric UTC offset (or `Z`), hostname, and `sshd[pid]` or `sshd-session[pid]` prefix:

```text
2026-10-16T12:00:01+00:00 host sshd[101]: Failed password for invalid user admin from 198.51.100.20 port 50001 ssh2
```

Supported outcomes are `Failed` and `Accepted`; supported methods are `password`, `publickey`, and `keyboard-interactive/pam`. IPv4 and IPv6 addresses are validated and canonicalized. Port and PID must be valid unsigned values. The normalized object includes timestamp, host, event type/outcome, user, source IP/port, process, and authentication method.

If an existing Linux log file uses this format, scan it directly. To process new appended lines using an external collector:

```sh
tail -n 0 -F /path/to/iso-dated-auth.log | chompedr scan -r rules/ssh.yaml --input-format ssh -f text
```

Run this pipeline in your system shell. Use an account that already has permission to read the log. `tail` is the external collector; Chomp does not configure logging, install a service, manage rotation, or maintain state across restarts. This command is an integration example, not evidence of a live-host test.

Yearless traditional syslog (`Oct 16 12:00:00 ...`) is not supported. Target authentication records with unsupported headers/methods or invalid fields stop the command with a line-numbered error. Unrelated lines are skipped; their count is reported on stderr at EOF. Blank scan lines are ignored.

## Linux journal input

`--input-format journal` accepts one JSON object per line from `journalctl -o json`. It reads `MESSAGE`, `_COMM`, `_HOSTNAME`, `_PID`, and `__REALTIME_TIMESTAMP` (microseconds since the Unix epoch). Records from `sshd`, `sshd-session`, and `sshd-auth` are supported. Missing or non-string message fields in SSH records are errors; binary/array message values are not supported. Required timestamp, host, and PID fields are checked for target authentication messages.

The adapter checks `_COMM`, not the user-supplied `SYSLOG_IDENTIFIER`. A record from another process merely labeling itself `sshd` is skipped. This relies on genuine journald metadata; an edited JSON file is not authenticated by Chomp.

From a Linux system shell with permission to read the journal:

```sh
set -o pipefail
journalctl --no-pager -o json -n 0 -f _COMM=sshd _COMM=sshd-session _COMM=sshd-auth | chompedr scan -r rules/ssh.yaml --input-format journal -f text
```

Repeated matches on the same journal field are alternatives. `-n 0 -f` starts with new records; remove those options and add an appropriate `--since` value for historical scanning. Run from the project folder or provide an absolute rule path. Chomp flushes alerts as it processes events. Stop the system-shell pipeline with Ctrl+C. This is an external journal pipeline, not a background service installed by Chomp. System clock corrections or combined logs can still cause the documented out-of-order timestamp error.

Use JSON Lines (`-o json`), not `json-pretty` or `json-seq`. Do not pass unfiltered arbitrary binary journal records as normalized event input.

## Isolated Linux integration test

The Linux CI job runs `sudo python3 scripts/live-ssh-test.py target/debug/chompedr`. It requires systemd and OpenSSH server on a disposable test host. The script creates its own temporary SSH keys/configuration and a transient service restricted to a random loopback port. Six password login attempts use a randomly generated nonexistent username; every login must be rejected. It reads that service's actual journal records and requires exactly one repeated-failure alert. A second check follows the journal continuously and requires an alert before EOF while both processes remain running.

The transient service has a 60-second runtime limit and is stopped in cleanup. The script never modifies the host SSH service or creates users. This test verifies a real OpenSSH/journald pipeline; it does not establish detection accuracy across distributions or production workloads. See the latest GitHub Actions run for the result.

## Threshold rules

```yaml
threshold:
  count: 5
  window_seconds: 60
  group_by: [host, source.ip]
```

The optional top-level `threshold` applies after a rule's normal `all`, `any`, and `none` conditions. Only matching events count. Grouping by both host and IP avoids combining failures on separate endpoints. Successful logins do not reset failure counts.

- Time comes from the event's RFC3339 `timestamp`, not the wall clock. Every event in a scan with an enabled threshold rule must have a valid timestamp, even if it does not match that rule.
- Events must be globally nondecreasing by timestamp; equal times are allowed. Older timestamps are errors. Sort combined logs before scanning. There is no late-event buffer.
- The window is inclusive: events exactly 60 seconds apart can count together. Millisecond precision is used.
- An alert fires when a group reaches the threshold. While it stays at or above that threshold, subsequent matches are suppressed. It can alert again after expiration reduces the active count below the threshold.
- Each scan starts fresh. Replayed/duplicate records count again; no event deduplication is implemented.
- `count` must be 2..1000; `window_seconds` must be 1..86400. There must be 1..8 dotted `group_by` paths. Each matching event must supply nonempty string group values of at most 256 bytes.
- At most 4096 active rule/group pairs are retained, each with at most `count` timestamps. Expired pairs are removed as event time advances. Exceeding capacity stops with an error rather than silently evicting detection history.
- JSON correlation alerts include `count` (the threshold), `window_seconds`, group paths/values, and the first contributing timestamp in milliseconds. The attached original event is the event that reached the threshold, not the entire history.

For library users, `Session::process` applies both stateless and threshold rules. `Engine::evaluate` handles only stateless rules; it never emits a threshold rule on a single event. Rules are validated before selection, so invalid configuration cannot be hidden with `--rule`.

## Verification and limitations

Tests cover normalization, invalid log formats, group isolation, boundary times, burst suppression/rearming, out-of-order events, malformed data, capacity/expiration, and equivalence between direct scans and normalization followed by JSON scanning. The SSH fixture also runs through the same cross-platform CI suite as the original engine.

These are review heuristics, not proof of compromise. Legitimate password mistakes and authorized root access can trigger them. Use local policy and representative real logs to tune rules before enabling any future responses. Automated endpoint actions are not implemented.

Implementation references: [OpenSSH authentication logging](https://github.com/openssh/openssh-portable/blob/master/auth.c), [Chrono timestamp parsing](https://docs.rs/chrono/latest/chrono/struct.DateTime.html), [systemd journal fields](https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml), and [journal JSON format](https://github.com/systemd/systemd/blob/main/docs/JOURNAL_EXPORT_FORMATS.md).

## Labeled regression scenarios

`tests/fixtures/ssh-scenarios.json` contains ten authored synthetic scenarios, not captured production traffic. `cargo test --test scenarios` checks each through SSH text, normalized JSON, and journal JSON: 30 combinations, including alert IDs, counts, and CLI exit codes.

| Scenario | Expected alerts |
| --- | --- |
| Normal non-root logins | None |
| Two password mistakes followed by success | None |
| Failures from separate sources | None; distributed attempts are a coverage gap |
| Four failures each on separate hosts | None; host counters stay separate |
| Failures spread beyond the time window | None; slow attempts are a coverage gap |
| Six different usernames from one source | One repeated-failure alert |
| Equivalent IPv6 address spellings | One repeated-failure alert |
| Two bursts separated by expiry | Two repeated-failure alerts |
| A successful login between five failures | One repeated-failure alert; success does not reset the window |
| Successful root login | One policy-review alert, even if authorized |

These fixtures lock down intended behavior; they do not measure production false-positive or false-negative rates. Before tuning thresholds, collect labeled samples from the intended deployment environment. Keep benign administration and legitimate retries in that evaluation set.

The continuous CI check verifies alert delivery without closing input. Optional checkpoint recovery is described below. Journal rotation and target-distribution deployment remain unverified. Without a checkpoint, a new scan starts a fresh correlation window.

## Restart recovery (journal JSON only)

Use a dedicated local checkpoint directory with unchanged rules and the same journal source/filter. Every journal record must include `__CURSOR`. Checkpoint mode requires JSON output and adds `alert_id` (an encoded cursor/rule-ID pair).

For a saved journal export that grows over time:

```sh
chompedr scan -r rules/ssh.yaml --input-format journal -i journal.jsonl --checkpoint .chomp-state
```

Rerun the same command after appending records. Chomp finds the saved cursor, skips the already processed prefix, and resumes with its saved threshold counters and suppression state. The export must retain the cursor record, even when earlier records are removed.

For a Linux journal pipeline, use the same command on every start:

```sh
set -o pipefail
journalctl --no-pager -o json --no-tail -f _COMM=sshd _COMM=sshd-session _COMM=sshd-auth | chompedr scan -r rules/ssh.yaml --input-format journal --checkpoint .chomp-state
```

`--no-tail` includes retained history even in follow mode ([systemd documentation](https://www.freedesktop.org/software/systemd/man/255/journalctl.html)). On the first run, historical events can generate alerts. Do not combine recovery with `-n 0`, `--after-cursor`, or a new filter that excludes the saved cursor. To check recovery against finite retained history, omit `-f`: a missing cursor returns status 2 without replacing the checkpoint. With an endless follow stream, Chomp keeps waiting for that cursor until EOF; it cannot infer a retention gap from silence. Archive loss requires an explicit decision to use a new checkpoint directory, which loses the old detection window.

The checkpoint contains the journal position, correlation state, exact compiled rule identity, and any alerts awaiting output. Changing rules, rule selection, or schema version rejects the old checkpoint. One process may own a directory at a time; the OS releases its lock on exit. Keep the directory private and on a local filesystem; checkpoints are trusted application state and may contain event details. Do not edit its files or delete its lock file while running.

The implementation writes and syncs a temporary snapshot before replacing the current snapshot. It commits pending alerts before writing stdout, then clears them after stdout flush succeeds. An interrupted delivery may repeat the same `alert_id`; consumers must deduplicate IDs if needed. A successful stdout flush does not prove a downstream consumer durably stored the alert. This is process-restart recovery, not an exactly-once delivery or power-loss guarantee. Checkpoint I/O/output failures return status 2, including broken pipes.

Snapshots are limited to 64 MiB and rewritten for every record (twice for an alert). This first implementation prioritizes recovery correctness for modest log volumes; it has not been throughput-benchmarked. The existing 4,096-group limit and event-time ordering requirements still apply. `scan` without `--checkpoint` remains stateless across processes.

## Managed monitor command

`chompedr monitor` owns the `journalctl` child process and the checkpoint lock. It uses the embedded SSH rules by default, so no repository working directory is required. `-r FILE` (repeatable) overrides the rules. The default state directory is `$XDG_STATE_HOME/chomp-edr/ssh` when that variable is an absolute path, otherwise `$HOME/.local/state/chomp-edr/ssh`; `--checkpoint DIRECTORY` overrides it.

The first start includes only the last 60 seconds of accessible SSH records, then follows new entries. This is a startup baseline, not a scan of all historical activity. Custom rules with longer windows need additional history; use the checkpoint scan command to seed the same state directory from retained journal records first. Subsequent starts probe the saved cursor against finite journal output and then resume inclusively from that cursor, avoiding an indefinite wait when history has expired. A retention race between the probe and collection is checked against the first returned record.

`monitor --once` processes available records and exits. Normal monitoring stays in the foreground until Ctrl+C. Run it in your system terminal. stdout contains only JSON alerts; stderr reports startup, resume, and collector errors. A quiet stream is not proof of journal permissions, SSH activity, or complete endpoint coverage. Access depends on the current user; Chomp neither elevates privileges nor changes journal permissions.

The collector is stopped on processing errors and when the monitor parent exits. An unexpected collector exit returns status 2; there is no automatic restart loop or background-service installation. Restart manually with the same directory. Invalid/changed rules, a locked checkpoint, and unavailable cursors fail without silently clearing saved state. Deduplicate stable alert IDs downstream as described above. Rule updates require an explicit new checkpoint decision.

This release supports only Linux systemd journals for live collection. Windows and macOS receive an explanatory error and can still scan exported logs. Journal rotation under sustained load, service installation, throughput, and production detection accuracy remain deployment work.

### Read-only status

`chompedr monitor --status` prints a JSON snapshot without launching journalctl, creating a checkpoint directory, acknowledging alerts, or changing saved progress. It may briefly acquire an existing free lock while reading; if another process already owns it, `in_use` is true and status reads the last atomically saved snapshot. Lock and progress observations are point-in-time information, not a live health check; `collector_health` explicitly remains `not_checked`.

Use the same custom rules and checkpoint directory as the monitor. Invalid state or changed rules returns status 2. A missing snapshot is reported as `saved_progress: false`, which can also mean a running collector has not received its first record. `active_groups` and `last_event_timestamp` reflect persisted event-time correlation, not wall-clock freshness; stateless-only rules may have no correlation timestamp. Pending counts describe committed alerts awaiting output acknowledgement. Raw event payloads and journal cursors are omitted.

Unlike live collection, status works on all supported platforms. On Windows, its default directory is `%LOCALAPPDATA%/ChompEDR/state/chomp-edr/ssh`; use `--checkpoint DIRECTORY` to inspect exported/copied state elsewhere. Status does not test whether the saved cursor is still retained by the Linux journal.

### Terminal alert highlighting

When `chompedr monitor` writes to a terminal, each alert starts with a bold red `ALERT` line above the JSON details. Redirecting or piping stdout keeps plain JSON Lines without headings or color codes. Restart the monitor after updating the executable to use this display.
