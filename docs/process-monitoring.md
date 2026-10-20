# Linux process observations

Run this in a Linux system terminal:

```sh
chompedr watch-processes
```

The command polls readable `/proc` process metadata once per second. Its first snapshot is a baseline; by default only later new observations are evaluated. It emits JSON review alerts for executables observed under `/tmp/`, `/var/tmp/`, or `/dev/shm/`. These locations can be used legitimately by installers, development tools, and other software. Alerts require review and do not trigger blocking or termination.

Options:

```sh
# Include already-running processes and stop after three snapshots.
chompedr watch-processes --include-existing --samples 3

# Emit normalized observations instead of alerts.
chompedr watch-processes --events > process-events.jsonl

# Evaluate your own rules, using a 500 ms polling delay.
chompedr watch-processes -r rules/processes.yaml --interval-ms 500

# Review an exported capture on any supported OS.
chompedr scan -r rules/processes.yaml -i process-events.jsonl
```

`--interval-ms` accepts 100..60000 milliseconds; the delay is between snapshots, so actual observation cadence also includes scan time. `--samples N` counts the initial baseline. `--events` cannot be combined with `-r`; pipe or save those events and use `scan` for custom evaluation. Stop with Ctrl+C. This command is separate from the SSH `monitor` command and the optional SSH user service.

## Event fields

Events use `event.type: process_observed`. `timestamp` is the snapshot's observation time, not the process creation time. `collector` records `method: proc_poll`, the boot ID, and configured interval. `process` includes PID, parent PID, boot-relative start ticks, and executable path. `user.effective_uid` is numeric. Hostname comes from the current namespace's kernel hostname.

No command-line arguments or environment variables are read. Non-UTF-8 executable paths are represented with replacement characters. Kernel ` (deleted)` suffixes are retained in executable paths. The collector reads identity metadata again to reduce races while a process exits or changes its executable; `/proc` reads are not an atomic snapshot.

The deduplication key is PID + start ticks + executable path, allowing reused PIDs and changed executable paths to be observed separately. Each snapshot replaces the previous in-memory set. A process that becomes temporarily unreadable and later readable may be emitted again. There is no persistent checkpoint or replay for process observations. Restarting creates a new baseline; with `--include-existing`, still-running processes may alert again.

## Coverage and limits

Polling can miss short-lived processes and executions between polls, including repeated exec calls to the same path. It is not auditd, eBPF, or complete execution tracing. Permissions, `hidepid`, namespaces, containers, kernel threads without executable links, and racing exits can limit visibility. stderr reports readable and unavailable/changing counts per snapshot; skipped counts are not all permission failures. Chomp does not elevate privileges.

Reads are bounded to 8 KiB for stat, 64 KiB for status, and 131,072 process directories per snapshot. Exceeding the directory limit stops collection with an error. Performance on large hosts remains unbenchmarked. Normal nonmatching processes produce no alert, which does not establish they are safe. The process rules deliberately use a different event type from the original synthetic `process_start` demo.

## Validation

Portable tests cover stat parsing with spaces/parentheses, rule boundaries, invalid CLI options, and platform guidance. The Linux CI test starts collection, launches a harmless copy of `sleep` in a temporary directory, and requires exactly one matching alert. It also checks include-existing/raw output, repeated-snapshot suppression, and replay through `scan`. The test cleans up its own child processes. This verifies basic collection/detection, not production attack coverage.

References: [Linux proc process stat fields](https://www.man7.org/linux/man-pages/man5/proc_pid_stat.5.html), [Linux process directories](https://www.man7.org/linux/man-pages/man5/proc_pid.5.html).
