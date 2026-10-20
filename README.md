# Chomp EDR

A lightweight Rust endpoint detection and response project for UNIX systems and defensive cybersecurity competitions. This first milestone implements the configurable YAML rule engine and CLI described in the team's project pitch.

## Project progress

Last updated: **2026-10-20**. Current phase: **Linux SSH, process, and selected-file monitoring**. Completed items below describe the current implementation, not a production-ready EDR.

### Completed

- [x] Create the Rust library and `chomp` CLI project structure.
- [x] Load and validate versioned YAML detection rules.
- [x] Support `all` / `any` conditions and six matching operators.
- [x] Compile regexes at rule load time and reject invalid configurations.
- [x] Add `validate`, `list-rules`, and `scan` commands.
- [x] Read JSON Lines from files or stdin and emit JSON or text alerts.
- [x] Define script-friendly exit codes and bounded input handling.
- [x] Include two demonstration rules and three sample events.
- [x] Test the engine, CLI, SSH adapters, correlation, checkpoint recovery, and monitor lifecycle.
- [x] Support rule exclusions (`none`) and optional case-insensitive matching.
- [x] Load multiple rule files or folders and detect duplicate IDs across files.
- [x] Select rules by ID for scans and list rule metadata as JSON Lines.
- [x] Configure a Linux, macOS, and Windows CI workflow.
- [x] Document setup, rule syntax, event format, and current limitations.

### Verification status

The latest CLI update removes interactive mode and updates its regression tests. Execution of these updated tests is pending; the recorded results below describe earlier checks.

| Check | Latest result | Evidence / remaining work |
| --- | --- | --- |
| Windows build | Passed locally | Rust stable 1.98.1 |
| Automated tests | 66 passed on Windows/macOS; 67 on Linux | 11 engine, 17 CLI, 8 SSH/correlation, 5 journal, and 3 scenario suites (30 scenario/input combinations), 11 checkpoint/status tests, and platform-specific monitor/process tests |
| Formatting | Passed locally | `cargo fmt --all -- --check` |
| Lint | Passed locally | `cargo clippy --locked --all-targets -- -D warnings` |
| Sample scan | Passed locally | Three events produce two alerts |
| Linux and macOS | Passed current branch CI | Formatting, lint, and platform-specific suites passed |
| GitHub CI | All three platforms passed | [Verified run for 36d674b](https://github.com/rmart1368/SeniorProject/actions/runs/39369147080) |
| Downloadable packages | All three native packages passed | Extracted executable demo and manifest hashes verified before upload |
| Real Linux process integration | Passed on Ubuntu CI | Newly launched process alerted once; raw observations and scan replay verified |
| Linux installer | 5 tests passed | User installation, unit validation, upgrades, path handling, and symlink refusal |
| Real Linux SSH integration | Passed on Ubuntu CI | Six rejected loopback logins produced one grouped alert; continuous pipeline emitted before EOF |

### Next work

- [x] Confirm the initial GitHub CI matrix passes on all three platforms.
- [x] Confirm merged rule-management changes pass the full CI matrix.
- [x] Confirm SSH detection branch passes the full CI matrix.
- [ ] Exercise interactive shell pipelines on Linux and macOS beyond automated stdin tests.
- [x] Add normalization for ISO-dated OpenSSH authentication logs.
- [x] Verify actual SSH/journal ingestion on an isolated Linux CI host.
- [x] Verify continuous journal output and checkpoint restart using actual SSH records on Ubuntu CI.
- [ ] Validate journal rotation, retention gaps, and deployment on the target Linux distribution.
- [x] Add ten labeled synthetic SSH scenarios across all three input formats.
- [ ] Collect representative target-host data and tune rules against benign and suspicious activity.
- [ ] Expand the starter rules into a tested default rule set.
- [x] Add bounded time-window thresholds grouped by event fields.
- [ ] Design explicit response policies and audit records before implementing endpoint actions.

### Pitch milestones

Dates below are the original pitch targets, not revised delivery commitments. Owners reflect the pitch's backlog assignments; unassigned work still needs a team decision.

| Target | Deliverable | Owner(s) from pitch | Current status |
| --- | --- | --- | --- |
| 2026-10-01 | Skeleton code and project design | Team | Rust skeleton implemented; broader EDR architecture remains open |
| 2026-10-22 | Configurable rule engine | Jake | Stateless matching and grouped time-window thresholds implemented; all three CI platforms pass |
| 2026-10-22 | CLI compatibility | Raymon | Command-based rule management and SSH/journal input; interactive prompt removed |
| 2026-10-22 | Robust default rule set | Jake | Two starter, two SSH, and two process review rules; representative-data tuning remains pending |
| 2026-11-01 | OS compatibility and quality-of-life improvements; optional UI start | Raymon (OS), Michael (UI) | Portable core and Ubuntu SSH/journal integration verified; deployment and optional GUI pending |
| 2026-11-12 | Finalized product | Team | Pending collection, detection coverage, response implementation, and end-to-end validation |

Later backlog from the pitch: host-client orchestration and CLI rule editing (Daniel); optional UI, browser dashboard, and web server (Michael).

### Progress log

| Date | Update | Validation |
| --- | --- | --- |
| 2026-10-20 | Added recursive directory selection to watch-files, including new/removed subtrees, overlapping-root deduplication, and bounded traversal | All three platforms passed; live Linux recursive tests passed ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39369147080)) |
| 2026-10-20 | Added a bold red ALERT heading above live SSH alerts displayed in a terminal; redirected output remains JSON Lines | 66 Windows tests and lint passed, including chunked alert formatting and unchanged redirected JSON |
| 2026-10-19 | Changed validate to list supplied rule metadata; list-rules inventories internal YAML files; added positional rule paths; removed standalone SSH normalization | 64 Windows tests, formatting, lint, and release build passed; Linux/macOS CI pending |
| 2026-09-17 | Implemented the initial rule engine, CLI, starter rules, sample events, documentation, and CI configuration | Windows build, all 12 tests, formatting, lint, and sample scan passed |
| 2026-09-17 | Added this progress tracker with milestone status and remaining work | Documentation checked against the current implementation and recorded test results |
| 2026-09-22 | Verified the initial GitHub CI run succeeded | Linux, macOS, and Windows matrix passed |
| 2026-09-22 | Added exclusions, case-insensitive matching, multi-file/folder loading, exact rule selection, and JSON rule listing | All 20 tests and lint passed locally on Windows; current CI verification pending |
| 2026-10-01 | Added the chompedr launcher with a gator welcome screen and preserved the chomp alias; installed the Windows release on the local user PATH | 22 tests, lint, release build, and installed launcher passed locally |
| 2026-10-01 | Added a persistent command prompt with help, exit/quit, quoted paths, and recovery after command errors | All 25 tests, Clippy, and release build passed on Windows |
| 2026-10-16 | Added OpenSSH log normalization, grouped time-window thresholds, two SSH rules, and an end-to-end demo | 34 tests and Clippy pass locally; current branch CI pending |
| 2026-10-16 | Added journal JSON ingestion and an isolated real-SSH Linux CI check | 39 tests, formatting, and lint pass on all three CI platforms; six actual rejected SSH logins produce one alert on Ubuntu ([run](https://github.com/rmart1368/SeniorProject/actions/runs/38957492982)) |
| 2026-10-17 | Added ten labeled SSH scenarios and a continuous journal pipeline check | 42 tests, formatting, and lint pass on all three platforms; continuous Linux journal check passed ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39001952944)) |
| 2026-10-17 | Added optional journal checkpoints with persisted windows, cursor replay, and retryable alert IDs | 50 tests, formatting, and lint passed on all three platforms; actual Linux journal replay preserved the window across restart without duplicating alerts ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39003922988)); Windows launcher updated |
| 2026-10-17 | Added managed Linux monitoring with built-in SSH rules, default checkpoints, cursor availability checks, and collector cleanup | All three platforms passed; real Linux monitoring emitted alerts and stopped its collector on termination ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39051370331)); installed Windows launcher updated |
| 2026-10-17 | Added read-only monitor status for saved progress, checkpoint ownership, and pending alerts | 57 Linux and 55 Windows/macOS tests passed; live Linux status check passed ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39051959097)); installed Windows command verified |
| 2026-10-17 | Added a Linux user installer and optional disabled systemd user service | Five isolated installer tests and systemd unit validation passed; all three platform suites and real Linux monitoring passed ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39080606501)) |
| 2026-10-18 | Added native snapshot packages, checksums, manifests, and extracted-package demo checks | Windows x86_64, Linux x86_64, and macOS ARM64 archives passed extracted demo/hash checks and uploaded successfully ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39137428057)) |
| 2026-10-18 | Added Linux process polling, raw event export, and two process review rules | 60 Linux and 59 Windows/macOS tests passed; real process observed once and replayed through scan; native packages passed ([run](https://github.com/rmart1368/SeniorProject/actions/runs/39140309074)) |
| 2026-10-18 | Added selected-file metadata monitoring and raw-event export | 62 Windows tests and lint passed locally; real-file Linux checks pending |

When updating this tracker, change the date, check off only completed work, record the platform and result of verification, and append a dated progress entry. Keep configured checks marked pending until they actually run.

## Download a build

The CI workflow packages native Windows, Linux, and macOS executables with rules, sample events, documentation, and checksums. Rust is not required to run a downloaded build. See the [download guide](docs/downloads.md) for choosing an architecture, finding artifacts, and running the demo. These are unsigned development snapshots with a 14-day artifact retention period.

## Web dashboard

A local read-only dashboard shows retained alerts, bundled rule YAML, collector status and diagnostics. It runs as a separate unprivileged system service on the VM and can be viewed from a desktop over an SSH tunnel. See the [dashboard installation and access guide](docs/dashboard.md); existing service installations need the updated binary for embedded-rule export.

## Always-on Linux services

Run SSH, process and selected-file collectors in the background, starting at boot and restarting automatically after unexpected exits:

```sh
cargo build --release --locked
sudo python3 scripts/install-system-linux.py
sudo systemctl daemon-reload
sudo systemctl enable --now chompedr.target
sudo systemctl status chompedr-ssh chompedr-processes chompedr-files
```

These system services run as root and default to watching account-file metadata. See the [system-service guide](docs/system-service.md) for custom watched paths, logs, crash/reboot checks, upgrades and recovery limits. The installer writes files; the explicit systemctl commands activate monitoring.

## Linux installation

Build on Linux and install into your user account:

```sh
cargo build --release --locked
python3 scripts/install-linux.py
```

Add `$HOME/.local/bin` to your PATH if needed. Add `--service` to write an optional systemd user-service file; it remains disabled and stopped. See the [installation guide](docs/linux-install.md) for startup, upgrades, journal access, and removal.

## Selected-file monitoring

`chompedr watch-files --path /etc/passwd --path /etc/shadow` watches selected Linux paths for metadata changes without reading contents. It reports creation, removal, and changed metadata; polling can miss changes between observations. See the [file monitoring guide](docs/file-monitoring.md).

## Linux process monitoring

`chompedr watch-processes` observes newly readable Linux processes and emits review alerts for temporary-directory/shared-memory executables. Use `--events` for normalized event output and `--include-existing` to include the first snapshot. This is polling and can miss short-lived processes. See the [process monitoring guide](docs/process-monitoring.md).

## Live Linux monitoring

On a Linux host with systemd journal access:

```sh
chompedr monitor
```

This uses built-in SSH rules, includes the last 60 seconds on first start, then follows new records. Checkpoints default to `$XDG_STATE_HOME/chomp-edr/ssh` or `$HOME/.local/state/chomp-edr/ssh`. Stop with Ctrl+C and run the same command to resume. Alerts are JSON on stdout; lifecycle messages and collector diagnostics go to stderr.

Use `monitor --once` to catch up and exit, `--checkpoint DIRECTORY` to choose state storage, or `-r FILE` to choose rules. Run this command in your system terminal. On Windows/macOS, use `scan` with exported logs. See the [monitor guide](docs/ssh-demo.md#managed-monitor-command) for limitations.

### Check monitoring progress

```sh
chompedr monitor --status
```

Status reports checkpoint use, saved progress, queued alerts, and the last correlation timestamp as JSON. It does not start collection or alter progress. Use the same `--checkpoint` and `-r` options as your monitor. A checkpoint lock is not a collector-health guarantee.

## Restart recovery

`scan --input-format journal --checkpoint DIRECTORY` saves detection windows and journal progress. Restart with input that includes the saved cursor. JSON alerts carry stable IDs for retry deduplication. See the [recovery guide](docs/ssh-demo.md#restart-recovery-journal-json-only) for commands and delivery limits.

## Linux journal support

Use `scan --input-format journal` with JSON Lines from `journalctl`. The [SSH walkthrough](docs/ssh-demo.md) includes the live pipeline command and the isolated Linux integration test. The journal adapter uses process metadata to identify SSH records; automatic service installation remains out of scope.

## SSH detection

Run `chompedr scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text` from the project folder. The demo emits two alerts. See [the SSH walkthrough](docs/ssh-demo.md) for supported log formats, normalization, threshold semantics, and Linux pipeline usage.

Loading the entire `rules` directory now includes threshold rules and requires timestamps on JSON input. Use `-r rules/starter.yaml` to retain stateless scanning without timestamps.

## Quick start

Run commands directly from your system terminal. Running `chompedr` without arguments prints help and exits successfully; it does not read stdin or open a prompt. The `chomp` alias works the same way.

```sh
chompedr --help
chompedr validate -r rules
chompedr list-rules
chompedr scan -r rules/starter.yaml -i examples/events.jsonl -f text
```

Rule and event paths are relative to your current directory. Your system shell handles quoting and pipelines.

Install stable Rust with Cargo, then run these commands from the repository root:

```sh
cargo build --locked
cargo run -- validate --rules rules/starter.yaml
cargo run -- list-rules
cargo run -- scan --rules rules/starter.yaml --input examples/events.jsonl
cargo run -- scan --rules rules/starter.yaml --input examples/events.jsonl --format text
```

The sample has one benign event and two matching events. JSON output contains two alerts, one each for `CHOMP-001` and `CHOMP-002`.

To install both `chompedr` and the compatible `chomp` command with Cargo (ensure Cargo's bin directory is on PATH):

```sh
cargo install --path . --locked
chompedr
cat examples/events.jsonl | chomp scan -r rules/starter.yaml > alerts.jsonl
```

PowerShell piping also works:

```powershell
Get-Content examples/events.jsonl | chomp scan -r rules/starter.yaml
```

For the local Windows demo, the release executable can also be installed in `%LOCALAPPDATA%\ChompEDR\bin` and that directory added to the user's PATH. After a PATH change, restart existing terminal applications so they inherit the updated value. Rebuild and reinstall after source changes to update the installed executable.

## CLI contract

- `validate PATH [PATH ...] [-f text|json]`: validate supplied rules and list their ID, name, description (JSON), severity, and enabled status. `-r` / `--rules` remains an optional alternative.
- `list-rules [-f text|json]`: list all rules grouped by internal `.yaml` file with enabled/disabled status. Reads the `rules` directory beside the executable when present; otherwise uses all `.yaml` files bundled from the project rules directory at build time. Independent of the current working directory. JSON includes `file`, `id`, `name`, and `enabled`.
- `scan -r PATH [-r PATH ...] [--rule ID ...] [-i FILE|-] [-f json|text] [--fail-on-alert]`: stream JSON Lines from a file or stdin (the default).
- `--help` and `--version` are available. No administrator permissions required.

Rule files/directories can be positional for `validate`, `scan`, `monitor`, `watch-processes`, and `watch-files`; `-r` / `--rules` remains supported. `validate` and `scan` still require at least one source. Each `-r` accepts one file or a directory. Directories load immediate regular `.yaml`/`.yml` files, case-insensitively by extension, in sorted path order; nested directories and symlink entries are ignored. Explicit file arguments may use any extension. Flagged sources are processed first, followed by positional sources, and repeated canonical file paths are loaded once. Empty rule directories, invalid files, and duplicate rule IDs across different files are errors. All loaded rules are validated before selection or event processing.

Repeat `--rule ID` to scan only those exact IDs. Unknown IDs are errors; repeated IDs do not duplicate alerts, and disabled rules stay disabled. Without `--rule`, all enabled rules are used. Selection preserves source order.

```sh
chomp validate -r rules
chomp list-rules --format json
chomp scan -r rules --rule CHOMP-002 -i examples/events.jsonl --fail-on-alert
# Load your own additional file alongside the starter rules:
chomp scan -r rules -r /path/to/custom.yaml -i examples/events.jsonl
```

Scan stdout contains alerts only; errors go to stderr. JSON is the default output and contains `rule_id`, `rule_name`, `severity`, and the original `event`. Redirect stdout to save alerts for downstream ingestion; SIEM-specific field mapping is not implemented. Each input event is flushed promptly for pipelines. Text output escapes rule strings to avoid terminal control sequences.

Exit codes: **0** for successful processing; **1** for a successful scan with detections when `--fail-on-alert` is set; **2** for argument, configuration, input, or output errors. A closed downstream pipe is treated as normal completion. Blank lines are ignored. Malformed events stop processing with a line number; alerts already written remain valid but represent only the successfully read prefix. Check the exit status before treating a scan as complete.

Rule files and individual input lines are limited to 1 MiB (line size includes line endings). Files are streamed one event at a time. The reusable library itself expects callers to enforce input size limits.

## Event contract

Every line must be a JSON object. Collectors should produce nested objects such as:

```json
{"timestamp":"2026-09-17T12:00:00Z","host":"lab-host","event":{"type":"process_start"},"process":{"pid":102,"executable":"/tmp/demo"}}
```

Timestamp and host are recommended, but not required by the engine. It preserves event fields without generating timestamps or host identifiers. Raw syslog, auditd, and journal text need collector/normalization adapters before scanning.

## Rule format (version 1)

```yaml
version: 1
rules:
  - id: CUSTOM-001
    name: Shell process observed
    description: Optional explanation
    severity: low
    enabled: true
    detection:
      all:
        - field: event.type
          op: equals
          value: process_start
        - field: process.executable
          op: regex
          value: '/(bash|sh)$'
          ignore_case: true
      none:
        - field: user.name
          op: equals
          value: approved-automation
```

Each rule needs a unique, nonblank `id`, a nonblank `name`, a severity (`low`, `medium`, `high`, `critical`), and at least one condition. `enabled` defaults to true. Unknown configuration fields, unsupported versions, duplicate IDs, and invalid regex patterns fail validation.

`all` requires every listed condition. `any` requires at least one listed condition. When both are nonempty, both groups must pass. At least one positive condition in `all` or `any` is required. Optional `none` suppresses the rule if any listed exclusion matches; an empty `none` imposes no constraint. A missing or mistyped exclusion field does not suppress an alert. Every enabled matching rule emits one alert per event, in source order.

| Operator | Meaning |
| --- | --- |
| `equals` | Exact string equality |
| `contains` | Literal substring |
| `starts_with` / `ends_with` | Literal prefix / suffix |
| `regex` | Rust regex search; use `^` and `$` for a full match |
| `exists` | Field is present and non-null; omit `value` |

Comparisons default to case-sensitive and require a nonempty string `value`; quote numeric-looking YAML values. Set `ignore_case: true` on a string comparison to use the regex engine's Unicode-aware case-insensitive matching. Literal comparisons still treat regex metacharacters literally. `exists` rejects `ignore_case: true`. Regex inline flags may override the rule-level setting within that pattern.

Fields use dotted object paths (`process.executable`). Missing fields, nulls, and non-string values fail comparisons. No implicit conversion, array indexing, literal dotted keys, or numeric comparison is supported yet. Optional threshold rules support time-window correlation; see [SSH detection](docs/ssh-demo.md). Regexes compile once when loading rules; lookaround and backreferences are not supported by the Rust regex engine. Existing version 1 rules keep their behavior when the new fields are omitted.

## Architecture and scope

`src/lib.rs` owns rule parsing, validation, compilation, and pure event evaluation. `src/main.rs` handles arguments, bounded streaming input, formatting, and exit codes. This boundary lets future UNIX collectors call the same engine without going through the CLI.

This release scans supplied events or supported SSH log records and correlates threshold matches across event-time windows. External shell pipelines can supply appended log records. It does not install a live collector, kill processes, isolate hosts, or execute rule-defined commands. The starter and SSH rules demonstrate the schema and can flag legitimate activity; they are not a validated production detection set.

The source uses portable Rust APIs. CI is configured for Linux, macOS, and Windows; actual compatibility should be confirmed by successful runs on each platform. UNIX-specific endpoint collection remains future work.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests cover operators, missing/mistyped fields, all/any/none semantics, case-insensitive literals and regexes, disabled rules, invalid configuration, deterministic multi-rule alerts, cross-file duplicates, atomic ID selection, sorted directory loading, JSON rule listing, CLI file/stdin input, JSON output, error codes, CRLF, and event size limits. Dependencies are recorded in `Cargo.lock`.

Next milestones: live Linux verification and broader log support; tuning against representative real activity; explicit response policy and audited response actions.

Dependency references: [Clap CLI derive documentation](https://docs.rs/clap/latest/clap/_derive/), [YAML parser](https://docs.rs/serde_yaml_ng/latest/serde_yaml_ng/), [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax).
