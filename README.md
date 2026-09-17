# Chomp EDR

A lightweight Rust endpoint detection and response project for UNIX systems and defensive cybersecurity competitions. This first milestone implements the configurable YAML rule engine and CLI described in the team's project pitch.

## Project progress

Last updated: **2026-09-17**. Current phase: **rule engine and CLI foundation implemented**. Completed items below describe the initial implementation, not a production-ready EDR.

### Completed

- [x] Create the Rust library and `chomp` CLI project structure.
- [x] Load and validate versioned YAML detection rules.
- [x] Support `all` / `any` conditions and six matching operators.
- [x] Compile regexes at rule load time and reject invalid configurations.
- [x] Add `validate`, `list-rules`, and `scan` commands.
- [x] Read JSON Lines from files or stdin and emit JSON or text alerts.
- [x] Define script-friendly exit codes and bounded input handling.
- [x] Include two demonstration rules and three sample events.
- [x] Add 12 automated tests for the engine and CLI.
- [x] Configure a Linux, macOS, and Windows CI workflow.
- [x] Document setup, rule syntax, event format, and current limitations.

### Verification status

| Check | Latest result | Evidence / remaining work |
| --- | --- | --- |
| Windows build | Passed locally | Rust stable 1.98.1 |
| Automated tests | 12 passed | 7 engine tests and 5 CLI tests |
| Formatting | Passed locally | `cargo fmt --all -- --check` |
| Lint | Passed locally | `cargo clippy --locked --all-targets -- -D warnings` |
| Sample scan | Passed locally | Three events produce two alerts |
| Linux and macOS | Pending | CI configured; successful runs still needed |
| GitHub CI | Pending | Check the Actions tab for results after publication |

### Next work

- [ ] Confirm the initial GitHub CI matrix passes on all three platforms.
- [ ] Confirm CLI behavior on Linux and macOS, including shell pipelines.
- [ ] Add a Linux telemetry adapter that normalizes events for the engine.
- [ ] Build representative benign and malicious event fixtures; tune detection rules against both.
- [ ] Expand the starter rules into a tested default rule set.
- [ ] Add time-window correlation for repeated or related events.
- [ ] Design explicit response policies and audit records before implementing endpoint actions.

### Pitch milestones

Dates below are the original pitch targets, not revised delivery commitments. Owners reflect the pitch's backlog assignments; unassigned work still needs a team decision.

| Target | Deliverable | Owner(s) from pitch | Current status |
| --- | --- | --- | --- |
| 2026-10-01 | Skeleton code and project design | Team | Rust skeleton implemented; broader EDR architecture remains open |
| 2026-10-22 | Configurable rule engine | Jake | Initial stateless engine implemented and tested locally |
| 2026-10-22 | CLI compatibility | Raymon | Initial CLI tested on Windows; UNIX verification pending |
| 2026-10-22 | Robust default rule set | Jake | Two demonstration rules only; validation and expansion pending |
| 2026-11-01 | OS compatibility and quality-of-life improvements; optional UI start | Raymon (OS), Michael (UI) | CI configured; OS verification and UI work pending |
| 2026-11-12 | Finalized product | Team | Pending collection, detection coverage, response implementation, and end-to-end validation |

Later backlog from the pitch: host-client orchestration and CLI rule editing (Daniel); optional UI, browser dashboard, and web server (Michael).

### Progress log

| Date | Update | Validation |
| --- | --- | --- |
| 2026-09-17 | Implemented the initial rule engine, CLI, starter rules, sample events, documentation, and CI configuration | Windows build, all 12 tests, formatting, lint, and sample scan passed |
| 2026-09-17 | Added this progress tracker with milestone status and remaining work | Documentation checked against the current implementation and recorded test results |

When updating this tracker, change the date, check off only completed work, record the platform and result of verification, and append a dated progress entry. Keep configured checks marked pending until they actually run.

## Quick start

Install stable Rust with Cargo, then run these commands from the repository root:

```sh
cargo build --locked
cargo run -- validate --rules rules/starter.yaml
cargo run -- list-rules --rules rules/starter.yaml
cargo run -- scan --rules rules/starter.yaml --input examples/events.jsonl
cargo run -- scan --rules rules/starter.yaml --input examples/events.jsonl --format text
```

The sample has one benign event and two matching events. JSON output contains two alerts, one each for `CHOMP-001` and `CHOMP-002`.

To install the `chomp` command locally:

```sh
cargo install --path . --locked
cat examples/events.jsonl | chomp scan -r rules/starter.yaml > alerts.jsonl
```

PowerShell piping also works:

```powershell
Get-Content examples/events.jsonl | chomp scan -r rules/starter.yaml
```

## CLI contract

- `validate -r FILE`: validate the entire rule file, including disabled rules and regex patterns.
- `list-rules -r FILE`: list rule ID, severity, enabled state and name.
- `scan -r FILE [-i FILE|-] [-f json|text] [--fail-on-alert]`: stream JSON Lines from a file or stdin (the default).
- `--help` and `--version` are available. No administrator permissions required.

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
```

Each rule needs a unique, nonblank `id`, a nonblank `name`, a severity (`low`, `medium`, `high`, `critical`), and at least one condition. `enabled` defaults to true. Unknown configuration fields, unsupported versions, duplicate IDs, and invalid regex patterns fail validation.

`all` requires every listed condition. `any` requires at least one listed condition. When both are nonempty, both groups must pass. Empty groups impose no constraint, but both cannot be empty. Every enabled matching rule emits one alert per event, in file order.

| Operator | Meaning |
| --- | --- |
| `equals` | Exact string equality |
| `contains` | Literal substring |
| `starts_with` / `ends_with` | Literal prefix / suffix |
| `regex` | Rust regex search; use `^` and `$` for a full match |
| `exists` | Field is present and non-null; omit `value` |

Comparisons are case-sensitive and require a nonempty string `value`; quote numeric-looking YAML values. Fields use dotted object paths (`process.executable`). Missing fields, nulls, and non-string values fail comparisons. No implicit conversion, array indexing, literal dotted keys, negation, temporal correlation, or numeric comparison is supported yet. Regexes compile once when loading rules; lookaround and backreferences are not supported by the Rust regex engine.

## Architecture and scope

`src/lib.rs` owns rule parsing, validation, compilation, and pure event evaluation. `src/main.rs` handles arguments, bounded streaming input, formatting, and exit codes. This boundary lets future UNIX collectors call the same engine without going through the CLI.

This release scans supplied events. It does not collect live endpoint telemetry, correlate events across time, kill processes, isolate hosts, or execute rule-defined commands. The two starter rules demonstrate the schema and can flag legitimate activity; they are not a validated production detection set.

The source uses portable Rust APIs. CI is configured for Linux, macOS, and Windows; actual compatibility should be confirmed by successful runs on each platform. UNIX-specific endpoint collection remains future work.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests cover operators, missing/mistyped fields, all/any semantics, disabled rules, invalid configuration, deterministic multi-rule alerts, CLI file/stdin input, JSON output, error codes, CRLF, and event size limits. Dependencies are recorded in `Cargo.lock`.

Next milestones: Linux telemetry adapter; representative benign/malicious event fixtures and tuned rules; time-window correlation; explicit response policy and audited response actions.

Dependency references: [Clap CLI derive documentation](https://docs.rs/clap/latest/clap/_derive/), [YAML parser](https://docs.rs/serde_yaml_ng/latest/serde_yaml_ng/), [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax).
