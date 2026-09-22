# Chomp EDR

A lightweight Rust endpoint detection and response project for UNIX systems and defensive cybersecurity competitions. This first milestone implements the configurable YAML rule engine and CLI described in the team's project pitch.

## Project progress

Last updated: **2026-09-22**. Current phase: **rule tuning and CLI rule management**. Completed items below describe the current implementation, not a production-ready EDR.

### Completed

- [x] Create the Rust library and `chomp` CLI project structure.
- [x] Load and validate versioned YAML detection rules.
- [x] Support `all` / `any` conditions and six matching operators.
- [x] Compile regexes at rule load time and reject invalid configurations.
- [x] Add `validate`, `list-rules`, and `scan` commands.
- [x] Read JSON Lines from files or stdin and emit JSON or text alerts.
- [x] Define script-friendly exit codes and bounded input handling.
- [x] Include two demonstration rules and three sample events.
- [x] Add 20 automated tests for the engine and CLI.
- [x] Support rule exclusions (`none`) and optional case-insensitive matching.
- [x] Load multiple rule files or folders and detect duplicate IDs across files.
- [x] Select rules by ID for scans and list rule metadata as JSON Lines.
- [x] Configure a Linux, macOS, and Windows CI workflow.
- [x] Document setup, rule syntax, event format, and current limitations.

### Verification status

| Check | Latest result | Evidence / remaining work |
| --- | --- | --- |
| Windows build | Passed locally | Rust stable 1.98.1 |
| Automated tests | 20 passed locally | 11 engine tests and 9 CLI tests |
| Formatting | Passed locally | `cargo fmt --all -- --check` |
| Lint | Passed locally | `cargo clippy --locked --all-targets -- -D warnings` |
| Sample scan | Passed locally | Three events produce two alerts |
| Linux and macOS | Initial version passed CI | New rule-management changes still need CI verification |
| GitHub CI | Initial version passed | [Initial run](https://github.com/rmart1368/SeniorProject/actions/runs/35282569184); check the current change's run separately |

### Next work

- [x] Confirm the initial GitHub CI matrix passes on all three platforms.
- [ ] Confirm new rule-management changes pass the full CI matrix.
- [ ] Exercise interactive shell pipelines on Linux and macOS beyond automated stdin tests.
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
| 2026-10-22 | CLI compatibility | Raymon | Initial CLI passed all three CI platforms; rule-management extensions tested locally |
| 2026-10-22 | Robust default rule set | Jake | Two demonstration rules only; validation and expansion pending |
| 2026-11-01 | OS compatibility and quality-of-life improvements; optional UI start | Raymon (OS), Michael (UI) | Initial portable core passed CI; live UNIX collection and UI work pending |
| 2026-11-12 | Finalized product | Team | Pending collection, detection coverage, response implementation, and end-to-end validation |

Later backlog from the pitch: host-client orchestration and CLI rule editing (Daniel); optional UI, browser dashboard, and web server (Michael).

### Progress log

| Date | Update | Validation |
| --- | --- | --- |
| 2026-09-17 | Implemented the initial rule engine, CLI, starter rules, sample events, documentation, and CI configuration | Windows build, all 12 tests, formatting, lint, and sample scan passed |
| 2026-09-17 | Added this progress tracker with milestone status and remaining work | Documentation checked against the current implementation and recorded test results |
| 2026-09-22 | Verified the initial GitHub CI run succeeded | Linux, macOS, and Windows matrix passed |
| 2026-09-22 | Added exclusions, case-insensitive matching, multi-file/folder loading, exact rule selection, and JSON rule listing | All 20 tests and lint passed locally on Windows; current CI verification pending |

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

- `validate -r PATH [-r PATH ...]`: validate all rule sources, including disabled rules and regex patterns.
- `list-rules -r PATH [-r PATH ...] [-f text|json]`: list rule metadata; text is the default. JSON emits one object per rule with `id`, `name`, `description`, `severity`, and `enabled`.
- `scan -r PATH [-r PATH ...] [--rule ID ...] [-i FILE|-] [-f json|text] [--fail-on-alert]`: stream JSON Lines from a file or stdin (the default).
- `--help` and `--version` are available. No administrator permissions required.

Each `-r` accepts one file or a directory. Directories load immediate regular `.yaml`/`.yml` files, case-insensitively by extension, in sorted path order; nested directories and symlink entries are ignored. Explicit file arguments may use any extension. Sources are processed in argument order, and repeated canonical file paths are loaded once. Empty rule directories, invalid files, and duplicate rule IDs across different files are errors. All loaded rules are validated before selection or event processing.

Repeat `--rule ID` to scan only those exact IDs. Unknown IDs are errors; repeated IDs do not duplicate alerts, and disabled rules stay disabled. Without `--rule`, all enabled rules are used. Selection preserves source order.

```sh
chomp validate -r rules
chomp list-rules -r rules --format json
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

Fields use dotted object paths (`process.executable`). Missing fields, nulls, and non-string values fail comparisons. No implicit conversion, array indexing, literal dotted keys, temporal correlation, or numeric comparison is supported yet. Regexes compile once when loading rules; lookaround and backreferences are not supported by the Rust regex engine. Existing version 1 rules keep their behavior when the new fields are omitted.

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

Tests cover operators, missing/mistyped fields, all/any/none semantics, case-insensitive literals and regexes, disabled rules, invalid configuration, deterministic multi-rule alerts, cross-file duplicates, atomic ID selection, sorted directory loading, JSON rule listing, CLI file/stdin input, JSON output, error codes, CRLF, and event size limits. Dependencies are recorded in `Cargo.lock`.

Next milestones: Linux telemetry adapter; representative benign/malicious event fixtures and tuned rules; time-window correlation; explicit response policy and audited response actions.

Dependency references: [Clap CLI derive documentation](https://docs.rs/clap/latest/clap/_derive/), [YAML parser](https://docs.rs/serde_yaml_ng/latest/serde_yaml_ng/), [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax).
