use std::io::Write;
use std::process::{Command, Output, Stdio};

fn scan(input: &str, extra: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chomp"))
        .args(["scan", "--rules", "rules/starter.yaml"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn stdin_emits_only_json_alerts() {
    let output = scan(include_str!("../examples/events.jsonl"), &[]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let alerts: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["rule_id"], "CHOMP-001");
    assert_eq!(alerts[1]["rule_id"], "CHOMP-002");
    assert_eq!(alerts[0]["event"]["process"]["pid"], 102);
}

#[test]
fn exit_codes_distinguish_alerts_and_errors() {
    assert_eq!(
        scan(
            include_str!("../examples/events.jsonl"),
            &["--fail-on-alert"]
        )
        .status
        .code(),
        Some(1)
    );
    assert_eq!(scan("{}\n\n", &["--fail-on-alert"]).status.code(), Some(0));
    for input in ["not json", "[]", "null", "{}\n{broken}"] {
        let result = scan(input, &[]);
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8(result.stderr)
            .unwrap()
            .contains("event line"));
    }
}

#[test]
fn file_input_text_format_and_crlf() {
    let output = Command::new(env!("CARGO_BIN_EXE_chomp"))
        .args([
            "scan",
            "-r",
            "rules/starter.yaml",
            "-i",
            "examples/events.jsonl",
            "-f",
            "text",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 2);
    assert!(scan("{}\r\n\r\n{}", &[]).status.success());
}

#[test]
fn help_version_validation_and_listing() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["validate", "-r", "rules/starter.yaml"],
        vec!["list-rules", "-r", "rules/starter.yaml"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chomp"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_chomp"))
        .args(["validate", "-r", "does-not-exist.yaml"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn oversized_event_rejected() {
    let oversized = format!("{{\"data\":\"{}\"}}\n", "x".repeat(1024 * 1024));
    let result = scan(&oversized, &[]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains("exceeds 1 MiB"));
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "chomp-tests-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, contents: &str) -> std::path::PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_chomp"));
        command.args([subcommand, "-r"]).arg(&self.0);
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn simple_rule(id: &str) -> String {
    format!("version: 1\nrules:\n- id: {id}\n  name: Demo\n  severity: low\n  detection:\n    all:\n    - field: event\n      op: exists\n")
}

#[test]
fn folder_listing_is_sorted_and_machine_readable() {
    let fixture = Fixture::new();
    fixture.write("b.YAML", &simple_rule("second"));
    fixture.write("a.yml", &simple_rule("first"));
    fixture.write("notes.txt", "not YAML");
    std::fs::create_dir(fixture.0.join("nested")).unwrap();
    fixture.write("nested/ignored.yaml", "invalid");
    let output = fixture
        .command("list-rules")
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], "first");
    assert_eq!(rows[1]["id"], "second");
    assert_eq!(rows[0]["enabled"], true);
}

#[test]
fn repeated_sources_deduplicate_paths_but_reject_duplicate_ids() {
    let fixture = Fixture::new();
    let first = fixture.write("one.yaml", &simple_rule("one"));
    let output = fixture
        .command("validate")
        .arg("-r")
        .arg(first)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "Valid: 1 rule(s)"
    );
    fixture.write("two.yaml", &simple_rule("one"));
    let output = fixture.command("validate").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("duplicate rule id"));
}

#[test]
fn empty_or_malformed_folder_fails_before_reading_events() {
    let fixture = Fixture::new();
    let output = fixture.command("validate").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    fixture.write("good.yaml", &simple_rule("good"));
    fixture.write("bad.yaml", "invalid: [");
    let output = fixture
        .command("scan")
        .args(["--rule", "good"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("bad.yaml"));
}

#[test]
fn selected_rules_control_alerts_and_exit_status() {
    let output = scan(
        include_str!("../examples/events.jsonl"),
        &["--rule", "CHOMP-002", "--fail-on-alert"],
    );
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["rule_id"],
        "CHOMP-002"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_chomp"))
        .args(["scan", "-r", "rules/starter.yaml", "--rule", "TYPO"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("unknown rule id"));
}
