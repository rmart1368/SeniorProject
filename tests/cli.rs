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
