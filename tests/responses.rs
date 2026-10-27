use chomp_edr::{
    response::{Action, Mode, Target},
    session::Session,
    Engine,
};
use serde_json::{json, Value};

fn yaml(response: &str) -> String {
    format!("version: 1\nrules:\n  - id: response-test\n    name: Response test\n    severity: high\n    detection:\n      all:\n        - field: event.type\n          op: exists\n{response}\n")
}

#[test]
fn catalog_parses_and_preserves_declarations_in_alerts() {
    for action in [
        "notify",
        "block_ip",
        "quarantine_file",
        "isolate_host",
        "disable_account",
        "delete_file",
    ] {
        let engine = Engine::from_yaml(&yaml(&format!(
            "    response:\n      - action: {action}\n        target:\n          field: source.ip"
        )))
        .unwrap();
        let rule = engine.rules().next().unwrap();
        assert_eq!(rule.response[0].mode, Mode::DryRun);
        assert_eq!(
            rule.response[0].target,
            Target::Field {
                field: "source.ip".into()
            }
        );
        // Targets are declarations: a missing event target does not suppress a detection.
        let event = json!({"event":{"type":"test"}});
        let output = serde_json::to_value(&engine.evaluate(&event)[0]).unwrap();
        assert_eq!(output["response"][0]["action"], action);
        assert_eq!(output["response"][0]["target"]["field"], "source.ip");
        assert_eq!(output["response"][0]["mode"], "dry_run");
    }
}

#[test]
fn process_targets_multiple_responses_and_modes_are_preserved() {
    let source = yaml("    response:\n      - action: terminate_process\n        target:\n          pid_field: process.pid\n          start_time_field: process.start_time\n        mode: approval_required\n      - action: suspend_process\n        target:\n          pid_field: process.pid\n          start_time_field: process.start_time\n        mode: automatic\n      - action: block_ip\n        target:\n          field: source.ip\n        duration: 15m");
    let engine = Engine::from_yaml(&source).unwrap();
    let responses = &engine.rules().next().unwrap().response;
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0].action, Action::TerminateProcess);
    assert_eq!(responses[0].mode, Mode::ApprovalRequired);
    assert_eq!(responses[1].mode, Mode::Automatic);
    assert_eq!(responses[2].duration.as_deref(), Some("15m"));
    // Threshold alerts use the same metadata path as stateless alerts.
    let source = source.replace("    detection:", "    threshold:\n      count: 2\n      window_seconds: 60\n      group_by: [host]\n    detection:");
    let mut session = Session::new(Engine::from_yaml(&source).unwrap());
    let event = json!({"timestamp":"2026-10-27T00:00:00Z", "host":"lab", "event":{"type":"test"}});
    assert!(session.process(&event).unwrap().is_empty());
    let alerts = session.process(&event).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0]["response"],
        serde_json::to_value(responses).unwrap()
    );
}

#[test]
fn invalid_response_definitions_are_rejected_even_when_disabled() {
    for response in [
        "action: execute_shell\n        target: {field: source.ip}",
        "action: block_ip",
        "action: block_ip\n        target: {}",
        "action: block_ip\n        target: {field: ''}",
        "action: block_ip\n        target: {field: source..ip}",
        "action: block_ip\n        target: {field: 'source. ip'}",
        "action: terminate_process\n        target: {field: process.pid}",
        "action: suspend_process\n        target: {pid_field: process.pid}",
        "action: terminate_process\n        target: {pid_field: process.pid, start_time_field: process.pid}",
        "action: block_ip\n        target: {pid_field: process.pid, start_time_field: process.start_time}",
        "action: block_ip\n        target: {field: source.ip, typo: true}",
        "action: block_ip\n        target: {field: source.ip, pid_field: process.pid, start_time_field: process.start_time}",
        "action: block_ip\n        target: {field: source.ip}\n        mode: typo",
        "action: block_ip\n        target: {field: source.ip}\n        command: echo",
        "action: delete_file\n        target: {field: file.path}\n        duration: 15m",
    ] {
        let source = yaml(&format!("    response:\n      - {response}"));
        for source in [source.clone(), source.replace("    severity:", "    enabled: false\n    severity:")] {
            assert!(Engine::from_yaml(&source).is_err(), "accepted {source}");
        }
    }
    for duration in ["0m", "-1m", "1.5h", "15", "1w", "4294967296s", "1hm"] {
        assert!(Engine::from_yaml(&yaml(&format!("    response:\n      - action: block_ip\n        target: {{field: source.ip}}\n        duration: '{duration}'"))).is_err(), "accepted {duration}");
    }
}

#[test]
fn existing_rules_keep_their_alert_contract() {
    let engine = Engine::from_yaml(&yaml("")).unwrap();
    let event = json!({"event":{"type":"test"}});
    let output = serde_json::to_value(&engine.evaluate(&event)[0]).unwrap();
    assert_eq!(
        output,
        json!({"rule_id":"response-test", "rule_name":"Response test", "severity":"high", "event":event})
    );
}

#[test]
fn cli_validates_and_emits_response_metadata_without_deleting_target() {
    let dir = std::env::temp_dir().join(format!("chomp-response-test-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("preserve-me");
    std::fs::write(&file, "preserved").unwrap();
    let rules = dir.join("rules.yaml");
    std::fs::write(&rules, yaml("    response:\n      - action: delete_file\n        target: {field: file.path}\n        mode: automatic")).unwrap();
    let input = dir.join("events.jsonl");
    std::fs::write(
        &input,
        json!({"event":{"type":"test"},"file":{"path":file}}).to_string(),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_chompedr");
    let validation = std::process::Command::new(binary)
        .args(["validate", "--format", "json", "--rules"])
        .arg(&rules)
        .output()
        .unwrap();
    assert!(validation.status.success(), "{:?}", validation);
    let metadata: Value = serde_json::from_slice(&validation.stdout).unwrap();
    assert_eq!(metadata["response"][0]["action"], "delete_file");
    let scan = std::process::Command::new(binary)
        .args(["scan", "--rules"])
        .arg(&rules)
        .arg("--input")
        .arg(&input)
        .output()
        .unwrap();
    assert!(scan.status.success(), "{:?}", scan);
    let alert: Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(alert["response"], metadata["response"]);
    assert_eq!(std::fs::read_to_string(file).unwrap(), "preserved");
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn main_cli_exposes_response_management_and_preserves_errors() {
    let dir = std::env::temp_dir().join(format!("chomp-unified-responses-{}", std::process::id()));
    let binary = env!("CARGO_BIN_EXE_chompedr");
    let run = |command: &[&str]| {
        std::process::Command::new(binary)
            .args(["responses", "--state"])
            .arg(&dir)
            .args(command)
            .output()
            .unwrap()
    };
    let list = run(&["list"]);
    assert!(list.status.success(), "{:?}", list);
    assert_eq!(
        serde_json::from_slice::<Value>(&list.stdout).unwrap(),
        json!([])
    );
    let audit = run(&["audit"]);
    assert!(audit.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&audit.stdout).unwrap(),
        json!([])
    );
    let invalid = run(&["approve", "missing-request"]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8(invalid.stderr)
        .unwrap()
        .contains("Only a pending request"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn preservation_requires_an_explicit_absolute_path() {
    let source = yaml("    response:\n      - action: preserve_file\n        target: {path: /etc/example-config}\n        mode: automatic");
    let engine = Engine::from_yaml(&source).unwrap();
    assert_eq!(
        engine.rules().next().unwrap().response[0].action,
        Action::PreserveFile
    );
    for invalid in [
        "/",
        "relative/path",
        "/etc/../etc",
        "/etc//example",
        "/etc/example/",
    ] {
        assert!(
            Engine::from_yaml(&source.replace("/etc/example-config", invalid)).is_err(),
            "{invalid}"
        );
    }
    assert!(
        Engine::from_yaml(&source.replace("path: /etc/example-config", "field: file.path"))
            .is_err()
    );
    assert!(Engine::from_yaml(&source.replace("preserve_file", "delete_file")).is_err());
}
