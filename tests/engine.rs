use chomp_edr::Engine;
use serde_json::json;

fn rule(op: &str, value: &str) -> String {
    format!("version: 1\nrules:\n  - id: test\n    name: Test\n    severity: high\n    detection:\n      all:\n        - field: process.name\n          op: {op}\n{value}")
}

#[test]
fn string_operators_and_types() {
    for (op, value) in [
        ("equals", "bash"),
        ("contains", "as"),
        ("starts_with", "ba"),
        ("ends_with", "sh"),
        ("regex", "^ba.*sh$"),
    ] {
        let engine = Engine::from_yaml(&rule(op, &format!("          value: '{value}'"))).unwrap();
        assert_eq!(
            engine.evaluate(&json!({"process":{"name":"bash"}})).len(),
            1,
            "{op}"
        );
        for event in [
            json!({}),
            json!({"process":{"name":null}}),
            json!({"process":{"name":123}}),
            json!({"process":{"name":"other"}}),
        ] {
            assert!(engine.evaluate(&event).is_empty(), "{op}: {event}");
        }
    }
}

#[test]
fn exists_requires_present_non_null_field() {
    let engine = Engine::from_yaml(&rule("exists", "")).unwrap();
    for v in [json!(false), json!(0), json!(""), json!([])] {
        assert_eq!(engine.evaluate(&json!({"process":{"name":v}})).len(), 1);
    }
    assert!(engine
        .evaluate(&json!({"process":{"name":null}}))
        .is_empty());
    assert!(engine.evaluate(&json!({})).is_empty());
}

#[test]
fn invalid_conditions_rejected() {
    for (op, value) in [
        ("unknown", ""),
        ("equals", ""),
        ("contains", "          value: ''"),
        ("regex", "          value: '['"),
        ("exists", "          value: nope"),
        ("equals", "          value: 42"),
    ] {
        assert!(Engine::from_yaml(&rule(op, value)).is_err());
    }
    assert!(
        Engine::from_yaml(&rule("exists", "").replace("process.name", "process..name")).is_err()
    );
}

#[test]
fn invalid_schema_rejected() {
    let base = rule("exists", "");
    for yaml in [
        base.replace("version: 1", "version: 2"),
        base.replace("severity: high", "severity: typo"),
        base.replace("name: Test", "name: ''"),
        base.replace("    severity:", "    typo: yes\n    severity:"),
        "version: 1\nrules: []".into(),
        "version: 1\nrules:\n- id: x\n  name: X\n  severity: low\n  detection: {}".into(),
    ] {
        assert!(Engine::from_yaml(&yaml).is_err(), "{yaml}");
    }
}

#[test]
fn duplicates_rejected_and_disabled_rules_do_not_match() {
    let base = rule("exists", "");
    let duplicate = format!("{base}\n{}", base.split("rules:\n").nth(1).unwrap());
    assert!(Engine::from_yaml(&duplicate).is_err());
    let disabled = base.replace("    name:", "    enabled: false\n    name:");
    let engine = Engine::from_yaml(&disabled).unwrap();
    assert!(engine
        .evaluate(&json!({"process":{"name":"bash"}}))
        .is_empty());
}

#[test]
fn all_and_any_combine_with_and() {
    let engine = Engine::from_yaml(include_str!("../rules/starter.yaml")).unwrap();
    for path in ["/tmp/demo", "/var/tmp/demo"] {
        assert_eq!(
            engine
                .evaluate(&json!({"event":{"type":"process_start"},"process":{"executable":path}}))
                .len(),
            1
        );
        assert!(engine
            .evaluate(&json!({"event":{"type":"file_write"},"process":{"executable":path}}))
            .is_empty());
    }
    assert!(engine
        .evaluate(&json!({"event":{"type":"process_start"},"process":{"executable":"/usr/bin/ls"}}))
        .is_empty());
}

#[test]
fn any_only_and_multiple_alerts_are_deterministic() {
    let base = rule("exists", "").replace("      all:", "      any:");
    let second = base
        .split("rules:\n")
        .nth(1)
        .unwrap()
        .replace("id: test", "id: second");
    let engine = Engine::from_yaml(&format!("{base}\n{second}")).unwrap();
    let event = json!({"process":{"name":"bash"}});
    let ids: Vec<_> = engine.evaluate(&event).iter().map(|a| a.rule_id).collect();
    assert_eq!(ids, ["test", "second"]);
}
