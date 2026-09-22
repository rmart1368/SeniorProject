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

#[test]
fn exclusions_suppress_any_matching_exception() {
    let yaml = format!("{}\n      none:\n        - field: user.name\n          op: equals\n          value: trusted\n        - field: process.path\n          op: starts_with\n          value: /opt/approved/", rule("exists", ""));
    let engine = Engine::from_yaml(&yaml).unwrap();
    for event in [
        json!({"process":{"name":"bash"},"user":{"name":"trusted"}}),
        json!({"process":{"name":"bash","path":"/opt/approved/task"}}),
    ] {
        assert!(engine.evaluate(&event).is_empty());
    }
    for user in [json!(null), json!(42), json!("other")] {
        assert_eq!(
            engine
                .evaluate(&json!({"process":{"name":"bash"},"user":{"name":user}}))
                .len(),
            1
        );
    }
    assert!(engine
        .evaluate(&json!({"user":{"name":"other"}}))
        .is_empty());
    assert!(Engine::from_yaml(&rule("exists", "").replace("all:", "none:")).is_err());
}

#[test]
fn case_insensitive_operators_keep_literal_and_anchor_semantics() {
    for (op, value, positive, negative) in [
        ("equals", "b.sh", "B.SH", "Bash"),
        ("contains", "b.sh", "aB.SHx", "aBashx"),
        ("starts_with", "b.sh", "B.SHx", "xB.SH"),
        ("ends_with", "b.sh", "xB.SH", "B.SH\n"),
        ("regex", "^b.sh$", "BASH", "XBASH"),
        ("equals", "é", "É", "e"),
    ] {
        let yaml = rule(
            op,
            &format!("          value: '{value}'\n          ignore_case: true"),
        );
        let engine = Engine::from_yaml(&yaml).unwrap();
        assert_eq!(
            engine.evaluate(&json!({"process":{"name":positive}})).len(),
            1,
            "{op}"
        );
        assert!(
            engine
                .evaluate(&json!({"process":{"name":negative}}))
                .is_empty(),
            "{op}"
        );
        assert!(engine.evaluate(&json!({"process":{"name":42}})).is_empty());
    }
    assert!(Engine::from_yaml(&rule("exists", "          ignore_case: true")).is_err());
    let sensitive = Engine::from_yaml(&rule("equals", "          value: bash")).unwrap();
    assert!(sensitive
        .evaluate(&json!({"process":{"name":"BASH"}}))
        .is_empty());
}

#[test]
fn combines_validate_global_ids_and_preserve_order() {
    let first = rule("exists", "");
    let second = first.replace("id: test", "id: second");
    let engine = Engine::combine([
        Engine::from_yaml(&second).unwrap(),
        Engine::from_yaml(&first).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        engine.rules().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["second", "test"]
    );
    assert!(Engine::combine([
        Engine::from_yaml(&first).unwrap(),
        Engine::from_yaml(&first).unwrap()
    ])
    .is_err());
    assert!(Engine::combine([]).is_err());
}

#[test]
fn selection_is_atomic_and_respects_disabled_rules() {
    let first = rule("exists", "");
    let second = first
        .replace("id: test", "id: second")
        .replace("    name:", "    enabled: false\n    name:");
    let mut engine = Engine::combine([
        Engine::from_yaml(&first).unwrap(),
        Engine::from_yaml(&second).unwrap(),
    ])
    .unwrap();
    assert!(engine.select(&["test".into(), "unknown".into()]).is_err());
    assert_eq!(engine.rules().count(), 2);
    engine.select(&["second".into(), "second".into()]).unwrap();
    assert_eq!(engine.rules().count(), 1);
    assert!(engine
        .evaluate(&json!({"process":{"name":"bash"}}))
        .is_empty());
}
