use serde_json::Value;
use std::process::Command;

#[test]
fn export_contains_compiled_defaults_and_sources_from_any_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .current_dir(std::env::temp_dir())
        .arg("export-rules")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["source"], "embedded");
    let files = data["files"].as_array().unwrap();
    assert_eq!(files.len(), 4);
    let mut count = 0;
    for file in files {
        let engine = chomp_edr::Engine::from_yaml(file["yaml"].as_str().unwrap()).unwrap();
        let rules = file["rules"].as_array().unwrap();
        assert_eq!(rules.len(), engine.rules().count());
        for (metadata, rule) in rules.iter().zip(engine.rules()) {
            assert_eq!(metadata["id"], rule.id);
            assert_eq!(metadata["enabled"], rule.enabled);
            assert!(metadata["severity"].is_string());
            count += 1;
        }
    }
    assert_eq!(count, 7);
    let ssh = files.iter().find(|f| f["file"] == "ssh.yaml").unwrap();
    assert_eq!(ssh["rules"][0]["threshold"]["count"], 5);
}
