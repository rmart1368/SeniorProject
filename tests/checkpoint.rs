use chomp_edr::{checkpoint, Engine};
use serde_json::{json, Value};
use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "chomp-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.0.join("snapshot.json")).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn engine() -> Engine {
    Engine::from_yaml(include_str!("../rules/ssh.yaml")).unwrap()
}
fn record(n: u64) -> String {
    json!({"__CURSOR":format!("cursor-{n}"),"_COMM":"sshd","_HOSTNAME":"lab","_PID":"123",
        "__REALTIME_TIMESTAMP":(1792152000000000_u64 + n * 1000000).to_string(),
        "MESSAGE":"Failed password for alice from 192.0.2.10 port 1234 ssh2"})
    .to_string()
        + "\n"
}
fn history(count: u64) -> String {
    (0..count).map(record).collect()
}
fn scan(dir: &Temp, input: String) -> Vec<Value> {
    let mut out = Vec::new();
    checkpoint::scan(engine(), &dir.0, Cursor::new(input), &mut out).unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn restart_preserves_window_and_suppression_without_replaying_alerts() {
    let dir = Temp::new();
    assert!(scan(&dir, history(4)).is_empty());
    let alerts = scan(&dir, history(6));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["rule_id"], "CHOMP-SSH-001");
    assert_eq!(alerts[0]["alert_id"], r#"["cursor-4","CHOMP-SSH-001"]"#);
    assert!(scan(&dir, history(6)).is_empty());
    let next = history(6) + &(70..75).map(record).collect::<String>();
    assert_eq!(scan(&dir, next).len(), 1);
}

struct FailedFlush(Vec<u8>);
impl Write for FailedFlush {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "simulated lost acknowledgement",
        ))
    }
}
#[test]
fn interrupted_delivery_retries_the_same_alert_id() {
    let dir = Temp::new();
    let mut out = FailedFlush(Vec::new());
    assert!(checkpoint::scan(engine(), &dir.0, Cursor::new(history(5)), &mut out).is_err());
    let original: Value = serde_json::from_slice(&out.0).unwrap();
    let retried = scan(&dir, history(6));
    assert_eq!(retried, vec![original]);
    assert!(scan(&dir, history(6)).is_empty());
}

#[test]
fn missing_cursor_never_resets_or_overwrites_state() {
    let dir = Temp::new();
    scan(&dir, history(4));
    let before = dir.bytes();
    let mut out = Vec::new();
    let error = checkpoint::scan(engine(), &dir.0, Cursor::new(record(10)), &mut out).unwrap_err();
    assert!(error.to_string().contains("cursor was not found"));
    assert!(out.is_empty());
    assert_eq!(before, dir.bytes());
}

#[test]
fn changed_detection_or_selection_cannot_reuse_checkpoint() {
    let dir = Temp::new();
    scan(&dir, history(4));
    let before = dir.bytes();
    for source in [
        include_str!("../rules/ssh.yaml").replace("count: 5", "count: 6"),
        include_str!("../rules/ssh.yaml").replace("value: failure", "value: success"),
    ] {
        let error = checkpoint::scan(
            Engine::from_yaml(&source).unwrap(),
            &dir.0,
            Cursor::new(history(5)),
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("rules changed"));
    }
    let mut selected = engine();
    selected.select(&["CHOMP-SSH-001".into()]).unwrap();
    assert!(checkpoint::scan(selected, &dir.0, Cursor::new(history(5)), Vec::new()).is_err());
    assert_eq!(before, dir.bytes());
}

#[test]
fn concurrent_writer_is_rejected_and_unlock_allows_reuse() {
    let dir = Temp::new();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.0.join("lock"))
        .unwrap();
    lock.try_lock().unwrap();
    assert!(
        checkpoint::scan(engine(), &dir.0, Cursor::new(history(1)), Vec::new())
            .unwrap_err()
            .to_string()
            .contains("locked")
    );
    // Release explicitly before reuse: parallel CLI tests may briefly inherit
    // the descriptor between fork and exec on Unix.
    lock.unlock().unwrap();
    drop(lock);
    assert!(scan(&dir, history(1)).is_empty());
}

#[test]
fn malformed_record_does_not_advance_saved_cursor() {
    let dir = Temp::new();
    scan(&dir, history(4));
    let before = dir.bytes();
    let input = history(4) + &record(4).replace("192.0.2.10", "bad-ip");
    assert!(checkpoint::scan(engine(), &dir.0, Cursor::new(input), Vec::new()).is_err());
    assert_eq!(before, dir.bytes());
    assert_eq!(scan(&dir, history(5)).len(), 1);
}

#[test]
fn corrupt_state_is_rejected_instead_of_starting_fresh() {
    let dir = Temp::new();
    scan(&dir, history(4));
    let original: Value = serde_json::from_slice(&dir.bytes()).unwrap();
    for key in ["version", "times", "expires"] {
        let mut state = original.clone();
        match key {
            "version" => state["version"] = json!(999),
            "times" => state["session"]["groups"][0]["times"] = json!([4, 1]),
            _ => state["session"]["groups"][0]["expires"] = json!(0),
        }
        std::fs::write(dir.0.join("snapshot.json"), state.to_string()).unwrap();
        assert!(checkpoint::scan(engine(), &dir.0, Cursor::new(history(5)), Vec::new()).is_err());
    }
}

#[test]
fn checkpoint_cli_requires_journal_json_output_and_valid_cursor() {
    let dir = Temp::new();
    for args in [
        vec!["--input-format", "json"],
        vec!["--input-format", "journal", "-f", "text"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_chompedr"))
            .args(["scan", "-r", "rules/ssh.yaml", "--checkpoint"])
            .arg(&dir.0)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("requires"));
    }
    let input = record(0).replace("__CURSOR", "unused");
    assert!(
        checkpoint::scan(engine(), &dir.0, Cursor::new(input), Vec::new())
            .unwrap_err()
            .to_string()
            .contains("__CURSOR")
    );
    let path = dir.0.join("journal.jsonl");
    std::fs::write(&path, history(5)).unwrap();
    for expected in [1, 0] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_chompedr"))
            .args([
                "scan",
                "-r",
                "rules/ssh.yaml",
                "--input-format",
                "journal",
                "--fail-on-alert",
                "--checkpoint",
            ])
            .arg(&dir.0)
            .arg("-i")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().lines().count(),
            expected as usize
        );
    }
}

#[test]
fn status_is_read_only_for_absent_and_saved_progress() {
    let dir = Temp::new();
    let missing = dir.0.join("not-created");
    let absent = checkpoint::status(engine(), &missing).unwrap();
    assert_eq!(absent["saved_progress"], false);
    assert!(!missing.exists());
    scan(&dir, history(4));
    let before = dir.bytes();
    let state = checkpoint::status(engine(), &dir.0).unwrap();
    assert_eq!(state["saved_progress"], true);
    assert_eq!(state["in_use"], false);
    assert_eq!(state["active_groups"], 1);
    assert_eq!(state["pending_alerts"], 0);
    assert_eq!(state["last_event_timestamp"], "2026-10-16T12:00:03+00:00");
    assert_eq!(before, dir.bytes());
    assert!(!state.to_string().contains("alice"));
}

#[test]
fn status_reports_locked_checkpoint_and_pending_delivery() {
    let dir = Temp::new();
    let mut out = FailedFlush(Vec::new());
    assert!(checkpoint::scan(engine(), &dir.0, Cursor::new(history(5)), &mut out).is_err());
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.0.join("lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let state = checkpoint::status(engine(), &dir.0).unwrap();
    assert_eq!(state["in_use"], true);
    assert_eq!(state["pending_alerts"], 1);
    assert_eq!(state["collector_health"], "not_checked");
    // Release explicitly before reuse: parallel CLI tests may briefly inherit
    // the descriptor between fork and exec on Unix.
    lock.unlock().unwrap();
    drop(lock);
    assert_eq!(scan(&dir, history(5)).len(), 1);
}

#[test]
fn status_cli_works_without_collector_and_rejects_corrupt_state() {
    let dir = Temp::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chompedr"))
        .args(["monitor", "--status", "--checkpoint"])
        .arg(&dir.0)
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(state["saved_progress"], false);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
    std::fs::write(dir.0.join("snapshot.json"), "corrupt").unwrap();
    assert!(checkpoint::status(engine(), &dir.0).is_err());
}

#[test]
fn response_changes_cannot_reuse_checkpoint_or_overwrite_saved_state() {
    let dir = Temp::new();
    let source = include_str!("../rules/ssh.yaml");
    scan(&dir, history(4));
    let before = dir.bytes();
    let changed = source.replacen(
        "    detection:",
        "    response:\n      - action: block_ip\n        target: {field: source.ip}\n        duration: 15m\n    detection:",
        1,
    );
    assert_ne!(source, changed);
    let engine = Engine::from_yaml(&changed).unwrap();
    let error =
        checkpoint::scan(engine, &dir.0, Cursor::new(history(6)), &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("rule"), "{error}");
    assert_eq!(dir.bytes(), before);
    assert_eq!(scan(&dir, history(6)).len(), 1);
}
