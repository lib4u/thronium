use serde_json::json;
use std::path::Path;
use thronium_engine::{settings::section, Engine};

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, engine)
}

#[tokio::test]
async fn settings_merge_unrelated_fields_and_keep_newer_untouched_values() {
    let (_dir, mut e) = setup();
    let baseline = section(&e.store.library, "appearance");
    let mut header = baseline.clone();
    header["theme"] = json!("dark");
    e.save_settings("appearance", baseline.clone(), header)
        .await
        .unwrap();
    let mut form = baseline.clone();
    form["compact"] = json!(true);
    let merged = e
        .save_settings("appearance", baseline.clone(), form)
        .await
        .unwrap();
    assert_eq!(merged["theme"], "dark");
    assert_eq!(merged["compact"], true);
    // A stale form with no edits must never roll back the newer settings.
    assert_eq!(
        e.save_settings("appearance", baseline.clone(), baseline)
            .await
            .unwrap(),
        merged
    );
}

#[tokio::test]
async fn same_field_conflicts_are_atomic_and_report_only_field_ids() {
    let (dir, mut e) = setup();
    let baseline = section(&e.store.library, "testing");
    let mut external = baseline.clone();
    external["test_concurrent"] = json!(3);
    e.save_settings("testing", baseline.clone(), external)
        .await
        .unwrap();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let mut mine = baseline.clone();
    mine["test_concurrent"] = json!(2);
    mine["url_test_timeout_ms"] = json!(2500);
    assert_eq!(
        e.save_settings("testing", baseline.clone(), mine.clone())
            .await
            .unwrap_err(),
        "settings_conflict:test_concurrent"
    );
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        before
    );
    // Explicitly accepting the current baseline permits keeping the local edit.
    let current = section(&e.store.library, "testing");
    let mut accepted = baseline;
    accepted["test_concurrent"] = current["test_concurrent"].clone();
    let updated = e.save_settings("testing", accepted, mine).await.unwrap();
    assert_eq!(updated["test_concurrent"], 2);
    assert_eq!(updated["url_test_timeout_ms"], 2500);
}

#[tokio::test]
async fn credential_conflict_does_not_include_either_value() {
    let (_dir, mut e) = setup();
    let baseline = section(&e.store.library, "inbound");
    let mut external = baseline.clone();
    external["inbound_pass"] = json!("external-fixture-secret");
    e.save_settings("inbound", baseline.clone(), external)
        .await
        .unwrap();
    let mut mine = baseline.clone();
    mine["inbound_pass"] = json!("local-fixture-secret");
    assert_eq!(
        e.save_settings("inbound", baseline, mine)
            .await
            .unwrap_err(),
        "settings_conflict:inbound_pass"
    );
}
