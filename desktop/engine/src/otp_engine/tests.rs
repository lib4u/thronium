use super::*;
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
fn draft(name: &str) -> Draft {
    serde_json::from_value(json!({"name":name,"issuer":"Synthetic RFC fixture","secret":SECRET,"algorithm":"SHA1","type":"hotp","digits":6,"period":30,"counter":"0"})).unwrap()
}
fn engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &path.join("unavailable-core")).unwrap()
}

#[test]
fn codes_and_secrets_are_explicit_and_hotp_reads_never_advance_the_counter() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let row = engine.otp_save("", "", draft("RFC counter")).unwrap();
    let id = row["id"].as_str().unwrap().to_string();
    for response in [
        row,
        engine.otp_list(),
        json!(engine.snapshot()),
        engine.backup_status(),
    ] {
        assert!(!response.to_string().contains(SECRET));
        assert!(!response.to_string().contains("755224"));
    }
    let before = json!(engine.store.library);
    for _ in 0..3 {
        assert_eq!(
            engine.otp_codes(std::slice::from_ref(&id)).unwrap()[0]["code"],
            "755224"
        );
    }
    assert_eq!(json!(engine.store.library), before);
    assert_eq!(engine.otp_get(&id).unwrap()["secret"], SECRET);
    assert!(engine.running.is_none() && engine.rpc.is_none());
}

#[test]
fn otp_survives_reopen_and_backup_undo_without_downgrading_library_support() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let old_backup = app.export_backup().unwrap();
    let mut value = draft("Large exact counter");
    value.counter = "9007199254740993".into();
    app.otp_save("", "", value).unwrap();
    let wanted = json!(app.store.library);
    assert_eq!(wanted["version"], 2);
    assert_eq!(wanted["otp"][0]["counter"], "9007199254740993");
    let backup = app.export_backup().unwrap();
    assert_eq!(app.backup_status()["current"]["otp"], 1);
    drop(app);
    let mut app = engine(dir.path());
    assert_eq!(json!(app.store.library), wanted);
    let preview = app.preview_backup(&old_backup).unwrap();
    app.restore_backup(&preview.token).unwrap();
    assert!(app.store.library.otp.is_empty());
    assert_eq!(app.store.library.version, 1);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), wanted);
    let mut disguised: Value = serde_json::from_str(&backup).unwrap();
    disguised["library"]["version"] = json!(1);
    assert!(app.preview_backup(&disguised.to_string()).is_err());
    assert_eq!(json!(app.store.library), wanted);
}

#[test]
fn entry_revisions_reject_stale_edits_deletions_and_invalid_input_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let first = app.otp_save("", "", draft("First name")).unwrap();
    let id = first["id"].as_str().unwrap();
    let revision = first["revision"].as_str().unwrap();
    let second = app.otp_save(id, revision, draft("New name")).unwrap();
    let before = json!(app.store.library);
    assert_eq!(
        app.otp_save(id, revision, draft("Stale name")).unwrap_err(),
        "otp_changed"
    );
    assert_eq!(app.otp_remove(id, revision).unwrap_err(), "otp_changed");
    let mut invalid = draft("Invalid");
    invalid.secret = "secret-error-sentinel!".into();
    let error = app
        .otp_save(id, second["revision"].as_str().unwrap(), invalid)
        .unwrap_err();
    assert!(!error.contains("secret-error-sentinel"));
    assert_eq!(json!(app.store.library), before);
    app.otp_remove(id, second["revision"].as_str().unwrap())
        .unwrap();
    assert!(app.store.library.otp.is_empty());
}

#[test]
fn batch_import_is_additive_atomic_and_reorder_rejects_stale_or_partial_lists() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let text = crate::otp::formats::export_json(&[draft("A"), draft("B")]).unwrap();
    assert_eq!(app.otp_import(&text).unwrap()["added"], 2);
    let before = json!(app.store.library);
    let malformed = format!(
        "{}\notpauth://totp/bad?secret=invalid-secret!",
        crate::otp::formats::export_uri(&draft("C")).unwrap()
    );
    assert!(app.otp_import(&malformed).is_err());
    assert_eq!(json!(app.store.library), before);
    let ids: Vec<_> = app.store.library.otp.iter().map(|e| e.id.clone()).collect();
    assert!(app.otp_reorder(&ids, &ids[..1]).is_err());
    assert!(app
        .otp_reorder(&ids, &[ids[0].clone(), ids[0].clone()])
        .is_err());
    let reversed = vec![ids[1].clone(), ids[0].clone()];
    app.otp_reorder(&ids, &reversed).unwrap();
    assert_eq!(app.otp_reorder(&ids, &ids).unwrap_err(), "otp_changed");
    assert_eq!(app.otp_list()[0]["name"], "B");
    let exported = app.otp_export(&reversed, "json").unwrap();
    let parsed = crate::otp::formats::import(&exported).unwrap();
    assert_eq!(parsed[0].name, "B");
    assert_eq!(parsed[1].name, "A");
    assert!(app.otp_export(&reversed, "uri").is_err());
}

#[test]
fn google_transfer_requires_every_part_before_persisting_and_keeps_existing_entries() {
    let golden: Value =
        serde_json::from_str(include_str!("../otp/fixtures/migration/golden.json")).unwrap();
    let fixture = |id: &str| {
        golden["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()["link"]
            .as_str()
            .unwrap()
    };
    let first = fixture("batch-two-fragment-0");
    let second = fixture("batch-two-fragment-1");
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    app.otp_save("", "", draft("Existing entry")).unwrap();
    let before = app.export_backup().unwrap();
    for (text, error) in [
        (first.to_string(), "otp_migration_batch_incomplete"),
        (
            format!("{first}\n{second}\n{first}"),
            "otp_migration_batch_duplicate",
        ),
        (
            format!("{first}\n{second}\n{}", fixture("future-version")),
            "otp_migration_version",
        ),
        (
            format!(
                "{first}\n{second}\n{}",
                crate::otp::formats::export_uri(&draft("Separate input")).unwrap()
            ),
            "otp_migration_mixed_input",
        ),
    ] {
        assert_eq!(app.otp_import(&text).unwrap_err(), error);
        // Export envelopes contain a timestamp; compare the actual saved library.
        let old: Value = serde_json::from_str(&before).unwrap();
        assert_eq!(json!(app.store.library), old["library"]);
        let saved: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("library.json")).unwrap())
                .unwrap();
        assert_eq!(saved, old["library"]);
    }
    assert_eq!(
        app.otp_import(&format!("{second}\n{first}")).unwrap()["added"],
        2
    );
    assert_eq!(
        app.otp_list()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Existing entry", "Batch part0", "Batch part1"]
    );
    let wanted = json!(app.store.library);
    drop(app);
    let mut app = engine(dir.path());
    assert_eq!(json!(app.store.library), wanted);
    let preview = app.preview_backup(&before).unwrap();
    app.restore_backup(&preview.token).unwrap();
    assert_eq!(app.otp_list().as_array().unwrap().len(), 1);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), wanted);
    assert!(app.running.is_none() && app.rpc.is_none());
}

#[test]
fn google_export_preserves_selected_order_and_large_counters_or_rejects_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let mut a = draft(" Exact: имя ");
    a.counter = "9223372036854775807".into();
    let mut b = draft("B");
    b.counter = "9007199254740993".into();
    let first = app.otp_save("", "", a.clone()).unwrap();
    let second = app.otp_save("", "", b.clone()).unwrap();
    let ids = [
        second["id"].as_str().unwrap().to_string(),
        first["id"].as_str().unwrap().to_string(),
    ];
    let before = json!(app.store.library);
    let exported = app.otp_export(&ids, "migration").unwrap();
    let values = crate::otp::formats::import(&exported).unwrap();
    assert_eq!(json!(values), json!([b, a]));
    assert_eq!(json!(app.store.library), before);
    let mut unsupported = draft("Custom period");
    unsupported.period = 60;
    let bad = app.otp_save("", "", unsupported).unwrap();
    let all = [ids[0].clone(), bad["id"].as_str().unwrap().to_string()];
    let before = json!(app.store.library);
    assert_eq!(
        app.otp_export(&all, "migration").unwrap_err(),
        "otp_migration_export_unsupported"
    );
    assert_eq!(json!(app.store.library), before);
    assert!(app
        .otp_export(&all, "json")
        .unwrap()
        .contains("Custom period"));
    assert!(!app.otp_list().to_string().contains(SECRET));
}
