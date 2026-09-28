//! Independent public-API tests of mixed real Qt sections and private plan reuse.
use serde_json::{json, Value};
use std::path::Path;
use thronium_engine::{
    backups::legacy::{prepare, Scopes},
    legacy_backup, Engine,
};
fn source(mixed: bool, name: &str) -> legacy_backup::SourceArchive {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    legacy_backup::read(
        &root
            .join(if mixed {
                "../tests/fixtures/legacy-otp"
            } else {
                "src/legacy_backup/otp/fixtures"
            })
            .join(name),
    )
    .unwrap()
}
fn engine(path: &Path) -> Engine {
    Engine::open(path, &path.join("deliberately-absent-core")).unwrap()
}
fn otp_scope() -> Scopes {
    Scopes {
        profiles: false,
        routes: false,
        otp: true,
        ..Default::default()
    }
}
fn safe(value: &Value) {
    let text = value.to_string();
    for secret in [
        "GEZDGNBV",
        "gezdgnbv",
        "private-mixed-configuration",
        "invalid-private-fixture",
        "private-blob",
        "outbound_json",
    ] {
        assert!(!text.contains(secret));
    }
}
#[test]
/// The archive's unconvertible profile is left out (F3b) rather than blocking;
/// OTP still imports on its own, touching nothing else, with exact undo.
fn actual_mixed_qt_skipped_profile_does_not_prevent_independent_otp_import_or_exact_version_undo() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let source = source(true, "blocked-profiles.thrbackup");
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    let review = first.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], true);
    assert_eq!(review["otpCount"], 6);
    assert!(
        review["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["code"] == "legacy_profile_skipped"
                && i["name"] == "Unsupported mixed profile")
    );
    let only = app.legacy_backup_scopes(&first.token, otp_scope()).unwrap();
    safe(&json!(only));
    assert_eq!(only.legacy.as_ref().unwrap()["canApply"], true);
    app.restore_backup(&only.token).unwrap();
    assert_eq!(app.store.library.otp.len(), 6);
    assert_eq!(app.store.library.version, 2);
    let mut after = json!(app.store.library);
    after.as_object_mut().unwrap().remove("otp");
    after["version"] = before["version"].clone();
    assert_eq!(after, before);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    assert!(app.owned_core_process().is_none());
}
#[test]
fn actual_mixed_qt_otp_blocker_cannot_partially_apply_and_opt_out_retains_source_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let source = source(true, "blocked-otp.thrbackup");
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    let both = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                otp: true,
                ..Default::default()
            },
        )
        .unwrap();
    safe(&json!(both));
    assert_eq!(both.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        app.restore_backup(&both.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    let profiles = app
        .legacy_backup_scopes(&both.token, Scopes::default())
        .unwrap();
    app.restore_backup(&profiles.token).unwrap();
    assert_eq!(app.store.library.profiles.len(), 13);
    assert!(app.store.library.otp.is_empty());
    assert_eq!(app.store.library.version, 1);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}
#[test]
fn public_prepare_clone_proves_toggle_refresh_preserve_original_uuid_and_revision_plan() {
    let source = source(false, "valid.thrbackup");
    let prepared = prepare(&source);
    let reference_dir = tempfile::tempdir().unwrap();
    let mut reference = engine(reference_dir.path());
    let first = reference.preview_legacy_import(prepared.clone()).unwrap();
    let picked = reference
        .legacy_backup_scopes(&first.token, otp_scope())
        .unwrap();
    reference.restore_backup(&picked.token).unwrap();
    let wanted = json!(reference.store.library.otp);
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let first = app.preview_legacy_import(prepared).unwrap();
    let selected = app.legacy_backup_scopes(&first.token, otp_scope()).unwrap();
    let off = app
        .legacy_backup_scopes(
            &selected.token,
            Scopes {
                profiles: false,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(off.legacy.as_ref().unwrap()["canApply"], false);
    let on = app.legacy_backup_scopes(&off.token, otp_scope()).unwrap();
    app.otp_save("","",serde_json::from_value(json!({"name":"Concurrent current entry","secret":"JBSWY3DPEHPK3PXP","type":"hotp","counter":"9223372036854775807"})).unwrap()).unwrap();
    assert_eq!(
        app.restore_backup(&on.token).unwrap_err(),
        "backup_preview_stale"
    );
    let current = json!(app.store.library);
    let fresh = app.refresh_backup_preview(&on.token).unwrap();
    safe(&json!(fresh));
    assert_eq!(fresh.incoming.otp, 7);
    app.restore_backup(&fresh.token).unwrap();
    assert_eq!(json!(&app.store.library.otp[1..]), wanted);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), current);
}
