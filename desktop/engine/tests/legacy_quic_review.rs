//! Independent Qt archive reader → preview/scopes → restore/undo/public export checks.
//! No core or network is started in these five tests.
#[path = "fixtures/legacy-quic/api.rs"]
mod api;
use serde_json::json;
use thronium_engine::backups::legacy::Scopes;

#[test]
fn actual_qt_archives_preserve_exact_dns_without_tls_or_current_policy_mutation() {
    for name in [
        "direct",
        "direct-hostname",
        "bootstrap",
        "both",
        "default-port",
        "remote-quic",
        "remote-udp",
    ] {
        let folder = tempfile::tempdir().unwrap();
        let mut app = api::app(folder.path(), &folder.path().join("missing-core"));
        let before = json!(app.store.library);
        let id = api::install(&mut app, name);
        let exported = app.export_routing_profile(&id).unwrap();
        assert_eq!(
            exported["profile"]["dns"],
            api::expected(name)["expectedDNS"]
        );
        let serialized = exported["profile"]["dns"].to_string();
        assert!(!serialized.contains("insecure"));
        assert!(!serialized.contains("certificate"));
        assert!(app.owned_core_process().is_none());
        let previous = app.preview_previous_backup().unwrap();
        app.restore_backup(&previous.token).unwrap();
        assert_eq!(json!(app.store.library), before);
    }
}

#[test]
/// A direct resolver may name a host (see the exact-DNS test above); a
/// bootstrap resolver still may not, and refuses the selected batch whole.
fn bootstrap_hostname_bound_refuses_whole_selected_batch_without_writes() {
    let name = "bootstrap-hostname";
    let folder = tempfile::tempdir().unwrap();
    let mut app = api::app(folder.path(), &folder.path().join("missing-core"));
    let before = json!(app.store.library);
    let disk = std::fs::read(folder.path().join("library.json")).unwrap();
    let p = api::preview(&mut app, name, true);
    let report = p.legacy.as_ref().unwrap();
    assert_eq!(report["canApply"], false);
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["code"] == api::expected(name)["expectedError"]),
        "{}",
        json!(p)
    );
    assert_eq!(
        app.restore_backup(&p.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    assert_eq!(
        std::fs::read(folder.path().join("library.json")).unwrap(),
        disk
    );
    assert!(!folder.path().join("backup-before-restore.json").exists());
    assert!(app.owned_core_process().is_none());
    // The selected routes scope owns this blocker; profile-only import stays valid.
    let profiles = app
        .legacy_backup_scopes(&p.token, Scopes::default())
        .unwrap();
    assert_eq!(profiles.legacy.as_ref().unwrap()["canApply"], true);
    app.restore_backup(&profiles.token).unwrap();
    assert_eq!(
        app.store.library.profiles.len(),
        before["profiles"].as_array().unwrap().len() + 1
    );
    assert_eq!(json!(app.routing()), before["routing"]);
}

#[test]
fn actual_qt_parts_cannot_be_overridden_by_scope_requests() {
    for name in ["no-settings", "no-routes"] {
        let folder = tempfile::tempdir().unwrap();
        let mut app = api::app(folder.path(), &folder.path().join("missing-core"));
        let before = json!(app.store.library);
        let p = api::preview(&mut app, name, true);
        assert_eq!(p.legacy.as_ref().unwrap()["canApply"], false);
        assert!(p.legacy.as_ref().unwrap()["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["code"] == "legacy_route_parts_required"));
        assert_eq!(
            app.restore_backup(&p.token).unwrap_err(),
            "legacy_import_blocked"
        );
        assert_eq!(json!(app.store.library), before);
    }
}

#[test]
fn stale_refresh_keeps_report_and_plan_cancel_is_inert_and_undo_restores_new_current_data() {
    let folder = tempfile::tempdir().unwrap();
    let mut app = api::app(folder.path(), &folder.path().join("missing-core"));
    let p = api::preview(&mut app, "both", false);
    let report = p.legacy.clone();
    let mut current = app.store.library.clone();
    current.profiles[0].name = "New current value".into();
    app.store.commit(current).unwrap();
    let before = json!(app.store.library);
    assert_eq!(
        app.restore_backup(&p.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = app.refresh_backup_preview(&p.token).unwrap();
    assert_eq!(refreshed.legacy, report);
    app.restore_backup(&refreshed.token).unwrap();
    let route = app.routing().profiles.last().unwrap().clone();
    assert_eq!(route.dns, api::expected("both")["expectedDNS"]);
    let backup = app.export_backup().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let mut other = api::app(destination.path(), &destination.path().join("missing-core"));
    let p = other.preview_backup(&backup).unwrap();
    other.restore_backup(&p.token).unwrap();
    assert_eq!(
        other.export_routing_profile(&route.id).unwrap(),
        app.export_routing_profile(&route.id).unwrap()
    );
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    let canceled = api::preview(&mut app, "direct", false);
    app.discard_backup_preview(&canceled.token);
    assert_eq!(
        app.restore_backup(&canceled.token).unwrap_err(),
        "backup_preview_expired"
    );
    assert_eq!(json!(app.store.library), before);
}

#[tokio::test]
async fn retained_runtime_constraints_reject_tun_before_core_spawn() {
    let folder = tempfile::tempdir().unwrap();
    let mut app = api::app(folder.path(), &folder.path().join("missing-core"));
    let id = api::install(&mut app, "both");
    let mut routing = app.routing();
    routing.active = id;
    app.save_routing(routing).unwrap();
    let mut library = app.store.library.clone();
    library.preferences.connection_mode = thronium_engine::system_proxy::ConnectionMode::Tun;
    app.store.commit(library).unwrap();
    let profile = app.store.library.profiles[0].clone();
    assert_eq!(
        app.check(&profile).await.unwrap_err(),
        "legacy_routing_tun_unsupported"
    );
    assert!(app.owned_core_process().is_none());
}
