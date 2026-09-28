//! Independent public Engine scope tests. Only synthetic settings and no core.
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};
use thronium_engine::{
    backups::legacy::{prepare, Scopes, SettingsScopes},
    legacy_backup::{self, Parts, SourceArchive, SourceDatabase, SourceSetting, SourceValue},
    store::{Profile, ProfileKind},
    Engine,
};

const URL: &str = "http://127.0.0.1:31871/probe?token=private-source-url";
fn setting(key: &str, value: &str) -> SourceSetting {
    SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: BTreeMap::from([
            ("key".into(), SourceValue::Text(key.into())),
            ("value".into(), SourceValue::Text(value.into())),
        ]),
    }
}
fn source() -> SourceArchive {
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            settings: vec![
                setting("language", "4"),
                setting("show_config_security", "1"),
                setting("skip_delete_confirmation", "true"),
                setting("test_url", URL),
                setting("url_test_timeout_ms", "1700"),
                setting("test_concurrent", "3"),
                setting("speed_test_mode", "2"),
                setting("speed_test_timeout_ms", "7600"),
                setting(
                    "simple_dl_url",
                    "http://127.0.0.1:31872/private-source-download",
                ),
                setting("log_auto_scroll", "false"),
                setting("private-unknown-key", "private-unknown-value"),
                setting("theme", "unknown-future-theme"),
                setting("remote_dns", "private-deferred-dns"),
            ],
            ..Default::default()
        }),
    }
}
fn engine(path: &Path) -> Engine {
    let mut app = Engine::open(path, &path.join("deliberately-absent-core")).unwrap();
    let mut current = app.store.library.clone();
    current.preferences.language = "en".into();
    current.preferences.theme = "dark".into();
    current.preferences.ping.url = "http://127.0.0.1:31873/current-url".into();
    current.settings.insert("compact".into(), json!(true));
    current.settings.insert("max_log_line".into(), json!(1500));
    app.store.commit(current).unwrap();
    app
}
fn scope(appearance: bool, testing: bool, logging: bool) -> Scopes {
    Scopes {
        profiles: false,
        routes: false,
        settings: SettingsScopes {
            appearance,
            testing,
            logging,
            geodata: false,
            warp: false,
            network: false,
            subscriptions: false,
            ..Default::default()
        },
        ..Default::default()
    }
}
fn safe(preview: &impl serde::Serialize) {
    let text = serde_json::to_string(preview).unwrap();
    for secret in [
        "private-source-url",
        "private-source-download",
        "private-unknown-key",
        "private-unknown-value",
        "unknown-future-theme",
        "private-deferred-dns",
    ] {
        assert!(!text.contains(secret));
    }
}
fn selected(
    app: &mut Engine,
    source: &SourceArchive,
    scopes: Scopes,
) -> thronium_engine::backups::Preview {
    let first = app.preview_legacy_import(prepare(source)).unwrap();
    app.legacy_backup_scopes(&first.token, scopes).unwrap()
}

#[test]
fn explicit_categories_apply_real_catalog_preference_paths_and_keep_all_other_values_with_exact_undo(
) {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let input = source();
    let first = app.preview_legacy_import(prepare(&input)).unwrap();
    let review = first.legacy.as_ref().unwrap();
    safe(&first);
    assert_eq!(review["canApply"], false);
    assert!(review["scopes"].get("settings").is_none());
    assert_eq!(review["settingsCount"], 0);
    assert_eq!(review["settingsDeferred"], 13);
    assert_eq!(review["settingsGroups"]["appearance"]["count"], 3);
    assert_eq!(review["settingsGroups"]["testing"]["count"], 6);
    assert_eq!(review["settingsGroups"]["logging"]["count"], 1);
    let picked = app
        .legacy_backup_scopes(&first.token, scope(true, true, true))
        .unwrap();
    safe(&picked);
    assert_eq!(picked.legacy.as_ref().unwrap()["settingsCount"], 10);
    assert_eq!(picked.legacy.as_ref().unwrap()["settingsDeferred"], 3);
    app.restore_backup(&picked.token).unwrap();
    let actual = app.settings();
    assert_eq!(actual["appearance"]["language"], "ru");
    assert_eq!(actual["testing"]["test_url"], URL);
    assert_eq!(actual["testing"]["url_test_timeout_ms"], 1700);
    assert_eq!(actual["testing"]["speed_test_mode"], "upload");
    assert_eq!(actual["security"]["skip_delete_confirmation"], true);
    assert_eq!(actual["logging"]["log_auto_scroll"], false);
    for key in ["language", "test_url", "url_test_timeout_ms"] {
        assert!(!app.store.library.settings.contains_key(key));
    }
    let mut wanted = before.clone();
    wanted["preferences"]["language"] = json!("ru");
    wanted["preferences"]["ping"]["url"] = json!(URL);
    wanted["preferences"]["ping"]["timeoutMs"] = json!(1700);
    for (key, value) in [
        ("show_config_security", json!(true)),
        ("skip_delete_confirmation", json!(true)),
        ("test_concurrent", json!(3)),
        ("speed_test_mode", json!("upload")),
        ("speed_test_timeout_ms", json!(7600)),
        (
            "simple_dl_url",
            json!("http://127.0.0.1:31872/private-source-download"),
        ),
        ("log_auto_scroll", json!(false)),
    ] {
        wanted["settings"][key] = value;
    }
    assert_eq!(json!(app.store.library), wanted);
    assert!(app.owned_core_process().is_none());
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}

#[test]
fn one_unsupported_category_blocks_whole_selected_batch_but_opt_out_preserves_valid_categories() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let mut input = source();
    input.database.as_mut().unwrap().settings[0] = setting("language", "0");
    let all = selected(&mut app, &input, scope(true, true, true));
    safe(&all);
    assert_eq!(all.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        app.restore_backup(&all.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    let rest = app
        .legacy_backup_scopes(&all.token, scope(false, true, true))
        .unwrap();
    assert_eq!(rest.legacy.as_ref().unwrap()["settingsCount"], 7);
    app.restore_backup(&rest.token).unwrap();
    assert_eq!(app.settings()["appearance"]["language"], "en");
    assert_eq!(app.settings()["appearance"]["show_config_security"], false);
    assert_eq!(app.settings()["testing"]["test_url"], URL);
    assert_eq!(app.settings()["logging"]["log_auto_scroll"], false);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}

#[test]
fn parts_boundary_precedes_malformed_rows_and_missing_fields_preserve_current_effective_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let mut input = source();
    input.parts.settings = false;
    input.database.as_mut().unwrap().settings[0]
        .columns
        .insert("value".into(), SourceValue::Blob(vec![1, 2, 3]));
    let excluded = selected(&mut app, &input, scope(true, true, true));
    safe(&excluded);
    assert_eq!(excluded.legacy.as_ref().unwrap()["settingsCount"], 0);
    assert_eq!(excluded.legacy.as_ref().unwrap()["canApply"], false);
    assert!(excluded.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["code"] == "legacy_settings_part_missing"));
    assert_eq!(
        app.restore_backup(&excluded.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    let mut partial = source();
    partial.database.as_mut().unwrap().settings = vec![setting("log_auto_scroll", "false")];
    let picked = selected(&mut app, &partial, scope(true, true, true));
    assert_eq!(picked.legacy.as_ref().unwrap()["settingsCount"], 1);
    app.restore_backup(&picked.token).unwrap();
    let mut wanted = before.clone();
    wanted["settings"]["log_auto_scroll"] = json!(false);
    assert_eq!(json!(app.store.library), wanted);
}

#[test]
fn toggle_and_stale_refresh_reuse_prepared_values_and_preserve_concurrent_unselected_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let mut input = source();
    let prepared = prepare(&input);
    input.database.as_mut().unwrap().settings[3] =
        setting("test_url", "http://127.0.0.1:31874/changed-after-prepare");
    let first = app.preview_legacy_import(prepared).unwrap();
    let on = app
        .legacy_backup_scopes(&first.token, scope(false, true, false))
        .unwrap();
    let off = app
        .legacy_backup_scopes(&on.token, scope(false, false, false))
        .unwrap();
    assert_eq!(off.legacy.as_ref().unwrap()["canApply"], false);
    let on = app
        .legacy_backup_scopes(&off.token, scope(false, true, false))
        .unwrap();
    let mut current = app.store.library.clone();
    current.preferences.theme = "light".into();
    current.settings.insert("max_log_line".into(), json!(3500));
    current.profiles.push(Profile {
        vpn_policy: None,
        id: "concurrent-profile".into(),
        name: "Concurrent profile".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    });
    app.store.commit(current).unwrap();
    let before = json!(app.store.library);
    assert_eq!(
        app.restore_backup(&on.token).unwrap_err(),
        "backup_preview_stale"
    );
    let fresh = app.refresh_backup_preview(&on.token).unwrap();
    safe(&fresh);
    assert_eq!(
        fresh.legacy.as_ref().unwrap()["scopes"]["settings"],
        json!({"appearance":false,"testing":true,"logging":false})
    );
    app.restore_backup(&fresh.token).unwrap();
    assert_eq!(app.settings()["testing"]["test_url"], URL);
    assert_eq!(app.settings()["appearance"]["theme"], "light");
    assert_eq!(app.settings()["logging"]["max_log_line"], 3500);
    assert!(app
        .store
        .library
        .profiles
        .iter()
        .any(|p| p.id == "concurrent-profile"));
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}

#[test]
fn settings_scopes_remain_opt_in_and_reject_unknown_or_wrongly_typed_categories() {
    let old: Scopes = serde_json::from_value(json!({"profiles":true,"routes":false})).unwrap();
    assert!(old.settings.is_empty());
    assert!(json!(old).get("settings").is_none());
    for settings in [
        Value::Null,
        json!(true),
        json!({"testing":"true"}),
        json!({"unknown_category":true}),
    ] {
        assert!(serde_json::from_value::<Scopes>(
            json!({"profiles":false,"routes":false,"settings":settings})
        )
        .is_err());
    }
    let partial: Scopes = serde_json::from_value(
        json!({"profiles":false,"routes":false,"settings":{"testing":true}}),
    )
    .unwrap();
    assert!(!partial.settings.appearance && partial.settings.testing && !partial.settings.logging);
}

fn qt(mixed: bool, name: &str) -> SourceArchive {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    legacy_backup::read(
        &root
            .join(if mixed {
                "../tests/fixtures/legacy-settings"
            } else {
                "src/legacy_backup/settings/fixtures"
            })
            .join(name),
    )
    .unwrap()
}
#[test]
fn actual_qt_archives_preserve_parts_boundary_and_allow_each_mixed_scope_opt_out_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    let excluded = qt(false, "excluded-settings.thrbackup");
    assert!(!excluded.parts.settings);
    assert!(excluded
        .database
        .as_ref()
        .unwrap()
        .settings
        .iter()
        .any(|row| row.key == "language" && row.value == "2"));
    let blocked = selected(&mut app, &excluded, scope(true, true, true));
    assert_eq!(blocked.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        app.restore_backup(&blocked.token).unwrap_err(),
        "legacy_import_blocked"
    );
    // Its unconvertible profile is left out (F3b); settings alone still import
    // without any profile and undo exactly.
    let source = qt(true, "blocked-profiles.thrbackup");
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    let only = app
        .legacy_backup_scopes(&first.token, scope(true, true, true))
        .unwrap();
    app.restore_backup(&only.token).unwrap();
    assert_eq!(app.settings()["appearance"]["language"], "ru");
    assert_eq!(app.settings()["testing"]["url_test_timeout_ms"], 4500);
    assert_eq!(app.settings()["testing"]["speed_test_mode"], "simple");
    assert!(app.store.library.profiles.is_empty());
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    let source = qt(true, "blocked-settings.thrbackup");
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    let both = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: true,
                ..scope(true, false, false)
            },
        )
        .unwrap();
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
    let mut preferences = json!(app.store.library.preferences);
    for profile in &app.store.library.profiles {
        preferences["vlessOverrides"]
            .as_object_mut()
            .unwrap()
            .remove(&profile.id);
    }
    assert_eq!(preferences, before["preferences"]);
    assert_eq!(json!(app.store.library.settings), before["settings"]);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}
#[test]
fn actual_qt_unknown_values_remain_private_and_empty_selection_cannot_claim_a_settings_restore() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let source = qt(false, "unknown-values.thrbackup");
    let selected = selected(&mut app, &source, scope(true, true, true));
    let public = json!(selected).to_string();
    assert!(!public.contains("synthetic-private"));
    assert_eq!(selected.legacy.as_ref().unwrap()["settingsCount"], 10);
    assert_eq!(selected.legacy.as_ref().unwrap()["settingsDeferred"], 1);
    let empty = qt(false, "empty.thrbackup");
    let first = app.preview_legacy_import(prepare(&empty)).unwrap();
    let picked = app
        .legacy_backup_scopes(&first.token, scope(true, true, true))
        .unwrap();
    assert_eq!(picked.legacy.as_ref().unwrap()["settingsCount"], 0);
    assert_eq!(picked.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        app.restore_backup(&picked.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert!(app.owned_core_process().is_none());
}
