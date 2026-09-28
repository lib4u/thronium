use super::*;
use std::collections::BTreeMap;

fn source() -> crate::legacy_backup::SourceArchive {
    use crate::legacy_backup::{Parts, SourceArchive, SourceDatabase, SourceSetting, SourceValue};
    let rows = [
        ("xray_geoip_url", "https://assets.test/private-source73/geoip.dat"),
        ("xray_geosite_url", "https://assets.test/private-source73/geosite.dat"),
        ("xray_geoip_url_history", "[]"),
        ("xray_geosite_url_history", "[\"https://assets.test/private-history73/a\",\"https://assets.test/private-history73/a\"]"),
        ("language", "invalid-unselected-language"),
    ];
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: Value::Null,
        created_at: None,
        parts: Parts {
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            settings: rows
                .into_iter()
                .map(|(key, value)| SourceSetting {
                    key: key.into(),
                    value: value.into(),
                    columns: BTreeMap::from([
                        ("key".into(), SourceValue::Text(key.into())),
                        ("value".into(), SourceValue::Text(value.into())),
                    ]),
                })
                .collect(),
            ..Default::default()
        }),
    }
}

#[test]
fn geodata_scope_is_explicit_and_preserves_old_serialized_scope_shape() {
    let old = json!({"appearance":false,"testing":true,"logging":false});
    let scopes: SettingsScopes = serde_json::from_value(old.clone()).unwrap();
    assert!(!scopes.geodata && scopes.testing);
    assert_eq!(json!(scopes), old);
    assert!(SettingsScopes::default().is_empty());
    assert!(!SettingsScopes {
        geodata: true,
        ..Default::default()
    }
    .is_empty());
    assert!(serde_json::from_value::<SettingsScopes>(json!({"geodata":"yes"})).is_err());
    assert!(serde_json::from_value::<SettingsScopes>(json!({"future":true})).is_err());
}

#[test]
fn geodata_import_reopen_and_undo_preserve_unselected_library_and_never_start_core() {
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("absent-core");
    let mut engine = Engine::open(dir.path(), &core).unwrap();
    let mut initial = engine.store.library.clone();
    initial.settings.insert(
        "xray_geoip_url_history".into(),
        json!(["https://prior.test/a"]),
    );
    initial.settings.insert("font_size".into(), json!(19));
    initial
        .settings
        .insert("custom-future-key".into(), json!({"keep":true}));
    engine.store.commit(initial).unwrap();
    let before = json!(engine.store.library);
    let preview = engine
        .preview_legacy_import(super::super::prepare(&source()))
        .unwrap();
    assert!(
        !preview.legacy.as_ref().unwrap()["scopes"]["settings"]["geodata"]
            .as_bool()
            .unwrap_or(false)
    );
    assert_eq!(json!(engine.store.library), before);
    let selected = engine
        .legacy_backup_scopes(
            &preview.token,
            super::super::Scopes {
                profiles: false,
                settings: SettingsScopes {
                    geodata: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let review = json!(selected);
    assert_eq!(review["legacy"]["canApply"], true);
    assert_eq!(review["legacy"]["settingsCount"], 4);
    assert!(
        !review.to_string().contains("private-source73")
            && !review.to_string().contains("private-history73")
    );
    engine.restore_backup(&selected.token).unwrap();
    let mut expected = before.clone();
    for (id, value) in crate::legacy_backup::settings::convert(&source(), &Group::Geodata)
        .unwrap_or_else(|_| panic!("source"))
        .values
    {
        expected["settings"][id] = value;
    }
    assert_eq!(json!(engine.store.library), expected);
    assert_eq!(engine.xray_geodata_sources()["history"]["geoip"], json!([]));
    assert_eq!(
        engine.xray_geodata_sources()["history"]["geosite"],
        json!(["https://assets.test/private-history73/a"])
    );
    assert!(engine.rpc.is_none() && engine.running.is_none());
    assert!(!dir.path().join("xray-assets").exists());
    drop(engine);
    let mut reopened = Engine::open(dir.path(), &core).unwrap();
    assert_eq!(json!(reopened.store.library), expected);
    let undo = reopened.preview_previous_backup().unwrap();
    reopened.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(reopened.store.library), before);
}

#[test]
fn geodata_internal_history_merge_revalidates_an_exact_allowlist() {
    fn plan(id: &str, value: Value) -> SettingsPlan {
        SettingsPlan {
            group: Group::Geodata,
            values: BTreeMap::from([(id.into(), value)]),
            imported_fields: vec![id.into()],
            deferred_count: 0,
            report: vec![],
        }
    }
    let mut library = Library::default();
    for value in [
        json!(null),
        json!([1]),
        json!(["file:///tmp/private73"]),
        json!(vec!["https://assets.test/a"; 6]),
    ] {
        assert!(merge(&mut library, &[&plan("xray_geoip_url_history", value)]).is_err());
    }
    assert!(merge(&mut library, &[&plan("other_url_history", json!([]))]).is_err());
    let valid = plan("xray_geoip_url_history", json!(["https://assets.test/a"]));
    merge(&mut library, &[&valid]).unwrap();
    assert_eq!(
        library.settings["xray_geoip_url_history"],
        json!(["https://assets.test/a"])
    );
    assert_eq!(
        merge(&mut library, &[&valid, &valid]).unwrap_err(),
        "legacy_settings_duplicate"
    );
}
