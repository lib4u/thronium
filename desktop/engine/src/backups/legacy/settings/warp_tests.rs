use super::*;
use crate::legacy_backup::{SourceGroup, SourceProfile, SourceRoute, SourceValue};
use std::collections::BTreeMap;

fn source(name: &str) -> crate::legacy_backup::SourceArchive {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/settings/warp-fixtures")
        .join(format!("{name}.thrbackup"));
    crate::legacy_backup::parse(&std::fs::read(path).unwrap()).unwrap()
}
#[test]
fn legacy_warp_scope_defaults_off_and_old_json_shape_is_preserved() {
    let old = json!({"appearance":false,"testing":true,"logging":false});
    let scopes: SettingsScopes = serde_json::from_value(old.clone()).unwrap();
    assert!(!scopes.warp);
    assert_eq!(json!(scopes), old);
    assert!(!SettingsScopes {
        warp: true,
        ..Default::default()
    }
    .is_empty());
    assert!(serde_json::from_value::<SettingsScopes>(json!({"warp":"yes"})).is_err());
}
#[test]
fn legacy_warp_import_reopens_undoes_and_never_starts_core_or_registration() {
    for fixture in ["valid", "disabled", "empty", "off-only"] {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("absent-core");
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        let mut initial = engine.store.library.clone();
        initial
            .settings
            .insert("warp_private_key".into(), json!("old-private-canary74"));
        initial
            .settings
            .insert("future-option74".into(), json!({"preserve":true}));
        engine.store.commit(initial).unwrap();
        let before = json!(engine.store.library);
        let archive = source(fixture);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive))
            .unwrap();
        let public = json!(preview);
        assert!(!public["legacy"]["scopes"]["settings"]["warp"]
            .as_bool()
            .unwrap_or(false));
        assert_eq!(json!(engine.store.library), before);
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: SettingsScopes {
                        warp: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(json!(selected)["legacy"]["canApply"], true);
        let plan = crate::legacy_backup::settings::convert(&archive, &Group::Warp)
            .unwrap_or_else(|_| panic!("fixture"));
        for key in ["warp_private_key", "warp_public_key"] {
            if let Some(value) = plan
                .values
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                assert!(!json!(selected).to_string().contains(value));
            }
        }
        engine.restore_backup(&selected.token).unwrap();
        let mut expected = before.clone();
        for (key, value) in plan.values {
            expected["settings"][key] = value;
        }
        assert_eq!(json!(engine.store.library), expected);
        assert!(engine.rpc.is_none() && engine.running.is_none());
        drop(engine);
        let mut reopened = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(json!(reopened.store.library), expected);
        let undo = reopened.preview_previous_backup().unwrap();
        reopened.restore_backup(&undo.token).unwrap();
        assert_eq!(json!(reopened.store.library), before);
    }
}
#[test]
fn legacy_warp_merge_revalidates_bundle_and_invalid_scope_leaves_library_unchanged() {
    let mut library = Library::default();
    let invalid = SettingsPlan {
        group: Group::Warp,
        values: BTreeMap::from([("warp_private_key".into(), json!("bad"))]),
        imported_fields: vec![],
        deferred_count: 0,
        report: vec![],
    };
    let before = json!(library);
    assert!(merge(&mut library, &[&invalid]).is_err());
    assert_eq!(json!(library), before);
    for fixture in [
        "incomplete",
        "bad-key",
        "bad-reserved",
        "ipv6-endpoint",
        "unknown-column",
        "excluded-settings",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        let before = json!(engine.store.library);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&source(fixture)))
            .unwrap();
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: SettingsScopes {
                        warp: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(json!(selected)["legacy"]["canApply"], false);
        assert!(engine.restore_backup(&selected.token).is_err());
        assert_eq!(json!(engine.store.library), before);
    }
}

#[test]
fn linked_routes_and_pools_require_same_archive_warp_and_undo_atomically() {
    for (routes, profiles) in [(true, false), (false, true), (true, true)] {
        let mut archive = source("valid");
        archive.parts.routes = routes;
        archive.parts.profiles = profiles;
        let db = archive.database.as_mut().unwrap();
        if routes {
            db.routes.push(SourceRoute {
                id: 1,
                name: "WARP source policy".into(),
                columns: BTreeMap::from([
                    ("is_raw".into(), SourceValue::Integer(1)),
                    (
                        "raw_route".into(),
                        SourceValue::Text(
                            json!({"final":-5,"rules":[{"domain":["bypass.test"],"outbound":-5}]})
                                .to_string(),
                        ),
                    ),
                ]),
            });
        }
        if profiles {
            db.groups.push(SourceGroup {
                id: 7,
                name: "Source pool".into(),
                columns: BTreeMap::from([(
                    "profiles_json".into(),
                    SourceValue::Text("[11,90]".into()),
                )]),
            });
            for (id, kind, outbound) in [
                (
                    11,
                    "socks",
                    json!({"type":"socks","server":"127.0.0.1","server_port":19001}),
                ),
                (
                    90,
                    "autoselector",
                    json!({"type":"autoselector","name":"Source selector","gid":7,"last_built":[11],"test_url":"http://127.0.0.1:19000/probe"}),
                ),
            ] {
                db.profiles.push(SourceProfile {
                    id,
                    group_id: 7,
                    kind: kind.into(),
                    name: Some(format!("Source {id}")),
                    columns: BTreeMap::from([(
                        "outbound_json".into(),
                        SourceValue::Text(outbound.to_string()),
                    )]),
                    outbound,
                });
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("absent-core");
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        engine.store.library.settings.insert(
            "warp_private_key".into(),
            json!("old-key-must-not-be-mixed"),
        );
        let before = json!(engine.store.library);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive))
            .unwrap();
        let mut scopes = super::super::Scopes {
            profiles,
            routes,
            auto_selectors: super::super::AutoSelectors::LastBuilt,
            ..Default::default()
        };
        let blocked = engine.legacy_backup_scopes(&preview.token, scopes).unwrap();
        let review = json!(blocked);
        assert_eq!(review["legacy"]["canApply"], false, "{review}");
        assert!(
            review["legacy"]["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["code"] == "legacy_import_requires_warp"),
            "{review}"
        );
        assert!(engine.restore_backup(&blocked.token).is_err());
        assert_eq!(json!(engine.store.library), before);
        scopes.settings.warp = true;
        let accepted = engine.legacy_backup_scopes(&blocked.token, scopes).unwrap();
        let review = json!(accepted);
        assert_eq!(review["legacy"]["canApply"], true, "{review}");
        assert!(!review["legacy"]["requirements"]
            .as_array()
            .unwrap()
            .contains(&json!("legacy_routing_warp_required")));
        let warp = crate::legacy_backup::settings::convert(&archive, &Group::Warp)
            .unwrap_or_else(|_| panic!("warp fixture"));
        for key in ["warp_private_key", "warp_public_key"] {
            assert!(!review
                .to_string()
                .contains(warp.values[key].as_str().unwrap()));
        }
        engine.restore_backup(&accepted.token).unwrap();
        for (key, value) in warp.values {
            assert_eq!(engine.store.library.settings[&key], value);
        }
        assert_eq!(
            engine.store.library.routing.active,
            before["routing"]["active"]
        );
        assert!(engine.rpc.is_none() && engine.running.is_none());
        let imported = json!(engine.store.library);
        drop(engine);
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(json!(engine.store.library), imported);
        let undo = engine.preview_previous_backup().unwrap();
        engine.restore_backup(&undo.token).unwrap();
        assert_eq!(json!(engine.store.library), before);
    }
}
