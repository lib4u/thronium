use super::*;

fn source(name: &str) -> crate::legacy_backup::SourceArchive {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/settings/network-fixtures")
        .join(format!("{name}.thrbackup"));
    crate::legacy_backup::parse(&std::fs::read(path).unwrap()).unwrap()
}
fn seeded(engine: &mut Engine) {
    let mut library = engine.store.library.clone();
    library
        .settings
        .insert("user_agent".into(), json!("old-agent75/1.0"));
    library
        .settings
        .insert("sub_auto_update".into(), json!(120));
    library
        .settings
        .insert("unrelated-setting75".into(), json!({"keep":true}));
    for inherit in [Some(true), Some(false), None] {
        library.groups.push(serde_json::from_value(json!({"id":uuid::Uuid::new_v4().to_string(),"name":format!("Group {inherit:?}"),
            "subscription":{"url":"https://owned.test/sub75","userAgent":"per-group-agent75","intervalMinutes":90,
                "inheritDefaults":inherit,"updatedAt":1700000000u64,"headers":{"Authorization":"private-header75"}}})).unwrap());
    }
    engine.store.commit(library).unwrap();
}
#[test]
fn legacy_network_scopes_are_independent_and_old_serialized_defaults_stay_unchanged() {
    let old = json!({"appearance":false,"testing":true,"logging":false});
    let scopes: SettingsScopes = serde_json::from_value(old.clone()).unwrap();
    assert!(!scopes.network && !scopes.subscriptions);
    assert_eq!(json!(scopes), old);
    assert!(!SettingsScopes {
        network: true,
        ..Default::default()
    }
    .is_empty());
    assert!(!SettingsScopes {
        subscriptions: true,
        ..Default::default()
    }
    .is_empty());
    assert!(serde_json::from_value::<SettingsScopes>(json!({"network":"true"})).is_err());
}
#[test]
fn legacy_network_import_updates_only_selected_inherited_fields_reopens_and_exactly_undoes() {
    for (network, subscriptions, fixture) in [
        (true, false, "valid"),
        (false, true, "valid"),
        (false, true, "clear-all"),
        (true, true, "valid"),
        (false, true, "negative-interval"),
        (true, false, "empty-agent"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("absent-core");
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        seeded(&mut engine);
        let before = json!(engine.store.library);
        let archive = source(fixture);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive))
            .unwrap();
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: SettingsScopes {
                        network,
                        subscriptions,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(json!(selected)["legacy"]["canApply"], true);
        let public = json!(selected).to_string();
        for marker in [
            "private-agent75",
            "private-hwid75",
            "private-model75",
            "private-header75",
        ] {
            assert!(!public.contains(marker));
        }
        assert_eq!(json!(engine.store.library), before);
        engine.restore_backup(&selected.token).unwrap();
        let mut expected = before.clone();
        for (chosen, group) in [
            (network, Group::Network),
            (subscriptions, Group::Subscriptions),
        ] {
            if chosen {
                for (key, value) in crate::legacy_backup::settings::convert(&archive, &group)
                    .unwrap_or_else(|_| panic!("source"))
                    .values
                {
                    expected["settings"][key] = value;
                }
            }
        }
        let agent = expected["settings"]["user_agent"].clone();
        let interval = expected["settings"]["sub_auto_update"].clone();
        for group in expected["groups"].as_array_mut().unwrap() {
            if group["subscription"]["inheritDefaults"] == true {
                if network {
                    group["subscription"]["userAgent"] = agent.clone();
                }
                if subscriptions {
                    group["subscription"]["intervalMinutes"] = interval.clone();
                }
            }
        }
        assert_eq!(json!(engine.store.library), expected);
        let inherited = engine
            .store
            .library
            .groups
            .iter()
            .filter_map(|g| g.subscription.as_ref())
            .find(|s| s.settings.inherit_defaults == Some(true))
            .unwrap();
        assert_eq!(inherited.updated_at, Some(1700000000));
        let minutes = inherited.settings.interval_minutes as u64;
        assert_eq!(
            crate::subscriptions::jobs::next_due(inherited),
            if minutes == 0 {
                None
            } else {
                Some(1700000000 + minutes * 60)
            }
        );
        assert!(
            engine.rpc.is_none() && engine.running.is_none() && !engine.subscription_jobs.busy()
        );
        drop(engine);
        let mut reopened = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(json!(reopened.store.library), expected);
        let undo = reopened.preview_previous_backup().unwrap();
        reopened.restore_backup(&undo.token).unwrap();
        assert_eq!(json!(reopened.store.library), before);
    }
}
#[test]
fn legacy_network_unsupported_selected_category_never_changes_library_and_can_be_unselected() {
    for (fixture, network, subscriptions) in [
        ("bad-agent", true, false),
        ("too-large-interval", false, true),
        ("unknown-column", true, true),
        ("excluded-settings", true, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        seeded(&mut engine);
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
                        network,
                        subscriptions,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(json!(selected)["legacy"]["canApply"], false);
        assert!(engine.restore_backup(&selected.token).is_err());
        assert_eq!(json!(engine.store.library), before);
        if fixture == "bad-agent" || fixture == "too-large-interval" {
            let alternative = engine
                .legacy_backup_scopes(
                    &selected.token,
                    super::super::Scopes {
                        profiles: false,
                        settings: SettingsScopes {
                            network: !network,
                            subscriptions: !subscriptions,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(json!(alternative)["legacy"]["canApply"], true);
        }
    }
}
