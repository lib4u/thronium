use super::legacy::{merge, Prepared};
use crate::{
    legacy_backup::profiles::ProfilePlan,
    store::{Group, Profile, ProfileKind},
    Engine,
};
use serde_json::json;
use std::collections::BTreeMap;

fn profile(id: &str, group: &str) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        group_id: group.into(),
        name: id.into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    }
}
fn prepared() -> Prepared {
    Prepared {
        resources: Default::default(),
        icons: None,
        icon_issues: vec![],
        settings: vec![],
        otp: None,
        otp_issues: vec![],
        routes: None,
        route_issues: vec![],
        traffic: None,
        scopes: Default::default(),
        plan: Some(ProfilePlan {
            resources: Default::default(),
            requires_warp: false,
            profiles: vec![Profile {
                config: json!({"dns":{"servers":["127.0.0.1"]},"routing":{"domainStrategy":"IPIfNonMatch"},"outbounds":[{"protocol":"freedom"}]}),
                kind: ProfileKind::XrayConfig,
                ..profile("imported-profile", "imported-group")
            }],
            groups: vec![Group {
                id: "imported-group".into(),
                name: "Same name".into(),
                collapsed: false,
                auto_clear_unavailable: false,
                proxy_chain: Default::default(),
                subscription: None,
            }],
            profile_ids: BTreeMap::from([(7, "imported-profile".into())]),
            group_ids: BTreeMap::from([(2, "imported-group".into())]),
            vless_overrides: Default::default(),
            vpn_bindings: Default::default(),
            selected: Some("imported-profile".into()),
            report: vec![],
        }),
        review: json!({"format":"throne-backup","createdAt":"Fri Sep 11 2026","canApply":false,"issues":[],"inventory":{"profiles":1,"groups":1,"settings":42,"routes":2}}),
    }
}
fn engine(path: &std::path::Path) -> Engine {
    let mut engine = Engine::open(path, &path.join("unavailable-core")).unwrap();
    let mut library = engine.store.library.clone();
    library.groups[0].name = "Same name".into();
    library.profiles.push(profile("existing", "personal"));
    library.selected = Some("existing".into());
    library.preferences.inbound_port = 17891;
    engine.store.commit(library).unwrap();
    engine
}

#[test]
fn selected_settings_refresh_keeps_the_private_source_plan_and_newer_unselected_values() {
    use super::legacy::{prepare, Scopes, SettingsScopes};
    use crate::legacy_backup::{Parts, SourceArchive, SourceDatabase, SourceSetting, SourceValue};
    let rows = [
        ("language", "1"),
        ("show_config_security", "false"),
        ("skip_delete_confirmation", "false"),
        ("test_url", "https://example.test/private-settings-url"),
        ("url_test_timeout_ms", "4321"),
        ("test_concurrent", "3"),
        ("speed_test_mode", "3"),
        ("speed_test_timeout_ms", "9876"),
        ("simple_dl_url", "https://example.test/private-download-url"),
        ("log_auto_scroll", "false"),
        ("unknown-private-key", "private-unmapped-value"),
        ("font_size", "18"),
    ];
    let mut source = SourceArchive {
        container_version: 1,
        content_version: None,
        metadata: json!({}),
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
    };
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert!(first.legacy.as_ref().unwrap()["scopes"]
        .get("settings")
        .is_none());
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], false);
    let selected = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                routes: false,
                otp: false,
                settings: SettingsScopes {
                    appearance: true,
                    testing: true,
                    logging: true,
                    geodata: false,
                    warp: false,
                    network: false,
                    subscriptions: false,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let review = json!(selected);
    assert_eq!(review["legacy"]["settingsCount"], 10);
    assert_eq!(review["legacy"]["settingsDeferred"], 2);
    for private in [
        "private-settings-url",
        "private-download-url",
        "unknown-private-key",
        "private-unmapped-value",
    ] {
        assert!(!review.to_string().contains(private));
    }
    // Refresh is based on the prepared values, not on mutable archive DTOs.
    source.database.as_mut().unwrap().settings.clear();
    let mut latest = app.store.library.clone();
    latest.settings.insert("font_size".into(), json!(21));
    latest
        .settings
        .insert("custom-future-value".into(), json!({"preserve":true}));
    app.store.commit(latest).unwrap();
    let before = json!(app.store.library);
    assert_eq!(
        app.restore_backup(&selected.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = app.refresh_backup_preview(&selected.token).unwrap();
    assert_ne!(selected.token, refreshed.token);
    assert_eq!(refreshed.legacy.as_ref().unwrap()["settingsCount"], 10);
    app.restore_backup(&refreshed.token).unwrap();
    for (id, wanted) in [
        ("language", json!("en")),
        (
            "test_url",
            json!("https://example.test/private-settings-url"),
        ),
        ("url_test_timeout_ms", json!(4321)),
        ("test_concurrent", json!(3)),
        ("speed_test_mode", json!("simple")),
        ("speed_test_timeout_ms", json!(9876)),
        (
            "simple_dl_url",
            json!("https://example.test/private-download-url"),
        ),
        ("log_auto_scroll", json!(false)),
        ("show_config_security", json!(false)),
        ("skip_delete_confirmation", json!(false)),
        ("font_size", json!(21)),
    ] {
        assert_eq!(
            crate::settings::value(&app.store.library, id),
            wanted,
            "{id}"
        );
    }
    let after = json!(app.store.library);
    for key in ["profiles", "groups", "routing", "selected", "otp"] {
        assert_eq!(after[key], before[key]);
    }
    assert_eq!(
        after["settings"]["custom-future-value"],
        before["settings"]["custom-future-value"]
    );
    assert!(app.running.is_none() && app.rpc.is_none());
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
}

#[test]
fn additive_import_preserves_current_library_network_selection_and_complete_custom_dns() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let original = engine.store.library.clone();
    let pending = prepared();
    let source = json!(pending.plan.as_ref().unwrap().profiles[0].config);
    let preview = engine.preview_legacy_import(pending).unwrap();
    assert_eq!(json!(engine.store.library), json!(original));
    assert_eq!(preview.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(preview.current.profiles, 1);
    assert_eq!(preview.incoming.profiles, 2);
    engine.restore_backup(&preview.token).unwrap();
    assert_eq!(engine.store.library.selected, original.selected);
    assert_eq!(
        json!(engine.store.library.preferences),
        json!(original.preferences)
    );
    assert_eq!(json!(engine.store.library.routing), json!(original.routing));
    assert_eq!(engine.store.library.settings, original.settings);
    assert_eq!(
        json!(engine.store.library.profiles[0]),
        json!(original.profiles[0])
    );
    assert_eq!(engine.store.library.profiles[1].config, source);
    assert!(engine.running.is_none());
    assert!(engine.rpc.is_none());
    let undo = engine.preview_previous_backup().unwrap();
    assert!(undo.legacy.is_none());
    engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(engine.store.library), json!(original));
}

#[test]
fn unsupported_import_cannot_be_applied_by_bypassing_the_disabled_button() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let before = json!(engine.store.library);
    let mut input = prepared();
    input.plan = None;
    input.review["issues"] = json!([{"code":"legacy_profile_external_core_unsupported"}]);
    let preview = engine.preview_legacy_import(input).unwrap();
    assert_eq!(preview.legacy.unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&preview.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(engine.store.library), before);
    assert!(!dir.path().join("backup-before-restore.json").exists());
}

#[test]
fn stale_import_refresh_reuses_the_plan_and_report_but_merges_against_the_current_library() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut input = prepared();
    input.review["issues"] = json!([{"code":"legacy_settings_deferred"}]);
    let preview = engine.preview_legacy_import(input).unwrap();
    let mut changed = engine.store.library.clone();
    changed
        .profiles
        .push(profile("added-after-preview", "personal"));
    changed.preferences.inbound_port = 17892;
    engine.store.commit(changed.clone()).unwrap();
    assert_eq!(
        engine.restore_backup(&preview.token).unwrap_err(),
        "backup_preview_stale"
    );
    let next = engine.refresh_backup_preview(&preview.token).unwrap();
    assert_ne!(next.token, preview.token);
    assert_eq!(next.incoming.profiles, 3);
    assert_eq!(
        next.legacy.as_ref().unwrap()["issues"],
        preview.legacy.as_ref().unwrap()["issues"]
    );
    assert_eq!(
        next.legacy.as_ref().unwrap()["createdAt"],
        "Fri Sep 11 2026"
    );
    engine.restore_backup(&next.token).unwrap();
    assert_eq!(
        engine.store.library.profiles.last().unwrap().id,
        "imported-profile"
    );
    assert_eq!(
        json!(engine.store.library.profiles[..2]),
        json!(changed.profiles)
    );
    assert_eq!(engine.store.library.preferences.inbound_port, 17892);
}

#[test]
fn refresh_does_not_overwrite_conflicting_profile_ids_or_core_preferences() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let input = prepared();
    let mut library = engine.store.library.clone();
    library
        .profiles
        .push(profile("imported-profile", "personal"));
    assert_eq!(
        merge(
            &library,
            input.plan.as_ref(),
            None,
            None,
            None,
            &[],
            Default::default()
        )
        .err()
        .unwrap(),
        "invalid_library_ids"
    );
    let preview = engine.preview_legacy_import(input).unwrap();
    engine.store.commit(library).unwrap();
    let next = engine.refresh_backup_preview(&preview.token).unwrap();
    assert_eq!(next.legacy.unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&next.token).unwrap_err(),
        "legacy_import_blocked"
    );
}

#[test]
fn archive_parts_are_applied_at_the_preview_boundary_before_conversion() {
    use crate::legacy_backup::{
        Parts, SourceArchive, SourceDatabase, SourceGroup, SourceProfile, SourceSetting,
        SourceValue,
    };
    let mut database = SourceDatabase::default();
    database.groups.push(SourceGroup {
        id: 2,
        name: "Legacy group".into(),
        columns: BTreeMap::from([("profiles_json".into(), SourceValue::Text("[7]".into()))]),
    });
    database.profiles.push(SourceProfile {id:7,kind:"trojan".into(),name:Some("Legacy TLS".into()),group_id:2,columns:Default::default(),
        outbound:json!({"type":"trojan","tag":"Legacy TLS","server":"example.invalid","server_port":443,"password":"fixture-secret","tls":{"enabled":true}})});
    for key in ["skip_cert", "mux_default_on", "fragment_default_on"] {
        database.settings.push(SourceSetting {
            key: key.into(),
            value: "true".into(),
            columns: Default::default(),
        });
    }
    let source = SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            profiles: true,
            ..Default::default()
        },
        files: Default::default(),
        database: Some(database),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let preview = engine
        .preview_legacy_import(super::legacy::prepare(&source))
        .unwrap();
    assert_eq!(preview.legacy.as_ref().unwrap()["canApply"], true);
    engine.restore_backup(&preview.token).unwrap();
    let imported = engine.store.library.profiles.last().unwrap();
    assert_eq!(imported.config["tls"]["insecure"], false);
    assert_eq!(imported.config["tls"]["fragment"], false);
    assert_eq!(imported.config["multiplex"]["enabled"], false);
}

fn with_routes(mut input: Prepared, references_profile: bool) -> Prepared {
    use crate::{
        legacy_backup::routes::RoutePlan,
        routing::{LegacyRoutingConstraints, RoutingProfile, Rule},
    };
    if references_profile {
        let profile = &mut input.plan.as_mut().unwrap().profiles[0];
        profile.kind = ProfileKind::SingBoxOutbound;
        profile.config = json!({"type":"direct"});
    }
    input.routes = Some(RoutePlan {
        resources: Default::default(),
        presets: vec![RoutingProfile {
            id: "legacy-route".into(),
            name: "Imported policy".into(),
            mode: "rules".into(),
            source: None,
            route: json!({"final":"direct","default_domain_resolver":"saved-dns"}),
            dns: json!({"servers":[{"type":"tcp","tag":"saved-dns","server":"127.0.0.1","server_port":5353}],"final":"saved-dns"}),
            rules: vec![Rule {
                id: "legacy-rule".into(),
                name: "Saved rule".into(),
                enabled: true,
                simple: None,
                config: json!({"domain":["private-policy.example.test"],"outbound":if references_profile {"profile:imported-profile"}else{"direct"}}),
            }],
            legacy_constraints: Some(LegacyRoutingConstraints {
                warp_enabled: false,
                version: 1,
                xray_dns_strategy: None,
                ..Default::default()
            }),
        }],
        route_ids: BTreeMap::from([(3, "legacy-route".into())]),
        selected: Some("legacy-route".into()),
        report: vec![],
    });
    input
}

#[test]
fn profile_and_route_scopes_commit_together_and_undo_restores_the_exact_active_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let before = engine.store.library.clone();
    let input = with_routes(prepared(), true);
    let dns = input.routes.as_ref().unwrap().presets[0].dns.clone();
    let first = engine.preview_legacy_import(input).unwrap();
    assert_eq!(first.incoming.routing_profiles, 1);
    let selected = engine
        .legacy_backup_scopes(
            &first.token,
            super::legacy::Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.incoming.routing_profiles, 2);
    assert_eq!(selected.incoming.profiles, 2);
    assert_eq!(
        engine.restore_backup(&first.token).unwrap_err(),
        "backup_preview_expired"
    );
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(engine.store.library.routing.active, before.routing.active);
    assert_eq!(
        engine.store.library.routing.revision,
        before.routing.revision + 1
    );
    assert_eq!(engine.store.library.routing.profiles[1].dns, dns);
    assert_eq!(
        engine.store.library.routing.profiles[1].rules[0].config["outbound"],
        "profile:imported-profile"
    );
    assert_eq!(engine.store.library.selected, before.selected);
    assert_eq!(engine.store.library.settings, before.settings);
    assert_eq!(
        json!(engine.store.library.preferences),
        json!(before.preferences)
    );
    assert_eq!(
        engine.store.library.routing.profiles[1]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .version,
        1
    );
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(engine.store.library), json!(before));
}

#[test]
fn route_only_import_is_explicit_and_cannot_drop_required_profile_references() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let before = engine.store.library.clone();
    let first = engine
        .preview_legacy_import(with_routes(prepared(), true))
        .unwrap();
    let blocked = engine
        .legacy_backup_scopes(
            &first.token,
            super::legacy::Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(blocked.legacy.as_ref().unwrap()["canApply"], false);
    assert!(blocked.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_routes_require_profiles"));
    assert_eq!(
        engine.restore_backup(&blocked.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(engine.store.library), json!(before));
    let first = engine
        .preview_legacy_import(with_routes(prepared(), false))
        .unwrap();
    let selected = engine
        .legacy_backup_scopes(
            &first.token,
            super::legacy::Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(json!(engine.store.library.profiles), json!(before.profiles));
    assert_eq!(json!(engine.store.library.groups), json!(before.groups));
    assert_eq!(engine.store.library.routing.profiles.len(), 2);
}

#[test]
fn unsupported_selected_routes_block_all_scopes_and_deselection_restores_the_profile_plan() {
    use crate::legacy_backup::profiles::Issue;
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let before = json!(engine.store.library);
    let mut input = prepared();
    input.route_issues = vec![Issue {
        code: "legacy_dns_dynamic_unsupported".into(),
        entity: Some("route".into()),
        source_id: Some(3),
        name: Some("Policy".into()),
    }];
    let first = engine.preview_legacy_import(input).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    let blocked = engine
        .legacy_backup_scopes(
            &first.token,
            super::legacy::Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(blocked.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&blocked.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(engine.store.library), before);
    let selected = engine
        .legacy_backup_scopes(
            &blocked.token,
            super::legacy::Scopes {
                profiles: true,
                routes: false,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    assert!(selected.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .is_empty());
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(
        engine.store.library.profiles.last().unwrap().id,
        "imported-profile"
    );
}

#[test]
fn route_refresh_keeps_uuids_and_rechecks_new_collisions_and_global_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut input = with_routes(prepared(), false);
    input.scopes.routes = true;
    let first = engine.preview_legacy_import(input).unwrap();
    let mut current = engine.store.library.clone();
    current
        .settings
        .insert("enable_dns_routing".into(), json!(true));
    engine.store.commit(current).unwrap();
    assert_eq!(
        engine.restore_backup(&first.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = engine.refresh_backup_preview(&first.token).unwrap();
    assert_eq!(refreshed.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(
        refreshed.legacy.as_ref().unwrap()["requirements"],
        json!(["legacy_routing_dns_follow_conflict"])
    );
    engine.restore_backup(&refreshed.token).unwrap();
    assert_eq!(engine.store.library.routing.active, "default");
    assert_eq!(engine.store.library.routing.profiles[1].id, "legacy-route");
    assert_eq!(
        engine.store.library.routing.profiles[1].rules[0].id,
        "legacy-rule"
    );
    let mut input = with_routes(prepared(), false);
    input.scopes = super::legacy::Scopes {
        profiles: false,
        routes: true,
        ..Default::default()
    };
    let conflict = engine.preview_legacy_import(input).unwrap();
    assert_eq!(conflict.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&conflict.token).unwrap_err(),
        "legacy_import_blocked"
    );
}

#[test]
fn unsupported_profile_scope_can_be_excluded_for_an_independent_route_import() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut input = with_routes(prepared(), false);
    input.plan = None;
    input.review["issues"] = json!([{"code":"legacy_profile_external_core_unsupported"}]);
    let first = engine.preview_legacy_import(input).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], false);
    let selected = engine
        .legacy_backup_scopes(
            &first.token,
            super::legacy::Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(selected.legacy.as_ref().unwrap()["issues"], json!([]));
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(engine.store.library.profiles.len(), 1);
    assert_eq!(engine.store.library.routing.profiles.len(), 2);
}

#[test]
fn inactive_generated_dns_requirements_use_each_incoming_preset_and_refresh_current_settings() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut current = engine.store.library.clone();
    current.routing.profiles[0].dns = json!({"servers":[{"type":"tcp","tag":"current","server":"127.0.0.1","server_port":5353}],"final":"current"});
    current.routing.profiles[0].route["default_domain_resolver"] = json!("current");
    current.settings.insert(
        "core_box_underlying_dns".into(),
        json!("tcp://127.0.0.1:5354"),
    );
    engine.store.commit(current).unwrap();
    let mut input = with_routes(prepared(), false);
    input.scopes = super::legacy::Scopes {
        profiles: false,
        routes: true,
        ..Default::default()
    };
    let preset = &mut input.routes.as_mut().unwrap().presets[0];
    preset.legacy_constraints.as_mut().unwrap().version = 2;
    preset.dns = json!({"servers":[{"type":"local","tag":"saved-dns"}],"final":"saved-dns"});
    let first = engine.preview_legacy_import(input).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(
        first.legacy.as_ref().unwrap()["requirements"],
        json!(["legacy_routing_local_dns_conflict"])
    );
    assert_eq!(engine.store.library.routing.active, "default");
    let mut changed = engine.store.library.clone();
    changed.settings.remove("core_box_underlying_dns");
    engine.store.commit(changed).unwrap();
    let refreshed = engine.refresh_backup_preview(&first.token).unwrap();
    assert_eq!(
        refreshed.legacy.as_ref().unwrap()["requirements"],
        json!([])
    );
    engine.restore_backup(&refreshed.token).unwrap();
    assert_eq!(engine.store.library.routing.active, "default");
    assert_eq!(
        engine.store.library.routing.profiles[1]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .version,
        2
    );
}

fn with_selector(mut input: Prepared) -> Prepared {
    let plan = input.plan.as_mut().unwrap();
    plan.profiles[0].kind = ProfileKind::SingBoxOutbound;
    plan.profiles[0].config =
        json!({"type":"socks","server":"127.0.0.1","server_port":19123,"version":"5"});
    plan.profiles.push(Profile { vpn_policy: None,
        id:"imported-selector".into(), name:"Saved selector".into(), group_id:"imported-group".into(),
        kind:ProfileKind::AutoSelector,
        config:json!({"type":"auto-selector","members":["imported-profile"],"pinned_profile":"imported-profile","url":"http://127.0.0.1:19124/private-probe-path"}),
        favorite:false,
    });
    plan.profile_ids.insert(8, "imported-selector".into());
    input.review["autoSelectorCount"] = json!(1);
    input.review["selectorSnapshots"] =
        json!([{"sourceId":8,"name":"Saved selector","members":1,"pinned":true}]);
    input
}

#[test]
fn selector_snapshot_requires_separate_choice_and_reuses_ids_through_toggle_refresh_and_undo() {
    use super::legacy::{AutoSelectors, Scopes};
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let original = json!(engine.store.library);
    let first = engine
        .preview_legacy_import(with_selector(prepared()))
        .unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&first.token).unwrap_err(),
        "legacy_import_blocked"
    );
    let selected = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    assert!(!json!(selected).to_string().contains("private-probe-path"));
    assert_eq!(
        engine.restore_backup(&first.token).unwrap_err(),
        "backup_preview_expired"
    );
    let blocked = engine
        .legacy_backup_scopes(&selected.token, Scopes::default())
        .unwrap();
    assert_eq!(blocked.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        engine.restore_backup(&selected.token).unwrap_err(),
        "backup_preview_expired"
    );
    assert_eq!(json!(engine.store.library), original);
    let selected = engine
        .legacy_backup_scopes(
            &blocked.token,
            Scopes {
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    let refreshed = engine.refresh_backup_preview(&selected.token).unwrap();
    assert_eq!(
        refreshed.legacy.as_ref().unwrap()["scopes"]["autoSelectors"],
        "last-built"
    );
    engine.restore_backup(&refreshed.token).unwrap();
    let selector = engine
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.id == "imported-selector")
        .unwrap();
    assert_eq!(selector.config["members"], json!(["imported-profile"]));
    assert_eq!(selector.config["pinned_profile"], "imported-profile");
    assert!(engine.running.is_none());
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(engine.store.library), original);
}

#[test]
fn selector_routes_cannot_bypass_profile_scope_or_the_separate_snapshot_choice() {
    use super::legacy::{AutoSelectors, Scopes};
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut input = with_routes(with_selector(prepared()), true);
    input.routes.as_mut().unwrap().presets[0].rules[0].config["outbound"] =
        json!("profile:imported-selector");
    let first = engine.preview_legacy_import(input).unwrap();
    let route_only = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                routes: true,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(route_only.legacy.as_ref().unwrap()["canApply"], false);
    assert!(route_only.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_routes_require_profiles"));
    assert_eq!(
        engine.restore_backup(&route_only.token).unwrap_err(),
        "legacy_import_blocked"
    );
    let require_choice = engine
        .legacy_backup_scopes(
            &route_only.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(require_choice.legacy.as_ref().unwrap()["canApply"], false);
    let selected = engine
        .legacy_backup_scopes(
            &require_choice.token,
            Scopes {
                profiles: true,
                routes: true,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(
        engine.store.library.routing.profiles[1].rules[0].config["outbound"],
        "profile:imported-selector"
    );
    assert_eq!(engine.store.library.routing.active, "default");
}

#[test]
fn older_scope_payloads_require_selector_choice_and_unknown_modes_are_rejected() {
    use super::legacy::{AutoSelectors, Scopes};
    let old: Scopes = serde_json::from_value(json!({"profiles":true,"routes":false})).unwrap();
    assert!(old.auto_selectors == AutoSelectors::RequireChoice);
    assert!(serde_json::from_value::<Scopes>(
        json!({"profiles":true,"routes":false,"autoSelectors":"dynamic"})
    )
    .is_err());
    assert!(serde_json::from_value::<Scopes>(
        json!({"profiles":true,"routes":false,"autoSelectors":true})
    )
    .is_err());
}

fn otp_archive(name: &str) -> crate::legacy_backup::SourceArchive {
    crate::legacy_backup::read(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/legacy_backup/otp/fixtures")
            .join(name),
    )
    .unwrap()
}
#[test]
fn actual_qt_otp_scope_keeps_private_plan_through_refresh_additive_commit_and_exact_undo() {
    use super::legacy::{prepare, Scopes};
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let source = otp_archive("valid.thrbackup");
    let prepared = prepare(&source);
    let wanted = prepared.otp.as_ref().unwrap().entries.clone();
    assert_eq!(wanted.len(), 6);
    let first = app.preview_legacy_import(prepared).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["scopes"]["otp"], false);
    assert_eq!(first.legacy.as_ref().unwrap()["otpCount"], 6);
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], false);
    let selected = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                otp: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(selected.incoming.otp, 6);
    for entry in &wanted {
        assert!(!json!(selected).to_string().contains(&entry.value.secret));
    }
    // A current entry added during review survives the required refresh.
    let draft: crate::otp::Draft = serde_json::from_value(
        json!({"name":"Current OTP","secret":"JBSWY3DPEHPK3PXP","counter":"9007199254740993"}),
    )
    .unwrap();
    app.otp_save("", "", draft).unwrap();
    let current = json!(app.store.library);
    assert_eq!(
        app.restore_backup(&selected.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = app.refresh_backup_preview(&selected.token).unwrap();
    assert_eq!(refreshed.incoming.otp, 7);
    assert_eq!(refreshed.legacy.as_ref().unwrap()["scopes"]["otp"], true);
    app.restore_backup(&refreshed.token).unwrap();
    assert!(app.store.library.otp[1..] == wanted);
    let mut actual = json!(app.store.library);
    actual["otp"] = current["otp"].clone();
    assert_eq!(actual, current);
    assert!(app.running.is_none() && app.rpc.is_none());
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), current);
}

#[test]
fn unsupported_or_excluded_otp_cannot_be_imported_by_forging_scopes_or_the_apply_button() {
    use super::legacy::{prepare, Scopes};
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    for (name, expected) in [
        ("excluded-otp.thrbackup", "legacy_otp_parts_required"),
        ("blocked.thrbackup", "legacy_otp_algorithm_invalid"),
    ] {
        let source = otp_archive(name);
        let first = app.preview_legacy_import(prepare(&source)).unwrap();
        let selected = app
            .legacy_backup_scopes(
                &first.token,
                Scopes {
                    profiles: false,
                    otp: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let review = selected.legacy.as_ref().unwrap();
        assert_eq!(review["canApply"], false);
        assert!(review["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["code"] == expected));
        assert_eq!(
            app.restore_backup(&selected.token).unwrap_err(),
            "legacy_import_blocked"
        );
        assert_eq!(json!(app.store.library), before);
    }
}

#[test]
fn mixed_otp_import_is_atomic_and_unchecking_unsupported_otp_retains_the_profile_plan() {
    use super::legacy::{prepare, Scopes};
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let mut mixed = prepared();
    let source = otp_archive("blocked.thrbackup");
    let bad = prepare(&source);
    mixed.otp = bad.otp;
    mixed.otp_issues = bad.otp_issues;
    let first = app.preview_legacy_import(mixed).unwrap();
    assert_eq!(first.legacy.as_ref().unwrap()["canApply"], true);
    let before = json!(app.store.library);
    let selected = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                otp: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(selected.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        app.restore_backup(&selected.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    let profiles = app
        .legacy_backup_scopes(&selected.token, Scopes::default())
        .unwrap();
    assert_eq!(profiles.legacy.as_ref().unwrap()["canApply"], true);
    app.restore_backup(&profiles.token).unwrap();
    assert!(app.store.library.otp.is_empty());
    assert!(app
        .store
        .library
        .profiles
        .iter()
        .any(|p| p.id == "imported-profile"));
}

/// What stays in the source backup is reported even when profiles are not
/// imported: extra database tables and container files the import skips.
#[test]
fn archive_notes_survive_a_scope_without_profiles_and_unknown_files_are_named() {
    use crate::legacy_backup::{
        Parts, SourceArchive, SourceDatabase, SourceGroup, SourceProfile, SourceValue,
    };
    let mut database = SourceDatabase::default();
    database.groups.push(SourceGroup {
        id: 2,
        name: "Legacy group".into(),
        columns: BTreeMap::from([("profiles_json".into(), SourceValue::Text("[7]".into()))]),
    });
    database.profiles.push(SourceProfile {
        id: 7,
        kind: "socks".into(),
        name: Some("Legacy".into()),
        group_id: 2,
        columns: Default::default(),
        outbound: json!({"type":"socks","tag":"Legacy","server":"192.0.2.1","server_port":1080}),
    });
    database
        .other_tables
        .insert("future_feature".into(), vec![]);
    let source = SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            profiles: true,
            ..Default::default()
        },
        files: BTreeMap::from([
            ("database".into(), Some(vec![1])),
            ("future/extra.bin".into(), Some(vec![2])),
        ]),
        database: Some(database),
    };
    let codes = |preview: &crate::backups::Preview| -> Vec<String> {
        preview.legacy.as_ref().unwrap()["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|issue| issue["code"].as_str().unwrap().to_owned())
            .collect()
    };
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine(dir.path());
    let mut prepared = super::legacy::prepare(&source);
    let all = codes(&engine.preview_legacy_import(prepared.clone()).unwrap());
    for code in [
        "legacy_other_tables_deferred",
        "legacy_backup_unknown_files_deferred",
    ] {
        assert!(all.iter().any(|c| c == code), "{code} in {all:?}");
    }
    prepared.scopes.profiles = false;
    let without = codes(&engine.preview_legacy_import(prepared).unwrap());
    assert!(without.iter().any(|c| c == "legacy_other_tables_deferred"));
    assert!(without
        .iter()
        .any(|c| c == "legacy_backup_unknown_files_deferred"));
    assert!(
        !without.iter().any(|c| c == "legacy_group_layout_deferred"),
        "profile findings do not apply without the profile scope"
    );
}
