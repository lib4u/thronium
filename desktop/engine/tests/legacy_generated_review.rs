//! Independent public-API checks of generated-DNS activation and portability.
//! No core executable, sockets, provider requests, or operating-system settings.
use serde_json::json;
use std::{collections::BTreeMap, path::Path};
use thronium_engine::{
    backups::legacy::{prepare, Scopes},
    legacy_backup::{Parts, SourceArchive, SourceDatabase, SourceRoute, SourceSetting},
    routing::{legacy_context::conflicts, RoutingProfile},
    store::{Profile, ProfileKind},
    Engine,
};

fn source(strategy: &str, cap: bool) -> SourceArchive {
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            routes: vec![SourceRoute {
                id: 7,
                name: "Saved generated policy".into(),
                columns: BTreeMap::new(),
            }],
            settings: [
                ("outbound_domain_strategy", strategy.to_owned()),
                ("direct_dns_disable_ipv6", cap.to_string()),
                (
                    "remote_dns",
                    "https://127.0.0.1:55353/dns-query?token=synthetic%2Fsecret@fixture".into(),
                ),
                (
                    "dns_object",
                    "inactive invalid JSON must stay inactive".into(),
                ),
            ]
            .into_iter()
            .map(|(key, value)| SourceSetting {
                key: key.into(),
                value,
                columns: BTreeMap::new(),
            })
            .collect(),
            ..Default::default()
        }),
    }
}

fn open(folder: &Path) -> Engine {
    Engine::open(folder, &folder.join("nonexistent-core")).unwrap()
}
fn installed(engine: &mut Engine, archive: &SourceArchive) -> String {
    let preview = engine.preview_legacy_import(prepare(archive)).unwrap();
    let reviewed = engine
        .legacy_backup_scopes(
            &preview.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(reviewed.legacy.as_ref().unwrap()["canApply"], true);
    let public = serde_json::to_string(&reviewed).unwrap();
    assert!(!public.contains("synthetic%2Fsecret"));
    assert!(!public.contains("127.0.0.1"));
    engine.restore_backup(&reviewed.token).unwrap();
    engine.routing().profiles.last().unwrap().id.clone()
}
fn marker(preset: &RoutingProfile, expected: &str) {
    let metadata = preset.legacy_constraints.as_ref().unwrap();
    assert_eq!(metadata.version, 2);
    assert_eq!(metadata.xray_dns_strategy.as_deref(), Some(expected));
}

#[test]
fn actual_prepare_persists_each_source_strategy_through_reopen_route_export_and_backup_restore() {
    for (strategy, cap, expected) in [
        ("", false, "UseIP"),
        ("prefer_ipv4", false, "UseIPv4v6"),
        ("prefer_ipv6", false, "UseIPv6v4"),
        ("ipv6_only", false, "ForceIPv6"),
        ("prefer_ipv6", true, "UseIPv4"),
        ("ipv4_only", true, "ForceIPv4"),
    ] {
        let archive = source(strategy, cap);
        let unchanged: Vec<_> = archive
            .database
            .as_ref()
            .unwrap()
            .settings
            .iter()
            .map(|s| (s.key.clone(), s.value.clone()))
            .collect();
        let folder = tempfile::tempdir().unwrap();
        let mut engine = open(folder.path());
        let original = json!(engine.store.library);
        let id = installed(&mut engine, &archive);
        for field in ["settings", "preferences", "profiles", "groups", "selected"] {
            assert_eq!(json!(engine.store.library)[field], original[field]);
        }
        assert_eq!(engine.routing().active, "default");
        drop(engine);
        let engine = open(folder.path());
        let exported = engine.export_routing_profile(&id).unwrap();
        let preset: RoutingProfile = serde_json::from_value(exported["profile"].clone()).unwrap();
        marker(&preset, expected);
        assert_eq!(
            preset.dns["servers"][0]["path"],
            "/dns-query?token=synthetic%2Fsecret@fixture"
        );
        assert_eq!(
            preset.route["default_domain_resolver"]["strategy"],
            if cap { "ipv4_only" } else { strategy }
        );
        let backup = engine.export_backup().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let mut restored = open(destination.path());
        let review = restored.preview_backup(&backup).unwrap();
        restored.restore_backup(&review.token).unwrap();
        let again = restored.export_routing_profile(&id).unwrap();
        assert_eq!(again, exported);
        assert!(restored.owned_core_process().is_none());
        assert!(engine.owned_core_process().is_none());
        assert!(archive
            .database
            .as_ref()
            .unwrap()
            .settings
            .iter()
            .map(|s| (s.key.clone(), s.value.clone()))
            .eq(unchanged));
    }
}

#[tokio::test]
async fn generated_import_remains_dormant_and_local_override_blocks_before_starting_a_core() {
    let folder = tempfile::tempdir().unwrap();
    let mut engine = open(folder.path());
    let selected = Profile {
        vpn_policy: None,
        id: "local-test".into(),
        name: "Local test".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    };
    let mut current = engine.store.library.clone();
    current.profiles.push(selected.clone());
    current.selected = Some(selected.id.clone());
    current.settings.insert(
        "core_box_underlying_dns".into(),
        json!("tcp://127.0.0.1:55354"),
    );
    // Current active DNS contains no local server. Requirements must inspect the incoming DNS.
    current.routing.profiles[0].dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1"}],"final":"dns-direct"});
    engine.store.commit(current).unwrap();
    let before = json!(engine.store.library);
    let prepared = prepare(&source("prefer_ipv6", true));
    let first = engine.preview_legacy_import(prepared).unwrap();
    let reviewed = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(reviewed.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(
        reviewed.legacy.as_ref().unwrap()["requirements"],
        json!(["legacy_routing_local_dns_conflict"])
    );
    engine.restore_backup(&reviewed.token).unwrap();
    assert_eq!(engine.routing().active, "default");
    assert_eq!(json!(engine.store.library)["settings"], before["settings"]);
    let mut routing = engine.routing();
    routing.active = routing.profiles[1].id.clone();
    engine.save_routing(routing).unwrap();
    assert_eq!(
        engine.check(&selected).await.unwrap_err(),
        "legacy_routing_local_dns_conflict"
    );
    assert!(engine.owned_core_process().is_none());
    assert_eq!(
        conflicts(
            &engine.store.library,
            engine.store.library.routing.active().unwrap()
        ),
        vec!["legacy_routing_local_dns_conflict"]
    );
    let snapshot = json!(engine.store.library);
    engine.check(&selected).await.unwrap_err();
    assert_eq!(json!(engine.store.library), snapshot);
}

#[test]
fn excluded_settings_cannot_generate_defaults_or_import_hidden_dns_secrets() {
    let mut archive = source("prefer_ipv6", true);
    archive.parts.settings = false;
    let folder = tempfile::tempdir().unwrap();
    let mut engine = open(folder.path());
    let before = json!(engine.store.library);
    let first = engine.preview_legacy_import(prepare(&archive)).unwrap();
    let reviewed = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    let review = reviewed.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], false);
    assert_eq!(review["routeCount"], 0);
    assert!(review["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_route_parts_required"));
    assert!(!serde_json::to_string(&reviewed)
        .unwrap()
        .contains("synthetic%2Fsecret"));
    assert_eq!(
        engine.restore_backup(&reviewed.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(engine.store.library), before);
    assert!(!folder.path().join("backup-before-restore.json").exists());
}
