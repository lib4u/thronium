//! Independent public-API review of legacy scopes, using actual prepare inputs.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use thronium_engine::{
    backups::legacy::{prepare, Scopes},
    legacy_backup::{
        self, Parts, SourceArchive, SourceDatabase, SourceGroup, SourceProfile, SourceRoute,
        SourceSetting, SourceValue,
    },
    store::{Profile, ProfileKind},
    Engine,
};

fn existing(id: &str) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        name: id.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    }
}
fn engine(folder: &std::path::Path) -> Engine {
    let mut engine = Engine::open(folder, &folder.join("deliberately-missing-core")).unwrap();
    let mut library = engine.store.library.clone();
    library.profiles.push(existing("existing"));
    library.selected = Some("existing".into());
    library.preferences.inbound_port = 17431;
    library
        .settings
        .insert("enable_dns_routing".into(), json!(true));
    engine.store.commit(library).unwrap();
    engine
}
fn source(references: bool) -> SourceArchive {
    let text = |s: &str| SourceValue::Text(s.into());
    let dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":5353},{"type":"https","tag":"dns-authenticated","server":"127.0.0.2","headers":{"Authorization":["Bearer scope-private-header"]}}],"rules":[],"final":"dns-direct"});
    let raw = json!({"rules":[{"type":"logical","mode":"and","rules":[{"domain":["scope-private-domain.invalid"]},{"network":"tcp"}],"outbound":if references{11}else{-2}}],"final":-2,"default_domain_resolver":"dns-direct"});
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            profiles: true,
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            profiles: vec![SourceProfile {
                id: 11,
                group_id: 8,
                kind: "socks".into(),
                name: Some("Source proxy".into()),
                outbound: json!({"type":"socks","server":"127.0.0.1","server_port":15321,"username":"synthetic","password":"scope-private-password"}),
                columns: BTreeMap::new(),
            }],
            groups: vec![SourceGroup {
                id: 8,
                name: "Source group".into(),
                columns: BTreeMap::from([
                    ("profiles_json".into(), text("[11]")),
                    (
                        "url".into(),
                        text("https://subscription.invalid/scope-private-url"),
                    ),
                ]),
            }],
            routes: vec![SourceRoute {
                id: 2,
                name: "Source policy".into(),
                columns: BTreeMap::from([
                    ("is_raw".into(), SourceValue::Integer(1)),
                    ("raw_route".into(), text(&raw.to_string())),
                ]),
            }],
            settings: vec![
                SourceSetting {
                    key: "use_dns_object".into(),
                    value: "true".into(),
                    columns: BTreeMap::new(),
                },
                SourceSetting {
                    key: "dns_object".into(),
                    value: dns.to_string(),
                    columns: BTreeMap::new(),
                },
            ],
            ..Default::default()
        }),
    }
}
fn review(preview: &thronium_engine::backups::Preview) -> &Value {
    preview.legacy.as_ref().unwrap()
}
fn has_code(preview: &thronium_engine::backups::Preview, code: &str) -> bool {
    review(preview)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == code)
}
fn safe(preview: &thronium_engine::backups::Preview) {
    let serialized = serde_json::to_string(preview).unwrap();
    for value in [
        "scope-private-password",
        "scope-private-header",
        "scope-private-domain",
        "scope-private-url",
        "127.0.0.1",
        "Authorization",
    ] {
        assert!(
            !serialized.contains(value),
            "source configuration leaked through review"
        );
    }
}

#[test]
fn real_qt_route_only_archive_requires_explicit_scope_and_keeps_current_network() {
    let archive = legacy_backup::read(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/legacy_backup/routes/fixtures/routes-explicit-dns.thrbackup"),
    )
    .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let mut engine = engine(folder.path());
    let before = json!(engine.store.library);
    let preview = engine.preview_legacy_import(prepare(&archive)).unwrap();
    assert_eq!(
        review(&preview)["scopes"],
        json!({"profiles":false,"routes":false,"autoSelectors":"require-choice","vpnBindings":"require-choice","otp":false,"icons":false})
    );
    assert_eq!(review(&preview)["canApply"], false);
    let selected = engine
        .legacy_backup_scopes(
            &preview.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&selected)["canApply"], true);
    assert_eq!(selected.incoming.routing_profiles, 3);
    assert_eq!(
        review(&selected)["requirements"],
        json!(["legacy_routing_dns_follow_conflict"])
    );
    safe(&selected);
    assert_eq!(json!(engine.store.library), before);
    assert!(engine.owned_core_process().is_none());
    engine.restore_backup(&selected.token).unwrap();
    let after = json!(engine.store.library);
    for field in ["profiles", "groups", "preferences", "settings", "selected"] {
        assert_eq!(after[field], before[field]);
    }
    assert_eq!(after["routing"]["active"], before["routing"]["active"]);
    assert_eq!(
        after["routing"]["profiles"][0],
        before["routing"]["profiles"][0]
    );
    assert!(engine.owned_core_process().is_none());
}

#[test]
fn real_prepare_mapped_references_survive_scope_changes_refresh_and_atomic_undo() {
    let source = source(true);
    let prepared = prepare(&source);
    let folder = tempfile::tempdir().unwrap();
    let mut first_engine = engine(folder.path());
    let original = json!(first_engine.store.library);
    let first = first_engine
        .preview_legacy_import(prepared.clone())
        .unwrap();
    assert_eq!(
        review(&first)["scopes"],
        json!({"profiles":true,"routes":false,"autoSelectors":"require-choice","vpnBindings":"require-choice","otp":false,"icons":false})
    );
    assert_eq!(first.incoming.routing_profiles, 1);
    safe(&first);
    let blocked = first_engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!review(&blocked)["canApply"].as_bool().unwrap());
    assert!(has_code(&blocked, "legacy_routes_require_profiles"));
    assert_eq!(
        first_engine.restore_backup(&blocked.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(first_engine.store.library), original);
    let all = first_engine
        .legacy_backup_scopes(
            &blocked.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    safe(&all);
    assert_eq!(
        first_engine.restore_backup(&blocked.token).unwrap_err(),
        "backup_preview_expired"
    );
    first_engine.restore_backup(&all.token).unwrap();
    let profile = first_engine.store.library.profiles.last().unwrap();
    let preset = &first_engine.store.library.routing.profiles[1];
    assert_eq!(
        preset.rules[0].config["outbound"],
        format!("profile:{}", profile.id)
    );
    assert_eq!(profile.config["password"], "scope-private-password");
    assert_eq!(
        preset.dns["servers"][1]["headers"]["Authorization"][0],
        "Bearer scope-private-header"
    );
    let ids = (
        profile.id.clone(),
        preset.id.clone(),
        preset.rules[0].id.clone(),
    );
    let folder2 = tempfile::tempdir().unwrap();
    let mut refreshed_engine = engine(folder2.path());
    let preview = refreshed_engine.preview_legacy_import(prepared).unwrap();
    let selected = refreshed_engine
        .legacy_backup_scopes(
            &preview.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    let mut current = refreshed_engine.store.library.clone();
    current.profiles.push(existing("concurrent-profile"));
    current.preferences.inbound_port += 1;
    refreshed_engine.store.commit(current).unwrap();
    assert_eq!(
        refreshed_engine
            .restore_backup(&selected.token)
            .unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = refreshed_engine
        .refresh_backup_preview(&selected.token)
        .unwrap();
    safe(&refreshed);
    refreshed_engine.restore_backup(&refreshed.token).unwrap();
    let actual = refreshed_engine.store.library.profiles.last().unwrap();
    let preset = &refreshed_engine.store.library.routing.profiles[1];
    assert_eq!(
        (
            actual.id.clone(),
            preset.id.clone(),
            preset.rules[0].id.clone()
        ),
        ids
    );
    assert!(refreshed_engine
        .store
        .library
        .profiles
        .iter()
        .any(|p| p.id == "concurrent-profile"));
    assert_eq!(
        refreshed_engine.store.library.preferences.inbound_port,
        17432
    );
    let undo = first_engine.preview_previous_backup().unwrap();
    first_engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(first_engine.store.library), original);
}

#[test]
fn excluded_archive_parts_cannot_be_reenabled_by_scope_payloads() {
    for excluded in ["routes", "settings", "profiles"] {
        let mut archive = source(true);
        match excluded {
            "routes" => archive.parts.routes = false,
            "settings" => archive.parts.settings = false,
            _ => archive.parts.profiles = false,
        }
        let folder = tempfile::tempdir().unwrap();
        let mut engine = engine(folder.path());
        let before = json!(engine.store.library);
        let preview = engine.preview_legacy_import(prepare(&archive)).unwrap();
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                Scopes {
                    profiles: true,
                    routes: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(review(&selected)["canApply"], false, "{excluded}");
        assert_eq!(
            engine.restore_backup(&selected.token).unwrap_err(),
            "legacy_import_blocked"
        );
        assert_eq!(json!(engine.store.library), before);
        safe(&selected);
        assert!(!folder.path().join("backup-before-restore.json").exists());
    }
}

#[test]
fn excluded_profile_payload_cannot_block_an_independent_route_only_import() {
    let mut archive = source(false);
    archive.parts.profiles = false;
    let profile = &mut archive.database.as_mut().unwrap().profiles[0];
    profile.kind = "extracore".into();
    profile.outbound = json!({"unconvertible":"scope-private-password"});
    let source_snapshot = profile.outbound.clone();
    let folder = tempfile::tempdir().unwrap();
    let mut engine = engine(folder.path());
    let before = json!(engine.store.library);
    let preview = engine.preview_legacy_import(prepare(&archive)).unwrap();
    let selected = engine
        .legacy_backup_scopes(
            &preview.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&selected)["canApply"], true);
    safe(&selected);
    engine.restore_backup(&selected.token).unwrap();
    assert_eq!(json!(engine.store.library.profiles), before["profiles"]);
    assert_eq!(json!(engine.store.library.groups), before["groups"]);
    assert_eq!(
        archive.database.as_ref().unwrap().profiles[0].outbound,
        source_snapshot
    );
    assert!(engine.owned_core_process().is_none());
}
