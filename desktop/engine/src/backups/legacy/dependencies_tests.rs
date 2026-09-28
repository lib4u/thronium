//! Merge dependencies through the public preview: endpoint-aware presets may
//! keep their VPN tunnels, custom inbound tags need the inbound settings.
use crate::{
    backups::legacy::{self, Scopes, SettingsScopes},
    legacy_backup::{
        Parts, SourceArchive, SourceDatabase, SourceGroup, SourceProfile, SourceRoute, SourceRule,
        SourceSetting, SourceValue,
    },
    Engine,
};
use serde_json::json;
use std::collections::BTreeMap;

fn text(value: &str) -> SourceValue {
    SourceValue::Text(value.into())
}
fn setting(key: &str, value: &str) -> SourceSetting {
    SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: BTreeMap::from([("key".into(), text(key)), ("value".into(), text(value))]),
    }
}
fn archive(endpoints: bool, inbound: bool) -> SourceArchive {
    let ovpn = json!({"type":"openvpn","tag":"Fixture tunnel","server":"192.0.2.10","server_port":1194,"username":"synthetic-user","password":"synthetic-password","use_tunnel_dns":true});
    let socks =
        json!({"type":"socks","tag":"Fixture socks","server":"127.0.0.1","server_port":31341});
    let mut settings = vec![setting("current_route_id", "1")];
    if inbound {
        settings.push(setting(
            "custom_inbound",
            r#"{"inbounds":[{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1085}]}"#,
        ));
    }
    let mut route = BTreeMap::from([("default_outbound_id".into(), SourceValue::Integer(-2))]);
    if endpoints {
        route.insert("endpoint_profile_ids".into(), text("[3]"));
    }
    let mut rules = vec![];
    if inbound {
        rules.push(SourceRule {
            route_id: 1,
            order: 0,
            kind: 0,
            columns: BTreeMap::from([
                ("inbound_json".into(), text("[\"lan-socks\"]")),
                ("outbound_id".into(), SourceValue::Integer(-1)),
            ]),
        });
    }
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
            profiles: vec![
                SourceProfile {
                    id: 3,
                    kind: "openvpn".into(),
                    name: None,
                    group_id: 0,
                    columns: BTreeMap::from([("outbound_json".into(), text(&ovpn.to_string()))]),
                    outbound: ovpn,
                },
                SourceProfile {
                    id: 42,
                    kind: "socks".into(),
                    name: None,
                    group_id: 0,
                    columns: BTreeMap::from([("outbound_json".into(), text(&socks.to_string()))]),
                    outbound: socks,
                },
            ],
            groups: vec![SourceGroup {
                id: 0,
                name: "Fixture".into(),
                columns: BTreeMap::from([("profiles_json".into(), text("[3,42]"))]),
            }],
            routes: vec![SourceRoute {
                id: 1,
                name: "Endpoint route".into(),
                columns: route,
            }],
            rules,
            settings,
            ..Default::default()
        }),
    }
}
fn codes(preview: &crate::backups::Preview) -> Vec<String> {
    preview.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn endpoint_aware_presets_keep_their_tunnel_through_merge_apply_and_undo() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), std::path::Path::new("no-core")).unwrap();
    let before = json!(engine.store.library);
    let p = engine
        .preview_legacy_import(legacy::prepare(&archive(true, false)))
        .unwrap();
    let p = engine
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    let review = p.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], true, "{}", json!(codes(&p)));
    assert!(codes(&p).contains(&"legacy_route_endpoint_rule_added".into()));
    assert!(codes(&p).contains(&"legacy_route_endpoint_tunnel_dns".into()));
    assert!(!json!(p).to_string().contains("synthetic-password"));
    engine.restore_backup(&p.token).unwrap();
    let preset = engine.routing().profiles[1].clone();
    let constraints = preset.legacy_constraints.as_ref().unwrap();
    assert_eq!(constraints.version, 6);
    assert_eq!(constraints.endpoints.len(), 1);
    let tunnel = engine
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.id == constraints.endpoints[0])
        .unwrap();
    assert_eq!(tunnel.config["type"], "openvpn-client");
    assert!(tunnel.vpn_policy.is_some());
    assert!(crate::routing::uses_profile(
        &engine.store.library.routing,
        &tunnel.id
    ));
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    let mut restored = json!(engine.store.library);
    restored["version"] = before["version"].clone();
    assert_eq!(restored, before);
}

#[test]
fn custom_inbound_rules_need_the_inbound_settings_or_matching_current_listeners() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), std::path::Path::new("no-core")).unwrap();
    let p = engine
        .preview_legacy_import(legacy::prepare(&archive(false, true)))
        .unwrap();
    let routes_only = engine
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(routes_only.legacy.as_ref().unwrap()["canApply"], false);
    assert!(codes(&routes_only).contains(&"legacy_route_inbound_requires_settings".into()));
    let with_inbound = engine
        .legacy_backup_scopes(
            &routes_only.token,
            Scopes {
                profiles: true,
                routes: true,
                settings: SettingsScopes {
                    inbound: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(with_inbound.legacy.as_ref().unwrap()["canApply"], true);
    assert!(codes(&with_inbound).contains(&"legacy_inbound_custom_listeners".into()));
    assert_eq!(
        with_inbound.legacy.as_ref().unwrap()["requirements"],
        json!([])
    );
    engine.restore_backup(&with_inbound.token).unwrap();
    let preset = engine.routing().profiles[1].clone();
    assert_eq!(
        preset.legacy_constraints.as_ref().unwrap().inbound_tags,
        ["lan-socks"]
    );
    assert_eq!(
        crate::settings::value(&engine.store.library, "custom_inbound")[0]["tag"],
        "lan-socks"
    );
    // Removing the listener later is reported per tag, not as a blanket conflict.
    let mut library = engine.store.library.clone();
    library.settings.insert("custom_inbound".into(), json!([]));
    assert_eq!(
        crate::routing::legacy_context::conflicts(&library, &preset),
        ["legacy_routing_inbound_missing"]
    );
    // A library that already has the listener needs no settings import.
    let other = tempfile::tempdir().unwrap();
    let mut target = Engine::open(other.path(), std::path::Path::new("no-core")).unwrap();
    let mut library = target.store.library.clone();
    library.settings.insert(
        "custom_inbound".into(),
        json!([{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1085}]),
    );
    target.store.commit(library).unwrap();
    let p = target
        .preview_legacy_import(legacy::prepare(&archive(false, true)))
        .unwrap();
    let p = target
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: true,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(p.legacy.as_ref().unwrap()["canApply"], true);
}
