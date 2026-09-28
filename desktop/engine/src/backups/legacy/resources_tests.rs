use crate::{
    backups::legacy::{self, Scopes},
    legacy_backup::{
        Parts, SourceArchive, SourceDatabase, SourceRoute, SourceSetting, SourceValue,
    },
    routing::resources::{Kind, Resource},
    Engine,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

fn archive() -> SourceArchive {
    SourceArchive {
        container_version: 2, content_version: Some(2), metadata: json!({}), created_at: None,
        parts: Parts { routes: true, settings: true, ..Default::default() }, files: BTreeMap::new(),
        database: Some(SourceDatabase {
            routes: vec![SourceRoute { id: 8, name: "Qt local files".into(), columns: BTreeMap::from([
                ("is_raw".into(), SourceValue::Integer(1)),
                ("prevent_modifications".into(), SourceValue::Integer(1)),
                ("raw_route".into(), SourceValue::Text(json!({"final":-2,"rules":[{"rule_set":["local"],"outbound":-2}],"rule_set":[{"type":"local","tag":"local","format":"source","path":"/old/computer/policy.json"}]}).to_string()))
            ]) }],
            settings: vec![
                SourceSetting { key:"use_dns_object".into(), value:"true".into(), columns:BTreeMap::new() },
                SourceSetting { key:"dns_object".into(), value:json!({"servers":[{"type":"hosts","tag":"hosts","path":["/old/computer/hosts"]}],"final":"hosts"}).to_string(), columns:BTreeMap::new() },
            ], ..Default::default()
        }),
    }
}
fn data(kind: Kind) -> Resource {
    Resource::parse(
        kind,
        match kind {
            Kind::Hosts => {
                b"127.0.0.1 local.fixture.invalid alias.fixture.invalid\n::1 ipv6.fixture.invalid\n"
                    .to_vec()
            }
            Kind::RuleSetSource => {
                br#"{"version":3,"rules":[{"domain_suffix":["fixture.invalid"]}]}"#.to_vec()
            }
            Kind::RuleSetBinary | Kind::Pem | Kind::Text | Kind::Geodata => unreachable!(),
        },
    )
    .unwrap()
}
fn start(engine: &mut Engine) -> crate::backups::Preview {
    let p = engine
        .preview_legacy_import(legacy::prepare(&archive()))
        .unwrap();
    engine
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap()
}
fn choose_all(engine: &mut Engine, mut p: crate::backups::Preview) -> crate::backups::Preview {
    let rows = p.legacy.as_ref().unwrap()["resources"]
        .as_array()
        .unwrap()
        .clone();
    for row in rows {
        let selection = engine
            .legacy_resource_selection(&p.token, row["id"].as_str().unwrap())
            .unwrap();
        let resource = data(selection.kind().unwrap());
        p = engine
            .finish_legacy_resource(selection.prepare(resource).unwrap())
            .unwrap();
    }
    p
}

#[test]
fn resource_review_is_inert_atomic_portable_and_reversible() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), Path::new("no-core")).unwrap();
    let before = json!(engine.store.library);
    let p = start(&mut engine);
    assert_eq!(
        p.legacy.as_ref().unwrap()["resources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(p.legacy.as_ref().unwrap()["canApply"], false);
    let p = choose_all(&mut engine, p);
    assert_eq!(p.legacy.as_ref().unwrap()["canApply"], true);
    assert_eq!(json!(engine.store.library), before);
    assert!(!root.path().join("routing-resources").exists());
    assert!(
        !json!(p).to_string().contains("alias.fixture.invalid"),
        "selected bytes stay out of public review"
    );
    engine.restore_backup(&p.token).unwrap();
    assert_eq!(engine.store.library.version, 6);
    let saved: Value = serde_json::from_str(&engine.export_backup().unwrap()).unwrap();
    assert_eq!(
        saved["library"]["routingResources"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert!(!saved.to_string().contains("/old/computer"));
    let mut route = engine.routing().profiles[1].clone();
    crate::routing::resources::resolve(
        &mut route,
        &engine.store.library.routing_resources,
        root.path(),
    )
    .unwrap();
    let hosts = route.dns["servers"][0]["path"][0].as_str().unwrap();
    assert!(Path::new(hosts).starts_with(root.path()));
    assert!(std::fs::read_to_string(hosts)
        .unwrap()
        .contains("alias.fixture.invalid"));
    let other = tempfile::tempdir().unwrap();
    let mut target = Engine::open(other.path(), Path::new("no-core")).unwrap();
    let p = target.preview_backup(&saved.to_string()).unwrap();
    target.restore_backup(&p.token).unwrap();
    let mut transferred = target.routing().profiles[1].clone();
    crate::routing::resources::resolve(
        &mut transferred,
        &target.store.library.routing_resources,
        other.path(),
    )
    .unwrap();
    assert!(
        Path::new(transferred.route["rule_set"][0]["path"].as_str().unwrap())
            .starts_with(other.path())
    );
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    assert!(engine.store.library.routing_resources.is_empty());
    assert_eq!(engine.routing().profiles.len(), 1);
    assert!(
        Path::new(hosts).exists(),
        "immutable files used by an older session are not removed"
    );
}

#[test]
fn stale_dialog_selection_scope_changes_and_failed_writes_cannot_apply_resources() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), Path::new("no-core")).unwrap();
    let p = start(&mut engine);
    let id = p.legacy.as_ref().unwrap()["resources"][0]["id"]
        .as_str()
        .unwrap();
    let selection = engine.legacy_resource_selection(&p.token, id).unwrap();
    let kind = selection.kind().unwrap();
    let refreshed = engine.refresh_backup_preview(&p.token).unwrap();
    assert_eq!(
        engine
            .finish_legacy_resource(selection.prepare(data(kind)).unwrap())
            .err()
            .as_deref(),
        Some("backup_preview_expired")
    );
    let p = choose_all(&mut engine, refreshed);
    let before = json!(engine.store.library);
    engine
        .store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert!(engine.restore_backup(&p.token).is_err());
    assert_eq!(json!(engine.store.library), before);
    assert!(!root.path().join("routing-resources").exists());
}

#[test]
fn replacing_a_chosen_file_preserves_the_prepared_route_and_rule_ids() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), Path::new("no-core")).unwrap();
    let p = start(&mut engine);
    let p = choose_all(&mut engine, p);
    let before = engine.restore.as_ref().unwrap().library.routing.profiles[1].clone();
    let id = p.legacy.as_ref().unwrap()["resources"][0]["id"]
        .as_str()
        .unwrap();
    let selection = engine.legacy_resource_selection(&p.token, id).unwrap();
    let kind = selection.kind().unwrap();
    let p = engine
        .finish_legacy_resource(selection.prepare(data(kind)).unwrap())
        .unwrap();
    let after = &engine.restore.as_ref().unwrap().library.routing.profiles[1];
    assert_eq!(before.id, after.id);
    assert_eq!(before.rules[0].id, after.rules[0].id);
    assert!(p.legacy.unwrap()["canApply"].as_bool().unwrap());
}

const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n";
fn profile_archive() -> SourceArchive {
    use crate::legacy_backup::{SourceGroup, SourceProfile};
    let full = json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "dns":{"servers":[{"type":"hosts","tag":"h","path":"/old/computer/hosts"}]},
        "route":{"rule_set":[{"type":"local","tag":"set","format":"source","path":"/old/computer/policy.json"}]}});
    let ssh = json!({"type":"ssh","server":"192.0.2.22","server_port":22,"user":"fixture","private_key_path":"/old/computer/id_ed25519"});
    let rows = [
        (1, "fullconfig", "Full config", full),
        (2, "outbound", "SSH outbound", ssh),
    ];
    SourceArchive {
        container_version: 2, content_version: Some(2), metadata: json!({}), created_at: None,
        parts: Parts { profiles: true, ..Default::default() }, files: BTreeMap::new(),
        database: Some(SourceDatabase {
            profiles: rows.iter().map(|(id, subtype, name, config)| {
                let outbound = json!({"type":"custom","name":name,"subtype":subtype,"config":config.to_string()});
                SourceProfile { id: *id, kind: "custom".into(), name: None, group_id: 0,
                    columns: BTreeMap::from([("outbound_json".into(), SourceValue::Text(outbound.to_string()))]), outbound }
            }).collect(),
            groups: vec![SourceGroup { id: 0, name: "Files".into(), columns: BTreeMap::from([("profiles_json".into(), SourceValue::Text("[1,2]".into()))]) }],
            ..Default::default()
        }),
    }
}

#[test]
fn profile_inputs_are_chosen_per_file_replace_paths_and_reach_the_core_request() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(root.path(), Path::new("no-core")).unwrap();
    let before = json!(engine.store.library);
    let p = engine
        .preview_legacy_import(legacy::prepare(&profile_archive()))
        .unwrap();
    let review = p.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], false);
    assert!(review["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_profile_resource_required"));
    let rows = review["resources"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .all(|r| r["entity"] == "profile" && r["selected"] == false));
    assert!(rows
        .iter()
        .any(|r| r["name"] == "SSH outbound" && r["kind"] == "pem"));
    // Hidden with the profiles scope, back with it; the chosen files survive.
    let routes_only = engine
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: false,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(routes_only.legacy.as_ref().unwrap()["resources"], json!([]));
    let mut p = engine
        .legacy_backup_scopes(
            &routes_only.token,
            Scopes {
                profiles: true,
                routes: false,
                ..Default::default()
            },
        )
        .unwrap();
    for row in rows {
        let selection = engine
            .legacy_resource_selection(&p.token, row["id"].as_str().unwrap())
            .unwrap();
        let kind = selection.kind().unwrap();
        let resource = match kind {
            Kind::Pem => Resource::parse(kind, PEM.to_vec()).unwrap(),
            Kind::Hosts | Kind::RuleSetSource => data(kind),
            _ => unreachable!(),
        };
        let wrong = Resource::parse(Kind::Text, b"not the right kind".to_vec()).unwrap();
        let attempt = engine
            .legacy_resource_selection(&p.token, row["id"].as_str().unwrap())
            .unwrap();
        assert!(attempt.prepare(wrong).is_err(), "kind mismatch is refused");
        p = engine
            .finish_legacy_resource(selection.prepare(resource).unwrap())
            .unwrap();
    }
    let review = p.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], true, "{}", review["issues"]);
    assert!(review["resources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["selected"] == true));
    assert_eq!(json!(engine.store.library), before);
    assert!(!json!(p).to_string().contains("alias.fixture.invalid"));
    engine.restore_backup(&p.token).unwrap();
    assert_eq!(engine.store.library.version, 7);
    let text = json!(engine.store.library).to_string();
    assert!(!text.contains("/old/computer"));
    assert_eq!(engine.store.library.routing_resources.kinds().count(), 3);
    let ssh = engine
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.name == "SSH outbound")
        .unwrap()
        .clone();
    assert!(ssh.config["private_key_path"]
        .as_str()
        .unwrap()
        .starts_with("thronium-resource:"));
    let request = Engine::build_with_library(&ssh, &engine.store.library, root.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let key = core["outbounds"][0]["private_key_path"].as_str().unwrap();
    assert!(Path::new(key).starts_with(root.path()));
    assert_eq!(std::fs::read(key).unwrap(), PEM);
    let full = engine
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.name == "Full config")
        .unwrap()
        .clone();
    let request = Engine::build_with_library(&full, &engine.store.library, root.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    assert!(
        Path::new(core["dns"]["servers"][0]["path"].as_str().unwrap()).starts_with(root.path())
    );
    assert_eq!(core["route"]["rule_set"][0]["format"], "source");
    let saved: Value = serde_json::from_str(&engine.export_backup().unwrap()).unwrap();
    assert_eq!(saved["library"]["version"], 7);
    let other = tempfile::tempdir().unwrap();
    let mut target = Engine::open(other.path(), Path::new("no-core")).unwrap();
    let p = target.preview_backup(&saved.to_string()).unwrap();
    target.restore_backup(&p.token).unwrap();
    assert_eq!(target.store.library.routing_resources.kinds().count(), 3);
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    // The store never lowers a library version it has already written.
    let mut restored = json!(engine.store.library);
    restored["version"] = before["version"].clone();
    assert_eq!(restored, before);
    assert!(engine.store.library.routing_resources.is_empty());
    // A forged plan with an unreplaced path cannot be merged.
    let prepared = legacy::prepare(&profile_archive());
    let plan = prepared.plan.as_ref().unwrap();
    assert_eq!(
        super::merge(
            &engine.store.library,
            Some(plan),
            None,
            None,
            None,
            &[],
            super::VpnBindings::RequireChoice
        )
        .err()
        .as_deref(),
        Some("legacy_profile_resource_required")
    );
}
