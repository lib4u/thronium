use super::*;
use crate::{
    connection::ActiveConnection,
    exports::Format,
    store::{CommitFault, Group, Profile, ProfileKind},
    subscriptions::{Download, GroupDraft},
    ProfileDraft,
};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path};

fn leaf(id: &str, group: &str) -> Profile {
    Profile {
        id: id.into(),
        name: id.into(),
        group_id: group.into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: id == "b",
        vpn_policy: None,
        config: json!({"type":"socks","server":"example.invalid","server_port":1080,"password":format!("private-{id}"),"future":{"value":id}}),
    }
}

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("no-core")).unwrap();
    let mut next = engine.store.library.clone();
    next.groups.push(Group {
        id: "other".into(),
        name: "Other".into(),
        collapsed: true,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: Default::default(),
    });
    next.profiles = ["a", "x", "b", "y", "c", "z", "d"]
        .into_iter()
        .map(|id| {
            leaf(
                id,
                if matches!(id, "x" | "y" | "z") {
                    "other"
                } else {
                    "personal"
                },
            )
        })
        .collect();
    next.selected = Some("b".into());
    engine.store.commit(next).unwrap();
    (dir, engine)
}

fn ids(engine: &Engine) -> Vec<String> {
    engine
        .store
        .library
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect()
}

fn aggregate_without_order(engine: &Engine) -> Value {
    let mut value = json!(engine.store.library);
    value["profiles"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|p| p["id"].as_str().unwrap().to_owned());
    value
}

fn disk(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("library.json")).unwrap()).unwrap()
}

#[test]
fn profile_reorder_preserves_foreign_slots_all_fields_and_reopen() {
    let (dir, mut engine) = setup();
    let before = aggregate_without_order(&engine);
    for (id, target, after, expected) in [
        ("d", "a", false, ["d", "x", "a", "y", "b", "z", "c"]),
        ("d", "c", true, ["a", "x", "b", "y", "c", "z", "d"]),
        ("b", "c", true, ["a", "x", "c", "y", "b", "z", "d"]),
        ("d", "b", false, ["a", "x", "c", "y", "d", "z", "b"]),
        ("a", "b", true, ["c", "x", "d", "y", "b", "z", "a"]),
    ] {
        engine.reorder_profile(id, target, after).unwrap();
        assert_eq!(ids(&engine), expected);
        assert_eq!(aggregate_without_order(&engine), before);
        assert_eq!(disk(dir.path()), json!(engine.store.library));
        assert!(engine.owned_core_process().is_none());
    }
    let saved = json!(engine.store.library);
    drop(engine);
    let reopened = Engine::open(dir.path(), &dir.path().join("no-core")).unwrap();
    assert_eq!(json!(reopened.store.library), saved);
}

#[test]
fn profile_reorder_rejects_missing_cross_group_and_never_commits_noop() {
    let (dir, mut engine) = setup();
    let before = json!(engine.store.library);
    engine.store.fail_next_commit(CommitFault::BeforeRename);
    for (id, target, expected) in [
        ("missing", "a", "profile_not_found"),
        ("a", "missing", "profile_not_found"),
        ("missing", "missing", "profile_not_found"),
        ("a", "x", "invalid_profile_order"),
    ] {
        assert_eq!(
            engine.reorder_profile(id, target, false).unwrap_err(),
            expected
        );
    }
    for (id, target, after) in [
        ("a", "a", true),
        ("a", "a", false),
        ("a", "b", false),
        ("b", "a", true),
    ] {
        engine.reorder_profile(id, target, after).unwrap();
    }
    // The fault is still armed: none of the refusals or no-ops reached commit.
    assert_eq!(
        engine.reorder_profile("d", "a", false).unwrap_err(),
        "store_injected_failure"
    );
    assert_eq!(json!(engine.store.library), before);
    assert_eq!(disk(dir.path()), before);
    engine.reorder_profile("d", "a", false).unwrap();
    assert_eq!(ids(&engine), ["d", "x", "a", "y", "b", "z", "c"]);
}

#[test]
fn profile_reorder_uses_current_objects_and_published_commit_failure_is_whole() {
    for fault in [CommitFault::AfterRename, CommitFault::DirectorySync] {
        let (dir, mut engine) = setup();
        let mut current = engine.profile("b").unwrap();
        current.name = "Edited after drag began".into();
        current.config["password"] = json!("new-current-private-value");
        engine
            .save_profile(ProfileDraft {
                id: Some(current.id.clone()),
                name: current.name.clone(),
                group_id: current.group_id.clone(),
                kind: current.kind,
                config: current.config.clone(),
                vpn_policy: Default::default(),
            })
            .unwrap();
        let before = aggregate_without_order(&engine);
        engine.store.fail_next_commit(fault);
        // After the rename the new order is already in place; only the sync is
        // unconfirmed, and the code says so instead of a generic failure.
        assert_eq!(
            engine.reorder_profile("b", "d", true).unwrap_err(),
            crate::store::Store::WRITTEN_UNCERTAIN
        );
        assert_eq!(ids(&engine), ["a", "x", "c", "y", "d", "z", "b"]);
        assert_eq!(aggregate_without_order(&engine), before);
        assert_eq!(engine.profile("b").unwrap().config, current.config);
        assert!(engine.store.durability_uncertain());
        let saved = json!(engine.store.library);
        assert_eq!(disk(dir.path()), saved);
        drop(engine);
        let reopened = Engine::open(dir.path(), &dir.path().join("no-core")).unwrap();
        assert_eq!(json!(reopened.store.library), saved);
        assert!(!reopened.store.durability_uncertain());
    }
}

fn subscription_stage(engine: &mut Engine, group: &str, names: &[&str]) -> String {
    let request = engine.subscription_request(group).unwrap();
    let ticket = engine
        .subscription_downloaded(
            request,
            Download {
                body: "offline owned fixture".into(),
                metadata: Default::default(),
                usage: None,
            },
        )
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let drafts = names.iter().map(|name| ProfileDraft {
        id: None, name: (*name).into(), group_id: group.into(), kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"example.invalid","server_port":1100 + name.as_bytes()[0] as u16}), vpn_policy: Default::default(),
    }).collect();
    engine.preview_subscription(&ticket, drafts).unwrap();
    ticket
}

#[test]
fn profile_reorder_invalidates_subscription_captures_but_fresh_refresh_uses_provider_order() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("no-core")).unwrap();
    let group = engine
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Provider".into(),
            proxy_chain: None,
            subscription: Some(
                serde_json::from_value(
                    json!({"url":"https://example.invalid/feed","inheritDefaults":false}),
                )
                .unwrap(),
            ),
        })
        .unwrap();
    let initial = subscription_stage(&mut engine, &group, &["A", "B", "C"]);
    engine.apply_subscription(&initial).unwrap();
    let names: HashMap<_, _> = engine
        .store
        .library
        .profiles
        .iter()
        .map(|p| (p.name.clone(), p.id.clone()))
        .collect();
    engine.favorite(&names["B"]).unwrap();
    engine.select(&names["A"]).unwrap();
    let request = engine.subscription_request(&group).unwrap();
    let old_preview = subscription_stage(&mut engine, &group, &["B", "A", "C"]);
    engine
        .reorder_profile(&names["C"], &names["A"], false)
        .unwrap();
    let manual = json!(engine.store.library);
    assert_eq!(
        engine
            .subscription_downloaded(
                request,
                Download {
                    body: "offline fixture".into(),
                    usage: None,
                    metadata: Default::default()
                }
            )
            .err()
            .as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(
        engine.apply_subscription(&old_preview).err().as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(json!(engine.store.library), manual);
    let fresh = subscription_stage(&mut engine, &group, &["B", "A", "C"]);
    engine.apply_subscription(&fresh).unwrap();
    assert_eq!(
        ids(&engine),
        vec![names["B"].clone(), names["A"].clone(), names["C"].clone()]
    );
    assert_eq!(engine.store.library.selected.as_ref(), Some(&names["A"]));
    assert!(engine.profile(&names["B"]).unwrap().favorite);
    assert!(engine.owned_core_process().is_none());
}

#[test]
fn profile_reorder_export_backup_and_undo_obey_existing_stale_previews() {
    let (_dir, mut engine) = setup();
    let initial = json!(engine.store.library);
    let backup = engine.export_backup().unwrap();
    let stale = engine.preview_backup(&backup).unwrap();
    engine.reorder_profile("d", "a", false).unwrap();
    let manual = json!(engine.store.library);
    assert_eq!(
        engine.restore_backup(&stale.token).unwrap_err(),
        "backup_preview_stale"
    );
    assert_eq!(json!(engine.store.library), manual);
    let exported: Value = serde_json::from_str(
        &engine
            .export_profiles(
                vec!["a".into(), "b".into(), "c".into(), "d".into()],
                Format::Profiles,
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        exported["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["d", "a", "b", "c"]
    );
    let fresh = engine.preview_backup(&backup).unwrap();
    engine.restore_backup(&fresh.token).unwrap();
    assert_eq!(json!(engine.store.library), initial);
    let undo = engine.preview_previous_backup().unwrap();
    engine.reorder_profile("a", "b", false).unwrap(); // no-op keeps preview valid
    engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(engine.store.library), manual);
    let stale_undo = engine.preview_previous_backup().unwrap();
    engine.reorder_profile("a", "c", true).unwrap();
    assert_eq!(
        engine.restore_backup(&stale_undo.token).unwrap_err(),
        "backup_preview_stale"
    );
}

#[test]
fn profile_reorder_changes_future_dynamic_pool_without_touching_frozen_session() {
    let (_dir, mut engine) = setup();
    let draft = ProfileDraft {
        id: None,
        name: "Dynamic".into(),
        group_id: "other".into(),
        kind: ProfileKind::AutoSelector,
        config: json!({"type":"auto-selector","member_source":{"group_id":"personal","name_regex":"","exclude_regex":""},"interval":"1m"}),
        vpn_policy: Default::default(),
    };
    let id = engine.save_profile(draft).unwrap();
    let profile = engine.profile(&id).unwrap();
    let request = engine.build(&profile).unwrap();
    let members = crate::vless::relevant(&engine.store.library, &profile).unwrap();
    engine.running = Some(id.clone());
    engine.active_connection = Some(ActiveConnection {
        id: id.clone(),
        profiles: members.clone(),
        groups: HashSet::from(["personal".into(), "other".into()]),
        request: request.clone(),
        routing_revision: 0,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    let selected = engine.store.library.selected.clone();
    engine.reorder_profile("d", "a", false).unwrap();
    assert_eq!(
        crate::auto_selector::resolve(&profile, &engine.store.library).unwrap(),
        ["d", "a", "b", "c"]
    );
    let after = engine.build(&profile).unwrap();
    assert_ne!(after.core_config, request.core_config);
    let frozen = engine.active_connection.as_ref().unwrap();
    assert_eq!(frozen.request, request);
    assert_eq!(frozen.profiles, members);
    assert_eq!(engine.running.as_deref(), Some(id.as_str()));
    assert_eq!(engine.store.library.selected, selected);
    assert!(engine.rpc.is_none());
}

#[test]
#[cfg(target_os = "linux")]
fn profile_reorder_bound_hotp_keeps_private_source_counter_and_request() {
    let (_dir, mut engine) = setup();
    let profile_id = engine.save_profile(ProfileDraft { id: None, name: "VPN".into(), group_id: "personal".into(), kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"openconnect","server":"127.0.0.1","server_port":443,"username":"private-user","password":"private-password"}), vpn_policy: Default::default() }).unwrap();
    let metadata = engine
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                name: "HOTP".into(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                kind: crate::otp::Kind::Hotp,
                counter: "9007199254740993".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let entry = engine
        .store
        .library
        .otp
        .iter()
        .find(|entry| entry.id == metadata["id"])
        .unwrap()
        .clone();
    let view = engine.get_vpn_otp_binding(&profile_id).unwrap();
    engine
        .save_vpn_otp_binding(crate::vpn_otp_bindings::SaveRequest {
            profile_id: profile_id.clone(),
            edit_token: view.edit_token,
            otp_id: Some(entry.id.clone()),
            otp_revision: Some(entry.revision.clone()),
            mode: None,
        })
        .unwrap();
    let profile = engine.profile(&profile_id).unwrap();
    let (request, bindings) = Engine::build_with_vpn_sources(
        &profile,
        &engine.store.library,
        &engine.data_dir,
        crate::vpn_auth::otp::Intent::Start,
    )
    .unwrap();
    assert_eq!(bindings.len(), 1);
    engine.running = Some(profile_id.clone());
    engine.active_connection = Some(ActiveConnection {
        id: profile_id.clone(),
        profiles: HashSet::from([profile_id.clone()]),
        groups: HashSet::from(["personal".into()]),
        request: request.clone(),
        routing_revision: 0,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: bindings,
        vpn_otp_start: Default::default(),
    });
    let before = aggregate_without_order(&engine);
    engine.reorder_profile(&profile_id, "a", false).unwrap();
    assert_eq!(aggregate_without_order(&engine), before);
    assert_eq!(engine.active_connection.as_ref().unwrap().request, request);
    assert_eq!(engine.active_connection.as_ref().unwrap().vpn_otp.len(), 1);
    assert_eq!(
        engine.store.library.otp[0].value.counter,
        "9007199254740993"
    );
    assert_eq!(engine.store.library.otp[0].revision, entry.revision);
    assert!(engine.rpc.is_none());
}
