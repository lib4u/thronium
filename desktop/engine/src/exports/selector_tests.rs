use super::*;
use crate::{
    chains,
    group_chains::GroupChain,
    store::{Group, Profile, ProfileKind},
};

fn leaf(id: &str, group: &str, port: u16) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        name: id.into(),
        group_id: group.into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":port}),
    }
}
fn fixture(front: bool, landing: bool, chain: bool, port: u16) -> (tempfile::TempDir, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    engine.store.library.groups[0].proxy_chain = GroupChain {
        front: front.then(|| "front".into()),
        landing: landing.then(|| "landing".into()),
    };
    engine.store.library.groups.push(Group {
        id: "members".into(),
        name: "Unrelated member group".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: GroupChain {
            front: Some("foreign".into()),
            landing: Some("foreign".into()),
        },
    });
    let mut one = leaf("one", "members", port);
    one.config = json!({"type":"vless","server":"127.0.0.1","server_port":port,"uuid":"00000000-0000-0000-0000-000000000001"});
    let mut two = leaf("two", "members", port);
    two.kind = ProfileKind::XrayOutbound;
    two.config = json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":port}});
    let mut exit = leaf("landing", "members", port);
    exit.config["type"] = json!("http");
    engine.store.library.profiles = vec![
        one,
        two,
        leaf("front", "members", port),
        exit,
        leaf("foreign", "members", port),
    ];
    engine.store.library.preferences.vless_core = crate::vless::Core::Xray;
    engine
        .store
        .library
        .preferences
        .vless_overrides
        .insert("one".into(), crate::vless::Core::SingBox);
    let mut selector = leaf("pool", "personal", port);
    selector.kind = ProfileKind::AutoSelector;
    selector.config = json!({"type":"auto-selector","members":["two","one"],"pinned_profile":"one", "url":format!("http://127.0.0.1:{port}/probe"),"interval":"40s","tolerance":123,"interrupt_exist_connections":false});
    if chain {
        let mut member = leaf("member-chain", "members", port);
        member.kind = ProfileKind::Chain;
        member.config = json!({"type":"chain","hops":["one","two"]});
        engine.store.library.profiles.push(member);
        selector.config["members"] = json!(["member-chain", "two"]);
        selector.config["pinned_profile"] = json!("member-chain");
    }
    engine.store.library.profiles.push(selector);
    crate::store::validate_library(&engine.store.library).unwrap();
    (directory, engine)
}
fn portable(engine: &Engine, ids: Vec<String>) -> Value {
    serde_json::from_str(&engine.export_profiles(ids, Format::Profiles).unwrap()).unwrap()
}
fn import(engine: &mut Engine, mut bundle: Value) -> Vec<Profile> {
    for entry in bundle["profiles"].as_array_mut().unwrap() {
        entry["groupId"] = json!("personal");
    }
    engine
        .import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())
        .unwrap()
        .iter()
        .map(|id| engine.profile(id).unwrap())
        .collect()
}
fn paths(engine: &Engine, selector: &Profile) -> Vec<Vec<String>> {
    crate::references::members(selector)
        .unwrap()
        .into_iter()
        .map(|id| {
            chains::flatten(&engine.profile(id).unwrap(), &engine.store.library.profiles)
                .unwrap()
                .into_iter()
                .map(|p| p.name.clone())
                .collect()
        })
        .collect()
}
fn assert_aliases(bundle: &Value, source: &Engine) {
    let entries = bundle["profiles"].as_array().unwrap();
    let aliases = entries
        .iter()
        .map(|p| p["reference"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(aliases.len(), entries.len());
    for entry in entries {
        assert!(entry.get("groupId").is_none());
        for key in ["members", "hops"] {
            if let Some(ids) = entry["config"][key].as_array() {
                assert!(ids.iter().all(|id| aliases.contains(id.as_str().unwrap())));
            }
        }
        if let Some(pin) = entry["config"]["pinned_profile"]
            .as_str()
            .filter(|pin| !pin.is_empty())
        {
            assert!(entry["config"]["members"]
                .as_array()
                .unwrap()
                .contains(&json!(pin)));
        }
        assert!(entry.get("id").is_none());
    }
    // Source IDs never survive as reference values even when source names equal IDs.
    for entry in entries {
        for key in ["members", "hops"] {
            if let Some(ids) = entry["config"][key].as_array() {
                assert!(ids.iter().all(|id| source
                    .store
                    .library
                    .profiles
                    .iter()
                    .all(|p| Some(p.id.as_str()) != id.as_str())));
            }
        }
    }
}

#[test]
fn explicit_pool_roundtrip_preserves_owner_paths_pin_core_choice_and_source_library() {
    for (front, landing) in [(false, false), (true, false), (false, true), (true, true)] {
        let (_directory, source) = fixture(front, landing, false, 31081);
        let before = json!(source.store.library);
        let bundle = portable(&source, vec!["pool".into()]);
        assert_aliases(&bundle, &source);
        assert!(!bundle.to_string().contains("foreign"));
        let target_dir = tempfile::tempdir().unwrap();
        let mut target = Engine::open(target_dir.path(), Path::new("missing-core")).unwrap();
        let imported = import(&mut target, bundle);
        let pool = imported
            .iter()
            .find(|p| p.kind == ProfileKind::AutoSelector)
            .unwrap();
        let expected = ["two", "one"]
            .into_iter()
            .map(|name| {
                front
                    .then_some("front")
                    .into_iter()
                    .chain([name])
                    .chain(landing.then_some("landing"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(paths(&target, pool), expected);
        assert_eq!(pool.config["pinned_profile"], pool.config["members"][1]);
        assert_eq!(pool.config["interval"], "40s");
        assert_eq!(pool.config["interrupt_exist_connections"], false);
        let one = imported
            .iter()
            .find(|p| p.name == "one" && p.kind == ProfileKind::SingBoxOutbound)
            .unwrap();
        assert_eq!(
            target.store.library.preferences.vless_overrides[&one.id],
            crate::vless::Core::SingBox
        );
        assert!(target.build(pool).is_ok());
        assert_eq!(json!(source.store.library), before);
        assert!(source.running.is_none() && source.active_connection.is_none());
        let backup = source.export_backup().unwrap();
        let preview = target.preview_backup(&backup).unwrap();
        target.restore_backup(&preview.token).unwrap();
        assert_eq!(json!(target.store.library), before);
    }
}

#[test]
fn chain_member_is_flattened_once_and_empty_or_absent_pin_remains_automatic() {
    for pin in [None, Some(json!("")), Some(json!("member-chain"))] {
        let (_directory, mut source) = fixture(true, true, true, 31082);
        match pin.clone() {
            Some(pin) => {
                source.store.library.profiles.last_mut().unwrap().config["pinned_profile"] = pin
            }
            None => {
                source
                    .store
                    .library
                    .profiles
                    .last_mut()
                    .unwrap()
                    .config
                    .as_object_mut()
                    .unwrap()
                    .remove("pinned_profile");
            }
        }
        let bundle = portable(&source, vec!["pool".into()]);
        assert_aliases(&bundle, &source);
        let directory = tempfile::tempdir().unwrap();
        let mut target = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
        let imported = import(&mut target, bundle);
        let pool = imported
            .iter()
            .find(|p| p.kind == ProfileKind::AutoSelector)
            .unwrap();
        assert_eq!(
            paths(&target, pool),
            vec![
                vec!["front", "one", "two", "landing"],
                vec!["front", "two", "landing"]
            ]
        );
        match pin {
            Some(pin) if pin == "member-chain" => {
                assert_eq!(pool.config["pinned_profile"], pool.config["members"][0])
            }
            Some(pin) => assert_eq!(pool.config["pinned_profile"], pin),
            None => assert!(pool.config.get("pinned_profile").is_none()),
        }
        assert!(target.build(pool).is_ok());
    }
}

#[test]
fn two_selected_pools_get_independent_owner_paths_even_with_alias_collision() {
    let (_directory, mut source) = fixture(true, true, false, 31083);
    source.store.library.groups.push(Group {
        id: "other".into(),
        name: "Other owner".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: GroupChain {
            front: Some("landing".into()),
            landing: None,
        },
    });
    let mut second = source.store.library.profiles.last().unwrap().clone();
    second.id = "other-pool".into();
    second.name = "Other pool".into();
    second.group_id = "other".into();
    source.store.library.profiles.push(second);
    source
        .store
        .library
        .profiles
        .push(leaf("selector-export-pool-two", "members", 31083));
    let snapshot = selector_snapshot(
        &source.store.library,
        &std::collections::HashSet::from(["pool".into(), "other-pool".into()]),
    )
    .unwrap();
    assert!(snapshot
        .profiles
        .iter()
        .any(|p| p.id == "selector-export-pool-two_" && p.kind == ProfileKind::Chain));
    let bundle = portable(
        &source,
        vec!["pool".into(), "other-pool".into(), "two".into()],
    );
    assert_aliases(&bundle, &source);
    let directory = tempfile::tempdir().unwrap();
    let mut target = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    let imported = import(&mut target, bundle);
    for (name, expected) in [
        (
            "pool",
            vec![
                vec!["front", "two", "landing"],
                vec!["front", "one", "landing"],
            ],
        ),
        (
            "Other pool",
            vec![vec!["landing", "two"], vec!["landing", "one"]],
        ),
    ] {
        let pool = imported
            .iter()
            .find(|p| p.kind == ProfileKind::AutoSelector && p.name == name)
            .unwrap();
        assert_eq!(paths(&target, pool), expected);
        assert_eq!(pool.config["pinned_profile"], pool.config["members"][1]);
    }
    assert_eq!(
        imported
            .iter()
            .filter(|p| p.name == "two" && p.kind == ProfileKind::XrayOutbound)
            .count(),
        1
    );
}

#[test]
fn invalid_wrapped_pin_or_combined_hop_limit_fail_without_mutating_source() {
    let (_directory, mut source) = fixture(true, true, false, 31084);
    source.store.library.profiles.last_mut().unwrap().config["pinned_profile"] = json!("foreign");
    let before = json!(source.store.library);
    assert_eq!(
        source
            .export_profiles(vec!["pool".into()], Format::Profiles)
            .unwrap_err(),
        "invalid_selector_pin"
    );
    assert_eq!(json!(source.store.library), before);
    source.store.library.profiles.last_mut().unwrap().config["pinned_profile"] = json!("one");
    let mut front = leaf("long-front", "members", 31084);
    front.kind = ProfileKind::Chain;
    front.config = json!({"type":"chain","hops":vec!["front";15]});
    source.store.library.profiles.push(front);
    source.store.library.groups[0].proxy_chain.front = Some("long-front".into());
    let before = json!(source.store.library);
    assert_eq!(
        source
            .export_profiles(vec!["pool".into()], Format::Profiles)
            .unwrap_err(),
        "chain_too_long"
    );
    assert_eq!(json!(source.store.library), before);
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; launches actual core Check only"]
async fn actual_core_accepts_exported_explicit_mixed_and_chain_pools_without_probe_connections() {
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE required");
    if std::env::var_os("THRONIUM_EXPLICIT_EXPORT_FIXTURE").is_none() {
        let bundle = tempfile::tempdir().unwrap();
        let executable = bundle.path().join("Thronium");
        let bundled_core = bundle.path().join("ThroniumCore");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(&core, &bundled_core).unwrap();
        let output=std::process::Command::new(executable).args(["--exact","exports::selector_tests::actual_core_accepts_exported_explicit_mixed_and_chain_pools_without_probe_connections","--ignored","--nocapture"])
            .env("THRONIUM_EXPLICIT_EXPORT_FIXTURE","1").env("THRONIUM_TEST_CORE",bundled_core).output().unwrap();
        assert!(
            output.status.success(),
            "owned core fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let mut target = Engine::open(directory.path(), Path::new(&core)).unwrap();
    for (front, landing, chain) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (true, true, true),
    ] {
        let (_source_dir, source) = fixture(front, landing, chain, port);
        let imported = import(&mut target, portable(&source, vec!["pool".into()]));
        let pool = imported
            .iter()
            .find(|p| p.kind == ProfileKind::AutoSelector)
            .unwrap();
        if let Err(error) = target.check(pool).await {
            target.shutdown().await;
            panic!("exported pool Check failed ({front}/{landing}/{chain}): {error}");
        }
        assert!(target.running.is_none() && target.active_connection.is_none());
    }
    target.shutdown().await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
            .await
            .is_err(),
        "Check attempted a proxy/probe connection"
    );
}
