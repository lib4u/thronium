use super::*;
use crate::{store::Profile, ProfileDraft};
fn setup() -> (tempfile::TempDir, Engine, Vec<String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let ids=(0..2).map(|i|e.save_profile(serde_json::from_value::<ProfileDraft>(json!({"name":format!("Member {i}"),"groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":1080+i,"password":"private-history-secret"}})).unwrap()).unwrap()).collect::<Vec<_>>();
    let id=e.save_profile(serde_json::from_value(json!({"name":"Pool","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","members":ids,"url":"https://example.test/private-history-url"}})).unwrap()).unwrap();
    (dir, e, ids, id)
}
fn request(e: &Engine, id: &str) -> proto::LoadConfigReq {
    Engine::build_with_library(&e.profile(id).unwrap(), &e.store.library, &e.data_dir).unwrap()
}
fn record(e: &mut Engine, id: &str, at: u64) {
    let next = e
        .store
        .library
        .selector_history
        .record(&e.store.library, id, &request(e, id), at)
        .unwrap()
        .unwrap();
    e.store.save_selector_history(next).unwrap();
}
#[test]
fn successful_membership_history_reopens_without_config_secrets_or_library_changes() {
    let (dir, mut e, ids, id) = setup();
    let library = std::fs::read(dir.path().join("library.json")).unwrap();
    let before = serde_json::to_value(&e.store.library).unwrap();
    let generation = e.store.generation();
    record(&mut e, &id, now());
    let expected = e.selector_history();
    assert_eq!(expected[0]["lastBuilt"], json!(ids));
    assert_eq!(expected[0]["entries"][0]["builds"], 1);
    assert!(e.store.generation() > generation);
    let file = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
    for private in [
        "private-history-secret",
        "private-history-url",
        "127.0.0.1",
        "coreConfig",
        "server_port",
    ] {
        assert!(!file.contains(private));
    }
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        library
    );
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join(FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(e.selector_history(), expected);
}
#[test]
fn order_counts_first_use_and_removed_members_follow_exact_compiled_membership() {
    let (_d, mut e, ids, id) = setup();
    record(&mut e, &id, 100);
    let p = e
        .store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap();
    p.config["members"] = json!([ids[1]]);
    record(&mut e, &id, 200);
    let h = e.selector_history();
    assert_eq!(h[0]["lastBuilt"], json!([ids[1]]));
    assert_eq!(h[0]["entries"][0]["profileId"], ids[1]);
    assert_eq!(h[0]["entries"][0]["builds"], 2);
    assert_eq!(h[0]["entries"][0]["firstUsed"], 100);
    assert_eq!(h[0]["entries"][1]["lastUsed"], 100);
    e.store.library.profiles.retain(|p| p.id != ids[0]);
    assert_eq!(e.selector_history()[0]["entries"][1]["missing"], true);
    record(&mut e, &id, 150);
    assert_eq!(e.selector_history()[0]["lastBuiltAt"], 200);
}
#[test]
fn preview_build_status_reads_and_portable_restore_do_not_add_history() {
    let (_d, mut e, _, id) = setup();
    for _ in 0..3 {
        request(&e, &id);
        assert_eq!(e.selector_history(), json!([]));
    }
    record(&mut e, &id, now());
    let before = e.selector_history();
    for _ in 0..3 {
        request(&e, &id);
        assert_eq!(e.selector_history(), before);
    }
    let portable = serde_json::to_value(&e.store.library).unwrap();
    assert!(portable.get("selectorHistory").is_none());
    let restored: Library = serde_json::from_value(portable).unwrap();
    assert!(restored.selector_history.pools.is_empty());
    e.store.commit(restored).unwrap();
    assert_eq!(e.selector_history(), before);
}
#[test]
fn full_configs_and_nonselector_connections_do_not_claim_library_history() {
    let (_d, mut e, ids, id) = setup();
    let req = request(&e, &id);
    let mut l = e.store.library.clone();
    l.profiles.iter_mut().find(|p| p.id == id).unwrap().kind = ProfileKind::SingBoxConfig;
    assert!(l
        .selector_history
        .record(&l, &id, &req, 100)
        .unwrap()
        .is_none());
    let req = request(&e, &ids[0]);
    assert!(e
        .store
        .library
        .selector_history
        .record(&e.store.library, &ids[0], &req, 100)
        .unwrap()
        .is_none());
    assert!(e.active_connection.is_none());
    e.remember_selector_start();
    assert_eq!(e.selector_history(), json!([]));
}
#[test]
fn auxiliary_routing_pools_map_the_actual_generated_tags() {
    let (_d, mut e, ids, id) = setup();
    let route = e
        .store
        .library
        .routing
        .profiles
        .iter_mut()
        .find(|p| p.id == e.store.library.routing.active)
        .unwrap();
    route.rules=vec![serde_json::from_value(json!({"id":"route-pool","name":"Pool","enabled":true,"config":{"domain":["example.test"],"outbound":format!("profile:{id}")}})).unwrap()];
    record(&mut e, &ids[0], now());
    let view = e.selector_history();
    assert_eq!(view[0]["profileId"], id);
    assert_eq!(view[0]["lastBuilt"], json!(ids));
}
#[test]
fn clear_is_per_pool_atomic_and_independent_of_profile_library() {
    let (dir, mut e, _, id) = setup();
    record(&mut e, &id, now());
    let before = e.selector_history();
    let file = std::fs::read(dir.path().join(FILE)).unwrap();
    let lib = std::fs::read(dir.path().join("library.json")).unwrap();
    let generation = e.store.generation();
    std::fs::remove_file(dir.path().join(FILE)).unwrap();
    std::fs::create_dir(dir.path().join(FILE)).unwrap();
    assert_eq!(e.clear_selector_history(&id).unwrap_err(), ERROR);
    assert_eq!(e.selector_history(), before);
    assert_eq!(e.store.generation(), generation);
    std::fs::remove_dir(dir.path().join(FILE)).unwrap();
    std::fs::write(dir.path().join(FILE), file).unwrap();
    e.clear_selector_history(&id).unwrap();
    assert_eq!(e.selector_history(), json!([]));
    assert_eq!(std::fs::read(dir.path().join("library.json")).unwrap(), lib);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(e.selector_history(), json!([]));
}
#[test]
fn malformed_oversized_unknown_versions_and_inconsistent_history_are_ignored() {
    let (dir, mut e, _, id) = setup();
    record(&mut e, &id, now());
    let good: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
    for (path, value) in [
        (vec!["version"], json!(2)),
        (
            vec!["pools", id.as_str(), "lastBuiltAt"],
            json!(now() + 1000),
        ),
        (
            vec!["pools", id.as_str(), "lastBuilt"],
            json!(["not-an-entry"]),
        ),
        (vec!["pools", id.as_str(), "entries"], json!([])),
    ] {
        let mut broken = good.clone();
        let mut target = &mut broken;
        for key in path {
            target = &mut target[key];
        }
        *target = value;
        std::fs::write(dir.path().join(FILE), broken.to_string()).unwrap();
        assert!(Cache::load(dir.path(), &e.store.library).pools.is_empty());
    }
    std::fs::write(dir.path().join(FILE), vec![b' '; MAX_BYTES + 1]).unwrap();
    assert!(Cache::load(dir.path(), &e.store.library).pools.is_empty());
    std::fs::write(dir.path().join(FILE), "{").unwrap();
    assert!(Cache::load(dir.path(), &e.store.library).pools.is_empty());
}
#[test]
fn history_limits_trim_old_pools_entries_and_long_utf8_names() {
    let (_d, mut e, ids, id) = setup();
    e.store.library.profiles[0].name = "Я".repeat(400);
    record(&mut e, &id, 100);
    assert_eq!(
        e.store.library.selector_history.pools[&id].entries[0]
            .name
            .len(),
        MAX_NAME_BYTES
    );
    let original = e.profile(&id).unwrap();
    let mut cache = e.store.library.selector_history.clone();
    let pool = cache.pools.get_mut(&id).unwrap();
    pool.entries.extend((0..MAX_ENTRIES).map(|i| Entry {
        profile_id: format!("old-{i}"),
        name: "old".into(),
        first_used: 1,
        last_used: 1,
        builds: 1,
    }));
    cache = cache
        .record(&e.store.library, &id, &request(&e, &id), 101)
        .unwrap()
        .unwrap();
    assert_eq!(cache.pools[&id].entries.len(), MAX_ENTRIES);
    assert_eq!(cache.pools[&id].last_built, ids);
    for i in 0..MAX_POOLS + 1 {
        let pid = format!("pool-{i}");
        e.store.library.profiles.push(Profile {
            id: pid.clone(),
            ..original.clone()
        });
        cache = cache
            .record(&e.store.library, &pid, &request(&e, &pid), 200 + i as u64)
            .unwrap()
            .unwrap();
    }
    assert_eq!(cache.pools.len(), MAX_POOLS);
    assert!(!cache.pools.contains_key(&id));
    assert!(!cache.pools.contains_key("pool-0"));
    assert!(cache.bytes().unwrap().len() <= MAX_BYTES);
}
#[test]
fn renamed_members_are_current_but_deleted_pool_histories_are_hidden_and_pruned() {
    let (dir, mut e, ids, id) = setup();
    record(&mut e, &id, now());
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == ids[0])
        .unwrap()
        .name = "Renamed".into();
    assert_eq!(e.selector_history()[0]["entries"][0]["name"], "Renamed");
    e.store.library.profiles.retain(|p| p.id != id);
    assert_eq!(e.selector_history(), json!([]));
    assert!(Cache::load(dir.path(), &e.store.library).pools.is_empty());
    assert!(e.clear_selector_history(&id).is_err());
}

#[test]
fn settings_warp_preserves_membership_history_under_the_library_pool_id() {
    let (_dir, mut e, ids, pool) = setup();
    e.store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    e.store
        .library
        .settings
        .insert("warp_ep".into(), json!("127.0.0.1:2408"));
    record(&mut e, &pool, 100);
    assert_eq!(e.selector_history()[0]["profileId"], pool);
    assert_eq!(e.selector_history()[0]["lastBuilt"], json!(ids));
}
