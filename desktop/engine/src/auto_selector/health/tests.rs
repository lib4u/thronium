use super::*;
use crate::ProfileDraft;
use std::path::Path;
const URL: &str = "https://health50-private.example/check?token=private-query";
fn setup() -> (
    tempfile::TempDir,
    Engine,
    String,
    String,
    proto::LoadConfigReq,
    State,
) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let member=e.save_profile(serde_json::from_value::<ProfileDraft>(json!({"name":"Member","groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":1080,"password":"health50-private-secret"}})).unwrap()).unwrap();
    let pool=e.save_profile(serde_json::from_value(json!({"name":"Pool","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","member_source":{"group_id":"personal","persist_health":true},"url":URL}})).unwrap()).unwrap();
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &pool, &request);
    state.captured_at_ms = now_ms() - 10000;
    (dir, e, member, pool, request, state)
}
fn reply(member: &str, at: u64) -> proto::QueryAutoSelectorsResponse {
    proto::QueryAutoSelectorsResponse {
        groups: vec![proto::AutoSelectorStatus {
            tag: Some("proxy".into()),
            phase: Some("ready".into()),
            suspended: Some(false),
            rounds_completed: Some(1),
            members: vec![proto::AutoSelectorMember {
                tag: Some(super::super::member_tag("proxy", member)),
                state: Some("ok".into()),
                probes: Some(1),
                samples: Some(1),
                average_ms: Some(20),
                last_probe_ms: Some(at as i64),
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}
#[test]
fn new_core_average_keeps_original_time_provenance_and_reopens_without_secrets() {
    let (dir, mut e, member, pool, _, mut state) = setup();
    let at = now_ms() - 2000;
    let before = json!(e.store.library);
    let cache = state
        .take(&e.store.library, reply(&member, at), now_ms())
        .unwrap();
    e.store.save_latency_measurements(cache).unwrap();
    let value = e
        .store
        .library
        .latency_measurements
        .fresh(&e.store.library, &member, URL, 60)
        .unwrap();
    assert_eq!(value.origin, latency_measurements::Origin::CoreAverage);
    assert_eq!(value.timeout_ms, None);
    assert_eq!(value.tested_at, at / 1000);
    assert_eq!(value.latency_ms, Some(20));
    assert_eq!(json!(e.store.library), before);
    let text = std::fs::read_to_string(dir.path().join("http-latencies-v1.json")).unwrap();
    for secret in [
        "private-query",
        "health50-private-secret",
        "127.0.0.1",
        "health50-private.example",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(!text.contains("timeoutMs"));
    assert!(text.contains("core-average"));
    let draft:ProfileDraft=serde_json::from_value(json!({"id":pool,"name":"Pool","groupId":"personal","kind":"auto-selector","config":e.profile(&pool).unwrap().config})).unwrap();
    assert_eq!(
        e.preview_selector(draft).unwrap()["members"][0]["httpSource"],
        "core-average"
    );
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        e.store
            .library
            .latency_measurements
            .fresh(&e.store.library, &member, URL, 60)
            .unwrap()
            .tested_at,
        at / 1000
    );
}
#[test]
fn restored_warm_is_not_a_new_probe_and_repeated_core_status_does_not_refresh_age() {
    let (_d, e, member, pool, mut request, _) = setup();
    let mut core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let group = core["outbounds"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|g| g["type"] == "auto-selector")
        .unwrap();
    group["warm"] = json!([{"tag":super::super::member_tag("proxy",&member),"rtt":20,"age":5}]);
    request.core_config = Some(core.to_string());
    let mut state = State::capture(&e.store.library, &pool, &request);
    state.captured_at_ms = now_ms() - 10000;
    let at = now_ms() - 2000;
    assert!(state
        .take(&e.store.library, reply(&member, at), now_ms())
        .is_none());
    let mut fresh = reply(&member, at);
    fresh.groups[0].members[0].probes = Some(2);
    fresh.groups[0].members[0].samples = Some(2);
    assert!(state
        .take(&e.store.library, fresh.clone(), now_ms())
        .is_some());
    fresh.groups[0].members[0].average_ms = Some(99);
    fresh.groups[0].members[0].probes = Some(3);
    assert!(state.take(&e.store.library, fresh, now_ms()).is_none());
}
#[test]
fn suspended_unknown_incomplete_future_and_inconclusive_statuses_are_not_observations() {
    let (_d, e, member, _, _, state) = setup();
    let at = now_ms() - 1000;
    let base = reply(&member, at);
    let mut cases = vec![];
    let mut r = base.clone();
    r.groups[0].suspended = Some(true);
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].suspended = None;
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].rounds_completed = Some(0);
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].phase = Some("starting".into());
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].tag = Some("unowned".into());
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].members[0].tag = Some("unowned".into());
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].members[0].samples = Some(0);
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].members[0].probes = Some(0);
    cases.push(r);
    let mut r = base.clone();
    r.groups[0].members[0].average_ms = Some(-1);
    cases.push(r);
    for name in ["cooldown", "untested", "unknown"] {
        let mut r = base.clone();
        r.groups[0].members[0].state = Some(name.into());
        cases.push(r);
    }
    let mut r = base.clone();
    r.groups[0].members[0].last_probe_ms = Some((now_ms() + 60000) as i64);
    cases.push(r);
    for r in cases {
        assert!(state.clone().take(&e.store.library, r, now_ms()).is_none());
    }
    let mut dead = base;
    dead.groups[0].members[0].state = Some("dead".into());
    let cache = state
        .clone()
        .take(&e.store.library, dead, now_ms())
        .unwrap();
    assert_eq!(
        cache
            .fresh(&e.store.library, &member, URL, 60)
            .unwrap()
            .latency_ms,
        None
    );
}
#[test]
fn original_member_and_pool_contexts_are_required_but_a_display_rename_is_harmless() {
    let (_d, e, member, pool, _, state) = setup();
    let r = reply(&member, now_ms() - 1000);
    let mut changed = e.store.library.clone();
    changed
        .profiles
        .iter_mut()
        .find(|p| p.id == member)
        .unwrap()
        .config["server_port"] = json!(1081);
    assert!(state.clone().take(&changed, r.clone(), now_ms()).is_none());
    let mut changed = e.store.library.clone();
    changed
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["url"] = json!("https://other.example/check");
    assert!(state.clone().take(&changed, r.clone(), now_ms()).is_none());
    let mut changed = e.store.library.clone();
    changed
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]["persist_health"] = json!(false);
    assert!(state.clone().take(&changed, r.clone(), now_ms()).is_none());
    let mut changed = e.store.library.clone();
    changed
        .profiles
        .iter_mut()
        .find(|p| p.id == member)
        .unwrap()
        .name = "Renamed".into();
    assert!(state.clone().take(&changed, r, now_ms()).is_some());
}
#[test]
fn core_cannot_replace_a_newer_manual_measurement_and_old_manual_files_still_load() {
    let (dir, mut e, member, _, _, mut state) = setup();
    let cache = e
        .store
        .library
        .latency_measurements
        .updated(&e.store.library, &member, URL, 3000, Some(7))
        .unwrap();
    e.store.save_latency_measurements(cache).unwrap();
    assert!(state
        .take(&e.store.library, reply(&member, now_ms() - 1000), now_ms())
        .is_none());
    let file = dir.path().join("http-latencies-v1.json");
    let mut json: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let at = now_ms() / 1000 - 3;
    json["entries"][&member]
        .as_object_mut()
        .unwrap()
        .remove("observedAtMs");
    json["entries"][&member]["testedAt"] = json!(at);
    std::fs::write(&file, json.to_string()).unwrap();
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let context = latency_measurements::core_context(&e.store.library, &member, URL).unwrap();
    let mut old = e.store.library.latency_measurements.clone();
    assert_eq!(
        old.fresh(&e.store.library, &member, URL, 60)
            .unwrap()
            .origin,
        latency_measurements::Origin::Manual
    );
    assert!(old
        .record_core(
            &e.store.library,
            &member,
            &context,
            Some(20),
            at * 1000 + 500
        )
        .is_none());
    assert!(old
        .record_core(
            &e.store.library,
            &member,
            &context,
            Some(20),
            (at + 1) * 1000
        )
        .is_some());
}
#[test]
fn clear_keeps_a_watermark_and_only_new_core_probes_can_fill_the_cache_again() {
    let (_d, mut e, member, _, _, mut state) = setup();
    let at = now_ms() - 2000;
    let cache = state
        .take(&e.store.library, reply(&member, at), now_ms())
        .unwrap();
    e.store.save_latency_measurements(cache).unwrap();
    e.selector_health = state;
    e.clear_url_tests().unwrap();
    assert!(e
        .store
        .library
        .latency_measurements
        .fresh(&e.store.library, &member, URL, 60)
        .is_none());
    assert!(e
        .selector_health
        .take(&e.store.library, reply(&member, at + 1), now_ms())
        .is_none());
    std::thread::sleep(Duration::from_millis(2));
    let at = now_ms();
    assert!(e
        .selector_health
        .take(&e.store.library, reply(&member, at), at)
        .is_some());
}
#[test]
fn capture_is_opt_in_and_full_configs_do_not_claim_saved_selector_tags() {
    let (_d, e, _, pool, request, state) = setup();
    assert_eq!(state.groups.len(), 1);
    assert_eq!(state.request, Some(request_hash(&request)));
    let mut library = e.store.library.clone();
    library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]
        .as_object_mut()
        .unwrap()
        .remove("persist_health");
    assert!(State::capture(&library, &pool, &request).groups.is_empty());
    library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .kind = ProfileKind::SingBoxConfig;
    assert!(State::capture(&library, &pool, &request).groups.is_empty());
}

#[test]
fn failed_cache_write_keeps_observation_watermark_and_retries_the_same_real_probe() {
    let (dir, mut e, member, _, _, state) = setup();
    e.selector_health = state;
    let path = dir.path().join("http-latencies-v1.json");
    std::fs::create_dir(&path).unwrap();
    let at = now_ms() - 1000;
    let mut r = reply(&member, at);
    r.groups[0].selected = Some(super::super::member_tag("proxy", &member));
    let generation = e.store.generation();
    e.accept_selector_health(r.clone(), true);
    assert!(e.selector_health.write_failed);
    let switches = || e.switch_history()["entries"].as_array().unwrap().len();
    assert_eq!(switches(), 1, "the selection is recorded despite the cache");
    assert_eq!(e.store.generation(), generation);
    assert!(e
        .store
        .library
        .latency_measurements
        .fresh(&e.store.library, &member, URL, 60)
        .is_none());
    assert_eq!(
        e.selector_health.groups["proxy"].members[&super::super::member_tag("proxy", &member)]
            .last_probe_ms,
        0
    );
    std::fs::remove_dir(path).unwrap();
    e.accept_selector_health(r, true);
    assert!(!e.selector_health.write_failed);
    assert_eq!(
        e.switch_history()["entries"].as_array().unwrap().len(),
        1,
        "the retry does not report the same selection twice"
    );
    assert_eq!(
        e.store
            .library
            .latency_measurements
            .fresh(&e.store.library, &member, URL, 60)
            .unwrap()
            .tested_at,
        at / 1000
    );
}
#[test]
fn zero_core_average_is_success_and_bad_provenance_or_timestamp_files_are_ignored() {
    let (dir, mut e, member, _, _, mut state) = setup();
    let mut r = reply(&member, now_ms() - 1000);
    r.groups[0].members[0].average_ms = Some(0);
    let cache = state.take(&e.store.library, r, now_ms()).unwrap();
    e.store.save_latency_measurements(cache).unwrap();
    assert_eq!(
        e.store
            .library
            .latency_measurements
            .fresh(&e.store.library, &member, URL, 60)
            .unwrap()
            .latency_ms,
        Some(0)
    );
    let path = dir.path().join("http-latencies-v1.json");
    let good: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (field, value) in [
        ("origin", json!("unknown")),
        ("timeoutMs", json!(2000)),
        ("observedAtMs", Value::Null),
        ("observedAtMs", json!(1000)),
        ("testedAt", json!(0)),
    ] {
        let mut bad = good.clone();
        bad["entries"][&member][field] = value;
        std::fs::write(&path, bad.to_string()).unwrap();
        assert!(Cache::load(dir.path(), &e.store.library)
            .fresh(&e.store.library, &member, URL, 60)
            .is_none());
    }
}
#[test]
fn only_built_limited_members_and_actual_auxiliary_tags_can_publish_core_results() {
    let (_d, mut e, member, pool, _, _) = setup();
    let other=e.save_profile(serde_json::from_value::<ProfileDraft>(json!({"name":"Extra","groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":1081}})).unwrap()).unwrap();
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]["build_limit"] = json!(1);
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &pool, &request);
    state.captured_at_ms = now_ms() - 10000;
    assert_eq!(state.groups["proxy"].members.len(), 1);
    assert!(state
        .take(&e.store.library, reply(&other, now_ms() - 1000), now_ms())
        .is_none());
    let route = e
        .store
        .library
        .routing
        .profiles
        .iter_mut()
        .find(|p| p.id == e.store.library.routing.active)
        .unwrap();
    route.rules=vec![serde_json::from_value(json!({"id":"health-route","name":"Pool","enabled":true,"config":{"domain":["example.test"],"outbound":format!("profile:{pool}")}})).unwrap()];
    let request = e.build(&e.profile(&member).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &member, &request);
    state.captured_at_ms = now_ms() - 10000;
    let tag = format!("thronium-route-{pool}");
    assert_eq!(state.groups.len(), 1);
    assert!(state.groups.contains_key(&tag));
    let mut r = reply(&member, now_ms() - 1000);
    assert!(state.take(&e.store.library, r.clone(), now_ms()).is_none());
    r.groups[0].tag = Some(tag.clone());
    r.groups[0].members[0].tag = Some(super::super::member_tag(&tag, &member));
    assert!(state.take(&e.store.library, r, now_ms()).is_some());
}
#[test]
fn empty_health_url_uses_the_core_default_for_capture_preview_and_next_warm_start() {
    let (_d, mut e, member, pool, _, _) = setup();
    let p = e
        .store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap();
    p.config["url"] = json!("");
    p.config["member_source"]["warm_start"] = json!(true);
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &pool, &request);
    state.captured_at_ms = now_ms() - 10000;
    let cache = state
        .take(&e.store.library, reply(&member, now_ms() - 1000), now_ms())
        .unwrap();
    e.store.save_latency_measurements(cache).unwrap();
    assert!(e
        .store
        .library
        .latency_measurements
        .fresh(
            &e.store.library,
            &member,
            "https://www.gstatic.com/generate_204",
            60
        )
        .is_some());
    let p = e.profile(&pool).unwrap();
    let preview=e.preview_selector(serde_json::from_value(json!({"id":pool,"name":p.name,"groupId":p.group_id,"kind":p.kind,"config":p.config})).unwrap()).unwrap();
    assert_eq!(preview["warmCandidatesCount"], 1);
    assert_eq!(preview["rankedByHttp"], 1);
    let request = e.build(&p).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(
        core["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .unwrap()["warm"][0]["rtt"],
        20
    );
}

#[test]
fn a_full_500_member_round_is_published_as_one_atomic_cache_generation() {
    let (dir, mut e, member, pool, _, _) = setup();
    let original = e.profile(&member).unwrap();
    let mut ids = vec![member.clone()];
    for i in 1..500 {
        let id = format!("health-batch-{i}");
        e.store.library.profiles.push(Profile {
            id: id.clone(),
            ..original.clone()
        });
        ids.push(id);
    }
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &pool, &request);
    state.captured_at_ms = now_ms() - 10000;
    assert_eq!(state.groups["proxy"].members.len(), 500);
    e.selector_health = state;
    let at = now_ms() - 1000;
    let mut r = reply(&member, at);
    let seed = r.groups[0].members[0].clone();
    r.groups[0].members = ids
        .iter()
        .map(|id| proto::AutoSelectorMember {
            tag: Some(super::super::member_tag("proxy", id)),
            ..seed.clone()
        })
        .collect();
    let generation = e.store.generation();
    e.accept_selector_health(r, true);
    assert_eq!(e.store.generation(), generation + 1);
    let file: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("http-latencies-v1.json")).unwrap())
            .unwrap();
    assert_eq!(file["entries"].as_object().unwrap().len(), 500);
    for id in &ids {
        let value = e
            .store
            .library
            .latency_measurements
            .fresh(&e.store.library, id, URL, 60)
            .unwrap();
        assert_eq!(value.tested_at, at / 1000);
        assert_eq!(value.latency_ms, Some(20));
    }
}

#[test]
fn settings_warp_keeps_health_attributed_to_the_original_pool_and_members() {
    let (_dir, mut e, member, pool, _, _) = setup();
    e.store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    e.store
        .library
        .settings
        .insert("warp_ep".into(), json!("127.0.0.1:2408"));
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let mut state = State::capture(&e.store.library, &pool, &request);
    assert_eq!(state.groups["settings-warp-base"].owner, pool);
    state.captured_at_ms = now_ms() - 10000;
    let at = now_ms() - 2000;
    let mut data = reply(&member, at);
    data.groups[0].tag = Some("settings-warp-base".into());
    assert!(state.take(&e.store.library, data, now_ms()).is_some());
}
#[test]
fn every_running_pool_is_captured_for_selection_polling_without_persisting_health() {
    let (_dir, mut e, member, _pool, _request, _state) = setup();
    let plain = e
        .save_profile(
            serde_json::from_value(
                json!({"name":"Plain pool","groupId":"personal","kind":"auto-selector",
                "config":{"type":"auto-selector","members":[member]}}),
            )
            .unwrap(),
        )
        .unwrap();
    let request = e.build(&e.profile(&plain).unwrap()).unwrap();
    let state = State::capture(&e.store.library, &plain, &request);
    assert!(
        state.groups.is_empty(),
        "no persist_health: nothing to cache"
    );
    assert_eq!(state.pools.iter().collect::<Vec<_>>(), ["proxy"]);
}
