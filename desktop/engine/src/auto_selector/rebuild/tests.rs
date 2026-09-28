use super::*;
use crate::connection::ActiveConnection;
use std::{collections::HashSet, path::Path};
const URL: &str = "http://127.0.0.1:39997/health";
fn setup() -> (tempfile::TempDir, Engine, Vec<String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core57")).unwrap();
    let mut ids = Vec::new();
    for name in ["A", "B", "C"] {
        ids.push(e.save_profile(serde_json::from_value(json!({"name":name,"groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":39998}})).unwrap()).unwrap());
    }
    let pool=e.save_profile(serde_json::from_value(json!({"name":"Pool","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","member_source":{"group_id":"personal","order":"saved-http-latency","measure_before_connect":true,"rebuild_on_exhaustion":true,"build_limit":1},"url":URL}})).unwrap()).unwrap();
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    e.store.library.selected = Some(pool.clone());
    e.running = Some(pool.clone());
    e.since = Some(7);
    e.routing_revision = Some(e.store.library.routing.revision);
    e.active_connection = Some(ActiveConnection {
        id: pool.clone(),
        profiles: ids.iter().cloned().chain([pool.clone()]).collect(),
        groups: HashSet::from(["personal".into()]),
        request: request.clone(),
        routing_revision: e.store.library.routing.revision,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    e.selector_rebuild = State::capture(&e.store.library, &pool, &request);
    (dir, e, ids, pool)
}
fn ticket(e: &Engine) -> Ticket {
    Ticket {
        id: e.selector_rebuild.id.clone(),
        generation: e.selector_rebuild.generation.clone(),
        token: uuid::Uuid::new_v4().to_string(),
        groups: vec!["proxy".into()],
        subscription_versions: BTreeMap::new(),
    }
}
fn measured(e: &mut Engine, id: &str, value: Option<i32>) {
    e.store.library.latency_measurements = e
        .store
        .library
        .latency_measurements
        .updated(
            &e.store.library,
            id,
            URL,
            e.store.library.preferences.ping.timeout_ms,
            value,
        )
        .unwrap();
}
#[test]
fn option_requires_connection_measurements_and_remains_off_by_default() {
    let (_dir, mut e, _, id) = setup();
    let mut profile = e.profile(&id).unwrap();
    profile.config["member_source"]["measure_before_connect"] = json!(false);
    assert_eq!(
        super::super::validate_saved(&profile, &e.store.library).unwrap_err(),
        "selector_rebuild_requires_measurements"
    );
    profile.config["member_source"]
        .as_object_mut()
        .unwrap()
        .remove("rebuild_on_exhaustion");
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap()
        .config = profile.config;
    assert!(State::capture(
        &e.store.library,
        &id,
        &e.active_connection.as_ref().unwrap().request
    )
    .pools
    .values()
    .all(|p| !p.on_exhaustion && !p.on_subscription));
}
#[test]
fn captures_only_actual_built_members_and_rejects_foreign_or_duplicate_tags() {
    let (_dir, e, ids, id) = setup();
    let state = &e.selector_rebuild;
    assert_eq!(state.pools.len(), 1);
    assert_eq!(
        state.pools["proxy"]
            .members
            .values()
            .cloned()
            .collect::<Vec<_>>(),
        vec![ids[0].clone()]
    );
    let mut request = e.active_connection.as_ref().unwrap().request.clone();
    let mut core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let outbound = core["outbounds"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    outbound["outbounds"] = json!([super::super::member_tag("proxy", &ids[0]), "foreign"]);
    request.core_config = Some(core.to_string());
    assert!(State::capture(&e.store.library, &id, &request)
        .pools
        .is_empty());
}
#[test]
fn session_and_network_changes_reject_tickets_but_appearance_and_library_order_do_not() {
    let (_dir, mut e, ids, _) = setup();
    let ticket = ticket(&e);
    let original = e.store.library.clone();
    assert!(e.selector_rebuild_current(&ticket));
    e.store.library.preferences.language = "ru".into();
    e.store.library.preferences.theme = "dark".into();
    e.store.library.profiles.reverse();
    assert!(e.selector_rebuild_current(&ticket));
    e.store.library = original.clone();
    e.store.library.selected = Some(ids[0].clone());
    assert!(!e.selector_rebuild_current(&ticket));
    e.store.library = original.clone();
    e.store.library.preferences.inbound_port += 1;
    assert!(!e.selector_rebuild_current(&ticket));
    e.store.library = original.clone();
    e.store.library.routing.revision += 1;
    assert!(!e.selector_rebuild_current(&ticket));
    e.store.library = original;
    e.selector_rebuild.generation = uuid::Uuid::new_v4().to_string();
    assert!(!e.selector_rebuild_current(&ticket));
}
#[test]
fn preparation_forces_built_members_reuses_other_fresh_results_and_claims_once() {
    let (_dir, mut e, ids, _) = setup();
    measured(&mut e, &ids[0], Some(5));
    measured(&mut e, &ids[1], Some(10));
    let ticket = ticket(&e);
    let before = json!(e.store.library);
    let plan = e.prepare_selector_rebuild(&ticket).unwrap();
    assert_eq!(plan.pools[0].ids, vec![ids[2].clone(), ids[0].clone()]);
    assert_eq!(plan.pools[0].fresh_count, 1);
    assert_eq!(json!(e.store.library), before);
    assert_eq!(e.selector_rebuild.pools["proxy"].monitor.attempts, 1);
    assert_eq!(
        e.prepare_selector_rebuild(&ticket).err().as_deref(),
        Some("selector_measurements_stale")
    );
    assert!(e.selector_rebuild_current(&ticket));
}
#[test]
fn busy_queue_does_not_consume_a_retry_or_replace_the_manual_batch() {
    let (_dir, mut e, ids, _) = setup();
    let ticket = ticket(&e);
    let batch = e
        .start_url_tests(crate::probes::Options {
            ids: vec![ids[0].clone()],
            url: URL.into(),
            timeout_ms: 3000,
            concurrency: None,
        })
        .unwrap();
    assert_eq!(
        e.prepare_selector_rebuild(&ticket).err().as_deref(),
        Some("probe_busy")
    );
    assert_eq!(e.selector_rebuild.pools["proxy"].monitor.attempts, 0);
    assert!(e.selector_rebuild.claimed.is_none());
    assert_eq!(e.url_tests_snapshot().unwrap().id, batch.id);
    e.cancel_url_test_batch(&batch.id);
    // A single exit-IP or speed diagnostic holds the queue just the same.
    e.reserve_probe(&ids[1]).unwrap();
    assert_eq!(
        e.prepare_selector_rebuild(&ticket).err().as_deref(),
        Some("probe_busy")
    );
    assert_eq!(e.selector_rebuild.pools["proxy"].monitor.attempts, 0);
    assert!(e.selector_rebuild.claimed.is_none());
}
#[test]
fn cancellation_is_owned_and_releases_claim_while_pausing_rebuilds() {
    let (_dir, mut e, _, _) = setup();
    let owner = ticket(&e);
    let foreign = ticket(&e);
    e.prepare_selector_rebuild(&owner).unwrap();
    e.finish_selector_rebuild(&foreign, true);
    assert!(!e.selector_rebuild.pools["proxy"].monitor.cancelled);
    assert!(e.selector_rebuild.claimed.is_some());
    e.finish_selector_rebuild(&owner, true);
    assert!(e.selector_rebuild.claimed.is_none());
    assert!(e.selector_rebuild.pools["proxy"].monitor.cancelled);
    assert!(!e.selector_rebuild_current(&owner));
}
#[tokio::test]
async fn checked_start_failure_retains_old_request_saved_ranking_and_retry_count() {
    let (_dir, mut e, ids, _) = setup();
    for id in &ids {
        measured(&mut e, id, Some(20));
    }
    let ticket = ticket(&e);
    let plan = e.prepare_selector_rebuild(&ticket).unwrap();
    let library = json!(e.store.library);
    let old = request_hash(&e.active_connection.as_ref().unwrap().request);
    assert!(e.connect_rebuilt(&ticket, &plan).await.is_err());
    assert_eq!(json!(e.store.library), library);
    assert_eq!(
        request_hash(&e.active_connection.as_ref().unwrap().request),
        old
    );
    e.finish_selector_rebuild(&ticket, false);
    assert!(e.selector_rebuild.claimed.is_none());
    assert_eq!(e.selector_rebuild.pools["proxy"].monitor.attempts, 1);
}

#[test]
fn forced_old_members_outside_current_filters_do_not_enlarge_the_plan() {
    let (_dir, mut e, ids, pool) = setup();
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]["name_regex"] = json!("^[ABC]$");
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    e.active_connection.as_mut().unwrap().request = request.clone();
    e.selector_rebuild = State::capture(&e.store.library, &pool, &request);
    // A metadata change can exclude a previous member without changing its
    // actual connection configuration (the same issue occurs with fresh country data).
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == ids[0])
        .unwrap()
        .name = "Excluded".into();
    let owner = ticket(&e);
    assert!(e.selector_rebuild_current(&owner));
    measured(&mut e, &ids[1], Some(5));
    let plan = e.prepare_selector_rebuild(&owner).unwrap();
    assert_eq!(plan.pools[0].ids, vec![ids[2].clone()]);
    assert_eq!(plan.pools[0].fresh_count, 1);
}

mod subscription;

#[test]
fn settings_warp_preserves_dynamic_rebuild_ownership_and_member_mapping() {
    let (_dir, mut e, ids, pool) = setup();
    e.store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    e.store
        .library
        .settings
        .insert("warp_ep".into(), json!("127.0.0.1:2408"));
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let state = State::capture(&e.store.library, &pool, &request);
    let captured = &state.pools["settings-warp-base"];
    assert_eq!(captured.id, pool);
    assert!(captured.on_exhaustion);
    assert_eq!(captured.members.values().next().unwrap(), &ids[0]);
    assert_eq!(
        state.former_member_name(
            "settings-warp-base",
            &super::super::member_tag("proxy", &ids[0])
        ),
        Some("A")
    );
}
