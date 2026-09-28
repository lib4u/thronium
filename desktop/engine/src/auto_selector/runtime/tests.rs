use super::*;
use crate::{auto_selector::AUTO_SELECT_ID, ProfileDraft};
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine, Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    let ids = (0..3)
        .map(|i| {
            engine.save_profile(serde_json::from_value::<ProfileDraft>(json!({
        "name": format!("Server {i}"), "groupId": "personal", "kind": "sing-box-outbound",
        "config": {"type":"socks", "server":"127.0.0.1", "server_port":1080+i}
    })).unwrap()).unwrap()
        })
        .collect();
    (directory, engine, ids)
}

fn reply(tag: &str, ids: &[String]) -> proto::QueryAutoSelectorsResponse {
    proto::QueryAutoSelectorsResponse {
        groups: vec![proto::AutoSelectorStatus {
            tag: Some(tag.into()),
            selected: Some(super::super::member_tag("proxy", &ids[1])),
            selected_udp: Some(super::super::member_tag("proxy", &ids[2])),
            members: ids
                .iter()
                .map(|id| proto::AutoSelectorMember {
                    tag: Some(super::super::member_tag("proxy", id)),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }],
    }
}

#[test]
fn virtual_pool_and_its_members_keep_library_identity_with_or_without_warp() {
    let (_dir, mut engine, ids) = setup();
    engine.running = Some(AUTO_SELECT_ID.into());
    engine.remember_quick_connection(ids[0].clone(), false);
    for tag in ["proxy", "settings-warp-base"] {
        // Runtime identity must work before and after an unsaved-to-Core toggle.
        for enabled in [false, true] {
            engine
                .store
                .library
                .settings
                .insert("enable_warp".into(), json!(enabled));
            let pools = engine.selector_status(reply(tag, &ids));
            let pool = &pools[0];
            assert_eq!(
                pool["tag"], tag,
                "RPC actions still target the actual Core pool"
            );
            assert_eq!(pool["profileId"], AUTO_SELECT_ID);
            assert_eq!(pool["name"], "auto-select");
            for (i, id) in ids.iter().enumerate() {
                assert_eq!(pool["members"][i]["profileId"], *id);
                assert_eq!(pool["members"][i]["name"], format!("Server {i}"));
            }
            assert_eq!(pool["needsReconnect"], true);
        }
    }
    assert!(!engine
        .store
        .library
        .profiles
        .iter()
        .any(|p| p.id == AUTO_SELECT_ID));
}

#[test]
fn manual_routing_pool_tags_remain_distinct_and_unknown_tags_do_not_claim_an_owner() {
    let (_dir, mut engine, ids) = setup();
    let pool = engine.save_profile(serde_json::from_value(json!({"name":"Manual pool", "groupId":"personal", "kind":"auto-selector", "config":{"type":"auto-selector", "members":ids}})).unwrap()).unwrap();
    engine.running = Some(AUTO_SELECT_ID.into());
    let tag = format!("thronium-route-{pool}");
    let mut data = reply(&tag, &ids);
    for (member, id) in data.groups[0].members.iter_mut().zip(&ids) {
        member.tag = Some(super::super::member_tag(&tag, id));
    }
    let pools = engine.selector_status(data);
    assert_eq!(pools[0]["profileId"], pool);
    assert_eq!(pools[0]["name"], "Manual pool");
    assert_eq!(pools[0]["members"][0]["profileId"], ids[0]);
    assert!(owner(
        &engine.store.library,
        engine.running.as_deref(),
        "user-pool"
    )
    .is_none());
    assert!(owner(&engine.store.library, Some(&ids[0]), "settings-warp-base").is_none());
}

#[test]
fn warp_is_an_exit_after_the_pool_never_an_extra_candidate() {
    let (_dir, mut engine, ids) = setup();
    let config = json!({"enable_warp":true, "warp_ep":"127.0.0.1:2408", "warp_private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "warp_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "warp_ifc_addrs":["10.77.0.2/32"]});
    engine
        .store
        .library
        .settings
        .extend(config.as_object().unwrap().clone());
    let request = engine
        .build(&engine.auto_select_profile().unwrap())
        .unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let pool = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "auto-selector")
        .unwrap();
    assert_eq!(pool["tag"], "settings-warp-base");
    assert_eq!(
        pool["outbounds"],
        json!(ids
            .iter()
            .map(|id| super::super::member_tag("proxy", id))
            .collect::<Vec<_>>())
    );
    let exit = core["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert_eq!(exit["type"], "wireguard");
    assert_eq!(exit["detour"], pool["tag"]);
    assert_eq!(engine.store.library.profiles.len(), 3);
}

#[test]
fn switch_history_under_warp_records_the_virtual_pool_and_server_names() {
    let (_dir, mut engine, ids) = setup();
    engine.running = Some(AUTO_SELECT_ID.into());
    engine.record_member_switch(
        "settings-warp-base",
        &super::super::member_tag("proxy", &ids[0]),
        &super::super::member_tag("proxy", &ids[1]),
    );
    let history = engine.switch_history();
    assert_eq!(history["entries"][0]["poolId"], AUTO_SELECT_ID);
    assert_eq!(history["entries"][0]["fromName"], "Server 0");
    assert_eq!(history["entries"][0]["toName"], "Server 1");
}

#[test]
fn settings_warp_keeps_warm_hints_on_the_renamed_pool() {
    let (_dir, mut engine, ids) = setup();
    let url = "https://example.test/warm";
    let pool = engine.save_profile(serde_json::from_value(json!({"name":"Warm pool", "groupId":"personal", "kind":"auto-selector", "config":{"type":"auto-selector", "url":url, "member_source":{"group_id":"personal", "warm_start":true, "result_validity_mins":10}}})).unwrap()).unwrap();
    engine
        .store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    engine
        .store
        .library
        .settings
        .insert("warp_ep".into(), json!("127.0.0.1:2408"));
    engine.store.library.latency_measurements = engine
        .store
        .library
        .latency_measurements
        .updated(
            &engine.store.library,
            &ids[0],
            url,
            engine.store.library.preferences.ping.timeout_ms,
            Some(12),
        )
        .unwrap();
    let request = engine.build(&engine.profile(&pool).unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let pool = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "auto-selector")
        .unwrap();
    assert_eq!(pool["tag"], "settings-warp-base");
    assert_eq!(
        pool["warm"][0]["tag"],
        super::super::member_tag("proxy", &ids[0])
    );
    assert_eq!(pool["warm"][0]["rtt"], 12);
}

#[test]
fn pool_statistics_reach_the_window_as_codes_never_as_core_text() {
    let (_dir, mut engine, ids) = setup();
    engine.running = Some(AUTO_SELECT_ID.into());
    let mut response = reply("proxy", &ids);
    let group = &mut response.groups[0];
    group.last_switch_reason = Some("failover succeeded".into());
    group.members_probed = Some(3);
    group.members_cooldown = Some(1);
    group.suspended_since_ms = Some(1700);
    group.rounds_completed = Some(7);
    let member = &mut group.members[0];
    member.min_ms = Some(40);
    member.max_ms = Some(310);
    member.dial_total = Some(9);
    member.dial_fail = Some(2);
    member.last_ok_ms = Some(1600);
    member.last_error = Some("dial tcp 192.0.2.10:443: connect: connection refused".into());
    let pools = engine.selector_status(response);
    let pool = &pools[0];
    assert_eq!(pool["lastSwitchReason"], "failover");
    assert_eq!(pool["membersProbed"], 3);
    assert_eq!(pool["membersCooldown"], 1);
    assert_eq!(pool["suspendedSinceMs"], 1700);
    let member = &pool["members"][0];
    assert_eq!(member["minMs"], 40);
    assert_eq!(member["maxMs"], 310);
    assert_eq!(member["dialTotal"], 9);
    assert_eq!(member["dialFailures"], 2);
    assert_eq!(member["lastOkMs"], 1600u64);
    // The core's own message, with its address, never reaches the window.
    assert_eq!(member["lastError"], "probe_connection_refused");
    assert_eq!(super::member_error(""), "");
    assert_eq!(super::member_error("i/o timeout"), "probe_timeout");
    assert_eq!(super::member_error("no route to host"), "probe_unreachable");
    assert_eq!(super::member_error("something new"), "probe_failed");
    assert_eq!(super::switch_reason("balance rotation"), "balance");
    assert_eq!(super::switch_reason("a future reason"), "");
}
