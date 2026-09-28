use super::*;
fn automatic() -> ProfileDraft {
    let mut d = ranked_draft("saved-http-latency", false, 60);
    d.config["member_source"]["measure_before_connect"] = json!(true);
    d.config["member_source"]["build_limit"] = json!(1);
    d.config["member_source"]["pool_cap"] = json!(2);
    d
}
#[test]
fn connection_preflight_is_opt_in_and_validates_order_and_lifetime() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let id = e
        .save_profile(ranked_draft("saved-http-latency", false, 60))
        .unwrap();
    assert!(e.connection_measurements(&id).unwrap().is_none());
    for (key, value, code) in [
        ("order", json!("library"), "selector_saved_order_required"),
        (
            "result_validity_mins",
            json!(0),
            "selector_measurement_lifetime_required",
        ),
        (
            "measure_before_connect",
            json!("yes"),
            "invalid_selector_source",
        ),
    ] {
        let mut d = automatic();
        d.config["member_source"][key] = value;
        assert_eq!(e.save_profile(d).unwrap_err(), code);
    }
}
#[test]
fn preparation_reuses_fresh_successes_and_failures_and_only_proposes_the_ranked_library() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    http_measured(&mut e, "a", Some(25));
    http_measured(&mut e, "b", None);
    let id = e.save_profile(automatic()).unwrap();
    let before = json!(e.store.library);
    let plan = e.connection_measurements(&id).unwrap().unwrap();
    assert_eq!(plan.pools.len(), 1);
    assert_eq!(plan.pools[0].ids, vec!["c"]);
    assert_eq!(plan.pools[0].fresh_count, 2);
    assert_eq!(
        e.ranked_connection_library(&plan).err().as_deref(),
        Some("selector_measurements_incomplete")
    );
    assert_eq!(json!(e.store.library), before);
    http_measured(&mut e, "c", Some(5));
    assert!(e.connection_measurements_current(&plan));
    let proposed = e.ranked_connection_library(&plan).unwrap();
    let p = proposed.profiles.iter().find(|p| p.id == id).unwrap();
    assert_eq!(
        p.config["member_source"]["saved_ranking"]["members"],
        json!(["c", "a"])
    );
    assert!(e.profile(&id).unwrap().config["member_source"]
        .get("saved_ranking")
        .is_none());
    assert_eq!(super::super::resolve(p, &proposed).unwrap(), vec!["c"]);
    assert!(e.rpc.is_none());
}
#[test]
fn edits_selection_network_context_and_candidate_changes_discard_the_connection_plan() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    let id = e.save_profile(automatic()).unwrap();
    let plan = e.connection_measurements(&id).unwrap().unwrap();
    let original = e.store.library.clone();
    e.store.library.preferences.language = "ru".into();
    e.store.library.preferences.theme = "dark".into();
    assert!(e.connection_measurements_current(&plan));
    for which in [
        "candidate",
        "source",
        "route",
        "settings",
        "selection",
        "mode",
        "port",
        "new-member",
    ] {
        e.store.library = original.clone();
        match which {
            "candidate" => e.store.library.profiles[0].config["server_port"] = json!(9999),
            "source" => {
                e.store
                    .library
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == id)
                    .unwrap()
                    .config["member_source"]["exclude_regex"] = json!("A")
            }
            "route" => e.store.library.routing.profiles[0].mode = "direct".into(),
            "settings" => {
                e.store
                    .library
                    .settings
                    .insert("skip_cert".into(), json!(true));
            }
            "selection" => e.store.library.selected = Some("b".into()),
            "mode" => {
                e.store.library.preferences.connection_mode =
                    crate::system_proxy::ConnectionMode::Tun
            }
            "port" => e.store.library.preferences.inbound_port += 1,
            _ => e.store.library.profiles.push(leaf("c", "C")),
        }
        assert!(!e.connection_measurements_current(&plan), "{which}");
        assert_eq!(
            e.ranked_connection_library(&plan).err().as_deref(),
            Some("selector_measurements_stale")
        );
    }
}
#[test]
fn auxiliary_routing_pools_are_prepared_and_primary_edits_are_detected() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    let id = e.save_profile(automatic()).unwrap();
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{id}"));
    let plan = e.connection_measurements("a").unwrap().unwrap();
    assert_eq!(plan.pools[0].profile_id, id);
    e.store.library.profiles[0].config["server_port"] = json!(9999);
    assert!(!e.connection_measurements_current(&plan));
}
#[test]
fn all_candidates_remain_in_the_plan_above_the_batch_and_both_pool_limits() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..3000)
        .map(|i| leaf(&format!("p{i:04}"), &format!("P{i:04}")))
        .collect();
    let id = e.save_profile(automatic()).unwrap();
    let plan = e.connection_measurements(&id).unwrap().unwrap();
    assert_eq!(plan.pools[0].ids.len(), 3000);
    e.store.library.profiles.push(leaf("overflow", "Overflow"));
    assert_eq!(
        e.connection_measurements(&id).err().as_deref(),
        Some("selector_too_many_candidates")
    );
}
#[tokio::test]
async fn incomplete_and_failed_connections_leave_the_saved_ranking_unchanged() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let id = e.save_profile(automatic()).unwrap();
    let plan = e.connection_measurements(&id).unwrap().unwrap();
    let before = json!(e.store.library);
    assert_eq!(
        e.connect_measured(&plan).await.unwrap_err(),
        "selector_measurements_incomplete"
    );
    assert_eq!(json!(e.store.library), before);
    http_measured(&mut e, "a", Some(1));
    let before = json!(e.store.library);
    assert!(e.connect_measured(&plan).await.is_err());
    assert_eq!(json!(e.store.library), before);
    assert!(e.rpc.is_none());
}
/// A pool may contain complete Xray configurations; their HTTP results are
/// saved like any member's, so measuring before connect can complete.
#[test]
fn complete_xray_members_are_saved_so_the_measured_pool_can_connect() {
    let (_dir, mut e) = setup();
    let mut full = leaf("x", "X");
    full.kind = ProfileKind::XrayConfig;
    full.config = json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
        "outbounds":[{"tag":"exit","protocol":"freedom","settings":{}}]});
    e.store.library.profiles = vec![leaf("a", "A"), full];
    let id = e.save_profile(automatic()).unwrap();
    let mut plan = e.connection_measurements(&id).unwrap().unwrap();
    assert_eq!(plan.pools[0].ids, vec!["a", "x"]);
    let run = e
        .start_preflight_tests(&plan.pools[0], &plan.pools[0].ids)
        .unwrap();
    for latency in [30, 10] {
        let probe = e.next_url_test(&run.id).unwrap();
        e.finish_url_test(&run.id, &probe.id, Ok(latency));
    }
    assert!(!e
        .complete_connection_measurements(&mut plan, Some(&run.id))
        .unwrap());
    let proposed = e.ranked_connection_library(&plan).unwrap();
    let p = proposed.profiles.iter().find(|p| p.id == id).unwrap();
    assert_eq!(
        p.config["member_source"]["saved_ranking"]["members"],
        json!(["x", "a"])
    );
}
