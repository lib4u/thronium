use super::*;
use crate::{exports, probes, ProfileDraft};
fn setup() -> (tempfile::TempDir, Engine, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), std::path::Path::new("missing")).unwrap();
    let ids=[(ProfileKind::SingBoxOutbound,json!({"type":"socks","server":"localhost","server_port":1080,"password":"selector-secret","future":{"a":true}})),(ProfileKind::XrayOutbound,json!({"protocol":"socks","settings":{"address":"localhost","port":1081,"user":"u","pass":"private"}}))].into_iter().enumerate().map(|(i,(kind,config))|e.save_profile(ProfileDraft{ vpn_policy: Default::default(),id:None,name:format!("Member {i}"),group_id:"personal".into(),kind,config}).unwrap()).collect();
    (dir, e, ids)
}
fn draft(members: Value) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Pool".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: json!({"type":"auto-selector","members":members,"url":"https://example.test/probe","future_option":{"enabled":true}}),
    }
}
#[test]
fn invalid_duplicate_missing_recursive_and_unsupported_members_leave_the_library_intact() {
    let (_d, mut e, ids) = setup();
    let before = json!(e.store.library);
    for members in [
        json!([]),
        json!([ids[0], ids[0]]),
        json!(["missing"]),
        json!(vec![ids[0].clone(); 501]),
        json!(null),
    ] {
        assert!(e.save_profile(draft(members)).is_err());
        assert_eq!(json!(e.store.library), before);
    }
    let id = e.save_profile(draft(json!(ids))).unwrap();
    assert!(e.save_profile(draft(json!([id]))).is_err());
    assert!(e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Chain".into(),
            group_id: "personal".into(),
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":[id]})
        })
        .is_err());
    let mut invalid = draft(json!(ids));
    invalid.config["pinned_profile"] = json!("missing");
    assert!(e.save_profile(invalid).is_err());
    for field in ["outbounds", "pinned", "warm"] {
        let mut invalid = draft(json!(ids));
        invalid.config[field] = json!([]);
        assert_eq!(
            e.save_profile(invalid).unwrap_err(),
            "selector_generated_fields"
        );
    }
}
#[test]
fn generated_mixed_pool_retains_options_and_leaf_secrets_uses_private_bridges_and_maps_preferred_member(
) {
    let (_d, mut e, ids) = setup();
    let mut d = draft(json!(ids));
    d.config["pinned_profile"] = json!(ids[1]);
    let id = e.save_profile(d).unwrap();
    let before = json!(e.store.library);
    let request = build(&e.profile(&id).unwrap(), &e.store.library.profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let pool = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["type"] == "auto-selector")
        .unwrap();
    assert_eq!(
        pool["outbounds"],
        json!([member_tag("proxy", &ids[0]), member_tag("proxy", &ids[1])])
    );
    assert_eq!(pool["pinned"], member_tag("proxy", &ids[1]));
    assert!(pool.get("members").is_none());
    assert!(pool.get("pinned_profile").is_none());
    assert_eq!(pool["future_option"], json!({"enabled":true}));
    assert_eq!(request.need_xray, Some(true));
    assert!(core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["password"] == "selector-secret"));
    assert_eq!(json!(e.store.library), before);
    assert!(!json!(e.snapshot()).to_string().contains("selector-secret"));
}
#[test]
fn pool_references_protect_deletion_active_edits_group_operations_and_duplicate_removal() {
    let (_d, mut e, ids) = setup();
    let id = e.save_profile(draft(json!(ids))).unwrap();
    assert_eq!(e.delete(&ids[0]).unwrap_err(), "profile_used_in_chain");
    e.running = Some(id.clone());
    let mut d = draft(json!([ids[0]]));
    d.id = Some(id.clone());
    assert_eq!(e.save_profile(d).unwrap_err(), "stop_before_editing");
    assert!(e.move_profiles(vec![ids[1].clone()], "personal").is_err());
    e.running = None;
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{id}"));
    assert!(e.routing_uses(&ids[0]));
    e.store.library.routing.profiles[0].route = json!({});
    e.delete_profiles([ids, vec![id]].concat()).unwrap();
    assert!(e.store.library.profiles.is_empty());
}
#[test]
fn exported_pool_remaps_members_and_saved_pin_and_rejects_incomplete_import_atomically() {
    let (_d, mut e, ids) = setup();
    let mut d = draft(json!(ids));
    d.config["pinned_profile"] = json!(ids[1]);
    let id = e.save_profile(d).unwrap();
    let text = e
        .export_profiles(vec![id.clone()], exports::Format::Profiles)
        .unwrap();
    assert!(ids.iter().all(|id| !text.contains(id)));
    assert!(!text.contains(&id));
    let mut bundle: Value = serde_json::from_str(&text).unwrap();
    for p in bundle["profiles"].as_array_mut().unwrap() {
        p["groupId"] = json!("personal");
    }
    let imported = e
        .import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())
        .unwrap();
    let p = e.profile(&imported[2]).unwrap();
    assert_eq!(p.config["members"], json!(&imported[..2]));
    assert_eq!(p.config["pinned_profile"], imported[1]);
    let before = json!(e.store.library);
    bundle["profiles"].as_array_mut().unwrap().remove(1);
    assert!(e
        .import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())
        .is_err());
    assert_eq!(json!(e.store.library), before);
    assert!(e
        .export_profiles(vec![id], exports::Format::Configurations)
        .is_err());
}
#[test]
fn generic_url_queue_reports_pool_as_unsupported_so_its_own_core_checks_remain_authoritative() {
    let (_d, mut e, ids) = setup();
    let id = e.save_profile(draft(json!(ids))).unwrap();
    let run = e
        .start_url_tests(probes::Options {
            ids: vec![id],
            url: "http://localhost/probe".into(),
            timeout_ms: 100,
            concurrency: None,
        })
        .unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        probes::Status::Unsupported
    );
}

fn wireguard(port: Option<u16>) -> Value {
    let mut config = json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.177.43.2/32"],
        "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]});
    if let Some(port) = port {
        config["listen_port"] = json!(port);
    }
    config
}
fn endpoint(e: &mut Engine, name: &str, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config,
    })
    .unwrap()
}
#[test]
fn wireguard_members_compile_into_endpoints_under_member_tags_and_fixed_ports_stay_unique() {
    let (_d, mut e, ids) = setup();
    let a = endpoint(&mut e, "WG A", wireguard(Some(51000)));
    let b = endpoint(&mut e, "WG B", wireguard(None));
    let mut d = draft(json!([a, b, ids[0]]));
    d.config["pinned_profile"] = json!(b);
    let id = e.save_profile(d).unwrap();
    let request = build(&e.profile(&id).unwrap(), &e.store.library.profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let endpoints = core["endpoints"].as_array().unwrap();
    let tags: Vec<&str> = endpoints
        .iter()
        .map(|v| v["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        [member_tag("proxy", &a), member_tag("proxy", &b)],
        "each member is its own endpoint under the member tag"
    );
    assert!(endpoints
        .iter()
        .all(|v| v["type"] == "wireguard" && v.get("detour").is_none()));
    assert_eq!(endpoints[0]["listen_port"], 51000);
    let group = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "auto-selector")
        .unwrap();
    assert_eq!(
        group["outbounds"],
        json!([
            member_tag("proxy", &a),
            member_tag("proxy", &b),
            member_tag("proxy", &ids[0])
        ])
    );
    assert_eq!(group["pinned"], member_tag("proxy", &b));
    assert!(!core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["type"] == "wireguard"));
    // A chain that starts with the endpoint is a member like any other chain.
    let chain = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "WG then socks".into(),
            group_id: "personal".into(),
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":[b, ids[0]]}),
        })
        .unwrap();
    assert!(e.save_profile(draft(json!([chain]))).is_ok());
    // Two members on one fixed UDP port cannot both bind; a system interface is not a pool member.
    let clash = endpoint(&mut e, "WG clash", wireguard(Some(51000)));
    assert_eq!(
        e.save_profile(draft(json!([a, clash]))).unwrap_err(),
        "selector_member_port_conflict"
    );
    let mut system = wireguard(None);
    system["system"] = json!(true);
    let system = endpoint(&mut e, "WG system", system);
    assert_eq!(
        e.save_profile(draft(json!([system]))).unwrap_err(),
        "selector_member_unsupported"
    );
    assert!(!e.export_backup().unwrap().is_empty());
}

#[test]
fn member_eligibility_follows_configuration_and_context_not_a_protocol_list() {
    let (_d, mut e, ids) = setup();
    let wg = endpoint(&mut e, "WG", wireguard(None));
    let mut system_cfg = wireguard(None);
    system_cfg["system"] = json!(true);
    let system = endpoint(&mut e, "WG system", system_cfg);
    let tailscale = endpoint(&mut e, "Tailscale", json!({"type":"tailscale"}));
    let full = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Full".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxConfig,
            config: json!({"outbounds":[{"type":"direct"}]}),
        })
        .unwrap();
    let chain = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Chain".into(),
            group_id: "personal".into(),
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":[ids[0].clone()]}),
        })
        .unwrap();
    let pool = e.save_profile(draft(json!([ids[0].clone()]))).unwrap();
    let all = &e.store.library.profiles;
    let eligible = |id: &str| member_eligible(all.iter().find(|p| p.id == id).unwrap(), all);
    assert!(eligible(&ids[0]), "plain sing-box");
    assert!(eligible(&ids[1]), "plain xray");
    assert!(eligible(&wg), "userspace wireguard endpoint");
    assert!(eligible(&chain), "explicit chain");
    assert!(!eligible(&system), "a system interface is not eligible");
    assert!(!eligible(&tailscale), "tailscale is an external process");
    assert!(!eligible(&full), "a complete configuration is not a member");
    assert!(!eligible(&pool), "a nested pool is not a member");
}

#[test]
fn quick_auto_select_pools_all_eligible_servers_and_honours_the_toggle() {
    let (_d, mut e, ids) = setup();
    let third = endpoint(&mut e, "WG member", wireguard(None));
    // An ineligible profile must never appear in the synthesized pool.
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "OpenVPN".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"openvpn-client"}),
    })
    .unwrap();
    let pool = e.auto_select_profile().expect("three eligible servers");
    assert_eq!(pool.id, AUTO_SELECT_ID);
    assert_eq!(pool.kind, ProfileKind::AutoSelector);
    assert_eq!(pool.config["type"], "auto-selector");
    assert_eq!(pool.config["interval"], "120s");
    let members: Vec<&str> = pool.config["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(members, [ids[0].as_str(), ids[1].as_str(), third.as_str()]);
    assert!(
        e.profile(AUTO_SELECT_ID).is_ok(),
        "resolvable by its reserved id"
    );
    assert!(
        e.select(AUTO_SELECT_ID).is_ok(),
        "selectable by its reserved id"
    );
    // The synthesized pool must build like any pool.
    assert!(build(&pool, &e.store.library.profiles, 2080).is_ok());
    // Turning the feature off hides it.
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.enabled = false;
    e.preferences(prefs).unwrap();
    assert!(e.auto_select_profile().is_none());
    assert_eq!(
        e.profile(AUTO_SELECT_ID).err().as_deref(),
        Some("profile_not_found")
    );
    // Fewer than two eligible servers makes the virtual pool unavailable.
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.enabled = true;
    e.preferences(prefs).unwrap();
    e.delete(&third).unwrap();
    e.delete(&ids[1]).unwrap();
    assert!(
        e.auto_select_profile().is_none(),
        "one eligible server is below the threshold"
    );
}
#[test]
fn quick_auto_select_sweeps_every_member_with_its_own_settings_and_ranks_by_that_sweep() {
    let (_d, mut e, ids) = setup();
    let third = endpoint(
        &mut e,
        "Third",
        json!({"type":"socks","server":"localhost","server_port":1082}),
    );
    // The shared ping settings differ on purpose: the quick pool never reads them.
    e.store.library.preferences.ping = probes::PingSettings {
        method: probes::Method::Tcp,
        url: "https://shared.example.test/ping".into(),
        timeout_ms: 900,
    };
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.config =
        json!({"url":"https://pool.example.test/204","timeout":"2s","concurrency":3});
    e.preferences(prefs).unwrap();
    let mut plan = e
        .connection_measurements(AUTO_SELECT_ID)
        .unwrap()
        .expect("the quick pool always measures before it connects");
    assert_eq!(plan.pools.len(), 1);
    let pool = &plan.pools[0];
    assert_eq!(pool.profile_id, AUTO_SELECT_ID);
    assert_eq!(pool.fresh_count, 0, "no member is skipped as fresh");
    let mut swept = pool.ids.clone();
    swept.sort();
    let mut expected = vec![ids[0].clone(), ids[1].clone(), third.clone()];
    expected.sort();
    assert_eq!(swept, expected, "every eligible member is measured");
    assert_eq!(pool.url, "https://pool.example.test/204");
    assert_eq!(pool.timeout_ms, 2000);
    assert_eq!(pool.concurrency, Some(3));
    assert_eq!(pool.source, probes::Source::AutoSelect);
    // The sweep runs as its own source with the pool's parallelism, and its
    // HTTP results rank the pool even though the shared ping method is TCP.
    let before = json!(e.store.library);
    let run = e.start_preflight_tests(pool, &pool.ids).unwrap();
    assert_eq!(run.concurrency, 3);
    assert_eq!(
        e.snapshot().url_tests.unwrap().source,
        probes::Source::AutoSelect
    );
    for _ in 0..3 {
        e.next_url_test(&run.id).unwrap();
    }
    for (id, latency) in [(&ids[0], 80), (&ids[1], 15), (&third, 40)] {
        e.finish_url_test(&run.id, id, Ok(latency));
    }
    // The sweep never becomes a library row measurement or a saved HTTP
    // latency, whatever the shared ping method; only the journal keeps it.
    assert_eq!(json!(e.store.library), before);
    e.store.library.preferences.ping.method = probes::Method::Http;
    assert!(e.measurement(&e.profile(&ids[1]).unwrap()).is_none());
    assert!(
        e.measurement_journal()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["source"] == "auto-select")
            .count()
            == 3
    );
    assert!(e.connection_measurements_current(&plan));
    assert!(!e
        .complete_connection_measurements(&mut plan, Some(&run.id))
        .unwrap());
    let library = e.ranked_connection_library(&plan).unwrap();
    let ranked = library
        .profiles
        .iter()
        .find(|p| p.id == AUTO_SELECT_ID)
        .unwrap();
    assert_eq!(ranked.config["members"], json!([ids[1], third, ids[0]]));
    assert_eq!(ranked.config["url"], "https://pool.example.test/204");
    assert!(
        e.store
            .library
            .profiles
            .iter()
            .all(|p| p.id != AUTO_SELECT_ID),
        "ranking never persists the reserved profile"
    );
    // Editing the pool's own settings discards the plan.
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.config["timeout"] = json!("3s");
    e.preferences(prefs).unwrap();
    assert!(!e.connection_measurements_current(&plan));
    assert_eq!(
        e.ranked_connection_library(&plan).err().as_deref(),
        Some("selector_measurements_stale")
    );
}
#[test]
fn vpn_endpoints_and_chains_through_them_are_not_pool_members() {
    let (_d, mut e, ids) = setup();
    let add = |e: &mut Engine, name: &str, kind: ProfileKind, config: Value| {
        e.save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: name.into(),
            group_id: "personal".into(),
            kind,
            config,
        })
        .unwrap()
    };
    let vpn = add(
        &mut e,
        "OpenVPN",
        ProfileKind::SingBoxOutbound,
        json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"username":"u","password":"p"}),
    );
    let tailscale = add(
        &mut e,
        "Tailscale",
        ProfileKind::SingBoxOutbound,
        json!({"type":"tailscale","auth_key":"tskey-fixture"}),
    );
    let through = add(
        &mut e,
        "Through VPN",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[ids[0], vpn]}),
    );
    for member in [&vpn, &tailscale, &through] {
        assert_eq!(
            e.save_profile(draft(json!([ids[0], member]))).unwrap_err(),
            "selector_member_unsupported"
        );
    }
    assert!(e.save_profile(draft(json!([ids[0], ids[1]]))).is_ok());
}
#[test]
fn complete_xray_members_run_as_their_own_instances_behind_the_member_tag() {
    let (_d, mut e, ids) = setup();
    let full = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Complete Xray".into(),
            group_id: "personal".into(),
            kind: ProfileKind::XrayConfig,
            config: json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
                "outbounds":[{"tag":"exit","protocol":"freedom","settings":{}}],
                "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]}}),
        })
        .unwrap();
    let all = &e.store.library.profiles;
    assert!(member_eligible(
        all.iter().find(|p| p.id == full).unwrap(),
        all
    ));
    let pool = e.save_profile(draft(json!([ids[0], full]))).unwrap();
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    assert_eq!(request.xray_full_configs.len(), 1);
    assert_eq!(request.xray_full_idle_seconds, Some(0));
    // The user's inbound tag and rule survive; only the listener is managed.
    let instance: Value = serde_json::from_str(&request.xray_full_configs[0]).unwrap();
    let inbounds = instance["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0]["tag"], "user-in");
    assert_ne!(inbounds[0]["port"], 1);
    assert_eq!(
        instance["routing"]["rules"][0]["inboundTag"],
        json!(["user-in"])
    );
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let outbounds = core["outbounds"].as_array().unwrap();
    let dialer = outbounds
        .iter()
        .find(|o| o["tag"] == member_tag("proxy", &full))
        .unwrap();
    assert_eq!(dialer["type"], "socks");
    assert_eq!(dialer["server"], "127.0.0.1");
    let group = outbounds
        .iter()
        .find(|o| o["type"] == "auto-selector")
        .unwrap();
    assert_eq!(
        group["outbounds"],
        json!([member_tag("proxy", &ids[0]), member_tag("proxy", &full)])
    );
    // Behind a group front proxy the complete configuration is no longer the
    // first hop of its member chain, as in Qt's xrayFullConfigFitsChain.
    e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
        front: Some(ids[1].clone()),
        landing: None,
    };
    e.store.commit(e.store.library.clone()).unwrap();
    assert_eq!(
        e.build(&e.profile(&pool).unwrap()).unwrap_err(),
        "chain_full_config_position"
    );
}
/// Group proxies are part of every member's route: a VPN front would open one
/// session per member, a fixed-port endpoint front would bind its port once
/// per member. Both are refused when the pool is built, and a dynamic source
/// behind a VPN front offers no members.
#[test]
fn a_group_proxy_counts_in_member_eligibility_and_fixed_ports() {
    let (_d, mut e, ids) = setup();
    let pool = e.save_profile(draft(json!([ids[0], ids[1]]))).unwrap();
    assert!(e.build(&e.profile(&pool).unwrap()).is_ok());
    let vpn = endpoint(
        &mut e,
        "OpenVPN front",
        json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"username":"u","password":"p"}),
    );
    let fixed = endpoint(&mut e, "WG front", wireguard(Some(51000)));
    for (front, code) in [
        (&vpn, "selector_member_unsupported"),
        (&fixed, "selector_member_port_conflict"),
    ] {
        e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
            front: Some(front.clone()),
            landing: None,
        };
        assert_eq!(e.build(&e.profile(&pool).unwrap()).unwrap_err(), code);
    }
    let pool_profile = e.profile(&pool).unwrap();
    let member = e.profile(&ids[0]).unwrap();
    e.store.library.groups[0].proxy_chain.front = None;
    assert!(member_route_eligible(
        &e.store.library,
        &pool_profile,
        &member
    ));
    e.store.library.groups[0].proxy_chain.front = Some(vpn.clone());
    assert!(!member_route_eligible(
        &e.store.library,
        &pool_profile,
        &member
    ));
    assert!(
        member_eligible(&member, &e.store.library.profiles),
        "without its group the member alone stays eligible"
    );
}
/// The probe queue keeps one batch: a check started after the sweep completed
/// but before Connect must not erase the ranking this plan measured.
#[test]
fn a_later_batch_does_not_erase_a_completed_quick_sweep() {
    let (_d, mut e, ids) = setup();
    let mut plan = e.connection_measurements(AUTO_SELECT_ID).unwrap().unwrap();
    let pool = &plan.pools[0];
    let run = e.start_preflight_tests(pool, &pool.ids).unwrap();
    for _ in 0..pool.ids.len() {
        let probe = e.next_url_test(&run.id).unwrap();
        let latency = if probe.id == ids[1] { 5 } else { 50 };
        e.finish_url_test(&run.id, &probe.id, Ok(latency));
    }
    assert!(!e
        .complete_connection_measurements(&mut plan, Some(&run.id))
        .unwrap());
    let later = e
        .start_url_tests(probes::Options {
            ids: vec![ids[0].clone()],
            url: "https://example.test/later".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    assert_ne!(e.snapshot().url_tests.unwrap().id, run.id);
    e.cancel_url_test_batch(&later.id);
    let library = e.ranked_connection_library(&plan).unwrap();
    let ranked = library
        .profiles
        .iter()
        .find(|p| p.id == AUTO_SELECT_ID)
        .unwrap();
    assert_eq!(ranked.config["members"][0], json!(ids[1]));
}
/// A pool created in the editor carries the quick pool's `reuse_ttl` default;
/// it is Thronium's own setting and never reaches the Core outbound.
#[test]
fn an_editor_seeded_reuse_ttl_is_not_sent_to_the_core() {
    let (_d, mut e, ids) = setup();
    let mut d = draft(json!([ids[0], ids[1]]));
    d.config["reuse_ttl"] = json!("30m");
    let pool = e.save_profile(d).unwrap();
    let request = e.build(&e.profile(&pool).unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let group = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "auto-selector")
        .unwrap();
    assert!(group.get("reuse_ttl").is_none());
    assert_eq!(e.profile(&pool).unwrap().config["reuse_ttl"], "30m");
}
