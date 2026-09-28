use super::*;
use crate::{probes::Options, vpn_auth::otp, Engine, ProfileDraft};
use std::path::Path;
fn hop(id: &str, xray: bool) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        name: id.into(),
        group_id: "personal".into(),
        favorite: false,
        kind: if xray {
            ProfileKind::XrayOutbound
        } else {
            ProfileKind::SingBoxOutbound
        },
        config: if xray {
            json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":1080},"streamSettings":{"network":"raw","sockopt":{"tcpFastOpen":true}}})
        } else {
            json!({"type":"socks","server":"127.0.0.1","server_port":1080,"password":"fixture-secret","future":{"list":[1,2]}})
        },
    }
}
fn chain(id: &str, hops: &[&str]) -> Profile {
    Profile {
        kind: ProfileKind::Chain,
        config: json!({"type":"chain","hops":hops}),
        ..hop(id, false)
    }
}
fn draft(p: &Profile) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: p.name.clone(),
        group_id: p.group_id.clone(),
        kind: p.kind,
        config: p.config.clone(),
    }
}
fn setup() -> (tempfile::TempDir, Engine, Vec<String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing")).unwrap();
    let ids = vec![
        e.save_profile(draft(&hop("A", false))).unwrap(),
        e.save_profile(draft(&hop("B", true))).unwrap(),
    ];
    let c = e
        .save_profile(draft(&chain("Chain", &[&ids[0], &ids[1]])))
        .unwrap();
    (dir, e, ids, c)
}
#[test]
fn nested_chains_keep_connection_order_and_reject_cycles_missing_members_and_unsupported_hops() {
    let a = hop("a", false);
    let b = hop("b", true);
    let inner = chain("inner", &["a", "b"]);
    let outer = chain("outer", &["inner", "a"]);
    let profiles = vec![a, b, inner, outer.clone()];
    assert_eq!(
        flatten(&outer, &profiles)
            .unwrap()
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b", "a"]
    );
    let cycle = chain("inner", &["outer"]);
    let cyclic = vec![
        profiles[0].clone(),
        profiles[1].clone(),
        cycle,
        outer.clone(),
    ];
    assert_eq!(flatten(&outer, &cyclic).err().unwrap(), "chain_cycle");
    assert_eq!(
        flatten(&chain("bad", &["missing"]), &profiles)
            .err()
            .unwrap(),
        "chain_profile_missing"
    );
    assert!(flatten(&chain("empty", &[]), &profiles).is_err());
    let full = Profile {
        kind: ProfileKind::XrayConfig,
        ..hop("full", true)
    };
    let sing_full = Profile {
        kind: ProfileKind::SingBoxConfig,
        ..hop("sing-full", false)
    };
    let a = hop("a", false);
    let with_full = vec![
        full.clone(),
        sing_full,
        a.clone(),
        chain("first", &["full", "a"]),
        chain("later", &["a", "full"]),
        chain("twice", &["full", "first"]),
        chain("box", &["sing-full"]),
    ];
    assert_eq!(
        flatten(&chain("first", &["full", "a"]), &with_full)
            .unwrap()
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        vec!["full", "a"]
    );
    assert_eq!(
        flatten(&chain("later", &["a", "full"]), &with_full)
            .err()
            .unwrap(),
        "chain_full_config_position"
    );
    assert_eq!(
        flatten(&chain("twice", &["full", "first"]), &with_full)
            .err()
            .unwrap(),
        "chain_full_config_limit"
    );
    assert_eq!(
        flatten(&chain("box", &["sing-full"]), &with_full)
            .err()
            .unwrap(),
        "chain_full_config_unsupported"
    );
    let long = chain("long", &["inner"; 16]);
    assert_eq!(flatten(&long, &profiles).err().unwrap(), "chain_too_long");
}
#[test]
fn singbox_hops_point_toward_the_entry_without_mutating_saved_fields() {
    let profiles = vec![hop("a", false), hop("b", false)];
    let original = serde_json::to_value(&profiles).unwrap();
    let request = build(&chain("c", &["a", "b"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let out = core["outbounds"].as_array().unwrap();
    let exit = out.iter().find(|o| o["tag"] == "proxy").unwrap();
    assert_eq!(exit["detour"], "thronium-chain-proxy-0");
    assert_eq!(exit["future"], profiles[1].config["future"]);
    assert!(out
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-0")
        .unwrap()
        .get("detour")
        .is_none());
    assert_eq!(request.need_xray, Some(false));
    assert_eq!(serde_json::to_value(&profiles).unwrap(), original);
}
#[test]
fn alternating_cores_get_authenticated_loopback_bridges_and_internal_routes_before_global_rules() {
    let profiles = vec![
        hop("a", false),
        hop("b", true),
        hop("c", false),
        hop("d", true),
    ];
    let c = chain("chain", &["a", "b", "c", "d"]);
    let mut request = build(&c, &profiles, 2080).unwrap();
    let mut route = crate::routing::Routing::default().profiles[0].clone();
    route.mode = "direct".into();
    crate::routing::apply(&mut request, &c, &route, &profiles).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let xray: Value = serde_json::from_str(request.xray_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["route"]["final"], "direct");
    let rules = core["route"]["rules"].as_array().unwrap();
    // Internal bridge routes come first, then the route's own sniff.
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[2], crate::routing::builtin::sniff());
    let mut ports = HashSet::new();
    for i in core["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["tag"] != "mixed-in")
    {
        assert_eq!(i["listen"], "127.0.0.1");
        assert!(!i["users"][0]["password"].as_str().unwrap().is_empty());
        assert!(ports.insert(i["listen_port"].as_u64().unwrap()));
    }
    for i in xray["inbounds"].as_array().unwrap() {
        assert_eq!(i["listen"], "127.0.0.1");
        assert_eq!(i["settings"]["auth"], "password");
        assert!(ports.insert(i["port"].as_u64().unwrap()));
    }
    assert_eq!(ports.len(), 4);
    assert_eq!(request.need_xray, Some(true));
    assert!(xray["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["tag"].as_str().unwrap().ends_with("-1")
            || o["tag"].as_str().unwrap().ends_with("-3"))
        .any(|o| o["streamSettings"]["sockopt"]["tcpFastOpen"] == true));
}
#[test]
fn live_members_and_external_chain_references_are_protected_atomically() {
    let (_dir, mut e, ids, c) = setup();
    let before = serde_json::to_value(&e.store.library).unwrap();
    assert_eq!(
        e.delete_profiles(vec![ids[0].clone(), ids[1].clone()])
            .unwrap_err(),
        "profile_used_in_chain"
    );
    e.running = Some(c.clone());
    assert_eq!(
        e.move_profiles(vec![ids[0].clone()], "personal")
            .unwrap_err(),
        "stop_before_editing"
    );
    let mut update = draft(&e.profile(&ids[0]).unwrap());
    update.id = Some(ids[0].clone());
    update.name = "Changed".into();
    assert_eq!(e.save_profile(update).unwrap_err(), "stop_before_editing");
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    e.running = None;
    let mut delete = ids;
    delete.push(c);
    e.delete_profiles(delete).unwrap();
    assert!(e.store.library.profiles.is_empty());
}
#[test]
fn changing_nested_members_invalidates_queued_probes_and_cached_latency() {
    let (_dir, mut e, ids, inner) = setup();
    e.store.library.preferences.ping.method = crate::probes::Method::Http;
    let c = e
        .save_profile(draft(&chain("Outer", &[&inner, &ids[0]])))
        .unwrap();
    let run = e
        .start_url_tests(Options {
            ids: vec![c.clone()],
            url: "http://127.0.0.1/".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    assert!(e.next_url_test(&run.id).is_some());
    e.finish_url_test(&run.id, &c, Ok(12));
    let p = e.profile(&c).unwrap();
    assert!(e.measurement(&p).is_some());
    let mut update = draft(&e.profile(&ids[0]).unwrap());
    update.id = Some(ids[0].clone());
    update.config["server_port"] = json!(1081);
    e.save_profile(update).unwrap();
    assert!(e.measurement(&p).is_none());
    let run = e
        .start_url_tests(Options {
            ids: vec![c.clone()],
            url: "http://127.0.0.1/".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    let mut update = draft(&e.profile(&ids[1]).unwrap());
    update.id = Some(ids[1].clone());
    update.config["settings"]["port"] = json!(1082);
    e.save_profile(update).unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(
        e.url_tests_snapshot().unwrap().entries[0].status,
        crate::probes::Status::Stale
    );
}

#[test]
fn portable_chain_export_includes_dependencies_and_reimports_rewritten_ids_atomically() {
    let (_dir, mut source, ids, inner) = setup();
    let mut outer_profile = chain("Outer", &[&ids[0], &inner]);
    outer_profile.config["pinned_profile"] = json!("opaque extension, not a pool reference");
    let outer = source.save_profile(draft(&outer_profile)).unwrap();
    let exported = source
        .export_profiles(vec![outer.clone()], crate::exports::Format::Profiles)
        .unwrap();
    assert!(!exported.contains(&outer));
    assert!(!exported.contains(&ids[0]));
    let mut value: Value = serde_json::from_str(&exported).unwrap();
    assert_eq!(value["profiles"].as_array().unwrap().len(), 4);
    for p in value["profiles"].as_array_mut().unwrap() {
        p["groupId"] = json!("personal");
    }
    let dir = tempfile::tempdir().unwrap();
    let mut target = Engine::open(dir.path(), Path::new("missing")).unwrap();
    let drafts = serde_json::from_value(value["profiles"].clone()).unwrap();
    let added = target.import_referenced_profiles(drafts).unwrap();
    let c = target
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.name == "Outer")
        .unwrap();
    let resolved = flatten(c, &target.store.library.profiles).unwrap();
    assert_eq!(
        c.config["pinned_profile"],
        outer_profile.config["pinned_profile"]
    );
    assert_eq!(
        resolved.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        vec!["A", "A", "B"]
    );
    assert!(resolved.iter().all(|p| added.contains(&p.id)));
    assert!(source
        .export_profiles(vec![outer], crate::exports::Format::Configurations)
        .is_err());
    let before = serde_json::to_value(&target.store.library).unwrap();
    let mut missing = value["profiles"].as_array().unwrap().clone();
    missing.remove(0);
    assert_eq!(
        target
            .import_referenced_profiles(serde_json::from_value(json!(missing)).unwrap())
            .unwrap_err(),
        "invalid_import_references"
    );
    let mut duplicate = value["profiles"].clone();
    duplicate[1]["reference"] = duplicate[0]["reference"].clone();
    assert!(target
        .import_referenced_profiles(serde_json::from_value(duplicate).unwrap())
        .is_err());
    assert_eq!(serde_json::to_value(&target.store.library).unwrap(), before);
}

#[test]
fn subscriptions_retain_removed_chain_members_and_do_not_update_live_hops() {
    use crate::subscriptions::{Download, GroupDraft, Settings};
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing")).unwrap();
    let g = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: None,
            name: "Source".into(),
            subscription: Some(Settings {
                name_rules: Default::default(),
                inherit_defaults: Some(false),
                allow_insecure: false,
                timeout_seconds: 30,
                url: "https://example.test/sub".into(),
                headers: Default::default(),
                user_agent: "test".into(),
                via_proxy: false,
                use_provider_routing: false,
                interval_minutes: 0,
            }),
        })
        .unwrap();
    fn update(e: &mut Engine, g: &str, p: ProfileDraft) -> Vec<crate::subscriptions::Change> {
        let request = e.subscription_request(g).unwrap();
        let response = e
            .subscription_downloaded(
                request,
                Download {
                    metadata: Default::default(),
                    body: "fixture".into(),
                    usage: None,
                },
            )
            .unwrap();
        let token = response["ticket"].as_str().unwrap();
        e.preview_subscription(token, vec![p]).unwrap();
        e.apply_subscription(token).unwrap()
    }
    let mut a = draft(&hop("A", false));
    a.group_id = g.clone();
    let first = update(&mut e, &g, a);
    let id = first[0].id.clone();
    let c = e.save_profile(draft(&chain("Chain", &[&id]))).unwrap();
    let mut other = draft(&hop("Other", false));
    other.group_id = g.clone();
    other.config["server_port"] = json!(1081);
    let changes = update(&mut e, &g, other);
    assert!(changes
        .iter()
        .any(|c| c.id == id && c.reason.as_deref() == Some("chain")));
    assert!(e.profile(&id).is_ok());
    e.running = Some(c);
    let mut changed = draft(&e.profile(&id).unwrap());
    changed.config["password"] = json!("changed");
    let changes = update(&mut e, &g, changed);
    assert!(changes
        .iter()
        .any(|c| c.id == id && c.reason.as_deref() == Some("running")));
    assert_eq!(e.profile(&id).unwrap().config["password"], "fixture-secret");
}

fn full_config(id: &str) -> Profile {
    Profile {
        kind: ProfileKind::XrayConfig,
        config: json!({
            "inbounds":[{"tag":"user-in","protocol":"socks","port":11080,"listen":"127.0.0.1","sniffing":{"enabled":true}}],
            "outbounds":[{"tag":"exit","protocol":"socks","settings":{"address":"127.0.0.1","port":1080}}],
            "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]},
            "dns":{"servers":["1.1.1.1"]}
        }),
        ..hop(id, true)
    }
}
fn full_instance(request: &LoadConfigReq) -> Value {
    assert_eq!(request.xray_full_configs.len(), 1);
    assert_eq!(request.xray_full_idle_seconds, Some(0));
    serde_json::from_str(&request.xray_full_configs[0]).unwrap()
}
#[test]
fn complete_xray_first_hop_runs_as_its_own_instance_behind_one_managed_inbound() {
    let profiles = vec![full_config("f"), hop("s", false), hop("x", true)];
    let original = serde_json::to_value(&profiles).unwrap();
    // Alone: sing-box dials the instance directly as the exit.
    let alone = build(&chain("alone", &["f"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(alone.core_config.as_deref().unwrap()).unwrap();
    let exit = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    let instance = full_instance(&alone);
    let inbound = &instance["inbounds"][0];
    assert_eq!(exit["type"], "socks");
    assert_eq!(exit["server_port"], inbound["port"]);
    assert_eq!(exit["username"], inbound["settings"]["accounts"][0]["user"]);
    assert_eq!(inbound["tag"], "user-in", "the user's rules keep matching");
    assert_eq!(inbound["sniffing"]["enabled"], true);
    assert_eq!(instance["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(instance["outbounds"], profiles[0].config["outbounds"]);
    assert_eq!(instance["routing"], profiles[0].config["routing"]);
    assert_eq!(instance["dns"], profiles[0].config["dns"]);
    assert_eq!(alone.need_xray, Some(false));
    // Before a sing-box hop: the hop detours to the dialing outbound.
    let through_sing = build(&chain("fs", &["f", "s"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(through_sing.core_config.as_deref().unwrap()).unwrap();
    let out = core["outbounds"].as_array().unwrap();
    let exit = out.iter().find(|o| o["tag"] == "proxy").unwrap();
    assert_eq!(exit["detour"], "thronium-chain-proxy-0");
    let dialer = out
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-0")
        .unwrap();
    assert_eq!(dialer["type"], "socks");
    assert_eq!(
        dialer["server_port"],
        full_instance(&through_sing)["inbounds"][0]["port"]
    );
    assert_eq!(through_sing.need_xray, Some(false));
    // Before an Xray hop: the main Xray instance owns the dialing outbound.
    let through_xray = build(&chain("fx", &["f", "x"]), &profiles, 2080).unwrap();
    let xray: Value = serde_json::from_str(through_xray.xray_config.as_deref().unwrap()).unwrap();
    let outbounds = xray["outbounds"].as_array().unwrap();
    let dialer = outbounds
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-0")
        .unwrap();
    assert_eq!(dialer["protocol"], "socks");
    assert_eq!(
        dialer["settings"]["port"],
        full_instance(&through_xray)["inbounds"][0]["port"]
    );
    let hop = outbounds
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-1")
        .unwrap();
    assert_eq!(
        hop["streamSettings"]["sockopt"]["dialerProxy"],
        "thronium-chain-proxy-0"
    );
    assert_eq!(through_xray.need_xray, Some(true));
    assert_eq!(serde_json::to_value(&profiles).unwrap(), original);
}
#[test]
fn complete_xray_hop_keeps_the_primary_validation_and_pins_tag_conflicts() {
    let mut foreign = full_config("f");
    foreign.config["inbounds"] = json!([{"tag":"tun-in","protocol":"tun"}]);
    assert_eq!(
        build(&chain("c", &["f"]), &[foreign], 2080).unwrap_err(),
        "xray_client_inbounds_unsupported"
    );
    let mut rules = full_config("f");
    rules.config["routing"]["rules"] =
        json!([{"type":"field","inboundTag":["other-in"],"outboundTag":"exit"}]);
    assert_eq!(
        build(&chain("c", &["f"]), &[rules], 2080).unwrap_err(),
        "xray_client_inbound_rules_unsupported"
    );
    let mut conflicting = hop("s", false);
    conflicting.config["type"] = json!("direct");
    let mut core = json!({"outbounds":[{"tag":"proxy","type":"direct"}]});
    let mut xray = json!({"inbounds":[],"outbounds":[]});
    assert_eq!(
        append(
            &chain("c", &["s"]),
            &[conflicting],
            &mut core,
            &mut xray,
            "proxy",
            &mut otp::Build::default()
        )
        .unwrap_err(),
        "chain_tag_conflict"
    );
}
fn wireguard(id: &str) -> Profile {
    Profile {
        config: json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.177.43.2/32"],"mtu":1420,
            "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}],"amnezia_wg":{"jc":2}}),
        ..hop(id, false)
    }
}
#[test]
fn wireguard_hops_are_endpoints_that_detour_like_outbounds_in_any_position() {
    let profiles = vec![wireguard("w"), hop("s", false), hop("x", true)];
    let original = serde_json::to_value(&profiles).unwrap();
    // Exit hop: the endpoint carries the exit tag and dials through the previous hop.
    let exit = build(&chain("sw", &["s", "w"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(exit.core_config.as_deref().unwrap()).unwrap();
    let endpoint = &core["endpoints"][0];
    assert_eq!(endpoint["type"], "wireguard");
    assert_eq!(endpoint["tag"], "proxy");
    assert_eq!(endpoint["detour"], "thronium-chain-proxy-0");
    assert_eq!(endpoint["amnezia_wg"], profiles[0].config["amnezia_wg"]);
    assert!(core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["tag"] != "proxy"));
    assert_eq!(core["route"]["final"], "proxy");
    // Device-side hop: the next sing-box hop detours into the endpoint.
    let entry = build(&chain("ws", &["w", "s"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(entry.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["endpoints"][0]["tag"], "thronium-chain-proxy-0");
    assert!(core["endpoints"][0].get("detour").is_none());
    let proxy = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert_eq!(proxy["detour"], "thronium-chain-proxy-0");
    // Before an Xray hop the endpoint is reached through the usual loopback bridge.
    let mixed = build(&chain("wx", &["w", "x"]), &profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(mixed.core_config.as_deref().unwrap()).unwrap();
    let xray: Value = serde_json::from_str(mixed.xray_config.as_deref().unwrap()).unwrap();
    let rule = &core["route"]["rules"][0];
    assert_eq!(rule["outbound"], "thronium-chain-proxy-0");
    assert_eq!(rule["inbound"][0], "thronium-chain-proxy-bridge-1-in");
    let hop = xray["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-1")
        .unwrap();
    assert_eq!(
        hop["streamSettings"]["sockopt"]["dialerProxy"],
        "thronium-chain-proxy-bridge-1"
    );
    assert_eq!(mixed.need_xray, Some(true));
    assert_eq!(serde_json::to_value(&profiles).unwrap(), original);
}
#[test]
fn wireguard_hops_refuse_system_interfaces_and_fixed_ports_behind_other_hops() {
    let mut system = wireguard("w");
    system.config["system"] = json!(true);
    let s = hop("s", false);
    assert_eq!(
        flatten(&chain("c", &["w"]), &[system, s.clone()])
            .err()
            .unwrap(),
        "chain_endpoint_context_unsupported"
    );
    let mut fixed = wireguard("w");
    fixed.config["listen_port"] = json!(51000);
    let profiles = vec![fixed, s];
    assert!(flatten(&chain("first", &["w", "s"]), &profiles).is_ok());
    assert_eq!(
        flatten(&chain("later", &["s", "w"]), &profiles)
            .err()
            .unwrap(),
        "chain_endpoint_listen_port_unsupported"
    );
    let mut core = json!({"outbounds":[{"tag":"proxy","type":"direct"}]});
    let mut xray = json!({"inbounds":[],"outbounds":[]});
    assert_eq!(
        append(
            &chain("c", &["w"]),
            &[wireguard("w")],
            &mut core,
            &mut xray,
            "proxy",
            &mut otp::Build::default()
        )
        .unwrap_err(),
        "chain_tag_conflict",
        "endpoints and outbounds share one tag namespace"
    );
}
fn openvpn(id: &str) -> Profile {
    Profile {
        config: json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"network":"udp",
            "username":"fixture-user","password":"fixture-password","tls":{"server_name":"vpn.fixture.invalid"}}),
        ..hop(id, false)
    }
}
fn openconnect(id: &str) -> Profile {
    Profile {
        config: json!({"type":"openconnect","server":"vpn.fixture.invalid","username":"fixture-user","password":"fixture-password"}),
        ..hop(id, false)
    }
}
fn tailscale(id: &str) -> Profile {
    Profile {
        config: json!({"type":"tailscale","auth_key":"tskey-fixture","exit_node":"exit"}),
        ..hop(id, false)
    }
}
fn core_of(request: &LoadConfigReq) -> Value {
    serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap()
}
#[test]
fn vpn_hops_are_endpoints_that_detour_in_any_position_but_never_pool_members() {
    let profiles = vec![
        openvpn("v"),
        hop("s", false),
        hop("x", true),
        openconnect("o"),
        tailscale("t"),
    ];
    let original = serde_json::to_value(&profiles).unwrap();
    // Exit hop: the endpoint carries the exit tag and dials through the previous hop.
    let core = core_of(&build(&chain("sv", &["s", "v"]), &profiles, 2080).unwrap());
    let endpoint = &core["endpoints"][0];
    assert_eq!(endpoint["type"], "openvpn-client");
    assert_eq!(endpoint["tag"], "proxy");
    assert_eq!(endpoint["detour"], "thronium-chain-proxy-0");
    assert_eq!(endpoint["password"], "fixture-password");
    assert_eq!(core["route"]["final"], "proxy");
    // Device-side hop of every VPN type: the next hop detours into the endpoint.
    for (pattern, hops, kind) in [
        ("vs", ["v", "s"], "openvpn-client"),
        ("os", ["o", "s"], "openconnect"),
        ("ts", ["t", "s"], "tailscale"),
    ] {
        let core = core_of(&build(&chain(pattern, &hops), &profiles, 2080).unwrap());
        assert_eq!(core["endpoints"][0]["type"], kind, "{pattern}");
        assert_eq!(core["endpoints"][0]["tag"], "thronium-chain-proxy-0");
        assert!(core["endpoints"][0].get("detour").is_none());
        let proxy = core["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["detour"], "thronium-chain-proxy-0", "{pattern}");
    }
    // Several VPN endpoints in one chain, around an Xray hop reached over a bridge.
    let request = build(&chain("vxo", &["v", "x", "o"]), &profiles, 2080).unwrap();
    let core = core_of(&request);
    let endpoints = core["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0]["tag"], "thronium-chain-proxy-0");
    assert_eq!(endpoints[1]["tag"], "proxy");
    assert_eq!(endpoints[1]["type"], "openconnect");
    assert_eq!(endpoints[1]["detour"], "thronium-chain-proxy-bridge-2");
    assert_eq!(request.need_xray, Some(true));
    // Pools start every member's session at once: VPN endpoints stay out (Qt parity).
    assert!(!crate::auto_selector::member_eligible(
        &profiles[0],
        &profiles
    ));
    assert!(!crate::auto_selector::member_eligible(
        &chain("sv", &["s", "v"]),
        &profiles
    ));
    assert!(crate::auto_selector::member_eligible(
        &profiles[1],
        &profiles
    ));
    assert_eq!(serde_json::to_value(&profiles).unwrap(), original);
}
#[test]
fn vpn_hops_refuse_host_interfaces_and_fixed_local_ports_behind_other_hops() {
    let mut fixed = openconnect("o");
    fixed.config["dtls_local_port"] = json!(4443);
    let profiles = vec![fixed, hop("s", false)];
    assert!(flatten(&chain("first", &["o", "s"]), &profiles).is_ok());
    assert_eq!(
        flatten(&chain("later", &["s", "o"]), &profiles)
            .err()
            .unwrap(),
        "chain_endpoint_listen_port_unsupported"
    );
    let mut host = tailscale("t");
    host.config["system_interface"] = json!(true);
    assert_eq!(
        flatten(&chain("c", &["t"]), &[host]).err().unwrap(),
        "chain_endpoint_context_unsupported"
    );
    let mut host = openvpn("v");
    host.config["system"] = json!(true);
    assert_eq!(
        flatten(&chain("c", &["v"]), &[host]).err().unwrap(),
        "chain_endpoint_context_unsupported"
    );
}
/// Two complete Xray members of one pool listen in separate instances; each
/// earlier instance's port must stay reserved for the next member, although
/// only its loopback dialer shows it and its bind guard is gone.
#[test]
fn a_complete_xray_member_port_stays_reserved_for_the_next_member() {
    let full = Profile {
        kind: ProfileKind::XrayConfig,
        config: json!({"inbounds":[],"outbounds":[{"tag":"exit","protocol":"freedom","settings":{}}]}),
        ..hop("full", false)
    };
    let profiles = vec![full.clone()];
    for dial_from_xray in [false, true] {
        let mut core = json!({"outbounds":[]});
        let mut xray = json!({"outbounds":[]});
        let next = if dial_from_xray {
            vec![full.clone(), hop("after", true)]
        } else {
            vec![full.clone()]
        };
        let member = if dial_from_xray {
            Profile {
                kind: ProfileKind::Chain,
                config: json!({"type":"chain","hops":["full","after"]}),
                ..hop("member", false)
            }
        } else {
            full.clone()
        };
        let mut all = profiles.clone();
        all.extend(next);
        all.push(member.clone());
        let instances = append(
            &member,
            &all,
            &mut core,
            &mut xray,
            "member-a",
            &mut otp::Build::default(),
        )
        .unwrap();
        let port = instances[0]["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "thronium-in")
            .unwrap()["port"]
            .as_u64()
            .unwrap() as u16;
        assert!(
            reserved_ports(&core, &xray).contains(&port),
            "dialed from {}",
            if dial_from_xray { "Xray" } else { "sing-box" }
        );
    }
}
