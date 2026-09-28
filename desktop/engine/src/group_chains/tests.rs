use super::*;
use crate::{subscriptions::GroupDraft, Engine, ProfileDraft};
use std::path::Path;
fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing")).unwrap();
    e.store.library.groups.push(crate::store::Group {
        id: "g".into(),
        name: "Group".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: GroupChain {
            front: Some("front".into()),
            landing: Some("landing".into()),
        },
    });
    for (i, id) in ["front", "server", "landing", "other"].iter().enumerate() {
        e.store.library.profiles.push(Profile { vpn_policy: None,id:id.to_string(),name:id.to_string(),group_id:if *id == "server" {"g"}else{"personal"}.into(),kind:ProfileKind::SingBoxOutbound,favorite:false,config:json!({"type":"socks","server":"127.0.0.1","server_port":1080+i,"password":"secret"})});
    }
    e.store.commit(e.store.library.clone()).unwrap();
    (dir, e)
}
fn compile(e: &Engine, id: &str) -> (Library, Profile) {
    let source = e.profile(id).unwrap();
    let (mut l, mut p) = crate::vless::library(&e.store.library, &source).unwrap();
    prepare(
        &mut l,
        &mut p,
        &crate::vless::roots(&e.store.library, &source).unwrap(),
    )
    .unwrap();
    (l, p)
}
fn ports(l: &Library, p: &Profile) -> Vec<u64> {
    chains::flatten(p, &l.profiles)
        .unwrap()
        .iter()
        .map(|p| p.config["server_port"].as_u64().unwrap())
        .collect()
}
fn draft(p: Profile) -> ProfileDraft {
    serde_json::from_value(json!(p)).unwrap()
}
fn group(value: Value) -> GroupDraft {
    serde_json::from_value(value).unwrap()
}

#[test]
fn front_server_landing_order_is_frozen_without_mutating_source() {
    let (_d, e) = setup();
    let before = json!(e.store.library);
    let (l, p) = compile(&e, "server");
    assert_eq!(ports(&l, &p), [1080, 1081, 1082]);
    let request = e.build(&e.profile("server").unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let out = core["outbounds"].as_array().unwrap();
    assert_eq!(
        out.iter().find(|p| p["tag"] == "proxy").unwrap()["server_port"],
        1082
    );
    assert_eq!(
        out.iter().find(|p| p["tag"] == "proxy").unwrap()["detour"],
        "thronium-chain-proxy-1"
    );
    assert_eq!(
        out.iter()
            .find(|p| p["tag"] == "thronium-chain-proxy-1")
            .unwrap()["server_port"],
        1081
    );
    assert!(out
        .iter()
        .find(|p| p["tag"] == "thronium-chain-proxy-0")
        .unwrap()
        .get("detour")
        .is_none());
    assert_eq!(json!(e.store.library), before);
}
#[test]
fn nested_chain_and_routing_roots_do_not_reapply_hop_groups() {
    let (_d, mut e) = setup();
    e.store.library.groups[0].proxy_chain.front = Some("other".into());
    let mut p = e.profile("server").unwrap();
    p.kind = ProfileKind::Chain;
    p.config = json!({"type":"chain","hops":["front","landing"]});
    e.store.library.profiles[1] = p;
    e.store.library.routing.profiles[0].route["final"] = json!("profile:front");
    let (l, p) = compile(&e, "server");
    assert_eq!(ports(&l, &p), [1080, 1080, 1082, 1082]);
    assert_eq!(
        ports(&l, l.profiles.iter().find(|p| p.id == "front").unwrap()),
        [1083, 1080]
    );
    assert!(e.routing_uses("other"));
}
#[test]
fn unsaved_profile_configuration_is_used_with_group_hops() {
    let (_d, e) = setup();
    let mut p = e.profile("server").unwrap();
    p.config["server_port"] = json!(9999);
    let mut l = e.store.library.clone();
    let roots = HashSet::from([p.id.clone()]);
    prepare(&mut l, &mut p, &roots).unwrap();
    assert_eq!(ports(&l, &p), [1080, 9999, 1082]);
    assert_eq!(e.profile("server").unwrap().config["server_port"], 1081);
    p = e.profile("server").unwrap();
    p.id = "new".into();
    p.config["server_port"] = json!(9998);
    let roots = HashSet::from([p.id.clone()]);
    prepare(&mut l, &mut p, &roots).unwrap();
    assert_eq!(ports(&l, &p), [1080, 9998, 1082]);
}
#[test]
fn selectors_wrap_each_raw_member_with_owner_policy_and_keep_pin_ids() {
    let (_d, mut e) = setup();
    let mut p = e.profile("server").unwrap();
    p.kind = ProfileKind::AutoSelector;
    p.config = json!({"type":"auto-selector","members":["front","other"],"pinned_profile":"other"});
    e.store.library.profiles[1] = p;
    e.store.library.groups[0].proxy_chain.front = Some("landing".into());
    e.store.library.routing.profiles[0].route["final"] = json!("profile:front");
    let (l, p) = compile(&e, "server");
    for (id, expected) in [
        ("front", vec![1080, 1080, 1082]),
        ("other", vec![1080, 1083, 1082]),
    ] {
        let chain = Profile {
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":p.config[MEMBER_HOPS][id]}),
            ..p.clone()
        };
        assert_eq!(ports(&l, &chain), expected);
    }
    assert_eq!(
        crate::auto_selector::validate(&p, &l.profiles).unwrap_err(),
        "selector_generated_fields"
    );
    let request = crate::auto_selector::build(&p, &l.profiles, 2080).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let selector = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["tag"] == "proxy")
        .unwrap();
    assert_eq!(
        selector["pinned"],
        crate::auto_selector::member_tag("proxy", "other")
    );
    assert!(!core.to_string().contains(MEMBER_HOPS));
    let mut persisted = e.profile("server").unwrap();
    persisted.config[MEMBER_HOPS] = json!({});
    assert!(crate::auto_selector::validate(&persisted, &e.store.library.profiles).is_err());
}
#[test]
fn legacy_defaults_preserve_settings_on_rename_and_explicit_clear_persists() {
    let (d, mut e) = setup();
    let before = e.group("g").unwrap().proxy_chain;
    e.save_group(group(json!({"id":"g","name":"Renamed"})))
        .unwrap();
    assert_eq!(e.group("g").unwrap().proxy_chain, before);
    e.save_group(group(json!({"id":"g","name":"Renamed","proxyChain":{}})))
        .unwrap();
    drop(e);
    let e = Engine::open(d.path(), Path::new("missing")).unwrap();
    assert!(!e.group("g").unwrap().proxy_chain.enabled());
    let mut old = json!(e.store.library);
    for g in old["groups"].as_array_mut().unwrap() {
        g.as_object_mut().unwrap().remove("proxyChain");
    }
    let library: Library = serde_json::from_value(old).unwrap();
    assert!(library.groups.iter().all(|g| !g.proxy_chain.enabled()));
}
#[test]
fn missing_or_unsupported_group_references_fail_atomically() {
    let (d, mut e) = setup();
    let before = std::fs::read(d.path().join("library.json")).unwrap();
    for id in ["", "missing"] {
        assert_eq!(
            e.save_group(group(
                json!({"id":"g","name":"Changed","proxyChain":{"front":id}})
            ))
            .unwrap_err(),
            "group_chain_profile_missing"
        );
    }
    let mut p = e.profile("other").unwrap();
    p.kind = ProfileKind::XrayConfig;
    p.config = json!({"outbounds":[]});
    e.store.library.profiles[3] = p;
    // A complete Xray configuration is the device-side hop: front only, never landing.
    assert_eq!(
        e.save_group(group(
            json!({"id":"g","name":"Changed","proxyChain":{"landing":"other"}})
        ))
        .unwrap_err(),
        "group_chain_hop_unsupported"
    );
    assert_eq!(
        std::fs::read(d.path().join("library.json")).unwrap(),
        before
    );
    assert!(serde_json::from_value::<GroupDraft>(
        json!({"name":"bad","proxyChain":{"typo":"front"}})
    )
    .is_err());
}
#[test]
fn complete_xray_member_without_front_runs_as_its_own_instance_before_the_landing_proxy() {
    let (_d, mut e) = setup();
    e.save_group(group(
        json!({"id":"g","name":"Group","proxyChain":{"landing":"landing"}}),
    ))
    .unwrap();
    let mut p = e.profile("server").unwrap();
    p.kind = ProfileKind::XrayConfig;
    p.config = json!({"inbounds":[{"tag":"user-in","protocol":"socks","port":1}],"outbounds":[{"tag":"exit","protocol":"freedom"}]});
    let request = e.build(&p).unwrap();
    assert_eq!(request.xray_full_configs.len(), 1);
    let instance: Value = serde_json::from_str(&request.xray_full_configs[0]).unwrap();
    assert_eq!(instance["inbounds"][0]["tag"], "user-in");
    assert_eq!(instance["outbounds"], p.config["outbounds"]);
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let out = core["outbounds"].as_array().unwrap();
    let exit = out.iter().find(|o| o["tag"] == "proxy").unwrap();
    assert_eq!(
        exit["server_port"], 1082,
        "the landing proxy stays the exit"
    );
    assert_eq!(exit["detour"], "thronium-chain-proxy-0");
    assert_eq!(
        out.iter()
            .find(|o| o["tag"] == "thronium-chain-proxy-0")
            .unwrap()["server_port"],
        instance["inbounds"][0]["port"]
    );
}
#[test]
fn wireguard_front_and_landing_proxies_compile_as_endpoints_around_the_server() {
    let (_d, mut e) = setup();
    let wg = |port: u16| {
        json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.177.43.2/32"],
        "peers":[{"address":"127.0.0.1","port":port,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]})
    };
    e.store.library.profiles[0].config = wg(51820);
    e.store.library.profiles[2].config = wg(51821);
    let request = e.build(&e.profile("server").unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let endpoints = core["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    let front = endpoints
        .iter()
        .find(|p| p["tag"] == "thronium-chain-proxy-0")
        .unwrap();
    let landing = endpoints.iter().find(|p| p["tag"] == "proxy").unwrap();
    assert!(front.get("detour").is_none());
    assert_eq!(landing["detour"], "thronium-chain-proxy-1");
    assert_eq!(landing["peers"][0]["port"], 51821);
    let server = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["tag"] == "thronium-chain-proxy-1")
        .unwrap();
    assert_eq!(server["detour"], "thronium-chain-proxy-0");
    assert_eq!(core["route"]["final"], "proxy");
}
#[test]
fn wrapped_full_config_endpoint_and_oversized_chain_fail_before_core_start() {
    let (_d, mut e) = setup();
    for (kind, config, code) in [
        // Behind a front proxy the complete configuration is no longer the first hop.
        (
            ProfileKind::XrayConfig,
            json!({"outbounds":[]}),
            "chain_full_config_position",
        ),
        // A host-owned interface is refused with its own code, before the wrapper.
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"openvpn-client","system":true}),
            "chain_endpoint_context_unsupported",
        ),
    ] {
        let mut p = e.profile("server").unwrap();
        p.kind = kind;
        p.config = config;
        assert_eq!(e.build(&p).unwrap_err(), code);
    }
    e.store.library.profiles[1].kind = ProfileKind::Chain;
    e.store.library.profiles[1].config = json!({"type":"chain","hops":vec!["front";16]});
    assert_eq!(
        e.build(&e.profile("server").unwrap()).unwrap_err(),
        "chain_too_long"
    );
    // A wrapped chain keeps its own structural code; only hop kinds become a group refusal.
    e.store.library.profiles[3].kind = ProfileKind::XrayConfig;
    e.store.library.profiles[3].config = json!({"outbounds":[]});
    for (hops, code) in [
        (json!(["front", "other"]), "chain_full_config_position"),
        (json!(["other", "other"]), "chain_full_config_limit"),
    ] {
        e.store.library.profiles[1].config = json!({"type":"chain","hops":hops});
        assert_eq!(e.build(&e.profile("server").unwrap()).unwrap_err(), code);
    }
    e.store.library.profiles[3].kind = ProfileKind::SingBoxConfig;
    e.store.library.profiles[1].config = json!({"type":"chain","hops":["other"]});
    assert_eq!(
        e.build(&e.profile("server").unwrap()).unwrap_err(),
        "group_chain_hop_unsupported"
    );
    // Without group proxies nothing is wrapped and the chain's own code passes through.
    let mut personal = e.profile("front").unwrap();
    personal.kind = ProfileKind::Chain;
    personal.config = json!({"type":"chain","hops":["other"]});
    assert_eq!(
        e.build(&personal).unwrap_err(),
        "chain_full_config_unsupported"
    );
}
#[test]
fn active_group_and_wrapper_dependencies_cannot_be_edited_or_deleted() {
    let (_d, mut e) = setup();
    assert_eq!(
        e.delete_profiles(vec!["front".into()]).unwrap_err(),
        "profile_used_in_group_chain"
    );
    e.running = Some("server".into());
    let before = json!(e.store.library);
    assert_eq!(
        e.save_profile(draft(e.profile("front").unwrap()))
            .unwrap_err(),
        "stop_before_editing"
    );
    assert_eq!(
        e.save_group(group(json!({"id":"g","name":"Group","proxyChain":{}})))
            .unwrap_err(),
        "stop_before_editing"
    );
    assert_eq!(
        e.delete_group("g", false).unwrap_err(),
        "stop_before_editing"
    );
    assert_eq!(json!(e.store.library), before);
    e.running = None;
    e.delete_group("g", true).unwrap();
    e.delete_profiles(vec!["front".into(), "landing".into()])
        .unwrap();
}
#[test]
fn captured_active_dependencies_survive_pending_routing_changes() {
    let (_d, mut e) = setup();
    let p = e.profile("server").unwrap();
    e.store.library.routing.profiles[0].route["final"] = json!("profile:other");
    e.active_connection = Some(crate::connection::ActiveConnection {
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
        id: p.id.clone(),
        profiles: crate::vless::relevant(&e.store.library, &p).unwrap(),
        groups: HashSet::from(["g".into(), "personal".into()]),
        request: e.build(&p).unwrap(),
        routing_revision: 0,
        system_port: None,
        tun: false,
    });
    e.store.library.routing.profiles[0].route["final"] = json!("proxy");
    assert!(e.running_uses("other"));
    assert!(e.running_group_uses("personal"));
}
#[test]
fn probe_cache_tracks_group_route_and_core_choices_but_ignores_names_and_hop_groups() {
    let (_d, mut e) = setup();
    e.store.library.preferences.ping.method = crate::probes::Method::Http;
    let p = e.profile("server").unwrap();
    let before = stamp(&e.store.library, &p);
    e.store.library.profiles[0].name = "Renamed".into();
    e.store.library.groups[0].proxy_chain.front = Some("other".into());
    assert_eq!(stamp(&e.store.library, &p), before);
    let run = e
        .start_url_tests(crate::probes::Options {
            ids: vec![p.id.clone()],
            url: "http://localhost/test".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    assert!(e.next_url_test(&run.id).is_some());
    e.finish_url_test(&run.id, &p.id, Ok(12));
    assert!(e.measurement(&p).is_some());
    e.store
        .library
        .preferences
        .vless_overrides
        .insert("front".into(), crate::vless::Core::SingBox);
    assert!(e.measurement(&p).is_none());
    e.store.library.preferences.vless_overrides.clear();
    let run = e
        .start_url_tests(crate::probes::Options {
            ids: vec![p.id.clone()],
            url: "http://localhost/test".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    e.save_group(group(
        json!({"id":"g","name":"Group","proxyChain":{"front":"other"}}),
    ))
    .unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        crate::probes::Status::Stale
    );
}
#[test]
fn vless_override_on_group_hop_is_compiled_and_source_is_retained() {
    let (_d, mut e) = setup();
    e.store.library.profiles[0].config = json!({"type":"vless","server":"localhost","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"});
    e.store
        .library
        .preferences
        .vless_overrides
        .insert("front".into(), crate::vless::Core::Xray);
    let (l, p) = compile(&e, "server");
    let hops = chains::flatten(&p, &l.profiles).unwrap();
    assert_eq!(hops[0].kind, ProfileKind::XrayOutbound);
    assert_eq!(hops[1].kind, ProfileKind::SingBoxOutbound);
    assert_eq!(
        e.build(&e.profile("server").unwrap()).unwrap().need_xray,
        Some(true)
    );
    assert_eq!(
        e.profile("front").unwrap().kind,
        ProfileKind::SingBoxOutbound
    );
}
#[test]
fn backups_preserve_group_policy_and_validate_dangling_references() {
    let (_d, e) = setup();
    let serialized = json!(e.store.library);
    let restored: Library = serde_json::from_value(serialized.clone()).unwrap();
    crate::store::validate_library(&restored).unwrap();
    assert_eq!(
        restored.groups[1].proxy_chain,
        e.store.library.groups[1].proxy_chain
    );
    let mut broken = restored;
    broken.profiles.retain(|p| p.id != "front");
    assert_eq!(
        crate::store::validate_library(&broken).unwrap_err(),
        "group_chain_profile_missing"
    );
    let export: Value = serde_json::from_str(
        &e.export_profiles(vec!["server".into()], crate::exports::Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(export["profiles"].as_array().unwrap().len(), 1);
    assert!(export["profiles"][0].get("proxyChain").is_none());
}

#[tokio::test]
async fn routing_validation_checks_wrapped_targets_before_contacting_the_core() {
    let (_d, mut e) = setup();
    e.store.library.profiles[1].kind = ProfileKind::SingBoxConfig;
    e.store.library.profiles[1].config = json!({"outbounds":[{"type":"direct"}]});
    let mut route = e.routing().profiles[0].clone();
    route.route["final"] = json!("profile:server");
    assert_eq!(
        e.check_routing(route).await.unwrap_err(),
        "group_chain_hop_unsupported"
    );
}
#[test]
fn backup_restore_and_undo_include_group_proxies() {
    let (_d, e) = setup();
    let dir = tempfile::tempdir().unwrap();
    let mut target = Engine::open(dir.path(), Path::new("missing")).unwrap();
    let initial = json!(target.store.library);
    let backup = e.export_backup().unwrap();
    let preview = target.preview_backup(&backup).unwrap();
    target.restore_backup(&preview.token).unwrap();
    assert_eq!(json!(target.store.library), json!(e.store.library));
    let undo = target.preview_previous_backup().unwrap();
    target.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(target.store.library), initial);
}
#[test]
fn vpn_front_and_landing_proxies_compile_as_endpoints_around_the_server() {
    let (_d, mut e) = setup();
    e.store.library.profiles[0].config = json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"network":"udp",
        "username":"fixture-user","password":"fixture-password"});
    e.store.library.profiles[2].config = json!({"type":"openconnect","server":"vpn.fixture.invalid","username":"fixture-user","password":"fixture-password"});
    let request = e.build(&e.profile("server").unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let endpoints = core["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    let front = endpoints
        .iter()
        .find(|p| p["tag"] == "thronium-chain-proxy-0")
        .unwrap();
    let landing = endpoints.iter().find(|p| p["tag"] == "proxy").unwrap();
    assert_eq!(front["type"], "openvpn-client");
    assert!(front.get("detour").is_none());
    assert_eq!(landing["type"], "openconnect");
    assert_eq!(landing["detour"], "thronium-chain-proxy-1");
    let server = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["tag"] == "thronium-chain-proxy-1")
        .unwrap();
    assert_eq!(server["detour"], "thronium-chain-proxy-0");
    // The VPN status session polls both hops by their emitted tags.
    let session = crate::vpn_auth::Session::start(&request, true, None);
    let mut tags: Vec<_> = session
        .snapshot()
        .endpoints
        .iter()
        .map(|e| e.tag.clone())
        .collect();
    tags.sort();
    assert_eq!(tags, ["proxy", "thronium-chain-proxy-0"]);
}
