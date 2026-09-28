//! Qt auxiliary endpoints and custom inbound tags: gate rules, tunnel DNS,
//! Qt's eligibility refusals and the endpoint-aware constraints they produce.
use super::tests::{code, fixture, n, plan, profiles, raw, route_col, rule, s, set};
use super::*;
use crate::{
    store::{Profile, ProfileKind},
    vpn_policy::Policy,
};
use sha2::Digest;

fn vpn(id: &str, kind: &str, tunnel_dns: bool) -> Profile {
    Profile {
        vpn_policy: Some(Policy {
            only_advertised_routes: true,
            use_tunnel_dns: tunnel_dns,
            block_outside_dns: false,
        }),
        id: id.into(),
        name: format!("Tunnel {id}"),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":kind,"server":"192.0.2.10","server_port":1194}),
        favorite: false,
    }
}
/// Profile 42 socks, 3 OpenVPN (tunnel DNS), 4 OpenConnect (no tunnel DNS),
/// 5 chain [42, 3], 6 chain [42], 7 chain [4, 3] — a VPN node inside a chain.
fn with_endpoints() -> ProfilePlan {
    let mut plan = profiles();
    plan.profiles.push(vpn("ovpn", "openvpn-client", true));
    plan.profiles.push(vpn("oc", "openconnect", false));
    let mut chain = plan.profiles[0].clone();
    chain.id = "chain".into();
    chain.kind = ProfileKind::Chain;
    chain.config = json!({"type":"chain","hops":["fixture-proxy","ovpn"]});
    plan.profiles.push(chain);
    let mut plain = plan.profiles[0].clone();
    plain.id = "plain-chain".into();
    plain.kind = ProfileKind::Chain;
    plain.config = json!({"type":"chain","hops":["fixture-proxy"]});
    plan.profiles.push(plain);
    let mut inner = plan.profiles[0].clone();
    inner.id = "inner-chain".into();
    inner.kind = ProfileKind::Chain;
    inner.config = json!({"type":"chain","hops":["oc","ovpn"]});
    plan.profiles.push(inner);
    plan.profile_ids.insert(3, "ovpn".into());
    plan.profile_ids.insert(4, "oc".into());
    plan.profile_ids.insert(5, "chain".into());
    plan.profile_ids.insert(6, "plain-chain".into());
    plan.profile_ids.insert(7, "inner-chain".into());
    plan
}
fn generated(source: &mut SourceArchive) {
    set(source, "use_dns_object", "false");
    set(source, "remote_dns", "https://8.8.8.8/dns-query");
    set(source, "direct_dns", "localhost");
}
fn convert_with(source: &SourceArchive, profiles: &ProfilePlan) -> RoutePlan {
    convert(source, Some(profiles))
        .unwrap_or_else(|e| panic!("{}", serde_json::to_string(&e).unwrap()))
}
fn codes_with(source: &SourceArchive, profiles: &ProfilePlan) -> Vec<String> {
    convert(source, Some(profiles))
        .err()
        .unwrap()
        .iter()
        .map(|i| i.code.clone())
        .collect()
}
fn gate(id: &str) -> Value {
    let tag = format!("profile:{id}");
    json!({"preferred_by":[tag],"action":"route","outbound":tag})
}

#[test]
fn positioned_gate_keeps_its_place_and_missing_gates_follow_the_user_rules() {
    let mut source = fixture();
    source.parts.profiles = true;
    generated(&mut source);
    route_col(&mut source, "endpoint_profile_ids", s("[3,4]"));
    route_col(&mut source, "default_outbound_id", n(-3));
    rule(
        &mut source,
        13,
        0,
        &[("outbound_id", n(3)), ("name", s("Tunnel route prefer"))],
    );
    rule(
        &mut source,
        1,
        4,
        &[("domain_json", s("[\"proxy.invalid\"]"))],
    );
    let p = convert_with(&source, &with_endpoints());
    let preset = &p.presets[0];
    let names: Vec<_> = preset.rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Throne · sniff",
            "Throne · hijack-dns",
            "Tunnel route prefer",
            "Throne · 1:4",
            "Tunnel oc route prefer",
            "Throne · reject"
        ]
    );
    assert_eq!(preset.rules[2].config, gate("ovpn"));
    assert_eq!(preset.rules[4].config, gate("oc"));
    let constraints = preset.legacy_constraints.as_ref().unwrap();
    assert_eq!(constraints.version, 6);
    assert_eq!(constraints.endpoints, ["ovpn", "oc"]);
    assert!(constraints.inbound_tags.is_empty());
    assert!(constraints.valid());
    // Tunnel DNS: one server before dns-local and one head rule, only for
    // endpoints whose saved policy uses the tunnel DNS.
    let servers = preset.dns["servers"].as_array().unwrap();
    let tags: Vec<_> = servers.iter().map(|s| s["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, ["dns-remote", "dns-direct", "dns-vpn-1", "dns-local"]);
    assert_eq!(servers[2]["type"], "openvpn");
    assert_eq!(servers[2]["endpoint"], "profile:ovpn");
    assert_eq!(
        preset.dns["rules"][0],
        json!({"preferred_by":["dns-vpn-1"],"action":"route","server":"dns-vpn-1"})
    );
    let report: Vec<_> = p.report.iter().map(|i| i.code.as_str()).collect();
    assert!(report.contains(&"legacy_route_endpoint_rule_added"));
    assert!(report.contains(&"legacy_route_endpoint_tunnel_dns"));
    assert_eq!(
        report
            .iter()
            .filter(|c| **c == "legacy_route_endpoint_rule_added")
            .count(),
        1
    );
    assert!(!json!(p.report).to_string().contains("192.0.2.10"));
    let mut check = crate::routing::Routing::default();
    check.profiles.push(preset.clone());
    assert!(crate::routing::profile_references(&check).contains("ovpn"));
    assert!(crate::routing::uses_profile(&check, "oc"));
}

#[test]
fn explicit_dns_is_untouched_and_raw_routes_append_gates_after_their_rules() {
    let mut source = fixture();
    source.parts.profiles = true;
    route_col(&mut source, "endpoint_profile_ids", s("[3]"));
    let explicit = convert_with(&source, &with_endpoints());
    assert!(explicit.presets[0].dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["type"] != "openvpn"));
    assert!(explicit
        .report
        .iter()
        .all(|i| i.code != "legacy_route_endpoint_tunnel_dns"));
    for verbatim in [false, true] {
        let mut source = fixture();
        source.parts.profiles = true;
        route_col(&mut source, "endpoint_profile_ids", s("[3]"));
        route_col(&mut source, "prevent_modifications", n(verbatim as i64));
        rule(&mut source, 13, 0, &[("outbound_id", n(3))]);
        raw(
            &mut source,
            json!({"rules":[{"action":"reject"}],"final":-2}),
        );
        let p = convert_with(&source, &with_endpoints());
        let rules = &p.presets[0].rules;
        assert_eq!(rules.len(), 2, "{verbatim}");
        assert_eq!(rules[1].config, gate("ovpn"));
        assert_eq!(p.presets[0].legacy_constraints.as_ref().unwrap().version, 6);
        assert_eq!(
            p.presets[0]
                .legacy_constraints
                .as_ref()
                .unwrap()
                .raw_verbatim,
            verbatim
        );
    }
}

#[test]
fn chain_exits_qualify_and_other_kinds_or_shared_targets_are_refused() {
    let plan = with_endpoints();
    let mut source = fixture();
    source.parts.profiles = true;
    route_col(&mut source, "endpoint_profile_ids", s("[5]"));
    let p = convert_with(&source, &plan);
    let constraints = p.presets[0].legacy_constraints.as_ref().unwrap();
    assert!(constraints.endpoints.contains(&"chain".to_owned()));
    assert!(constraints.endpoints.contains(&"ovpn".to_owned()));
    assert_eq!(p.presets[0].rules.last().unwrap().config, gate("chain"));
    // Qt marks inner hops per endpoint; a hop that does not advertise routes
    // cannot be preferred, so such a chain converts exactly as before.
    route_col(&mut source, "inner_hop_endpoint_ids", s("[5]"));
    let marked = convert_with(&source, &plan);
    assert_eq!(
        marked.presets[0].rules.last().unwrap().config,
        gate("chain")
    );
    assert_eq!(marked.presets[0].rules.len(), p.presets[0].rules.len());
    for (ids, code) in [
        ("[6]", "legacy_route_endpoint_unsupported"),
        ("[42]", "legacy_route_endpoint_unsupported"),
        ("[99]", "legacy_route_reference_missing"),
        ("[3,3]", "legacy_route_structure"),
        ("[-1]", "legacy_route_structure"),
        ("{}", "legacy_route_structure"),
    ] {
        let mut source = fixture();
        source.parts.profiles = true;
        route_col(&mut source, "endpoint_profile_ids", s(ids));
        assert_eq!(codes_with(&source, &plan), [code], "{ids}");
    }
    // Qt: an endpoint may not also be a route destination or a group proxy.
    let mut source = fixture();
    source.parts.profiles = true;
    route_col(&mut source, "endpoint_profile_ids", s("[3]"));
    rule(&mut source, 0, 0, &[("outbound_id", n(3))]);
    assert_eq!(
        codes_with(&source, &plan),
        ["legacy_route_endpoint_unsupported"]
    );
    let mut grouped = plan.clone();
    grouped.groups[0].proxy_chain.landing = Some("ovpn".into());
    let mut source = fixture();
    source.parts.profiles = true;
    route_col(&mut source, "endpoint_profile_ids", s("[3]"));
    assert_eq!(
        codes_with(&source, &grouped),
        ["legacy_route_endpoint_unsupported"]
    );
    // A positioned endpoint row with match conditions would lose them silently.
    let mut source = fixture();
    source.parts.profiles = true;
    route_col(&mut source, "endpoint_profile_ids", s("[3]"));
    rule(
        &mut source,
        13,
        0,
        &[("outbound_id", n(3)), ("domain_json", s("[\"x.invalid\"]"))],
    );
    assert_eq!(
        codes_with(&source, &plan),
        ["legacy_route_field_unsupported"]
    );
    // Without the profiles part, endpoints cannot be resolved at all.
    let mut source = fixture();
    route_col(&mut source, "endpoint_profile_ids", s("[3]"));
    assert_eq!(code(&source), ["legacy_route_reference_missing"]);
}

#[test]
fn custom_inbound_tags_are_matched_recorded_and_unknown_or_builtin_tags_refused() {
    let mut source = fixture();
    set(
        &mut source,
        "custom_inbound",
        r#"{"inbounds":[{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1085}]}"#,
    );
    rule(
        &mut source,
        0,
        0,
        &[("inbound_json", s("[\"lan-socks\",\"mixed-in\"]"))],
    );
    let p = plan(&source);
    let preset = &p.presets[0];
    assert_eq!(
        preset.rules[2].config["inbound"],
        json!(["lan-socks", "mixed-in"])
    );
    let constraints = preset.legacy_constraints.as_ref().unwrap();
    assert_eq!(constraints.version, 6);
    assert_eq!(constraints.inbound_tags, ["lan-socks"]);
    assert!(constraints.endpoints.is_empty());
    assert!(constraints.valid());
    let mut source = fixture();
    rule(&mut source, 0, 0, &[("inbound_json", s("[\"mixed-in\"]"))]);
    assert_eq!(
        plan(&source).presets[0]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .version,
        2
    );
    for (tag, expected) in [
        ("tun-in", "legacy_route_inbound_unsupported"),
        ("hijack-dns", "legacy_route_inbound_unsupported"),
        ("throne-bridge", "legacy_route_inbound_unsupported"),
        ("ghost", "legacy_route_inbound_unknown"),
    ] {
        let mut source = fixture();
        rule(
            &mut source,
            0,
            0,
            &[("inbound_json", s(&format!("[\"{tag}\"]")))],
        );
        assert_eq!(code(&source), [expected], "{tag}");
        let mut source = fixture();
        raw(
            &mut source,
            json!({"rules":[{"inbound":[tag],"outbound":-2}]}),
        );
        assert_eq!(code(&source), [expected], "raw {tag}");
    }
    let mut source = fixture();
    set(
        &mut source,
        "custom_inbound",
        r#"{"inbounds":[{"tag":"x"}]}"#,
    );
    assert_eq!(code(&source), ["legacy_route_settings_invalid"]);
    // DNS rules name inbounds through the same list.
    let mut source = fixture();
    set(
        &mut source,
        "custom_inbound",
        r#"{"inbounds":[{"type":"socks","tag":"lan-socks"}]}"#,
    );
    set(&mut source,"dns_object",&json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1"}],"rules":[{"inbound":["lan-socks"],"server":"dns-direct"}],"final":"dns-direct"}).to_string());
    let p = plan(&source);
    assert_eq!(
        p.presets[0]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .inbound_tags,
        ["lan-socks"]
    );
    set(&mut source,"dns_object",&json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1"}],"rules":[{"inbound":["dns-in"],"server":"dns-direct"}],"final":"dns-direct"}).to_string());
    assert_eq!(code(&source), ["legacy_route_inbound_unsupported"]);
}

fn golden(name: &str) -> (SourceArchive, Option<ProfilePlan>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "src/legacy_backup/routes/fixtures/{name}.thrbackup"
    ));
    let source = crate::legacy_backup::parse(&std::fs::read(path).unwrap()).unwrap();
    let plan = source.parts.profiles.then(|| {
        crate::legacy_backup::profiles::convert_selected_with_selectors(
            source.database.as_ref().unwrap(),
            true,
            crate::legacy_backup::autoselector::Choice::LastBuilt,
        )
        .unwrap_or_else(|e| panic!("{}", serde_json::to_string(&e).unwrap()))
    });
    (source, plan)
}

#[test]
fn actual_qt_endpoint_archives_convert_gates_tunnel_dns_and_refuse_inner_hops() {
    let manifest: Value = serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    for name in ["routes-endpoints", "routes-endpoints-blocked"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "src/legacy_backup/routes/fixtures/{name}.thrbackup"
        ));
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&bytes)),
            manifest["archives"][name]["sha256"].as_str().unwrap()
        );
    }
    let (source, plan) = golden("routes-endpoints");
    let plan = plan.unwrap();
    let ovpn = plan.profile_ids[&3].clone();
    let oc = plan.profile_ids[&4].clone();
    let p = convert_with(&source, &plan);
    assert_eq!(p.presets.len(), 2);
    let structured = &p.presets[0];
    let names: Vec<_> = structured.rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Throne · sniff",
            "Throne · hijack-dns",
            "Fixture OpenVPN route prefer",
            "Proxy",
            "Fixture OpenConnect route prefer",
            "Throne · reject"
        ]
    );
    assert_eq!(structured.rules[2].config, gate(&ovpn));
    assert_eq!(structured.rules[4].config, gate(&oc));
    let constraints = structured.legacy_constraints.as_ref().unwrap();
    assert_eq!(constraints.version, 6);
    assert_eq!(constraints.endpoints, [ovpn.clone(), oc.clone()]);
    let servers = structured.dns["servers"].as_array().unwrap();
    assert!(servers
        .iter()
        .any(|s| s["type"] == "openvpn" && s["endpoint"] == format!("profile:{ovpn}")));
    assert!(servers.iter().all(|s| s["type"] != "openconnect"));
    let raw = &p.presets[1];
    assert_eq!(raw.rules.len(), 2);
    assert_eq!(raw.rules[1].config, gate(&ovpn));
    assert!(raw.legacy_constraints.as_ref().unwrap().raw_verbatim);
    assert!(!json!(p.report).to_string().contains("synthetic-password"));
    // The archive that marks inner hops: its chain carries a plain socks hop
    // before the tunnel, so there is nothing extra to prefer and it converts
    // like any other chain endpoint.
    let (blocked, plan) = golden("routes-endpoints-blocked");
    let plan = plan.unwrap();
    let chain = plan.profile_ids[&5].clone();
    let marked = convert_with(&blocked, &plan);
    assert_eq!(marked.presets[0].rules.last().unwrap().config, gate(&chain));
    let servers = marked.presets[0].dns["servers"].as_array().unwrap();
    assert!(servers
        .iter()
        .any(|s| s["type"] == "openvpn" && s["endpoint"] == format!("profile:{chain}")));
    assert_eq!(
        marked.presets[0]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .endpoints,
        [chain, plan.profile_ids[&3].clone()]
    );
}

/// A VPN node a chain endpoint carries before its exit is addressable on
/// its own — Qt's inner hops. It receives its own gate and, when it asks for
/// it, its own tunnel resolver; the exit keeps both of its own.
#[test]
fn an_inner_vpn_hop_of_a_chain_endpoint_receives_its_own_gate_and_resolver() {
    let mut plan = with_endpoints();
    let mut source = fixture();
    source.parts.profiles = true;
    generated(&mut source);
    route_col(&mut source, "endpoint_profile_ids", s("[7]"));
    route_col(&mut source, "inner_hop_endpoint_ids", s("[7]"));
    let p = convert_with(&source, &plan);
    let rules = &p.presets[0].rules;
    assert_eq!(rules[rules.len() - 2].config, gate("inner-chain"));
    assert_eq!(
        rules.last().unwrap().config,
        gate("oc"),
        "the node inside the chain is preferred by name of its own"
    );
    let servers = p.presets[0].dns["servers"].as_array().unwrap();
    assert!(
        servers
            .iter()
            .any(|s| s["type"] == "openvpn" && s["endpoint"] == "profile:inner-chain"),
        "the exit keeps its tunnel resolver: {}",
        p.presets[0].dns
    );
    assert!(
        servers.iter().all(|s| s["type"] != "openconnect"),
        "a node that does not ask for its tunnel resolver receives none"
    );
    // The same chain with a tunnel resolver on the inner node: both are served,
    // each under its own tag.
    for profile in &mut plan.profiles {
        if profile.id == "oc" {
            profile.vpn_policy = Some(Policy {
                only_advertised_routes: true,
                use_tunnel_dns: true,
                block_outside_dns: false,
            });
        }
    }
    let p = convert_with(&source, &plan);
    let servers = p.presets[0].dns["servers"].as_array().unwrap();
    let served: Vec<_> = servers
        .iter()
        .filter(|s| s["endpoint"].is_string())
        .map(|s| (s["tag"].clone(), s["type"].clone(), s["endpoint"].clone()))
        .collect();
    assert_eq!(
        served,
        [
            (
                json!("dns-vpn-1"),
                json!("openvpn"),
                json!("profile:inner-chain")
            ),
            (
                json!("dns-vpn-2"),
                json!("openconnect"),
                json!("profile:oc")
            ),
        ]
    );
    // Both nodes belong to the connection this preset describes.
    let endpoints = &p.presets[0].legacy_constraints.as_ref().unwrap().endpoints;
    assert!(endpoints.contains(&"inner-chain".to_owned()) && endpoints.contains(&"oc".to_owned()));
}

#[test]
fn actual_qt_inbound_archives_record_custom_tags_and_refuse_injected_or_unknown_ones() {
    let (source, _) = golden("routes-inbounds");
    let p = plan(&source);
    let preset = &p.presets[0];
    assert_eq!(preset.rules[2].config["inbound"], json!(["lan-socks"]));
    assert_eq!(
        preset.rules[3].config["inbound"],
        json!(["mixed-in", "lan-socks"])
    );
    let constraints = preset.legacy_constraints.as_ref().unwrap();
    assert_eq!(constraints.version, 6);
    assert_eq!(constraints.inbound_tags, ["lan-socks"]);
    let (blocked, _) = golden("routes-inbounds-blocked");
    let mut codes = code(&blocked);
    codes.sort();
    assert_eq!(
        codes,
        [
            "legacy_route_inbound_unknown",
            "legacy_route_inbound_unsupported"
        ]
    );
}
