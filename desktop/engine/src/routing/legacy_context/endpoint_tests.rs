//! Endpoint-aware (version 6) presets: their tunnel endpoints and custom
//! inbound tags are declared by the preset, so the runtime checks those
//! declarations instead of refusing every endpoint or additional inbound.
use super::tests::{library, selected};
use super::*;
use crate::{
    routing::{LegacyRoutingConstraints, Rule},
    vpn_policy::Policy,
    Engine,
};
use serde_json::{json, Value};

fn aware(library: &mut Library, endpoints: &[&str], inbound_tags: &[&str]) {
    library.routing.profiles[0].legacy_constraints = Some(LegacyRoutingConstraints {
        version: 6,
        xray_dns_strategy: None,
        endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
        inbound_tags: inbound_tags.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    });
}
fn tunnel(id: &str) -> Profile {
    Profile {
        vpn_policy: Some(Policy {
            only_advertised_routes: true,
            use_tunnel_dns: true,
            block_outside_dns: false,
        }),
        id: id.into(),
        name: id.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"openvpn-client","server":"192.0.2.10","server_port":1194,"username":"u","password":"p"}),
        favorite: false,
    }
}

#[test]
fn declared_inbound_tags_replace_the_blanket_inbound_conflict() {
    let mut library = library();
    library.settings.insert(
        "custom_inbound".into(),
        json!([{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1085}]),
    );
    let preset = library.routing.profiles[0].clone();
    assert_eq!(
        conflicts(&library, &preset),
        ["legacy_routing_inbounds_conflict"]
    );
    aware(&mut library, &[], &["lan-socks"]);
    let preset = library.routing.profiles[0].clone();
    assert!(conflicts(&library, &preset).is_empty());
    assert!(validate(&library, &selected()).is_ok());
    aware(&mut library, &[], &["lan-socks", "other"]);
    let preset = library.routing.profiles[0].clone();
    assert_eq!(
        conflicts(&library, &preset),
        ["legacy_routing_inbound_missing"]
    );
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_inbound_missing"
    );
    library.settings.remove("custom_inbound");
    aware(&mut library, &["x"], &[]);
    let preset = library.routing.profiles[0].clone();
    assert!(conflicts(&library, &preset).is_empty());
}

#[test]
fn aware_presets_build_auxiliary_tunnels_with_translated_gates_and_tunnel_dns() {
    let dir = tempfile::tempdir().unwrap();
    let mut library = library();
    library.profiles.push(tunnel("ovpn"));
    library.routing.profiles[0].rules.push(Rule {
        id: "gate".into(),
        name: "Gate".into(),
        enabled: true,
        simple: None,
        config: json!({"preferred_by":["profile:ovpn"],"action":"route","outbound":"profile:ovpn"}),
    });
    library.routing.profiles[0].dns["servers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"openvpn","tag":"dns-vpn-1","endpoint":"profile:ovpn"}));
    library.routing.profiles[0].dns["rules"]
        .as_array_mut()
        .unwrap()
        .insert(
            0,
            json!({"preferred_by":["dns-vpn-1"],"action":"route","server":"dns-vpn-1"}),
        );
    // Presets converted before endpoints existed keep both guards: the VPN
    // policy context refusal runs first, the endpoint guard after it.
    assert_eq!(
        Engine::build_with_library(&selected(), &library, dir.path()).unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_endpoint_unsupported"
    );
    aware(&mut library, &["ovpn"], &[]);
    assert_eq!(carried_endpoints(&library), ["ovpn".to_owned()].into());
    let request = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["endpoints"][0]["tag"], "thronium-route-ovpn");
    assert_eq!(core["endpoints"][0]["type"], "openvpn-client");
    let gate = &core["route"]["rules"][0];
    assert_eq!(gate["preferred_by"], json!(["thronium-route-ovpn"]));
    assert_eq!(gate["outbound"], "thronium-route-ovpn");
    assert_eq!(core["dns"]["servers"][1]["endpoint"], "thronium-route-ovpn");
    assert_eq!(
        core["dns"]["rules"][0]["preferred_by"],
        json!(["dns-vpn-1"])
    );
    assert!(core["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["tag"] != "thronium-vpn-dns-proxy"));
    // A chain endpoint carries its hops; the aux target of a selected tunnel
    // keeps the vpn_policy refusal since only the carried set is exempt.
    let mut chain = selected();
    chain.id = "chain".into();
    chain.kind = ProfileKind::Chain;
    chain.config = json!({"type":"chain","hops":["proxy","ovpn"]});
    library.profiles.push(chain);
    aware(&mut library, &["chain"], &[]);
    assert!(carried_endpoints(&library).contains("ovpn"));
    library.profiles.push(tunnel("other"));
    library.routing.profiles[0].rules.push(Rule {
        id: "other".into(),
        name: "Other".into(),
        enabled: true,
        simple: None,
        config: json!({"domain":["other.fixture.invalid"],"outbound":"profile:other"}),
    });
    assert_eq!(
        Engine::build_with_library(&selected(), &library, dir.path()).unwrap_err(),
        "vpn_policy_context_unsupported"
    );
}

#[test]
fn version_six_accepts_declarations_and_older_versions_refuse_them() {
    let mut constraints = LegacyRoutingConstraints {
        version: 6,
        xray_dns_strategy: None,
        endpoints: vec!["a".into()],
        inbound_tags: vec!["lan".into()],
        raw_verbatim: true,
        adaptive_dns: true,
        ..Default::default()
    };
    assert!(constraints.valid());
    assert!(constraints.adapt_remote_dns());
    for version in 2..=5 {
        constraints.version = version;
        assert!(!constraints.valid(), "{version}");
    }
    let wire = json!({"version":6,"endpoints":["a"],"inboundTags":["lan"]});
    let parsed: LegacyRoutingConstraints = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(json!(parsed), wire);
    let plain = LegacyRoutingConstraints {
        version: 6,
        ..Default::default()
    };
    assert_eq!(json!(plain), json!({"version":6}));
}

/// A route that prefers a node inside a chain endpoint sends traffic to
/// that hop of the chain, under the tag the chain compiler gave it. The node is
/// never built a second time, so one tunnel is opened, not two.
#[test]
fn a_preferred_node_inside_a_chain_endpoint_is_that_chain_s_own_hop() {
    let dir = tempfile::tempdir().unwrap();
    let mut library = library();
    library.profiles.push(tunnel("inner"));
    library.profiles.push(tunnel("exit"));
    let mut chain = selected();
    chain.id = "chain".into();
    chain.kind = ProfileKind::Chain;
    chain.vpn_policy = None;
    chain.config = json!({"type":"chain","hops":["inner","exit"]});
    library.profiles.push(chain);
    for (id, name) in [("chain", "Chain gate"), ("inner", "Inner gate")] {
        library.routing.profiles[0].rules.push(Rule {
            id: id.into(),
            name: name.into(),
            enabled: true,
            simple: None,
            config: json!({"preferred_by":[format!("profile:{id}")],"action":"route","outbound":format!("profile:{id}")}),
        });
    }
    for (tag, id) in [("dns-vpn-1", "chain"), ("dns-vpn-2", "inner")] {
        library.routing.profiles[0].dns["servers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"openvpn","tag":tag,"endpoint":format!("profile:{id}")}));
    }
    aware(&mut library, &["chain", "inner"], &[]);
    let request = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let endpoints = core["endpoints"].as_array().unwrap();
    let tags: Vec<_> = endpoints.iter().map(|e| e["tag"].clone()).collect();
    assert_eq!(
        tags,
        [
            json!("thronium-chain-thronium-route-chain-0"),
            json!("thronium-route-chain")
        ],
        "one hop and one exit, each once"
    );
    let inner = &endpoints[0];
    let exit = &endpoints[1];
    assert_eq!(exit["detour"], "thronium-chain-thronium-route-chain-0");
    assert!(inner.get("detour").is_none_or(Value::is_null));
    let gates: Vec<_> = core["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule.get("preferred_by").is_some())
        .map(|rule| (rule["preferred_by"].clone(), rule["outbound"].clone()))
        .collect();
    assert_eq!(
        gates,
        [
            (
                json!(["thronium-route-chain"]),
                json!("thronium-route-chain")
            ),
            (
                json!(["thronium-chain-thronium-route-chain-0"]),
                json!("thronium-chain-thronium-route-chain-0")
            )
        ]
    );
    assert_eq!(
        core["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["endpoint"].as_str())
            .collect::<Vec<_>>(),
        [
            "thronium-route-chain",
            "thronium-chain-thronium-route-chain-0"
        ]
    );
}
