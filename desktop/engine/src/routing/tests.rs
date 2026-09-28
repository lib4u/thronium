use super::*;
#[test]
fn subscription_default_yields_to_explicit_client_policy() {
    let mut routing = Routing::default();
    assert!(!routing.customized());
    routing.profiles[0].name = "Renamed default".into();
    assert!(!routing.customized());
    routing.profiles[0].mode = "direct".into();
    assert!(routing.customized());
    routing.profiles[0].mode = "rules".into();
    routing.profiles[0].rules.push(Rule {
        id: "rule".into(),
        name: "Rule".into(),
        enabled: false,
        config: json!({"domain":["example.test"],"outbound":"direct"}),
        simple: None,
    });
    assert!(!routing.customized());
    routing.profiles[0].rules[0].enabled = true;
    assert!(routing.customized());
    routing.profiles[0].rules.clear();
    routing.profiles[0].dns["final"] = json!("custom");
    assert!(routing.customized());
    routing.profiles[0] = RoutingProfile::default();
    assert!(!routing.customized());
    routing.profiles[0].id = "explicit".into();
    routing.active = "explicit".into();
    assert!(routing.customized());
}
fn profile(id: &str, kind: ProfileKind, config: Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        name: id.into(),
        group_id: "personal".into(),
        favorite: false,
        kind,
        config,
    }
}
#[test]
fn modes_order_disabled_rules_references_and_opaque_configs() {
    let p = profile(
        "selected",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let aux = profile(
        "aux",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks", "server":"127.0.0.1", "server_port":9999}),
    );
    let mut r = RoutingProfile {
        rules: vec![
            Rule {
                id: "one".into(),
                name: "First".into(),
                enabled: true,
                simple: None,
                config: json!({"domain_suffix":["example.test"], "outbound":"profile:aux"}),
            },
            Rule {
                id: "two".into(),
                name: "Off".into(),
                enabled: false,
                simple: None,
                config: json!({"action":"reject"}),
            },
        ],
        ..Default::default()
    };
    let mut req = crate::config::build(&p, 2080, None).unwrap();
    apply(&mut req, &p, &r, &[p.clone(), aux.clone()]).unwrap();
    let c: Value = serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(
        c["route"]["rules"],
        json!([builtin::sniff(), {"domain_suffix":["example.test"], "outbound":"thronium-route-aux"}])
    );
    assert!(c["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["tag"] == "thronium-route-aux"));
    r.mode = "direct".into();
    let mut req = crate::config::build(&p, 2080, None).unwrap();
    apply(&mut req, &p, &r, &[]).unwrap();
    let c: Value = serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(c["route"]["final"], "direct");
    // Modes drop the profile's rules but keep the sniff that ad blocking needs.
    assert_eq!(c["route"]["rules"], json!([builtin::sniff()]));
    let full = profile(
        "full",
        ProfileKind::SingBoxConfig,
        json!({"outbounds":[{"type":"direct"}], "route":{"rules":[{"action":"reject"}]}}),
    );
    let mut req = crate::config::build(&full, 2080, None).unwrap();
    let before = req.core_config.clone();
    apply(&mut req, &full, &r, &[]).unwrap();
    assert_eq!(before, req.core_config);
}
#[test]
fn dns_endpoint_references_generate_auxiliary_endpoints_and_prevent_deletion() {
    let selected = profile(
        "selected",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let vpn = profile(
        "vpn",
        ProfileKind::SingBoxOutbound,
        json!({"type":"openvpn-client", "server":"vpn.test", "server_port":1194}),
    );
    let mut r = RoutingProfile::default();
    r.dns["servers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"openvpn", "tag":"vpn-dns", "endpoint":"profile:vpn"}));
    let mut req = crate::config::build(&selected, 2080, None).unwrap();
    apply(&mut req, &selected, &r, &[selected.clone(), vpn]).unwrap();
    let c: Value = serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(c["dns"]["servers"][1]["endpoint"], "thronium-route-vpn");
    assert_eq!(c["endpoints"][0]["tag"], "thronium-route-vpn");
    assert!(uses_profile(
        &Routing {
            profiles: vec![r],
            ..Routing::default()
        },
        "vpn"
    ));
}
#[test]
fn settings_validate_ids_and_keep_metadata_out_of_core_rules() {
    let mut routing = Routing::default();
    routing.validate().unwrap();
    routing.profiles.push(RoutingProfile::default());
    assert!(routing.validate().is_err());
    routing.profiles.pop();
    routing.profiles[0].route["rules"] = json!([]);
    assert!(routing.validate().is_err());
}
#[test]
fn preferred_by_gates_translate_profile_references_like_outbounds() {
    let selected = profile(
        "selected",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let vpn = profile(
        "vpn",
        ProfileKind::SingBoxOutbound,
        json!({"type":"openconnect", "server":"vpn.fixture.invalid", "server_port":443}),
    );
    let mut r = RoutingProfile::default();
    r.rules.push(Rule {
        id: "gate".into(),
        name: "Gate".into(),
        enabled: true,
        simple: None,
        config: json!({"preferred_by":["profile:vpn"],"action":"route","outbound":"profile:vpn"}),
    });
    r.dns["rules"] = json!([{"preferred_by":["dns-vpn-1"],"action":"route","server":"dns-vpn-1"}]);
    let routing = Routing {
        profiles: vec![r.clone()],
        ..Routing::default()
    };
    assert_eq!(profile_references(&routing), ["vpn".to_owned()].into());
    assert!(uses_profile(&routing, "vpn"));
    let mut req = crate::config::build(&selected, 2080, None).unwrap();
    apply(&mut req, &selected, &r, &[selected.clone(), vpn]).unwrap();
    let c: Value = serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(
        c["route"]["rules"][1],
        json!({"preferred_by":["thronium-route-vpn"],"action":"route","outbound":"thronium-route-vpn"})
    );
    assert_eq!(c["dns"]["rules"][0]["preferred_by"], json!(["dns-vpn-1"]));
    assert_eq!(c["endpoints"][0]["tag"], "thronium-route-vpn");
    // A gate naming the selected profile itself points at the primary tunnel.
    let mut own = RoutingProfile::default();
    own.rules.push(Rule {
        id: "own".into(),
        name: "Own".into(),
        enabled: true,
        simple: None,
        config: json!({"preferred_by":["profile:selected"],"action":"route","outbound":"profile:selected"}),
    });
    let mut req = crate::config::build(&selected, 2080, None).unwrap();
    apply(&mut req, &selected, &own, std::slice::from_ref(&selected)).unwrap();
    let c: Value = serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(c["route"]["rules"][1]["preferred_by"], json!(["proxy"]));
}

#[test]
fn structured_routes_sniff_before_their_rules_unless_they_sniff_themselves() {
    let p = profile("p", ProfileKind::SingBoxOutbound, json!({"type":"direct"}));
    let rule = |config: Value| Rule {
        id: "r".into(),
        name: "r".into(),
        enabled: true,
        simple: None,
        config,
    };
    let domain = json!({"domain_suffix":["example.test"],"outbound":"direct"});
    let compiled = |routing: &RoutingProfile| {
        let mut req = crate::config::build(&p, 2080, None).unwrap();
        apply(&mut req, &p, routing, std::slice::from_ref(&p)).unwrap();
        serde_json::from_str::<Value>(req.core_config.as_ref().unwrap()).unwrap()["route"]["rules"]
            .clone()
    };
    let mut routing = RoutingProfile::default();
    routing.rules.push(rule(domain.clone()));
    assert_eq!(
        compiled(&routing),
        json!([builtin::sniff(), domain.clone()])
    );
    // A sniff limited by conditions leaves every other connection unsniffed.
    let partial = json!({"inbound":["mixed-in"],"action":"sniff"});
    routing.rules.insert(0, rule(partial.clone()));
    assert_eq!(
        compiled(&routing),
        json!([builtin::sniff(), partial, domain.clone()])
    );
    // The user's own sniff with an override stays the only one the core runs.
    let own = json!({"action":"sniff","override_destination":true,"sniffer":["tls"]});
    routing.rules[0] = rule(own.clone());
    assert_eq!(compiled(&routing), json!([own, domain.clone()]));
    // Presets converted from Throne carry the sniff among their own rules.
    routing.rules.remove(0);
    routing.legacy_constraints = Some(LegacyRoutingConstraints::default());
    assert_eq!(compiled(&routing), json!([domain]));
}
