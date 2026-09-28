use super::*;

fn library(global: bool) -> Library {
    let mut library = Library::default();
    for (key, val) in [
        ("enable_warp", json!(global)),
        (
            "warp_private_key",
            json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ),
        (
            "warp_public_key",
            json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        ),
        ("warp_ep", json!("[::1]:2408")),
        ("warp_ifc_addrs", json!(["10.77.0.2/32"])),
        ("warp_reserved", json!(["1", "2", "3"])),
    ] {
        library.settings.insert(key.into(), val);
    }
    library
}

#[test]
fn explicit_targets_resolve_without_renaming_dns_servers_or_domain_conditions() {
    for global in [false, true] {
        let mut core = json!({
            "outbounds":[{"type":"direct","tag":"proxy"},{"type":"direct","tag":"direct"}],
            "route":{"final":"warp","rules":[{"type":"logical","mode":"or","rules":[{"domain":["warp","warp-bypass"]}],"outbound":"warp-bypass"}],"rule_set":[{"download_detour":"warp"}]},
            "dns":{"final":"warp","servers":[{"tag":"warp","type":"udp","server":"1.1.1.1","detour":"warp-bypass"}],"rules":[{"server":"warp","domain":["warp"]}]},
            "ntp":{"detour":"warp"}
        });
        apply(&mut core, &library(global)).unwrap();
        let exit = if global { "proxy" } else { EXIT_TAG };
        let base = if global { BASE_TAG } else { "proxy" };
        assert_eq!(core["route"]["final"], exit);
        assert_eq!(core["route"]["rules"][0]["outbound"], base);
        assert_eq!(core["dns"]["servers"][0]["detour"], base);
        assert_eq!(core["route"]["rule_set"][0]["download_detour"], exit);
        assert_eq!(core["ntp"]["detour"], exit);
        assert_eq!(core["dns"]["final"], "warp");
        assert_eq!(
            core["dns"]["rules"][0],
            json!({"server":"warp","domain":["warp"]})
        );
        assert_eq!(
            core["route"]["rules"][0]["rules"][0]["domain"],
            json!(["warp", "warp-bypass"])
        );
        assert_eq!(core["endpoints"][0]["tag"], exit);
        assert_eq!(core["endpoints"][0]["detour"], base);
        assert_eq!(
            core["endpoints"][0]["peers"][0]["reserved"],
            json!([1, 2, 3])
        );
        assert_eq!(core["endpoints"][0]["peers"][0]["address"], "::1");
    }
}

#[test]
fn bypass_without_global_warp_needs_no_credentials_and_keeps_primary_unchanged() {
    let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"warp-bypass"},"dns":{"final":"warp"}});
    apply(&mut core, &Library::default()).unwrap();
    assert_eq!(core["route"]["final"], "proxy");
    assert_eq!(core["outbounds"], json!([{"type":"direct","tag":"proxy"}]));
    assert!(core.get("endpoints").is_none());
}

#[test]
fn explicit_warp_requires_credentials_even_with_global_toggle_off() {
    let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"warp"}});
    assert_eq!(
        apply(&mut core, &Library::default()).unwrap_err(),
        "settings_invalid:warp_private_key"
    );
    assert_eq!(core["outbounds"][0]["tag"], "proxy");
}

#[test]
fn explicit_warp_rejects_reserved_collision_without_replacing_existing_outbounds() {
    for tag in [BASE_TAG, EXIT_TAG] {
        let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"},{"type":"direct","tag":tag}],"route":{"final":"warp"}});
        let before = core.clone();
        assert_eq!(
            apply(&mut core, &library(false)).unwrap_err(),
            "route_tag_conflict"
        );
        assert_eq!(core, before);
    }
}

#[test]
fn followed_dns_keeps_explicit_rules_and_separates_warp_from_bypass() {
    for global in [false, true] {
        let mut library = library(global);
        library
            .settings
            .insert("enable_dns_routing".into(), json!(true));
        let source = json!({"tag":"dns-remote","type":"https","server":"1.1.1.1","path":"/dns-query","detour":"proxy"});
        let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"rules":[
            {"domain_suffix":["warp.test"],"outbound":"warp"},
            {"domain_suffix":["base.test"],"outbound":"warp-bypass"},
            {"process_name":["app"],"outbound":"warp"}
        ]},"dns":{"servers":[source.clone()],"rules":[{"domain":["explicit.test"],"server":"dns-remote"}]}});
        apply(&mut core, &library).unwrap();
        crate::settings::intercept::follow_routing(&mut core, &library).unwrap();
        let special = if global {
            "settings-warp-dns-bypass"
        } else {
            "settings-warp-dns-exit"
        };
        assert_eq!(core["dns"]["servers"].as_array().unwrap().len(), 2);
        assert_eq!(core["dns"]["servers"][0], source);
        assert_eq!(core["dns"]["servers"][1]["tag"], special);
        assert_eq!(
            core["dns"]["servers"][1]["detour"],
            if global { BASE_TAG } else { EXIT_TAG }
        );
        assert_eq!(core["dns"]["rules"].as_array().unwrap().len(), 3);
        assert_eq!(
            core["dns"]["rules"][0],
            json!({"domain":["explicit.test"],"server":"dns-remote"})
        );
        assert_eq!(
            core["dns"]["rules"][if global { 2 } else { 1 }]["server"],
            special
        );
    }
}

#[test]
fn process_only_warp_rules_do_not_require_a_domain_dns_resolver() {
    let mut library = library(false);
    library
        .settings
        .insert("enable_dns_routing".into(), json!(true));
    let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"rules":[{"process_name":["app"],"outbound":"warp"}]},"dns":{"servers":[]}});
    apply(&mut core, &library).unwrap();
    crate::settings::intercept::follow_routing(&mut core, &library).unwrap();
    assert_eq!(core["dns"]["servers"], json!([]));
    assert_eq!(core["dns"]["rules"], json!([]));
}

#[test]
fn composition_guards_distinguish_active_destinations_from_names_and_disabled_rules() {
    let mut library = Library::default();
    library.routing.profiles[0].dns["final"] = json!("warp");
    library.routing.profiles[0]
        .rules
        .push(crate::routing::Rule {
            id: "rule".into(),
            name: "warp".into(),
            enabled: false,
            simple: None,
            config: json!({"domain":["warp"],"outbound":"warp"}),
        });
    assert!(!enabled_for(&library));
    library.routing.profiles[0].rules[0].enabled = true;
    assert!(enabled_for(&library));
    library.routing.profiles[0].mode = "direct".into();
    assert!(!enabled_for(&library));
    library.routing.profiles[0].dns["servers"] =
        json!([{"type":"udp","server":"1.1.1.1","detour":"warp"}]);
    assert!(enabled_for(&library));
}

#[test]
fn explicit_warp_cannot_bypass_external_vpn_policy_or_legacy_context_guards() {
    use crate::store::{Profile, ProfileKind};
    let mut library = library(false);
    library.routing.profiles[0].route["final"] = json!("warp");
    let mut profile = Profile {
        id: "selected".into(),
        name: "Selected".into(),
        group_id: "personal".into(),
        favorite: false,
        vpn_policy: None,
        kind: ProfileKind::ExternalCore,
        config: json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":39173,"extra_core_path":"/never-run-fixture","extra_core_args":"","extra_core_conf":"","no_logs":true}),
    };
    library.profiles = vec![profile.clone()];
    if cfg!(target_os = "linux") {
        // Qt carries an external core under WARP: WARP is what gives such a
        // connection its UDP, so the composition stands.
        crate::external_core::runtime::context(&library, &profile).unwrap();
    }
    profile.kind = ProfileKind::SingBoxOutbound;
    profile.config = json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194});
    profile.vpn_policy = Some(crate::vpn_policy::Policy {
        only_advertised_routes: true,
        use_tunnel_dns: true,
        block_outside_dns: true,
    });
    library.profiles = vec![profile.clone()];
    assert_eq!(
        crate::vpn_policy::validate_context(&library, &profile).unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    assert!(
        crate::routing::legacy_context::conflicts(&library, &library.routing.profiles[0])
            .contains(&"legacy_routing_warp_conflict")
    );
    let preset = crate::routing::RoutingProfile::default();
    assert!(
        !crate::routing::legacy_context::conflicts(&library, &preset)
            .contains(&"legacy_routing_warp_conflict")
    );
}
