use super::*;
use crate::{
    routing::{LegacyRoutingConstraints, Rule},
    Engine,
};
use serde_json::{json, Value};

pub(super) fn selected() -> Profile {
    Profile {
        vpn_policy: None,
        id: "proxy".into(),
        name: "Selected".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    }
}
pub(super) fn library() -> Library {
    let mut library = Library::default();
    library.profiles.push(selected());
    library.routing.profiles[0].legacy_constraints = Some(LegacyRoutingConstraints {
        warp_enabled: false,
        version: 1,
        xray_dns_strategy: None,
        ..Default::default()
    });
    library.routing.profiles[0].dns = json!({"servers":[{"type":"tcp","tag":"legacy-dns","server":"127.0.0.1","server_port":5353}],"rules":[{"domain":["fixture.test"],"action":"route","server":"legacy-dns"}],"final":"legacy-dns","disable_cache":true});
    library.routing.profiles[0].route =
        json!({"final":"proxy","default_domain_resolver":"legacy-dns","find_process":false});
    library
}

#[test]
fn marked_preset_keeps_dns_and_rules_through_the_actual_build_pipeline() {
    let library = library();
    let dir = tempfile::tempdir().unwrap();
    let req = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
    let core: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["dns"], library.routing.profiles[0].dns);
    assert_eq!(core["route"]["default_domain_resolver"], "legacy-dns");
    assert_eq!(core["route"]["rules"], json!([]));
    assert_eq!(core["route"]["find_process"], false);
    assert!(!dir.path().join("config.json").exists());
}

#[tokio::test]
async fn all_policy_overlays_fail_before_spawning_or_stopping_a_connection() {
    for (key, value, code) in [
        (
            "enable_dns_routing",
            json!(true),
            "legacy_routing_dns_follow_conflict",
        ),
        (
            "enable_dns_server",
            json!(true),
            "legacy_routing_dns_listener_conflict",
        ),
        (
            "adblock_enable",
            json!(true),
            "legacy_routing_adblock_conflict",
        ),
        ("enable_warp", json!(true), "legacy_routing_warp_conflict"),
        (
            "enable_redirect",
            json!(true),
            "legacy_routing_redirect_conflict",
        ),
        (
            "use_mozilla_certs",
            json!(true),
            "legacy_routing_certificates_conflict",
        ),
        (
            "core_dns_in_port",
            json!(5353),
            "legacy_routing_core_dns_conflict",
        ),
        (
            "custom_inbound",
            json!([{"type":"direct","tag":"extra","listen":"127.0.0.1","listen_port":1234}]),
            "legacy_routing_inbounds_conflict",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        let mut library = library();
        library.settings.insert(key.into(), value);
        // Deliberately bypass settings-specific validation to prove this guard
        // runs before core use, even for a partially configured overlay.
        engine.store.library = library;
        engine.running = Some("working-session".into());
        let before = json!(engine.store.library);
        assert_eq!(engine.connect("proxy").await.unwrap_err(), code, "{key}");
        assert_eq!(engine.running.as_deref(), Some("working-session"));
        assert!(engine.rpc.is_none());
        assert_eq!(json!(engine.store.library), before);
        assert_eq!(
            engine
                .connection_configuration("proxy", false)
                .await
                .unwrap_err(),
            code
        );
    }
}

#[test]
fn constraints_survive_backups_and_unknown_versions_are_rejected() {
    let library = library();
    let encoded = json!(library);
    assert_eq!(
        encoded["routing"]["profiles"][0]["legacyConstraints"],
        json!({"version":1})
    );
    let parsed: Library = serde_json::from_value(encoded.clone()).unwrap();
    parsed.routing.validate().unwrap();
    let mut future = encoded.clone();
    future["routing"]["profiles"][0]["legacyConstraints"]["version"] = json!(3);
    assert_eq!(
        serde_json::from_value::<Library>(future)
            .unwrap()
            .routing
            .validate()
            .unwrap_err(),
        "invalid_routing"
    );
    let mut future = encoded;
    future["routing"]["profiles"][0]["legacyConstraints"]["newPolicy"] = json!(true);
    assert!(serde_json::from_value::<Library>(future).is_err());
    assert!(json!(Library::default())["routing"]["profiles"][0]
        .get("legacyConstraints")
        .is_none());
}

#[test]
fn warp_aware_import_requires_global_warp_and_preserves_other_guards() {
    let mut library = library();
    let preset = &mut library.routing.profiles[0];
    preset.legacy_constraints = Some(LegacyRoutingConstraints {
        version: 3,
        warp_enabled: true,
        xray_dns_strategy: None,
        ..Default::default()
    });
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_warp_required"
    );
    library.settings.insert("enable_warp".into(), json!(true));
    assert!(validate(&library, &selected()).is_ok());
    library.preferences.connection_mode = crate::system_proxy::ConnectionMode::Tun;
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_tun_unsupported"
    );
    for version in 1..=4 {
        for warp_enabled in [false, true] {
            let constraints = LegacyRoutingConstraints {
                version,
                warp_enabled,
                xray_dns_strategy: None,
                ..Default::default()
            };
            assert_eq!(
                constraints.valid(),
                matches!((version, warp_enabled), (1 | 2, false) | (3, true) | (4, _))
            );
        }
    }
}

#[test]
fn generated_remote_dns_adapts_to_actual_xray_paths_without_mutating_the_preset() {
    let dir = tempfile::tempdir().unwrap();
    for transport in ["udp", "quic"] {
        for mode in ["sing", "xray", "auxiliary", "full-chain"] {
            let mut library = library();
            library.routing.profiles[0]
                .legacy_constraints
                .as_mut()
                .unwrap()
                .version = 4;
            library.routing.profiles[0]
                .legacy_constraints
                .as_mut()
                .unwrap()
                .xray_dns_strategy = Some("UseIP".into());
            library.routing.profiles[0].dns = json!({"servers":[
                {"tag":"dns-remote","type":transport,"server":"1.1.1.1","server_port":1053,"domain_resolver":"dns-local","detour":"proxy"},
                {"tag":"dns-local","type":"local"},
                {"tag":"legacy-dns","type":"tcp","server":"127.0.0.1","server_port":5353}
            ],"final":"dns-remote"});
            let mut selected = selected();
            let mut xray = selected.clone();
            xray.kind = ProfileKind::XrayOutbound;
            xray.config = json!({"protocol":"freedom","settings":{}});
            match mode {
                "xray" => selected = xray,
                "auxiliary" => {
                    xray.id = "aux".into();
                    library.profiles.push(xray);
                    library.routing.profiles[0].rules.push(Rule {
                        id: "aux".into(),
                        name: "Auxiliary".into(),
                        enabled: true,
                        simple: None,
                        config: json!({"domain":["aux.fixture.test"],"outbound":"profile:aux"}),
                    });
                }
                "full-chain" => {
                    xray.id = "full".into();
                    xray.kind = ProfileKind::XrayConfig;
                    xray.config = json!({"outbounds":[{"protocol":"freedom","tag":"exit"}]});
                    library.profiles.push(xray);
                    selected.kind = ProfileKind::Chain;
                    selected.config = json!({"type":"chain","hops":["full"]});
                }
                _ => {}
            }
            library.profiles[0] = selected.clone();
            let before = json!(library);
            let request = Engine::build_with_library(&selected, &library, dir.path()).unwrap();
            let built: Value =
                serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
            let remote = &built["dns"]["servers"][0];
            assert_eq!(
                remote["type"],
                if mode == "sing" { transport } else { "https" },
                "{mode}"
            );
            if mode != "sing" {
                assert_eq!(remote["server"], "1.1.1.1");
                assert_eq!(remote["path"], "/dns-query");
                assert!(remote.get("server_port").is_none());
            }
            assert_eq!(json!(library), before);
        }
    }
}

#[test]
fn only_the_active_preset_and_relevant_endpoints_constrain_builds() {
    let mut library = library();
    let mut endpoint = selected();
    endpoint.id = "endpoint".into();
    endpoint.config = json!({"type":"wireguard"});
    library.profiles.push(endpoint.clone());
    assert!(validate(&library, &selected()).is_ok());
    assert_eq!(
        validate(&library, &endpoint).unwrap_err(),
        "legacy_routing_endpoint_unsupported"
    );
    library.routing.profiles[0].rules.push(Rule {id:"target".into(),name:"Target".into(),enabled:true,simple:None,config:json!({"type":"logical","mode":"and","rules":[{"domain":["fixture.test"]}],"action":"route","outbound":"profile:endpoint"})});
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_endpoint_unsupported"
    );
    library
        .routing
        .profiles
        .push(crate::routing::RoutingProfile {
            id: "normal".into(),
            ..Default::default()
        });
    library.routing.active = "normal".into();
    library
        .settings
        .insert("enable_dns_routing".into(), json!(true));
    assert!(validate(&library, &selected()).is_ok());
    library.routing.active = "default".into();
    let mut full = selected();
    full.kind = ProfileKind::XrayConfig;
    assert!(validate(&library, &full).is_ok());
    full.kind = ProfileKind::SingBoxConfig;
    assert!(validate(&library, &full).is_ok());
}

#[test]
fn first_static_import_stage_rejects_tun_without_changing_preferences() {
    let mut library = library();
    library.preferences.connection_mode = ConnectionMode::Tun;
    let before = json!(library.preferences);
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_tun_unsupported"
    );
    assert_eq!(json!(library.preferences), before);
    library.preferences.connection_mode = ConnectionMode::SystemProxy;
    assert!(validate(&library, &selected()).is_ok());
}

#[test]
fn endpoint_guards_follow_chain_selector_and_group_hops() {
    for shape in ["chain", "selector", "front", "landing"] {
        let mut library = library();
        let mut endpoint = selected();
        endpoint.id = "endpoint".into();
        endpoint.config = json!({"type":"wireguard"});
        library.profiles.push(endpoint);
        let mut p = selected();
        match shape {
            "chain" => {
                p.kind = ProfileKind::Chain;
                p.config = json!({"type":"chain","hops":["endpoint"]});
            }
            "selector" => {
                p.kind = ProfileKind::AutoSelector;
                p.config = json!({"type":"auto-selector","members":["endpoint"]});
            }
            "front" => library.groups[0].proxy_chain.front = Some("endpoint".into()),
            _ => library.groups[0].proxy_chain.landing = Some("endpoint".into()),
        }
        library.profiles[0] = p.clone();
        assert_eq!(
            validate(&library, &p).unwrap_err(),
            "legacy_routing_endpoint_unsupported",
            "{shape}"
        );
    }
}

#[test]
fn local_dns_override_conflicts_only_with_the_actual_imported_preset() {
    let mut library = library();
    library.routing.profiles[0].legacy_constraints = Some(LegacyRoutingConstraints {
        warp_enabled: false,
        version: 2,
        xray_dns_strategy: None,
        ..Default::default()
    });
    library.settings.insert(
        "core_box_underlying_dns".into(),
        json!("tcp://127.0.0.1:5353"),
    );
    assert!(validate(&library, &selected()).is_ok());
    library.routing.profiles[0].dns =
        json!({"servers":[{"type":"local","tag":"legacy-dns"}],"final":"legacy-dns"});
    assert_eq!(
        validate(&library, &selected()).unwrap_err(),
        "legacy_routing_local_dns_conflict"
    );
    library.settings.remove("core_box_underlying_dns");
    let dir = tempfile::tempdir().unwrap();
    let req = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
    let core: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["dns"], library.routing.profiles[0].dns);
    library.routing.validate().unwrap();
}

#[test]
fn saved_xray_dns_strategy_reaches_the_real_request_for_main_and_auxiliary_paths() {
    let dir = tempfile::tempdir().unwrap();
    for strategy in [
        "UseIP",
        "UseIPv4v6",
        "UseIPv6v4",
        "UseIPv4",
        "ForceIPv4",
        "ForceIPv6",
    ] {
        let mut library = library();
        let mut xray = selected();
        xray.kind = ProfileKind::XrayOutbound;
        xray.config = json!({"protocol":"freedom","settings":{}});
        library.profiles[0] = xray.clone();
        library.routing.profiles[0].legacy_constraints = Some(LegacyRoutingConstraints {
            warp_enabled: false,
            version: 2,
            xray_dns_strategy: Some(strategy.into()),
            ..Default::default()
        });
        let req = Engine::build_with_library(&xray, &library, dir.path()).unwrap();
        assert_eq!(req.need_xray, Some(true));
        assert_eq!(req.xray_outbound_dns_strategy.as_deref(), Some(strategy));
        let core: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
        assert_eq!(core["dns"], library.routing.profiles[0].dns);
        xray.id = "auxiliary-xray".into();
        library.profiles = vec![selected(), xray];
        library.routing.profiles[0].rules.push(Rule {id:"auxiliary".into(),name:"Auxiliary".into(),enabled:true,simple:None,config:json!({"domain":["auxiliary.fixture.invalid"],"action":"route","outbound":"profile:auxiliary-xray"})});
        let req = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
        assert_eq!(req.need_xray, Some(true));
        assert_eq!(req.xray_outbound_dns_strategy.as_deref(), Some(strategy));
    }
}

#[test]
fn old_imports_cannot_guess_the_lost_xray_dns_strategy_and_invalid_metadata_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut library = library();
    let mut xray = selected();
    xray.kind = ProfileKind::XrayOutbound;
    xray.config = json!({"protocol":"freedom","settings":{}});
    library.profiles[0] = xray.clone();
    assert_eq!(
        Engine::build_with_library(&xray, &library, dir.path())
            .err()
            .unwrap(),
        "legacy_routing_xray_dns_missing"
    );
    assert!(Engine::build_with_library(&selected(), &library, dir.path()).is_ok());
    library.routing.profiles[0]
        .legacy_constraints
        .as_mut()
        .unwrap()
        .xray_dns_strategy = Some("UnknownFutureStrategy".into());
    assert_eq!(library.routing.validate().unwrap_err(), "invalid_routing");
    library.routing.profiles[0].legacy_constraints = None;
    assert_eq!(
        Engine::build_with_library(&xray, &library, dir.path())
            .unwrap()
            .xray_outbound_dns_strategy
            .as_deref(),
        Some("UseIP")
    );
}

#[test]
fn verbatim_route_build_omits_automatic_fields_and_rejects_bridge_injection() {
    let mut library = library();
    let preset = &mut library.routing.profiles[0];
    preset.legacy_constraints.as_mut().unwrap().version = 5;
    preset.legacy_constraints.as_mut().unwrap().raw_verbatim = true;
    preset.route = json!({});
    let dir = tempfile::tempdir().unwrap();
    let request = Engine::build_with_library(&selected(), &library, dir.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(core["route"], json!({"rules":[]}));
    let mut request = request;
    let mut with_bridge = core;
    with_bridge["route"]["rules"] =
        json!([{"inbound":["internal-bridge"],"outbound":"internal-hop"}]);
    request.core_config = Some(with_bridge.to_string());
    let original = request.core_config.clone();
    assert_eq!(
        crate::routing::apply(
            &mut request,
            &selected(),
            library.routing.active().unwrap(),
            &library.profiles
        )
        .unwrap_err(),
        "legacy_routing_verbatim_bridge_conflict"
    );
    assert_eq!(request.core_config, original);
}
