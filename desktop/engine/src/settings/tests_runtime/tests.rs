use super::*;
use crate::{
    group_chains::GroupChain,
    store::{Group, Profile, ProfileKind},
};
use std::path::Path;
fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    e.store.library.groups.push(Group {
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
        e.store.library.profiles.push(Profile {
            vpn_policy: None,
            id: id.to_string(),
            name: id.to_string(),
            group_id: if *id == "server" { "g" } else { "personal" }.into(),
            kind: ProfileKind::SingBoxOutbound,
            favorite: false,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":1080+i}),
        });
    }
    (dir, e)
}
pub(super) fn core(test: &ProfileTest) -> Value {
    serde_json::from_str(match &test.request {
        Request::Speed(r) => r.config.as_deref().unwrap(),
        Request::Ip(r) => r.config.as_deref().unwrap(),
    })
    .unwrap()
}
#[test]
fn speed_ip_and_latency_share_the_same_group_route_and_have_no_public_listener() {
    let (_d, mut e) = setup();
    let speed = e.speed_test("server").unwrap();
    let ip = e.ip_test("server").unwrap();
    let ping = crate::probes::prepared_request(
        &e.store.library,
        &e.profile("server").unwrap(),
        "http://localhost/",
        1000,
    )
    .unwrap();
    let c = core(&speed);
    assert_eq!(c, core(&ip));
    assert_eq!(
        c,
        serde_json::from_str::<Value>(ping.config.as_deref().unwrap()).unwrap()
    );
    assert_eq!(c["inbounds"], json!([]));
    let out = c["outbounds"].as_array().unwrap();
    for (tag, port) in [
        ("thronium-chain-proxy-0", 1080),
        ("thronium-chain-proxy-1", 1081),
        ("proxy", 1082),
    ] {
        assert_eq!(
            out.iter().find(|p| p["tag"] == tag).unwrap()["server_port"],
            port
        );
    }
    assert_eq!(
        out.iter().find(|p| p["tag"] == "proxy").unwrap()["detour"],
        "thronium-chain-proxy-1"
    );
    assert!(e.rpc.is_none());
}
#[test]
fn tests_ignore_global_routes_and_unrelated_vless_conversion_errors() {
    let (_d, mut e) = setup();
    let before = core(&e.speed_test("server").unwrap());
    e.store.library.profiles[3].kind = ProfileKind::XrayOutbound;
    e.store.library.profiles[3].config =
        json!({"protocol":"vless","streamSettings":{"network":"xhttp"}});
    e.store
        .library
        .preferences
        .vless_overrides
        .insert("other".into(), crate::vless::Core::SingBox);
    e.store.library.routing.profiles[0].route["final"] = json!("profile:other");
    assert_eq!(core(&e.speed_test("server").unwrap()), before);
    assert_eq!(core(&e.ip_test("server").unwrap()), before);
    e.store.library.routing.profiles[0].mode = "direct".into();
    assert_eq!(core(&e.ip_test("server").unwrap()), before);
}
#[test]
fn mixed_vless_group_hops_use_effective_core_and_private_bridges() {
    let (_d, mut e) = setup();
    e.store.library.profiles[0].config = json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"});
    e.store
        .library
        .preferences
        .vless_overrides
        .insert("front".into(), crate::vless::Core::Xray);
    for test in [
        e.speed_test("server").unwrap(),
        e.ip_test("server").unwrap(),
    ] {
        let (need, xray) = match &test.request {
            Request::Speed(r) => (r.need_xray, &r.xray_config),
            Request::Ip(r) => (r.need_xray, &r.xray_config),
        };
        assert_eq!(need, Some(true));
        assert!(xray.as_deref().unwrap().contains("vless"));
        assert!(core(&test)["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["listen"] == "127.0.0.1"
                && i["tag"] != "mixed-in"
                && !i["users"][0]["password"].as_str().unwrap().is_empty()));
    }
}
#[test]
fn result_identity_tracks_profile_group_core_and_presets_but_not_selection_or_names() {
    let (_d, mut e) = setup();
    let speed = e.speed_test("server").unwrap();
    let ip = e.ip_test("server").unwrap();
    let original = e.store.library.clone();
    e.store.library.profiles[0].name = "Renamed".into();
    e.store.library.profiles[1].favorite = true;
    e.store.library.selected = Some("other".into());
    assert!(e.test_matches(&speed));
    assert!(e.test_matches(&ip));
    for what in ["hop", "policy", "core", "preset", "security", "deleted"] {
        e.store.library = original.clone();
        match what {
            "hop" => e.store.library.profiles[0].config["server_port"] = json!(9999),
            "policy" => e.store.library.groups[1].proxy_chain.front = Some("other".into()),
            "core" => {
                e.store
                    .library
                    .preferences
                    .vless_overrides
                    .insert("front".into(), crate::vless::Core::SingBox);
            }
            "preset" => {
                e.store
                    .library
                    .settings
                    .insert("mux_default_on".into(), json!(true));
            }
            "security" => {
                e.store
                    .library
                    .settings
                    .insert("skip_cert".into(), json!(true));
            }
            _ => e.store.library.profiles.retain(|p| p.id != "server"),
        }
        assert!(!e.test_matches(&speed), "{what}");
        assert!(!e.test_matches(&ip), "{what}");
    }
}
#[test]
fn speed_and_ip_use_their_own_saved_test_parameters() {
    let (_d, mut e) = setup();
    let speed = e.speed_test("server").unwrap();
    let ip = e.ip_test("server").unwrap();
    e.store
        .library
        .settings
        .insert("speed_test_mode".into(), json!("simple"));
    assert!(!e.test_matches(&speed));
    assert!(e.test_matches(&ip));
    e.store.library.preferences.ping.timeout_ms += 1;
    assert!(!e.test_matches(&ip));
    let test = e.speed_test("server").unwrap();
    let Request::Speed(r) = test.request else {
        panic!()
    };
    assert_eq!(r.simple_download, Some(true));
    assert_eq!(r.test_current, Some(false));
    assert_eq!(r.test_upload, Some(false));
}
#[test]
fn unsupported_profiles_are_explicit_and_dont_touch_the_connection() {
    let (_d, mut e) = setup();
    e.running = Some("other".into());
    let original = json!(e.store.library);
    for (kind, config) in [
        (ProfileKind::XrayConfig, json!({"outbounds":[]})),
        (ProfileKind::SingBoxOutbound, json!({"type":"wireguard"})),
        // A dynamic pool has no fixed member to measure through.
        (
            ProfileKind::AutoSelector,
            json!({"type":"auto-selector","member_source":{"group":"personal"}}),
        ),
    ] {
        e.store.library.profiles[1].kind = kind;
        e.store.library.profiles[1].config = config;
        assert!(e.speed_test("server").is_err());
        assert!(e.ip_test("server").is_err());
        assert_eq!(e.running.as_deref(), Some("other"));
        assert!(e.rpc.is_none());
    }
    e.store.library = serde_json::from_value(original).unwrap();
}
#[test]
fn ip_response_validates_ip_and_country_without_guessing() {
    assert_eq!(
        ip_result(Some("2001:db8::1"), Some("jp")).unwrap(),
        json!({"ip":"2001:db8::1","countryCode":"JP","provider":"IP2Location"})
    );
    for code in [None, Some(""), Some("-")] {
        assert!(ip_result(Some("203.0.113.5"), code).unwrap()["countryCode"].is_null());
    }
    for (ip, code) in [
        ("not-an-ip", "US"),
        ("127.0.0.1/path", "US"),
        ("203.0.113.1", "secret"),
        ("203.0.113.1", "РФ"),
        ("203.0.113.1", "U1"),
    ] {
        assert_eq!(
            ip_result(Some(ip), Some(code)).unwrap_err(),
            "ip_test_invalid_response"
        );
    }
    assert_eq!(
        check_error(Some("timeout private-secret-url")).unwrap_err(),
        "probe_timeout"
    );
    assert_eq!(
        check_error(Some("bad private-secret-url")).unwrap_err(),
        "probe_failed"
    );
}
#[tokio::test]
async fn cancellation_and_missing_core_fail_without_changing_library_or_primary_session() {
    let (_d, mut e) = setup();
    e.running = Some("other".into());
    let before = json!(e.store.library);
    let (sender, mut receiver) = watch::channel(true);
    for test in [
        e.speed_test("server").unwrap(),
        e.ip_test("server").unwrap(),
    ] {
        assert_eq!(
            test.execute(&mut receiver).await.unwrap_err(),
            "probe_cancelled"
        );
    }
    sender.send(false).unwrap();
    let (_sender, mut receiver) = watch::channel(false);
    assert_eq!(
        e.ip_test("server")
            .unwrap()
            .execute(&mut receiver)
            .await
            .unwrap_err(),
        "probe_core_failed"
    );
    assert_eq!(json!(e.store.library), before);
    assert_eq!(e.running.as_deref(), Some("other"));
}

fn advertised(e: &mut Engine, id: &str) -> bool {
    e.snapshot()
        .profiles
        .iter()
        .find(|p| p["id"] == id)
        .unwrap()["ipSpeedSupported"]
        .as_bool()
        .unwrap()
}
fn refused(e: &mut Engine, id: &str) {
    assert_eq!(e.ip_test(id).err().as_deref(), Some("probe_unsupported"));
    assert_eq!(e.speed_test(id).err().as_deref(), Some("probe_unsupported"));
}
#[test]
fn snapshot_and_both_requests_share_the_profile_capability_matrix() {
    let (_d, mut e) = setup();
    e.store.library.profiles[1].group_id = "personal".into();
    for (kind, config, expected) in [
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
            true,
        ),
        (
            ProfileKind::XrayOutbound,
            json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":1080}}),
            true,
        ),
        (
            ProfileKind::Chain,
            json!({"type":"chain","hops":["front","landing"]}),
            true,
        ),
        (
            ProfileKind::SingBoxConfig,
            json!({"outbounds":[{"type":"direct"}]}),
            true,
        ),
        (
            ProfileKind::XrayConfig,
            json!({"outbounds":[{"protocol":"freedom"}]}),
            true,
        ),
        (
            // Measured through its first member, which is supported.
            ProfileKind::AutoSelector,
            json!({"type":"auto-selector","members":["front"]}),
            true,
        ),
        (
            ProfileKind::AutoSelector,
            json!({"type":"auto-selector","member_source":{"group":"personal"}}),
            false,
        ),
        (
            ProfileKind::ExternalCore,
            json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":1080}),
            false,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard"}),
            false,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.0.0.2/32"],"peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]}),
            true,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.0.0.2/32"],"peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}],"amnezia_wg":{"jc":4,"h1":"100-200"}}),
            true,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","peers":[{"address":"127.0.0.1","port":51820}]}),
            false,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"tailscale"}),
            false,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"openvpn-client"}),
            false,
        ),
        (
            ProfileKind::SingBoxOutbound,
            json!({"type":"openconnect"}),
            false,
        ),
    ] {
        e.store.library.profiles[1].kind = kind;
        e.store.library.profiles[1].config = config;
        assert_eq!(advertised(&mut e, "server"), expected, "{kind:?}");
        let before = json!(e.store.library);
        if expected {
            assert!(e.ip_test("server").is_ok());
            assert!(e.speed_test("server").is_ok());
        } else {
            refused(&mut e, "server");
            assert!(ip_stamp(&e.store.library, "server").is_none());
        }
        assert_eq!(json!(e.store.library), before);
        assert!(e.rpc.is_none());
    }
}
#[test]
fn capability_checks_nested_and_group_hops_without_following_the_hops_own_groups() {
    let (_d, mut e) = setup();
    e.store.library.profiles[0].group_id = "g".into();
    assert!(advertised(&mut e, "server"));
    assert!(e.ip_test("server").is_ok());
    let original = e.store.library.clone();
    for where_ in ["group", "nested", "missing", "cycle", "too-many"] {
        e.store.library = original.clone();
        match where_ {
            "group" => e.store.library.profiles[0].config = json!({"type":"tailscale"}),
            "nested" => {
                e.store.library.profiles[1].kind = ProfileKind::Chain;
                e.store.library.profiles[1].config = json!({"type":"chain","hops":["other"]});
                e.store.library.profiles[3].kind = ProfileKind::Chain;
                e.store.library.profiles[3].config = json!({"type":"chain","hops":["front"]});
                e.store.library.profiles[0].kind = ProfileKind::ExternalCore;
            }
            "missing" => e.store.library.groups[1].proxy_chain.front = Some("missing".into()),
            "cycle" => {
                e.store.library.profiles[1].kind = ProfileKind::Chain;
                e.store.library.profiles[1].config = json!({"type":"chain","hops":["server"]});
            }
            _ => {
                e.store.library.profiles[1].kind = ProfileKind::Chain;
                e.store.library.profiles[1].config =
                    json!({"type":"chain","hops":vec!["other";16]});
            }
        }
        assert!(!advertised(&mut e, "server"), "{where_}");
        refused(&mut e, "server");
    }
}
#[test]
fn losing_capability_invalidates_prepared_results_and_country_observations() {
    let (_d, mut e) = setup();
    let ip = e.ip_test("server").unwrap();
    let speed = e.speed_test("server").unwrap();
    e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    assert!(e
        .store
        .library
        .country_measurements
        .current(&e.store.library, "server")
        .is_some());
    e.store.library.profiles[0].config = json!({"type":"openvpn-client"});
    assert!(!e.test_matches(&ip));
    assert!(!e.test_matches(&speed));
    assert_eq!(
        e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"US"}))
            .unwrap_err(),
        "probe_stale"
    );
    assert!(e
        .store
        .library
        .country_measurements
        .current(&e.store.library, "server")
        .is_none());
}
#[test]
fn incomplete_vpn_drafts_cannot_produce_a_prepared_ip_or_speed_request_or_fingerprint() {
    let (_d, mut e) = setup();
    e.store.library.profiles[1].group_id = "personal".into();
    for protocol in ["openvpn-client", "openconnect"] {
        e.store.library.profiles[1].config = json!({"type":protocol});
        for policy in [
            None,
            Some(crate::vpn_policy::Policy {
                only_advertised_routes: true,
                use_tunnel_dns: true,
                block_outside_dns: true,
            }),
        ] {
            e.store.library.profiles[1].vpn_policy = policy;
            refused(&mut e, "server");
            assert!(ip_stamp(&e.store.library, "server").is_none());
            assert!(crate::country_measurements::fingerprint(&e.store.library, "server").is_none());
        }
    }
}
#[test]
#[cfg(target_os = "linux")]
fn ip_speed_and_http_share_disposable_vpn_readiness_without_touching_connection() {
    let (_d, mut e) = setup();
    e.store.library.profiles[1].group_id = "personal".into();
    e.running = Some("other".into());
    for config in [
        json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"username":"synthetic","password":"synthetic"}),
        json!({"type":"openconnect","server":"https://127.0.0.1:4443","flavor":"anyconnect","username":"synthetic","password":"synthetic"}),
    ] {
        e.store.library.profiles[1].config = config;
        let before = json!(e.store.library);
        let ip = e.ip_test("server").unwrap();
        let speed = e.speed_test("server").unwrap();
        let Request::Ip(ip_request) = &ip.request else {
            panic!()
        };
        let Request::Speed(speed_request) = &speed.request else {
            panic!()
        };
        assert_eq!(ip_request.vpn_endpoint_tags, vec!["proxy"]);
        assert_eq!(speed_request.vpn_endpoint_tags, vec!["proxy"]);
        assert_eq!(ip_request.vpn_status_timeout_ms, Some(10_000));
        assert_eq!(speed_request.vpn_status_timeout_ms, Some(10_000));
        assert_eq!(ip.vpn_ready_ms, 10_000);
        assert_eq!(speed.vpn_ready_ms, 10_000);
        assert!(advertised(&mut e, "server"));
        let request = crate::probes::prepared_request(
            &e.store.library,
            &e.profile("server").unwrap(),
            "http://127.0.0.1/",
            1000,
        )
        .unwrap();
        assert_eq!(request.vpn_endpoint_tags, vec!["proxy"]);
        assert_eq!(request.vpn_status_timeout_ms, Some(10_000));
        assert_eq!(json!(e.store.library), before);
        assert_eq!(e.running.as_deref(), Some("other"));
        assert!(e.rpc.is_none());
    }
}

#[test]
fn diagnostics_accept_only_the_requested_bridge_tag() {
    assert!(matches_tag(&["proxy".into()], Some("proxy")));
    assert!(matches_tag(
        &["owned-client-bridge".into()],
        Some("owned-client-bridge")
    ));
    assert!(!matches_tag(&["owned-client-bridge".into()], Some("proxy")));
    assert!(!matches_tag(&["owned-client-bridge".into()], None));
    assert!(!matches_tag(&[], Some("proxy")));
    assert!(!matches_tag(
        &["proxy".into(), "extra".into()],
        Some("proxy")
    ));
}
