use super::*;
use crate::{Engine, ProfileDraft};
use std::path::Path;
fn profile() -> Profile {
    Profile {
        id: "full-sing".into(),
        name: "Client69".into(),
        group_id: "personal".into(),
        favorite: false,
        vpn_policy: None,
        kind: ProfileKind::SingBoxConfig,
        config: json!({"log":{"output":"/must/not/write","level":"debug"},
            "inbounds":[{"type":"http","tag":"http","listen":"0.0.0.0","listen_port":1234},{"type":"mixed","tag":"client","listen":"::","listen_port":1235}],
            "outbounds":[{"type":"direct","tag":"proxy"},{"type":"socks","tag":"other","server":"127.0.0.1","server_port":2345}],
            "dns":{"servers":[{"type":"udp","tag":"dns","server":"1.1.1.1"}],"final":"dns"},
            "route":{"final":"proxy","default_domain_resolver":"dns","rules":[{"type":"logical","mode":"and","rules":[{"inbound":["client"]},{"domain_suffix":["blocked.test"]}],"action":"reject"}],
                "rule_set":[{"type":"inline","tag":"inline","rules":[{"domain":["inline.test"]}]}]}}),
    }
}
#[test]
fn a_private_bridge_enters_client_router_without_renaming_or_reordering_source_outbounds() {
    let p = profile();
    let before = p.config.clone();
    assert!(supported(&Library::default(), &p));
    let request =
        crate::probes::prepared_request(&Library::default(), &p, "https://target.test/", 1500)
            .unwrap();
    let config: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(config["dns"], before["dns"]);
    assert_eq!(config["route"], before["route"]);
    assert_eq!(
        &config["outbounds"].as_array().unwrap()[..2],
        before["outbounds"].as_array().unwrap().as_slice()
    );
    let bridge = &config["outbounds"][2];
    assert_eq!(bridge["tag"], request.outbound_tags[0]);
    assert_ne!(bridge["tag"], "proxy");
    assert_eq!(bridge["server"], "127.0.0.1");
    assert_eq!(bridge["server_port"], config["inbounds"][0]["listen_port"]);
    assert_eq!(config["inbounds"][0]["tag"], "client");
    assert_eq!(config["inbounds"][0]["type"], "socks");
    assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    assert!(!config.to_string().contains("/must/not/write"));
    assert_eq!(request.use_default_outbound, Some(false));
    assert_eq!(request.test_current, Some(false));
    assert_eq!(request.need_xray, Some(false));
    assert!(request.xray_config.is_none());
    assert_eq!(p.config, before);
}
#[test]
fn absent_ingress_and_implicit_default_outbound_remain_supported() {
    let mut p = profile();
    p.config = json!({"outbounds":[{"type":"direct"}]});
    let a = request(&p, "http://test/", 1000).unwrap();
    let b = request(&p, "http://test/", 1000).unwrap();
    assert_ne!(a.outbound_tags, b.outbound_tags);
    let config: Value = serde_json::from_str(a.config.as_ref().unwrap()).unwrap();
    assert!(config.get("route").is_none());
    assert_eq!(config["outbounds"][0], json!({"type":"direct"}));
}
#[test]
fn external_state_endpoints_and_background_outbounds_are_explicitly_refused() {
    // Sections that own host state are dropped for the check, as Qt drops the
    // client's inbounds for its own test configuration; the rest is kept.
    let mut p = profile();
    for key in ["experimental", "services", "network_namespaces"] {
        p.config[key] = json!([{"type":"resolved","tag":"r"}]);
    }
    p.config["ntp"] = json!({"server":"192.0.2.53"});
    p.config["a_future_section"] = json!({"kept": true});
    assert!(client_shape(&p.config));
    let config: Value = serde_json::from_str(
        request(&p, "http://test/", 1000)
            .unwrap()
            .config
            .unwrap()
            .as_str(),
    )
    .unwrap();
    for key in ["experimental", "services", "network_namespaces"] {
        assert!(config.get(key).is_none(), "{key}");
    }
    assert_eq!(config["ntp"], p.config["ntp"]);
    assert_eq!(config["a_future_section"], json!({"kept": true}));
    let mut p = profile();
    p.config["endpoints"] = json!([{"type":"tun"}]);
    assert!(!client_shape(&p.config));
    for kind in [
        "urltest",
        "selector",
        "auto-selector",
        "wireguard",
        "tailscale",
        "openconnect",
        "openvpn-client",
        "tor",
    ] {
        let mut p = profile();
        p.config["outbounds"][0]["type"] = json!(kind);
        assert!(!client_shape(&p.config), "{kind}");
    }
    for kind in ["remote", "local"] {
        let mut p = profile();
        p.config["route"]["rule_set"][0]["type"] = json!(kind);
        assert!(!client_shape(&p.config));
    }
}
#[test]
fn ingress_of_other_listeners_stays_in_the_configuration_without_deciding_the_check() {
    // Qt tests a complete client with its inbounds cleared; here the check has
    // its own ingress under the client's tag, so policy bound to another
    // listener stays in the configuration and simply never matches.
    let mut p = profile();
    p.config["route"]["rules"][0]["rules"][1]["Inbound"] = json!(["http"]);
    p.config["dns"]["rules"] = json!([{"inbound":["http"],"server":"dns"}]);
    p.config["inbounds"][0]["users"] = json!([{"username":"user","password":"synthetic"}]);
    p.config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"tun","tag":"tun-in"}));
    p.config["route"]["rules"][0]["auth_user"] = json!(["user"]);
    assert!(client_shape(&p.config));
    let request = request(&p, "http://test/", 1000).unwrap();
    let config: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(config["route"]["rules"], p.config["route"]["rules"]);
    assert_eq!(config["dns"]["rules"], p.config["dns"]["rules"]);
    // One anonymous ingress under the client's own tag, no host listener.
    assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(config["inbounds"][0]["type"], "socks");
    // The client's own mixed listener names the check's ingress, as it does
    // without other listeners, so its policy still decides.
    assert_eq!(config["inbounds"][0]["tag"], "client");
    assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    // A configuration whose inbounds are not a list is still not a client.
    let mut broken = profile();
    broken.config["inbounds"] = json!({"type": "socks"});
    assert!(!client_shape(&broken.config));
}
#[test]
fn full_sing_ip_speed_and_country_track_saved_inline_client_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("/missing-core69")).unwrap();
    let p = profile();
    let draft: ProfileDraft = serde_json::from_value(
        json!({"name":p.name,"groupId":p.group_id,"kind":p.kind,"config":p.config}),
    )
    .unwrap();
    let id = e.save_profile(draft).unwrap();
    let ip = e.ip_test(&id).unwrap();
    let speed = e.speed_test(&id).unwrap();
    assert!(
        ip.matches(&e.store.library, &Default::default())
            && speed.matches(&e.store.library, &Default::default())
    );
    e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    assert!(e
        .store
        .library
        .country_measurements
        .current(&e.store.library, &id)
        .is_some());
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap()
        .config["route"]["rule_set"][0]["rules"][0]["domain"] = json!(["new.test"]);
    assert!(
        !ip.matches(&e.store.library, &Default::default())
            && !speed.matches(&e.store.library, &Default::default())
    );
    assert!(e
        .store
        .library
        .country_measurements
        .current(&e.store.library, &id)
        .is_none());
    assert!(e.rpc.is_none());
}
#[test]
fn own_userspace_endpoints_are_readiness_dependencies_but_host_interfaces_are_refused() {
    let mut p = profile();
    p.config["endpoints"] = json!([
        {"type":"openvpn-client","tag":"vpn","server":"192.0.2.10","server_port":1194,"username":"u","password":"p"},
        {"type":"wireguard","tag":"wg","private_key":"cHJpdmF0ZQ==","address":["10.7.0.2/32"],
         "peers":[{"address":"192.0.2.11","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]}
    ]);
    assert!(supported(&Library::default(), &p));
    assert!(crate::probes::vpn::involves(&Library::default(), &p));
    let request =
        crate::probes::prepared_request(&Library::default(), &p, "https://target.test/", 1500)
            .unwrap();
    assert_eq!(request.vpn_endpoint_tags, ["vpn"]);
    assert_eq!(request.vpn_status_timeout_ms, Some(10_000));
    let config: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(config["endpoints"], p.config["endpoints"]);
    // Qt keeps the client's endpoints; the disposable core owns no host device,
    // so the check runs them in userspace instead of refusing the client.
    let mut host = p.clone();
    host.config["endpoints"][1]["system"] = json!(true);
    host.config["endpoints"][1]["name"] = json!("tun9");
    assert!(supported(&Library::default(), &host));
    let adapted: Value = serde_json::from_str(
        crate::probes::prepared_request(&Library::default(), &host, "https://target.test/", 1500)
            .unwrap()
            .config
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(adapted["endpoints"][1].get("system"), None);
    assert_eq!(adapted["endpoints"][1].get("name"), None);
    assert_eq!(
        adapted["endpoints"][1]["private_key"],
        p.config["endpoints"][1]["private_key"]
    );
    let mut duplicate = p.clone();
    duplicate.config["endpoints"][1]["tag"] = json!("vpn");
    assert!(!supported(&Library::default(), &duplicate));
    let mut tailscale = p.clone();
    tailscale.config["endpoints"][0] = json!({"type":"tailscale","tag":"ts"});
    assert!(!supported(&Library::default(), &tailscale));
}
#[test]
fn a_complete_client_with_a_fixture_shaped_openvpn_endpoint_is_issued_as_a_disposable_vpn_test() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let id = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Complete client with OpenVPN".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxConfig,
            config: json!({"log":{"level":"warn"},
                "endpoints":[{"type":"openvpn-client","tag":"user-vpn","server":"127.0.0.1","server_port":1194,"network":"udp",
                    "system":false,"auth_retry":"none","username":"u","password":"p",
                    "tls":{"certificate_path":"/tmp/ca.pem","server_name":"vpn.fixture.invalid"}}],
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"final":"user-vpn"}}),
        })
        .unwrap();
    let profile = e.profile(&id).unwrap();
    assert!(supported(&e.store.library, &profile));
    let request =
        crate::probes::prepared_request(&e.store.library, &profile, "http://10.0.0.1/", 1500)
            .unwrap();
    assert_eq!(request.vpn_endpoint_tags, ["user-vpn"]);
    let run = e.start_ping(vec![id.clone()]).unwrap();
    let probe = e.next_url_test(&run.id);
    let batch = e.url_tests_snapshot().unwrap();
    assert!(probe.is_some(), "not issued: {:?}", batch.entries[0].error);
    assert!(probe.unwrap().is_disposable_vpn());
}
#[test]
fn stand_shaped_complete_client_is_supported_with_spaced_credentials_and_a_certificate_path() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let config: Value = serde_json::from_str(r#"{"endpoints":[{"auth_retry":"none","network":"udp","password":" credentials-fixture-new-password-31 ","server":"127.0.0.1","server_port":53932,"system":false,"tag":"user-vpn","tls":{"certificate_path":"/tmp/x/certificate.pem","server_name":"vpn.fixture.invalid"},"type":"openvpn-client","username":" credentials-fixture-new-user "}],"log":{"level":"warn"},"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"user-vpn"}}"#).unwrap();
    assert!(client_shape(&config), "client_shape");
    let id = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Stand client".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxConfig,
            config,
        })
        .unwrap();
    let profile = e.profile(&id).unwrap();
    assert!(supported(&e.store.library, &profile), "supported");
    let run = e
        .start_url_tests(crate::probes::Options {
            ids: vec![id.clone()],
            url: "http://10.79.80.1:1/chain".into(),
            timeout_ms: 5000,
            concurrency: None,
        })
        .unwrap();
    let probe = e.next_url_test(&run.id);
    let batch = e.url_tests_snapshot().unwrap();
    assert!(probe.is_some(), "not issued: {:?}", batch.entries[0].error);
}
