use super::*;
use crate::{group_chains::GroupChain, store::Group, ProfileDraft};

fn wireguard() -> Value {
    json!({"type":"wireguard","private_key":"cHJpdmF0ZS1rZXk=","address":["10.177.43.2/32","fd00:43::2/128"],"mtu":1420,
        "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGljLWtleQ==","pre_shared_key":"cHNr","allowed_ips":["10.177.43.1/32"]}],
        "amnezia_wg":{"jc":4,"jmin":10,"jmax":50,"h1":"100-200","random_trailers":true}})
}
fn setup(config: Value) -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let id = engine
        .save_profile(ProfileDraft {
            id: None,
            name: "Owned WG diagnostics".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            vpn_policy: Default::default(),
            config,
        })
        .unwrap();
    (dir, engine, id)
}

#[test]
fn wireguard_ip_speed_and_http_share_one_endpoint_box_without_listeners() {
    let (_dir, mut engine, id) = setup(wireguard());
    let ip = engine.ip_test(&id).unwrap();
    let speed = engine.speed_test(&id).unwrap();
    let http = crate::probes::prepared_request(
        &engine.store.library,
        &engine.profile(&id).unwrap(),
        "http://localhost/",
        1000,
    )
    .unwrap();
    let core = super::tests::core(&ip);
    assert_eq!(core, super::tests::core(&speed));
    assert_eq!(
        core,
        serde_json::from_str::<Value>(http.config.as_deref().unwrap()).unwrap()
    );
    let endpoint = &core["endpoints"][0];
    assert_eq!(endpoint["type"], "wireguard");
    assert_eq!(endpoint["tag"], "proxy");
    assert_eq!(endpoint["amnezia_wg"], wireguard()["amnezia_wg"]);
    assert_eq!(endpoint["peers"], wireguard()["peers"]);
    assert_eq!(core["inbounds"], json!([]));
    assert_eq!(core["services"], json!([]));
    assert_eq!(core["route"]["final"], "proxy");
    assert!(core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["type"] == "direct"));
    assert!(http.vpn_endpoint_tags.is_empty());
    assert_eq!(http.need_xray, Some(false));
    assert_eq!(http.outbound_tags, vec!["proxy"]);
    assert_eq!(
        (ip.kind_name(), ip.transport()),
        ("ip", "wireguard-endpoint")
    );
    assert_eq!(speed.kind_name(), "speed");
    assert!(engine.rpc.is_none());
}

#[test]
fn wireguard_key_and_peer_changes_invalidate_pending_measurements_and_country() {
    let (_dir, mut engine, id) = setup(wireguard());
    let ip = engine.ip_test(&id).unwrap();
    engine
        .remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    let cache = std::fs::read_to_string(_dir.path().join("exit-countries-v1.json")).unwrap();
    assert!(!cache.contains("cHJpdmF0ZS1rZXk=") && !cache.contains("cHNr"));
    let baseline = engine.store.library.clone();
    for change in ["private_key", "peer-port", "peer-key", "group-front"] {
        engine.store.library = baseline.clone();
        match change {
            "private_key" => {
                engine.store.library.profiles[0].config["private_key"] = json!("b3RoZXI=")
            }
            "peer-port" => {
                engine.store.library.profiles[0].config["peers"][0]["port"] = json!(51821)
            }
            "peer-key" => {
                engine.store.library.profiles[0].config["peers"][0]["public_key"] =
                    json!("b3RoZXI=")
            }
            _ => {
                engine.store.library.groups.push(Group {
                    id: "g".into(),
                    name: "Wrapped".into(),
                    collapsed: false,
                    auto_clear_unavailable: false,
                    subscription: None,
                    proxy_chain: GroupChain {
                        front: Some("missing-front".into()),
                        landing: None,
                    },
                });
                engine.store.library.profiles[0].group_id = "g".into();
            }
        }
        assert!(
            !ip.matches(&engine.store.library, &Default::default()),
            "{change}"
        );
        assert_eq!(
            engine
                .remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"US"}))
                .unwrap_err(),
            "probe_stale"
        );
    }
    engine.store.library = baseline;
    engine.store.library.profiles[0].name = "Renamed".into();
    engine.store.library.profiles[0].favorite = true;
    assert!(ip.matches(&engine.store.library, &Default::default()));
}

#[test]
fn wireguard_contexts_a_disposable_core_cannot_own_are_refused_before_any_core() {
    let (_dir, mut engine, id) = setup(wireguard());
    let baseline = engine.store.library.clone();
    for (key, value) in [
        ("system", json!(true)),
        ("name", json!("wg-owned")),
        ("detour", json!("other")),
    ] {
        engine.store.library = baseline.clone();
        engine.store.library.profiles[0].config[key] = value;
        assert!(
            !supported(
                &engine.store.library,
                &engine.store.library.profiles[0],
                &Default::default()
            ),
            "{key}"
        );
        assert_eq!(
            engine.ip_test(&id).err().as_deref(),
            Some("probe_unsupported")
        );
        assert_eq!(
            crate::probes::prepared_request(
                &engine.store.library,
                &engine.store.library.profiles[0],
                "http://localhost/",
                1000
            )
            .unwrap_err(),
            "probe_endpoint_context_unsupported",
            "{key}"
        );
    }
    engine.store.library = baseline;
    engine.store.library.profiles[0].config["type"] = json!("tailscale");
    assert!(!supported(
        &engine.store.library,
        &engine.store.library.profiles[0],
        &Default::default()
    ));
    assert_eq!(
        engine.speed_test(&id).err().as_deref(),
        Some("probe_unsupported")
    );
    assert!(engine.rpc.is_none());
}
