use super::*;

fn setup(protocol: &str) -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let id = engine.save_profile(crate::ProfileDraft {
        id: None, name: "Owned VPN diagnostics".into(), group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound, vpn_policy: Default::default(),
        config: json!({"type":protocol,"server":"127.0.0.1","server_port":4443,"username":"synthetic-user","password":"synthetic-password"}),
    }).unwrap();
    (dir, engine, id)
}

#[test]
fn vpn_credentials_policy_and_context_invalidate_measurements_and_country() {
    for protocol in ["openvpn-client", "openconnect"] {
        let (_dir, mut engine, id) = setup(protocol);
        let ip = engine.ip_test(&id).unwrap();
        let speed = engine.speed_test(&id).unwrap();
        engine
            .remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
            .unwrap();
        let baseline = engine.store.library.clone();
        for change in ["password", "policy", "managed-context", "group-context"] {
            engine.store.library = baseline.clone();
            match change {
                "password" => {
                    engine.store.library.profiles[0].config["password"] =
                        json!("other-synthetic-password")
                }
                "policy" => {
                    engine.store.library.profiles[0].vpn_policy = Some(crate::vpn_policy::Policy {
                        only_advertised_routes: true,
                        use_tunnel_dns: true,
                        block_outside_dns: true,
                    })
                }
                "managed-context" => {
                    engine.store.library.preferences.connection_mode =
                        crate::system_proxy::ConnectionMode::Tun
                }
                _ => {
                    engine.store.library.groups[0].proxy_chain.front = Some("missing-front".into())
                }
            }
            assert!(!engine.test_matches(&ip), "{protocol}/{change}");
            assert!(!engine.test_matches(&speed), "{protocol}/{change}");
            assert!(engine
                .store
                .library
                .country_measurements
                .current(&engine.store.library, &id)
                .is_none());
            assert_eq!(
                engine
                    .remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"US"}))
                    .unwrap_err(),
                "probe_stale"
            );
        }
        assert!(engine.rpc.is_none());
    }
}

#[test]
fn vpn_ip_speed_refuse_contexts_that_cannot_own_an_isolated_test() {
    for protocol in ["openvpn-client", "openconnect"] {
        let (_dir, mut engine, id) = setup(protocol);
        let baseline = engine.store.library.clone();
        for (key, value) in [
            ("system", json!(true)),
            ("name", json!("custom-interface")),
            ("detour", json!("other")),
            ("password", json!("{otp}")),
            ("token", json!("synthetic-token")),
        ] {
            engine.store.library = baseline.clone();
            engine.store.library.profiles[0].config[key] = value;
            assert!(
                !supported(
                    &engine.store.library,
                    &engine.store.library.profiles[0],
                    &Default::default()
                ),
                "{protocol}/{key}"
            );
            assert_eq!(
                engine.ip_test(&id).err().as_deref(),
                Some("probe_unsupported")
            );
            assert_eq!(
                engine.speed_test(&id).err().as_deref(),
                Some("probe_unsupported")
            );
            assert!(engine.rpc.is_none());
        }
    }
}

fn state(name: &str, connected: bool, auth: bool) -> proto::VpnEndpointStatus {
    proto::VpnEndpointStatus {
        tag: Some("proxy".into()),
        state: Some(name.into()),
        connected: Some(connected),
        auth_failed: Some(auth),
        ..Default::default()
    }
}

#[test]
fn failed_vpn_measurements_distinguish_auth_and_connected_state_strictly() {
    let requested = vec!["proxy".into()];
    assert_eq!(
        measurement_error(
            Some("synthetic failure"),
            &requested,
            &[state("connected", true, false)]
        )
        .unwrap_err(),
        "probe_vpn_diagnostic_failed"
    );
    assert_eq!(
        measurement_error(
            Some("synthetic failure"),
            &requested,
            &[state("error", false, true)]
        )
        .unwrap_err(),
        "probe_vpn_auth_required"
    );
    assert_eq!(
        measurement_error(
            Some("certificate failure"),
            &requested,
            &[state("connecting", false, false)]
        )
        .unwrap_err(),
        "probe_tls_failed"
    );
    assert_eq!(
        measurement_error(
            Some("context deadline exceeded"),
            &requested,
            &[state("error", false, false)]
        )
        .unwrap_err(),
        "probe_timeout"
    );
    let mut pending = state("auth-pending", false, false);
    pending.challenge = Some(proto::VpnChallenge {
        id: Some("owned-challenge".into()),
        endpoint_tag: Some("proxy".into()),
        ..Default::default()
    });
    assert_eq!(
        measurement_error(Some("failed"), &requested, &[pending.clone()]).unwrap_err(),
        "probe_vpn_auth_required"
    );
    pending.challenge.as_mut().unwrap().endpoint_tag = Some("unrelated".into());
    assert_eq!(
        measurement_error(Some("failed"), &requested, &[pending]).unwrap_err(),
        "probe_failed"
    );
    for statuses in [
        vec![state("connected", false, true)],
        vec![state("connected", true, false), state("error", false, true)],
    ] {
        assert_eq!(
            measurement_error(Some("failed"), &requested, &statuses).unwrap_err(),
            "probe_failed"
        );
    }
    let good = state("connected", true, false);
    assert!(measurement_error(Some(""), &requested, std::slice::from_ref(&good)).is_err());
    assert!(measurement_error(Some("failed"), &[], &[good]).is_err());
    assert!(measurement_error(Some(""), &requested, &[]).is_ok());
}

#[test]
fn ordinary_country_stamp_keeps_its_existing_shape() {
    let (_dir, mut engine, id) = setup("openvpn-client");
    assert_eq!(
        ip_stamp(&engine.store.library, &id)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        6
    );
    engine.store.library.profiles[0].config = json!({"type":"direct"});
    assert_eq!(
        ip_stamp(&engine.store.library, &id)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(engine.ip_test(&id).unwrap().vpn_ready_ms, 0);
}
