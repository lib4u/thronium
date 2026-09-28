use super::{runtime::*, *};
use crate::{proto, store::ProfileKind, Engine, ProfileDraft};
use std::{collections::HashSet, path::Path};

fn fixture() -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Synthetic external".into(),
        group_id: "personal".into(),
        kind: ProfileKind::ExternalCore,
        config: json!({"type":"extracore","name":"Original name","socks_address":"127.0.0.1","socks_port":32124,
            "extra_core_path":"/tmp/nonexistent-synthetic-private-path","extra_core_args":"  --literal '$HOME; no-shell' --config '%s'  ",
            "extra_core_conf":"synthetic-private-secret\r\n  opaque = true\n","no_logs":true}),
    }
}
fn setup() -> (tempfile::TempDir, Engine, String) {
    let d = tempfile::tempdir().unwrap();
    let mut e = Engine::open(d.path(), Path::new("no-core-must-not-start")).unwrap();
    let id = e.save_profile(fixture()).unwrap();
    (d, e, id)
}
fn frozen(id: &str, request: proto::LoadConfigReq) -> crate::connection::ActiveConnection {
    crate::connection::ActiveConnection {
        id: id.into(),
        profiles: HashSet::from([id.into()]),
        groups: HashSet::from(["personal".into()]),
        request,
        routing_revision: 0,
        system_port: None,
        tun: false,
        external_instance: Some("0123456789abcdef0123456789abcdef".into()),
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    }
}

#[tokio::test]
async fn external_preview_is_lossless_private_and_active_request_is_frozen() {
    let (_d, mut e, id) = setup();
    let p = e.profile(&id).unwrap();
    let source = p.config.clone();
    let request = e.build(&p).unwrap();
    assert_eq!(request.need_extra_process, Some(true));
    assert_eq!(request.need_xray, Some(false));
    assert_eq!(
        request.extra_process_path.as_deref(),
        source["extra_core_path"].as_str()
    );
    assert_eq!(
        request.extra_process_args.as_deref(),
        source["extra_core_args"].as_str()
    );
    assert_eq!(
        request.extra_process_conf.as_deref(),
        source["extra_core_conf"].as_str()
    );
    assert_eq!(request.extra_no_out, Some(true));
    let options = request.extra_process_options.as_ref().unwrap();
    assert_eq!(
        (options.version, options.startup_timeout_ms),
        (Some(1), Some(10000))
    );
    assert_eq!(port(&request), Some(32124));
    let config: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    // Qt carries whatever the external core carries; the pinned TCP of the
    // first stage would have kept WARP's own UDP out of it.
    assert!(config["outbounds"][0]["network"].is_null());
    // The path is in the rules that keep the core's own traffic out; what it is
    // started with, and the opaque configuration it is given, are not.
    assert!(!config.to_string().contains("synthetic-private-secret"));
    assert!(!config.to_string().contains("--literal"));
    let preview = e.connection_configuration(&id, false).await.unwrap();
    assert_eq!(preview["parts"][1]["name"], "external-core");
    assert_eq!(
        preview["parts"][1]["config"],
        configuration(&request).unwrap()
    );
    assert!(e.rpc.is_none());
    e.running = Some(id.clone());
    e.active_connection = Some(frozen(&id, request.clone()));
    let mut edited = fixture();
    edited.id = Some(id.clone());
    edited.config["extra_core_conf"] = json!("new private source");
    assert_eq!(
        e.save_profile(edited).err().as_deref(),
        Some("stop_before_editing")
    );
    // Model an independent source refresh in memory: runtime must still use its frozen request.
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap()
        .config["extra_core_conf"] = json!("new private source");
    assert_eq!(
        e.connection_configuration(&id, true).await.unwrap()["parts"][1]["config"],
        configuration(&request).unwrap()
    );
    assert_eq!(
        e.connection_configuration(&id, false).await.unwrap()["parts"][1]["config"]
            ["extra_core_conf"],
        "new private source"
    );
    let snapshot = serde_json::to_string(&e.snapshot()).unwrap();
    for secret in [
        "synthetic-private",
        "new private source",
        "extra_core_path",
        "extra_core_conf",
        "0123456789abcdef",
    ] {
        assert!(!snapshot.contains(secret));
    }
    assert!(e.rpc.is_none());
}

#[tokio::test]
async fn external_context_rejects_before_core_start_or_asset_side_effects() {
    let (d, mut e, id) = setup();
    let before = serde_json::to_value(&e.store.library).unwrap();
    // Qt's own compositions: a tunnel, a system proxy and WARP all carry an
    // external core, and each configuration keeps the core's own traffic out.
    for mode in [
        crate::system_proxy::ConnectionMode::Tun,
        crate::system_proxy::ConnectionMode::SystemProxy,
    ] {
        e.store.library.preferences.connection_mode = mode;
        let request = e.build(&e.profile(&id).unwrap()).unwrap();
        let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
        assert!(
            core["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["outbound"] == "direct"
                        && rule["process_path"][0] == "/tmp/nonexistent-synthetic-private-path"
                }),
            "every connection mode keeps the external core's own traffic direct"
        );
        assert!(e.rpc.is_none());
    }
    e.store.library.preferences.connection_mode = crate::system_proxy::ConnectionMode::Local;
    e.store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    e.store.library.settings.remove("enable_warp");
    e.store.library.routing.profiles[0].legacy_constraints =
        Some(crate::routing::LegacyRoutingConstraints {
            warp_enabled: false,
            version: 2,
            xray_dns_strategy: Some("UseIP".into()),
            ..Default::default()
        });
    assert_eq!(
        e.connection_configuration(&id, false)
            .await
            .err()
            .as_deref(),
        Some("external_routing_unsupported")
    );
    assert_eq!(
        e.check(&e.profile(&id).unwrap()).await.err().as_deref(),
        Some("external_routing_unsupported")
    );
    e.store.library.routing.profiles[0].legacy_constraints = None;
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    assert!(e.rpc.is_none());
    assert!(!d.path().join("geodata").exists());
    assert!(!d.path().join("external-core").exists());
}

#[tokio::test]
async fn external_provider_policy_blocks_before_any_geodata_or_core_work() {
    let (d, mut e, id) = setup();
    let settings=serde_json::from_value(json!({"url":"https://example.invalid/private-subscription","userAgent":"fixture","viaProxy":false,"useProviderRouting":true,"intervalMinutes":0})).unwrap();
    e.store.library.groups[0].subscription = Some(crate::subscriptions::Subscription {
        settings,
        metadata: crate::subscriptions::metadata::Metadata {
            routing: Some(crate::subscriptions::provider_routing::ProviderRouting {
                action: "add".into(),
                config: json!({"Geositeurl":"https://example.invalid/private-geodata","ProxySites":["geosite:google"]}),
                error: None,
            }),
            ..Default::default()
        },
        updated_at: None,
        usage: None,
        managed_ids: vec![],
        last_update: None,
    });
    assert!(crate::geodata::enabled(
        &e.profile(&id).unwrap(),
        &e.store.library
    ));
    for error in [
        e.connect(&id).await.err(),
        e.check(&e.profile(&id).unwrap()).await.err(),
        e.connection_configuration(&id, false).await.err(),
    ] {
        assert_eq!(error.as_deref(), Some("external_routing_unsupported"));
    }
    assert!(e.rpc.is_none());
    assert!(!d.path().join("xray-assets").exists());
}

#[test]
fn external_diagnostics_never_drop_process_fields_into_an_ordinary_test_request() {
    let (_d, mut e, id) = setup();
    let p = e.profile(&id).unwrap();
    assert_eq!(
        crate::probes::prepared_request(&e.store.library, &p, "http://127.0.0.1:30000", 1000)
            .err()
            .as_deref(),
        Some("probe_unsupported")
    );
    assert_eq!(
        e.speed_test(&id).err().as_deref(),
        Some("probe_unsupported")
    );
    assert_eq!(e.ip_test(&id).err().as_deref(), Some("probe_unsupported"));
}

#[test]
fn external_saved_kind_does_not_override_an_edited_validation_draft() {
    let (_d, e, id) = setup();
    let mut draft = e.profile(&id).unwrap();
    draft.kind = ProfileKind::SingBoxOutbound;
    draft.config = json!({"type":"direct"});
    let built = e.build(&draft).unwrap();
    assert_eq!(built.need_extra_process, Some(false));
    assert_eq!(e.profile(&id).unwrap().kind, ProfileKind::ExternalCore);
}

#[test]
fn external_effective_listener_collision_is_rejected_after_settings_compilation() {
    let (_d, mut e, id) = setup();
    e.store.library.preferences.inbound_port = 32124;
    assert_eq!(
        e.build(&e.profile(&id).unwrap()).err().as_deref(),
        Some("external_port_conflict")
    );
    e.store.library.preferences.inbound_port = 2080;
    e.store.library.settings.insert(
        "custom_inbound".into(),
        json!([{"type":"socks","tag":"custom","listen":"127.0.0.1","listen_port":32124}]),
    );
    assert_eq!(
        e.build(&e.profile(&id).unwrap()).err().as_deref(),
        Some("external_port_conflict")
    );
    e.store.library.settings.remove("custom_inbound");
    assert!(e.build(&e.profile(&id).unwrap()).is_ok());
    for (key, value) in [
        ("core_box_clash_enabled", json!(true)),
        ("core_box_clash_api", json!(32124)),
    ] {
        e.store.library.settings.insert(key.into(), value);
    }
    assert_eq!(
        e.build(&e.profile(&id).unwrap()).err().as_deref(),
        Some("external_port_conflict"),
        "the Clash API controller listens on the external SOCKS port"
    );
}

#[test]
fn external_membership_is_not_silently_adapted_into_chains_or_selectors() {
    let (_d, mut e, id) = setup();
    let before = json!(e.store.library);
    let result = e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Unsupported".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: json!({"type":"auto-selector","members":[id]}),
    });
    assert!(
        result.is_err(),
        "a pool switches between members; an external core is a program, not a server"
    );
    assert_eq!(json!(e.store.library), before);
    let ordinary = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Ordinary".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();
    let pool = ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Dynamic".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: json!({"type":"auto-selector","member_source":{"group_id":"personal","name_regex":"","exclude_regex":""}}),
    };
    assert_eq!(
        e.preview_selector(pool).unwrap(),
        json!({"total":1,"members":[{"id":ordinary,"name":"Ordinary"}]})
    );
    e.store.library.groups[0].proxy_chain.front = Some(ordinary.clone());
    assert_eq!(
        context(&e.store.library, &e.profile(&id).unwrap())
            .err()
            .as_deref(),
        Some("external_chain_unsupported")
    );
}

#[tokio::test]
async fn external_cleanup_waits_for_listener_release_without_connecting_or_killing() {
    let (_d, mut e, _id) = setup();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(8).unwrap();
    let p = listener.local_addr().unwrap().port();
    e.external_cleanup_ports.insert(p);
    let started = tokio::time::Instant::now();
    let release = tokio::spawn(async move {
        // A bind-only probe must never create an accepted stream.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        drop(listener);
    });
    e.wait_external_cleanup().await.unwrap();
    release.await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
    assert!(e.external_cleanup_ports.is_empty());
}

#[tokio::test]
async fn external_cleanup_ignores_time_wait_but_waits_for_still_open_server_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_d, mut e, _id) = setup();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(8).unwrap();
    let p = listener.local_addr().unwrap().port();
    let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, p))
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    server.write_all(b"x").await.unwrap();
    server.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    drop(client);
    drop(server);
    drop(listener);
    e.external_cleanup_ports.insert(p);
    tokio::time::timeout(
        std::time::Duration::from_millis(250),
        e.wait_external_cleanup(),
    )
    .await
    .unwrap()
    .unwrap();
}

fn add(e: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind,
        config,
    })
    .unwrap()
}

/// Qt allows one external core in a chain and only where sing-box dials its
/// local server directly: the first physical hop. Everything the chain holds
/// after it is carried by the core the person runs.
#[test]
fn a_chain_dials_the_external_core_first_and_keeps_its_own_traffic_out() {
    let (_d, mut e, id) = setup();
    let exit = add(
        &mut e,
        "Exit",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    let chain = add(
        &mut e,
        "External first",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[id.clone(), exit.clone()]}),
    );
    let request = e.build(&e.profile(&chain).unwrap()).unwrap();
    assert_eq!(request.need_extra_process, Some(true));
    assert_eq!(
        request.extra_process_path.as_deref(),
        Some("/tmp/nonexistent-synthetic-private-path"),
        "the chain starts the program of its first hop"
    );
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let outbounds = core["outbounds"].as_array().unwrap();
    let first = outbounds
        .iter()
        .find(|o| o["tag"] == "thronium-chain-proxy-0")
        .expect("the external core is the first hop");
    assert_eq!(
        (&first["type"], &first["server"], &first["server_port"]),
        (&json!("socks"), &json!("127.0.0.1"), &json!(32124))
    );
    assert!(
        first.get("detour").is_none_or(Value::is_null),
        "nothing is dialled before a server that is already local"
    );
    let proxy = outbounds.iter().find(|o| o["tag"] == "proxy").unwrap();
    assert_eq!(proxy["detour"], "thronium-chain-proxy-0");
    let path = json!("/tmp/nonexistent-synthetic-private-path");
    assert!(
        core["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["process_path"][0] == path && rule["outbound"] == "direct"),
        "the external core's own traffic leaves outside the chain it feeds"
    );
    assert_eq!(core["dns"]["rules"][0]["process_path"][0], path);
    assert_eq!(core["dns"]["rules"][0]["server"], "dns-direct");
    // A disposable test box never starts the program the person runs.
    assert!(!crate::settings::tests_runtime::supported(
        &e.store.library,
        &e.profile(&chain).unwrap(),
        &Default::default()
    ));
    assert!(e.rpc.is_none());
}

/// Anywhere else in a chain the external core has no way to be reached, and a
/// pool would have to start and stop it as it switches.
#[test]
fn an_external_core_is_refused_anywhere_but_the_first_hop_of_one_chain() {
    let (_d, mut e, id) = setup();
    let second = add(
        &mut e,
        "Second external",
        ProfileKind::ExternalCore,
        json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":32125,
            "extra_core_path":"/tmp/nonexistent-second-core","extra_core_args":"","extra_core_conf":"","no_logs":false}),
    );
    let ordinary = add(
        &mut e,
        "Ordinary",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    for (hops, code) in [
        (json!([ordinary, id]), "external_chain_position"),
        (json!([id, second]), "external_chain_limit"),
    ] {
        let result = e.save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Refused".into(),
            group_id: "personal".into(),
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":hops}),
        });
        assert_eq!(result.err().as_deref(), Some(code));
    }
    assert!(e.rpc.is_none());
}
