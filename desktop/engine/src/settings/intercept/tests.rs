use crate::{settings, store::ProfileKind, Engine, ProfileDraft};
use serde_json::{json, Value};

#[test]
fn warp_materializes_only_direct_fragmentation_default() {
    for source in [
        json!({"type":"direct","tag":"proxy"}),
        json!({"type":"direct","tag":"proxy","udp_fragment":null}),
        json!({"type":"direct","tag":"proxy","udp_fragment":false}),
        json!({"type":"direct","tag":"proxy","udp_fragment":true}),
        json!({"type":"direct","tag":"proxy","udp_fragment":"invalid but retained for Check"}),
        json!({"type":"direct","tag":"proxy","domain_strategy":"as_is","connect_timeout":"0.0000000001s","routing_mark":"0x0","network_type":[]}),
        json!({"type":"socks","tag":"proxy"}),
    ] {
        let mut library = crate::store::Library::default();
        library.settings.insert("enable_warp".into(), json!(true));
        library
            .settings
            .insert("warp_ep".into(), json!("127.0.0.1:19111"));
        let mut core = json!({"outbounds":[source.clone(),{"type":"direct","tag":"direct"}]});
        super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
        let mut expected = source.clone();
        expected["tag"] = json!("settings-warp-base");
        if source["type"] == "direct" && source.get("udp_fragment").is_none_or(Value::is_null) {
            expected["udp_fragment"] = json!(true);
        }
        assert_eq!(core["outbounds"][0], expected);
        assert_eq!(
            core["outbounds"][1],
            json!({"type":"direct","tag":"direct"})
        );
        assert_eq!(core["endpoints"][0]["detour"], "settings-warp-base");
        assert!(core["endpoints"][0].get("udp_fragment").is_none());
    }
}

#[test]
fn warp_keeps_proxy_and_nonempty_direct_detours_and_all_source_fields() {
    for source in [
        json!({"type":"direct","tag":"proxy"}),
        json!({"type":"direct","tag":"proxy","udp_fragment":false}),
        json!({"type":"direct","tag":"proxy","inet4_bind_address":"127.0.0.2"}),
        json!({"type":"direct","tag":"proxy","connect_timeout":"9s"}),
        json!({"type":"direct","tag":"proxy","unknown":"kept for core rejection"}),
        json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":19080,"version":"5","username":"synthetic-user","password":"synthetic-password"}),
    ] {
        let mut library = crate::store::Library::default();
        library.settings.insert("enable_warp".into(), json!(true));
        library
            .settings
            .insert("warp_ep".into(), json!("127.0.0.1:19111"));
        let mut core = json!({"outbounds":[source.clone(),{"type":"direct","tag":"direct"},{"type":"socks","tag":"aux","detour":"proxy"}],"route":{"final":"proxy"}});
        super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
        let mut expected = source.clone();
        expected["tag"] = json!("settings-warp-base");
        if source["type"] == "direct" && source.get("udp_fragment").is_none_or(Value::is_null) {
            expected["udp_fragment"] = json!(true);
        }
        assert_eq!(core["outbounds"][0], expected);
        assert_eq!(core["outbounds"][2]["detour"], "settings-warp-base");
        assert_eq!(core["route"]["final"], "proxy");
        let endpoint = &core["endpoints"][0];
        assert_eq!(endpoint["detour"], "settings-warp-base");
        assert!(endpoint.get("udp_fragment").is_none());
    }
}

#[test]
fn warp_preserves_endpoint_base_and_rejects_reserved_tag_collision() {
    let mut library = crate::store::Library::default();
    library.settings.insert("enable_warp".into(), json!(true));
    library
        .settings
        .insert("warp_ep".into(), json!("127.0.0.1:19111"));
    let mut core =
        json!({"endpoints":[{"type":"wireguard","tag":"proxy","private_key":"synthetic"}]});
    super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
    assert_eq!(
        core["endpoints"][0],
        json!({"type":"wireguard","tag":"settings-warp-base","private_key":"synthetic"})
    );
    assert_eq!(core["endpoints"][1]["detour"], "settings-warp-base");
    assert!(core["endpoints"][1].get("udp_fragment").is_none());
    assert_eq!(
        super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap_err(),
        "route_tag_conflict"
    );
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; actual loopback-only WireGuard initiation"]
async fn warp_direct_sends_initiation_and_preserves_explicit_bind() {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};
    const NAME: &str =
        "settings::intercept::tests::warp_direct_sends_initiation_and_preserves_explicit_bind";
    if std::env::var_os("THRONIUM_WARP_DIRECT_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(core, directory.path().join("ThroniumCore")).unwrap();
        let output = std::process::Command::new(executable)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_WARP_DIRECT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http.local_addr().unwrap();
    let http_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = http.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                if socket.read(&mut request).await.is_ok() {
                    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nwarp-test").await;
                }
            });
        }
    });
    for (name, source, global_timeout, source_ip) in [
        ("plain direct", json!({"type":"direct"}), false, "127.0.0.1"),
        (
            "explicit zero defaults",
            json!({"type":"direct","bind_interface":"","tcp_fast_open":false,"reuse_addr":false,"routing_mark":0,"connect_timeout":"0s","domain_strategy":"as_is"}),
            false,
            "127.0.0.1",
        ),
        (
            "explicit bind",
            json!({"type":"direct","inet4_bind_address":"127.0.0.2"}),
            false,
            "127.0.0.2",
        ),
        (
            "inherited timeout",
            json!({"type":"direct"}),
            true,
            "127.0.0.1",
        ),
        (
            "explicit fragmentation false",
            json!({"type":"direct","udp_fragment":false}),
            false,
            "127.0.0.1",
        ),
    ] {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let directory = tempfile::tempdir().unwrap();
        let core = std::env::current_exe()
            .unwrap()
            .with_file_name("ThroniumCore");
        let mut engine = Engine::open(directory.path(), &core).unwrap();
        engine.store.library.preferences.inbound_port = port;
        engine
            .store
            .library
            .settings
            .insert("log_level".into(), json!("debug"));
        if global_timeout {
            engine
                .store
                .library
                .settings
                .insert("singbox_connect_timeout".into(), json!(3));
        }
        let result: Result<(), String> = async {
            let id = engine.save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: name.into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: source.clone(),
            })?;
            engine.connect(&id).await?;
            let client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://{http_address}/");
            assert_eq!(
                client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?
                    .text()
                    .await
                    .map_err(|e| e.to_string())?,
                "warp-test"
            );
            let previous = settings::section(&engine.store.library, "intercept");
            let mut next = previous.clone();
            next["enable_warp"] = json!(true);
            next["warp_private_key"] =
                json!(base64::engine::general_purpose::STANDARD.encode([1u8; 32]));
            next["warp_public_key"] =
                json!(base64::engine::general_purpose::STANDARD.encode([2u8; 32]));
            next["warp_ep"] = json!(udp.local_addr().unwrap().to_string());
            next["warp_ifc_addrs"] = json!(["10.77.0.2/32"]);
            engine.save_settings("intercept", previous, next).await?;
            let mut packet = [0u8; 2048];
            assert_eq!(
                udp.try_recv_from(&mut packet).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "Check must not start WireGuard"
            );
            engine.apply_routing().await?;
            // Trigger an encapsulated connection only: the WireGuard peer is
            // our loopback socket; TEST-NET-1 is never contacted directly.
            let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .map_err(|e| e.to_string())?;
            socket
                .write_all(b"GET http://192.0.2.1:80/ HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
                .await
                .map_err(|e| e.to_string())?;
            let (size, address) = timeout(Duration::from_secs(5), udp.recv_from(&mut packet))
                .await
                .map_err(|_| format!("{name}: no WireGuard initiation at owned UDP peer"))?
                .map_err(|e| e.to_string())?;
            assert_eq!(size, 148, "WireGuard handshake initiation size");
            assert_eq!(
                &packet[..4],
                &[1, 0, 0, 0],
                "WireGuard handshake initiation type"
            );
            assert_eq!(
                address.ip().to_string(),
                source_ip,
                "explicit source binding must remain effective"
            );
            let active: Value = serde_json::from_str(
                engine
                    .active_connection
                    .as_ref()
                    .unwrap()
                    .request
                    .core_config
                    .as_deref()
                    .unwrap(),
            )
            .unwrap();
            let base = active["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == "settings-warp-base")
                .unwrap();
            for (key, value) in source.as_object().unwrap() {
                assert_eq!(&base[key], value);
            }
            if global_timeout {
                assert_eq!(base["connect_timeout"], "3s");
            }
            let endpoint = active["endpoints"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == "proxy")
                .unwrap();
            assert_eq!(endpoint["detour"], "settings-warp-base");
            assert!(endpoint.get("udp_fragment").is_none());
            assert_eq!(
                base["udp_fragment"],
                source.get("udp_fragment").cloned().unwrap_or(json!(true))
            );
            drop(socket);
            let previous = settings::section(&engine.store.library, "intercept");
            let mut next = previous.clone();
            next["enable_warp"] = json!(false);
            engine.save_settings("intercept", previous, next).await?;
            engine.apply_routing().await?;
            assert_eq!(
                client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?
                    .text()
                    .await
                    .map_err(|e| e.to_string())?,
                "warp-test"
            );
            engine.disconnect().await?;
            let released =
                std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|e| e.to_string())?;
            drop(released);
            Ok(())
        }
        .await;
        if result.is_err() {
            println!(
                "FIXTURE CORE LOG: {}",
                serde_json::to_string(&engine.logs.view(crate::logs::Filter::default()).unwrap())
                    .unwrap()
            );
            if let Some(active) = &engine.active_connection {
                let mut config: Value =
                    serde_json::from_str(active.request.core_config.as_deref().unwrap()).unwrap();
                for endpoint in config["endpoints"].as_array_mut().into_iter().flatten() {
                    endpoint.as_object_mut().unwrap().remove("private_key");
                }
                println!("FIXTURE ACTIVE REDACTED: {config}");
            }
        }
        engine.shutdown().await;
        result.unwrap();
        println!("PASS {name}: real UDP initiation, owned peer/source, preserved settings, no Check traffic, HTTP restored, listener released");
    }
    http_task.abort();
}

#[test]
fn legacy_warp_global_runtime_preserves_original_qt_fixed_parameters() {
    let qt = crate::qt_source::frozen("generate-warp-profile.cpp");
    let function = qt
        .split("std::shared_ptr<Profile> getWarpProfile() {")
        .nth(1)
        .unwrap()
        .split("return warpProfile;")
        .next()
        .unwrap();
    assert!(function.contains("outbound->mtu = 1280;"));
    assert!(function.contains("peer->persistent_keepalive = \"10\";"));
    let mut library = crate::store::Library::default();
    for (key, value) in [
        ("enable_warp", json!(true)),
        ("warp_private_key", json!("synthetic-private74")),
        ("warp_public_key", json!("synthetic-peer74")),
        ("warp_ep", json!("127.0.0.1:2408")),
        (
            "warp_ifc_addrs",
            json!(["10.177.43.2/32", "fd00:43::2/128"]),
        ),
        ("warp_reserved", json!(["0", "128", "255"])),
    ] {
        library.settings.insert(key.into(), value);
    }
    let mut core = json!({"outbounds":[{"type":"direct","tag":"proxy"}]});
    super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
    let endpoint = &core["endpoints"][0];
    assert_eq!(endpoint["mtu"], 1280);
    assert_eq!(endpoint["peers"][0]["persistent_keepalive_interval"], 10);
    assert_eq!(endpoint["private_key"], "synthetic-private74");
    assert_eq!(endpoint["peers"][0]["public_key"], "synthetic-peer74");
    assert_eq!(endpoint["peers"][0]["reserved"], json!([0, 128, 255]));
    assert_eq!(
        endpoint["address"],
        json!(["10.177.43.2/32", "fd00:43::2/128"])
    );
    assert_eq!(endpoint["detour"], "settings-warp-base");
}

#[test]
fn unused_verbatim_preset_does_not_change_full_xray_rule_set_defaults() {
    let mut library = crate::store::Library::default();
    let active = library.routing.active.clone();
    library
        .routing
        .profiles
        .iter_mut()
        .find(|p| p.id == active)
        .unwrap()
        .legacy_constraints = Some(crate::routing::LegacyRoutingConstraints {
        version: 5,
        raw_verbatim: true,
        ..Default::default()
    });
    library
        .settings
        .insert("route_auto_update".into(), json!(7));
    let original = json!({"route":{"rule_set":[{"tag":"fixture","type":"remote","format":"binary","url":"https://example.invalid/set.srs","update_interval":"2h"}]}});
    for (kind, expected) in [
        (ProfileKind::SingBoxOutbound, "2h"),
        (ProfileKind::XrayConfig, "7m"),
    ] {
        let mut core = original.clone();
        super::apply(&mut core, &library, &kind).unwrap();
        assert_eq!(core["route"]["rule_set"][0]["update_interval"], expected);
    }
}

#[test]
fn ad_blocking_follows_guards_and_the_sniff_it_depends_on() {
    let mut library = crate::store::Library::default();
    library
        .settings
        .insert("adblock_enable".into(), json!(true));
    library
        .settings
        .insert("enable_redirect".into(), json!(true));
    let user = json!({"domain_suffix":["example.test"],"action":"route","outbound":"direct"});
    let mut core = json!({"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[crate::routing::builtin::sniff(), user.clone()]}});
    super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
    let rules = core["route"]["rules"].as_array().unwrap();
    // The redirect sniff overrides the destination; the core skips any later sniff.
    assert_eq!(
        rules[0],
        json!({"inbound":["settings-redirect"],"action":"sniff","override_destination":true})
    );
    assert_eq!(rules[1], crate::routing::builtin::sniff());
    assert_eq!(
        rules[2],
        json!({"rule_set":["settings-adblock"],"action":"reject"})
    );
    assert_eq!(rules[3], user);
    // Without any decision the block still lands after the sniff.
    let mut core = json!({"route":{"rules":[crate::routing::builtin::sniff()]}});
    library
        .settings
        .insert("enable_redirect".into(), json!(false));
    super::apply(&mut core, &library, &ProfileKind::SingBoxOutbound).unwrap();
    assert_eq!(
        core["route"]["rules"][1]["rule_set"],
        json!(["settings-adblock"])
    );
}
