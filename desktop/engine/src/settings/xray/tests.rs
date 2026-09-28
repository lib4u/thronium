use super::*;
use crate::{settings, Engine};
use std::path::Path;

fn profile(config: Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: "xray".into(),
        name: "Xray".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: ProfileKind::XrayOutbound,
        config,
    }
}

#[test]
fn inheritance_preserves_explicit_transport_and_mux_without_editing_stored_profiles() {
    let mut library = Library::default();
    library.settings.extend([
        ("xray_mux_default_on".into(), json!(true)),
        ("xray_tcp_fast_open".into(), json!("enabled")),
        ("xray_tcp_keep_alive_idle".into(), json!(40)),
        ("xray_tcp_mptcp".into(), json!(true)),
    ]);
    let original = json!({"protocol":"vless","settings":{"id":"fixture"},"mux":{"enabled":false},
        "streamSettings":{"sockopt":{"tcpFastOpen":false,"tcpMptcp":false,"mark":12}}});
    let mut p = profile(original.clone());
    library.profiles.push(p.clone());
    let stored = library.clone();
    settings::prepare_profiles(&mut library, &mut p);
    assert_eq!(p.config["mux"], original["mux"]);
    assert_eq!(
        p.config["streamSettings"]["sockopt"],
        json!({"tcpFastOpen":false,"tcpMptcp":false,"mark":12,"tcpKeepAliveIdle":40})
    );
    assert_eq!(stored.profiles[0].config, original);
    for invalid in [
        json!({"streamSettings":false}),
        json!({"streamSettings":{"sockopt":false}}),
    ] {
        let mut p = profile(invalid.clone());
        settings::prepare_profiles(&mut library, &mut p);
        assert_eq!(p.config, invalid);
    }
}

#[test]
fn mux_supports_xudp_and_avoids_tcp_mux_on_vision_or_xhttp() {
    let mut library = Library::default();
    library.settings.extend([
        ("xray_mux_default_on".into(), json!(true)),
        ("xray_mux_concurrency".into(), json!(4)),
        ("xray_mux_xudp_concurrency".into(), json!(16)),
        ("xray_mux_udp443".into(), json!("skip")),
    ]);
    for settings in [
        json!({}),
        json!({"flow":"xtls-rprx-vision"}),
        json!({"vnext":[{"users":[{"flow":"xtls-rprx-vision-udp443"}]}]}),
    ] {
        let mut outbound = json!({"protocol":"vless","settings":settings});
        prepare_outbound(&mut outbound, &library);
        assert_eq!(
            outbound["mux"]["concurrency"],
            if settings == json!({}) { 4 } else { -1 }
        );
        assert_eq!(outbound["mux"]["xudpConcurrency"], 16);
        assert_eq!(outbound["mux"]["xudpProxyUDP443"], "skip");
    }
    let mut xhttp = json!({"protocol":"vless","streamSettings":{"network":"xhttp"}});
    prepare_outbound(&mut xhttp, &library);
    assert!(xhttp.get("mux").is_none());
}

#[test]
fn generated_instance_gets_policy_logs_and_one_loopback_api_but_full_json_is_unchanged() {
    let mut library = Library::default();
    library.settings.extend([
        ("xray_policy_enabled".into(), json!(true)),
        ("xray_policy_handshake".into(), json!(15)),
        ("xray_policy_buffer_size".into(), json!(0)),
        ("xray_api_enabled".into(), json!(true)),
        ("xray_access_log".into(), json!(false)),
        ("xray_dns_log".into(), json!(true)),
        ("xray_log_mask_address".into(), json!("half")),
    ]);
    let p = profile(json!({"protocol":"freedom"}));
    let mut request = crate::config::build(&p, 2080, Some(23456)).unwrap();
    let raw = json!({"log":{"loglevel":"debug","access":"none"},"policy":{"levels":{"1":{"connIdle":8}}}}).to_string();
    request.xray_full_configs.push(raw.clone());
    apply(&mut request, &p, &library).unwrap();
    let config: Value = serde_json::from_str(request.xray_config.as_deref().unwrap()).unwrap();
    assert_eq!(config["policy"]["levels"]["0"]["handshake"], 15);
    assert_eq!(config["policy"]["levels"]["0"]["bufferSize"], 0);
    assert_eq!(
        config["log"],
        json!({"loglevel":"warning","access":"none","dnsLog":true,"maskAddress":"half"})
    );
    assert_eq!(config["api"]["listen"], "127.0.0.1:10085");
    assert_eq!(
        config["api"]["services"],
        json!(["StatsService", "ReflectionService"])
    );
    assert_eq!(config["policy"]["system"]["statsOutboundDownlink"], true);
    assert_eq!(request.xray_full_configs, vec![raw.clone()]);
    let full = Profile {
        kind: ProfileKind::XrayConfig,
        ..p
    };
    request.xray_config = Some(raw.clone());
    apply(&mut request, &full, &library).unwrap();
    assert_eq!(request.xray_config, Some(raw));
}

#[test]
fn defaults_do_not_enable_api_policy_or_change_transport() {
    let library = Library::default();
    let mut p = profile(json!({"protocol":"vless","settings":{"id":"fixture"}}));
    let original = p.config.clone();
    prepare_outbound(&mut p.config, &library);
    assert_eq!(p.config, original);
    let mut request = crate::config::build(&p, 2080, Some(23456)).unwrap();
    apply(&mut request, &p, &library).unwrap();
    let config: Value = serde_json::from_str(request.xray_config.as_deref().unwrap()).unwrap();
    assert!(
        config.get("api").is_none()
            && config.get("stats").is_none()
            && config.get("policy").is_none()
    );
}

#[test]
fn invalid_values_and_overlapping_local_ports_are_rejected() {
    for (key, value) in [
        ("xray_api_port", json!(65536)),
        ("xray_policy_buffer_size", json!(-1)),
        ("xray_policy_handshake", json!(1.5)),
        ("xray_mux_xudp_concurrency", json!(1025)),
        ("xray_mux_udp443", json!("invalid")),
        ("xray_log_mask_address", json!("invalid")),
        ("xray_tcp_fast_open", json!(true)),
    ] {
        let mut library = Library::default();
        library.settings.insert(key.into(), value);
        assert_eq!(
            settings::validate(&library).unwrap_err(),
            format!("settings_invalid:{key}")
        );
    }
    let mut library = Library::default();
    library.settings.extend([
        ("xray_api_enabled".into(), json!(true)),
        ("xray_api_port".into(), json!(2080)),
    ]);
    assert_eq!(
        settings::validate(&library).unwrap_err(),
        "settings_invalid:xray_api_port"
    );
    library
        .settings
        .insert("xray_api_port".into(), json!(10085));
    let p = profile(json!({"protocol":"freedom"}));
    let mut request = crate::config::build(&p, 2080, Some(10085)).unwrap();
    assert_eq!(
        apply(&mut request, &p, &library).unwrap_err(),
        "xray_api_port_conflict"
    );
}

#[tokio::test]
async fn reorganized_values_persist_and_protect_concurrent_edits() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    engine.store.library.settings.extend([
        ("xray_log_level".into(), json!("debug")),
        ("xray_mux_concurrency".into(), json!(1024)),
    ]);
    engine.store.commit(engine.store.library.clone()).unwrap();
    let previous = settings::section(&engine.store.library, "core");
    assert_eq!(previous["xray_log_level"], "debug");
    assert_eq!(previous["xray_mux_concurrency"], 1024);
    assert!(settings::section(&engine.store.library, "logging")
        .get("xray_log_level")
        .is_none());
    assert!(settings::section(&engine.store.library, "presets")
        .get("xray_mux_concurrency")
        .is_none());
    let mut next = previous.clone();
    next["xray_tcp_fast_open"] = json!("enabled");
    engine
        .save_settings("core", previous.clone(), next.clone())
        .await
        .unwrap();
    next["xray_tcp_fast_open"] = json!("disabled");
    assert_eq!(
        engine
            .save_settings("core", previous, next)
            .await
            .unwrap_err(),
        "settings_conflict:xray_tcp_fast_open"
    );
    drop(engine);
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        settings::section(&engine.store.library, "core")["xray_tcp_fast_open"],
        "enabled"
    );
    let p = profile(json!({"protocol":"freedom"}));
    let test =
        crate::probes::prepared_request(&engine.store.library, &p, "https://example.test", 3000)
            .unwrap();
    let config: Value = serde_json::from_str(test.xray_config.as_deref().unwrap()).unwrap();
    assert_eq!(
        config["outbounds"][0]["streamSettings"]["sockopt"]["tcpFastOpen"],
        true
    );
    assert!(config.get("api").is_none());
}
