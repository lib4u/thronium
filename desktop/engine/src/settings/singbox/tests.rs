use super::*;
use crate::{settings, Engine};

fn profile(config: Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: "fixture".into(),
        name: "Fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        config,
    }
}

fn configured() -> Library {
    let mut l = Library::default();
    l.settings.extend([
        ("singbox_connect_timeout".into(), json!(12)),
        ("singbox_tcp_fast_open".into(), json!("enabled")),
        ("singbox_tcp_multi_path".into(), json!("disabled")),
        ("singbox_tcp_keep_alive".into(), json!("enabled")),
        ("singbox_tcp_keep_alive_idle".into(), json!(30)),
        ("singbox_tcp_keep_alive_interval".into(), json!(5)),
        ("singbox_udp_fragment".into(), json!("disabled")),
        ("singbox_cache_enabled".into(), json!(true)),
        ("singbox_cache_store_dns".into(), json!(true)),
        ("singbox_cache_store_fakeip".into(), json!(true)),
        ("singbox_mux_limits".into(), json!("connections")),
        ("singbox_mux_max_connections".into(), json!(3)),
        ("singbox_mux_min_streams".into(), json!(6)),
    ]);
    l
}

#[test]
fn defaults_preserve_configuration_and_do_not_create_a_cache() {
    let l = Library::default();
    let mut p = profile(json!({"type":"socks","server":"127.0.0.1","server_port":1234}));
    let before = p.config.clone();
    prepare_outbound(&mut p.config, &l);
    assert_eq!(p.config, before);
    let mut request = crate::config::build(&p, 2080, None).unwrap();
    let before = request.core_config.clone();
    let dir = tempfile::tempdir().unwrap();
    configure_cache(&mut request, &p, &l, dir.path()).unwrap();
    assert_eq!(request.core_config, before);
    assert_eq!(dir.path().read_dir().unwrap().count(), 0);
}

#[test]
fn dialer_defaults_preserve_explicit_false_zero_and_profile_timings() {
    let l = configured();
    let mut o = json!({"type":"socks","tcp_fast_open":false,"connect_timeout":"0s","tcp_keep_alive":"90s","udp_fragment":true});
    prepare_outbound(&mut o, &l);
    assert_eq!(o["tcp_fast_open"], false);
    assert_eq!(o["connect_timeout"], "0s");
    assert_eq!(o["tcp_keep_alive"], "90s");
    assert_eq!(o["tcp_keep_alive_interval"], "5s");
    assert_eq!(o["udp_fragment"], true);
    assert_eq!(o["tcp_multi_path"], false);
    let once = o.clone();
    prepare_outbound(&mut o, &l);
    assert_eq!(o, once);

    let mut off = l.clone();
    off.settings
        .insert("singbox_tcp_keep_alive".into(), json!("disabled"));
    for explicit in [
        json!({}),
        json!({"disable_tcp_keep_alive":false}),
        json!({"tcp_keep_alive":"45s"}),
    ] {
        let mut o = explicit.clone();
        o["type"] = json!("direct");
        prepare_outbound(&mut o, &off);
        if explicit.as_object().unwrap().is_empty() {
            assert_eq!(o["disable_tcp_keep_alive"], true);
            assert!(
                o.get("tcp_keep_alive").is_none() && o.get("tcp_keep_alive_interval").is_none()
            );
        } else {
            assert_ne!(o["disable_tcp_keep_alive"], true);
            if explicit.get("tcp_keep_alive").is_some() {
                assert_eq!(o["tcp_keep_alive"], "45s");
            }
        }
    }
}

#[test]
fn trusttunnel_shares_the_ordinary_dialer_defaults() {
    let l = configured();
    let mut o = json!({"type":"trusttunnel","server":"127.0.0.1","server_port":443,"username":"u","password":"p","tls":{"enabled":true}});
    prepare_outbound(&mut o, &l);
    assert_eq!(o["tcp_keep_alive_interval"], "5s");
    assert_eq!(o["tls"], json!({"enabled":true}));
    assert_eq!(o["username"], "u");
}

#[test]
fn defaults_skip_detours_endpoints_and_other_cores() {
    let l = configured();
    for mut o in [
        json!({"type":"socks","detour":"next"}),
        json!({"type":"selector"}),
        json!({"type":"wireguard"}),
        json!({"type":"openconnect"}),
        json!({"type":"custom"}),
    ] {
        let before = o.clone();
        prepare_outbound(&mut o, &l);
        assert_eq!(o, before);
    }
    let mut library = l;
    let mut p = Profile {
        kind: ProfileKind::XrayOutbound,
        ..profile(json!({"protocol":"freedom"}))
    };
    let before = p.config.clone();
    settings::prepare_profiles(&mut library, &mut p);
    assert_eq!(p.config, before);
    let mut p = Profile {
        kind: ProfileKind::SingBoxConfig,
        ..profile(json!({"outbounds":[{"type":"direct"}]}))
    };
    let before = p.config.clone();
    settings::prepare_profiles(&mut library, &mut p);
    assert_eq!(p.config, before);
}

#[test]
fn custom_fragmentation_and_explicit_tfo_take_priority_over_inherited_options() {
    let mut l = configured();
    l.settings.extend([
        ("fragment_default_on".into(), json!(true)),
        ("fragment_implementation".into(), json!("custom")),
    ]);
    let mut p = profile(json!({"type":"trojan","tls":{"enabled":true}}));
    settings::prepare_profiles(&mut l.clone(), &mut p);
    assert_eq!(p.config["tls_fragment"]["enabled"], true);
    assert!(p.config.get("tcp_fast_open").is_none());

    let mut p = profile(json!({"type":"trojan","tcp_fast_open":true,"tls":{"enabled":true}}));
    settings::prepare_profiles(&mut l, &mut p);
    assert_eq!(p.config["tcp_fast_open"], true);
    assert!(p.config.get("tls_fragment").is_none());
    let mut o = json!({"type":"trojan","tls_fragment":{"enabled":true}});
    prepare_outbound(&mut o, &l);
    assert!(o.get("tcp_fast_open").is_none());
}

#[test]
fn mux_modes_never_mix_constraints_or_override_profile_limits() {
    let l = configured();
    let mut mux = json!({"enabled":true});
    mux_limits(&mut mux, &l);
    assert_eq!(
        mux,
        json!({"enabled":true,"max_connections":3,"min_streams":6})
    );
    for mut mux in [
        json!({"max_streams":0}),
        json!({"max_connections":2}),
        json!({"min_streams":8}),
    ] {
        let before = mux.clone();
        mux_limits(&mut mux, &l);
        assert_eq!(mux, before);
    }
    let mut mux = json!({"enabled":true});
    mux_limits(&mut mux, &Library::default());
    assert_eq!(mux, json!({"enabled":true,"max_streams":8}));
    let mut p = profile(json!({"type":"trojan","multiplex":{"enabled":false}}));
    settings::prepare_profiles(&mut l.clone(), &mut p);
    assert_eq!(p.config["multiplex"], json!({"enabled":false}));
}

#[test]
fn cache_is_stable_and_isolated_by_profile_dns_and_routing_without_preview_io() {
    let l = configured();
    let p = profile(json!({"type":"direct"}));
    let dir = tempfile::tempdir().unwrap();
    let cache = |p: &Profile, l: &Library| {
        let req = Engine::build_with_library(p, l, dir.path()).unwrap();
        let core: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
        core["experimental"]["cache_file"].clone()
    };
    let initial = cache(&p, &l);
    assert_eq!(initial, cache(&p, &l));
    assert_eq!(initial["store_dns"], true);
    assert_eq!(initial["store_fakeip"], true);
    assert!(Path::new(initial["path"].as_str().unwrap()).starts_with(dir.path()));
    assert_ne!(
        initial["path"],
        cache(
            &Profile {
                id: "another".into(),
                ..p.clone()
            },
            &l
        )["path"]
    );
    // The cache identity is derived from the effective configuration, including
    // DNS content even when a transport keeps the same tag.
    let mut req = crate::config::build(&p, 2080, None).unwrap();
    let mut core: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    configure_cache(&mut req, &p, &l, dir.path()).unwrap();
    let base: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    core["dns"]["servers"][0]["server"] = json!("192.0.2.1");
    req.core_config = Some(core.to_string());
    configure_cache(&mut req, &p, &l, dir.path()).unwrap();
    let dns: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    assert_ne!(
        base["experimental"]["cache_file"]["path"],
        dns["experimental"]["cache_file"]["path"]
    );
    core["route"]["final"] = json!("direct");
    req.core_config = Some(core.to_string());
    configure_cache(&mut req, &p, &l, dir.path()).unwrap();
    let routing: Value = serde_json::from_str(req.core_config.as_deref().unwrap()).unwrap();
    assert_ne!(
        dns["experimental"]["cache_file"]["path"],
        routing["experimental"]["cache_file"]["path"]
    );
    assert_eq!(dir.path().read_dir().unwrap().count(), 0);
}

#[test]
fn full_json_is_unchanged_and_xray_bridge_gets_cache_but_no_singbox_dialer_defaults() {
    let l = configured();
    let dir = tempfile::tempdir().unwrap();
    let raw = json!({"inbounds":[],"outbounds":[{"type":"direct"}],"experimental":{"cache_file":{"enabled":true,"path":"owned.db"}}});
    let p = Profile {
        kind: ProfileKind::SingBoxConfig,
        ..profile(raw.clone())
    };
    let request = Engine::build_with_library(&p, &l, dir.path()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(request.core_config.as_deref().unwrap()).unwrap(),
        raw
    );
    let p = Profile {
        kind: ProfileKind::XrayOutbound,
        ..profile(json!({"protocol":"freedom"}))
    };
    let request = Engine::build_with_library(&p, &l, dir.path()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["experimental"]["cache_file"]["enabled"], true);
    let bridge = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert!(bridge.get("tcp_fast_open").is_none() && bridge.get("connect_timeout").is_none());
}

#[tokio::test]
async fn settings_validate_persist_and_protect_concurrent_core_edits() {
    for (key, value) in [
        ("singbox_connect_timeout", json!(-1)),
        ("singbox_tcp_fast_open", json!(true)),
        ("singbox_mux_limits", json!("bad")),
        ("singbox_mux_min_streams", json!(0)),
        ("singbox_tcp_keep_alive_interval", json!(86401)),
    ] {
        let mut l = Library::default();
        l.settings.insert(key.into(), value);
        assert_eq!(
            settings::validate(&l),
            Err(format!("settings_invalid:{key}"))
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("absent-core")).unwrap();
    let before = settings::section(&e.store.library, "core");
    let mut desired = before.clone();
    desired["singbox_connect_timeout"] = json!(15);
    e.store
        .library
        .settings
        .insert("xray_dns_log".into(), json!(true));
    let saved = e
        .save_settings("core", before.clone(), desired.clone())
        .await
        .unwrap();
    assert_eq!(saved["xray_dns_log"], true);
    desired["singbox_connect_timeout"] = json!(20);
    assert_eq!(
        e.save_settings("core", before, desired).await.unwrap_err(),
        "settings_conflict:singbox_connect_timeout"
    );
    drop(e);
    let e = Engine::open(dir.path(), Path::new("absent-core")).unwrap();
    assert_eq!(
        settings::integer(&e.store.library, "singbox_connect_timeout"),
        15
    );
}
