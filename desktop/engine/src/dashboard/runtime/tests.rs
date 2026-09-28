use super::*;

fn request(assets: &Assets, host: &str) -> proto::LoadConfigReq {
    proto::LoadConfigReq{core_config:Some(json!({"services":[{"type":"api","listen":host,"listen_port":19091,"secret":"a&b#=+","dashboard":{"enabled":true,"path":assets.serving_path()}}]}).to_string()),..Default::default()}
}
fn profile(kind: ProfileKind) -> Profile {
    Profile {
        id: "owned".into(),
        name: "Owned".into(),
        group_id: "personal".into(),
        kind,
        config: json!({"type":"direct"}),
        favorite: false,
        vpn_policy: None,
    }
}
#[test]
fn generated_dashboard_is_seeded_without_altering_listener_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path());
    let mut source = request(&assets, "127.0.0.1");
    let mut library = Library::default();
    library
        .settings
        .insert("core_box_api_enabled".into(), json!(true));
    library
        .settings
        .insert("core_box_api_dashboard".into(), json!(true));
    configure(
        &mut source,
        &profile(ProfileKind::XrayConfig),
        &library,
        dir.path(),
    )
    .unwrap();
    let core: Value = serde_json::from_str(source.core_config.as_deref().unwrap()).unwrap();
    assert_eq!(core["services"][0]["listen_port"], 19091);
    assert_eq!(core["services"][0]["secret"], "a&b#=+");
    assert!(assets.serving_path().join("index.html").is_file());
    assert!(!assets.serving_path().join(".etag").exists());
    assert!(assets.inspect().unwrap().is_none());
}
#[test]
fn disabled_feature_and_full_sing_box_json_are_untouched() {
    for enabled in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let assets = Assets::new(dir.path());
        let mut source = request(&assets, "127.0.0.1");
        let before = source.core_config.clone();
        let mut library = Library::default();
        library
            .settings
            .insert("core_box_api_enabled".into(), json!(enabled));
        library
            .settings
            .insert("core_box_api_dashboard".into(), json!(enabled));
        let kind = if enabled {
            ProfileKind::SingBoxConfig
        } else {
            ProfileKind::SingBoxOutbound
        };
        configure(&mut source, &profile(kind), &library, dir.path()).unwrap();
        assert_eq!(source.core_config, before);
        assert!(!assets.serving_path().exists());
    }
}
#[test]
fn browser_address_contains_the_secret_only_in_the_fragment() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path());
    for (host, authority) in [
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "[::1]"),
        ("0.0.0.0", "127.0.0.1"),
        ("::", "[::1]"),
    ] {
        let text = url(listener(&request(&assets, host), &assets).unwrap(), "en").unwrap();
        let url = reqwest::Url::parse(&text).unwrap();
        assert!(url.query().is_none());
        assert_eq!(url.path(), "/thronium-dashboard.html");
        assert!(text.starts_with(&format!(
            "http://{authority}:19091/thronium-dashboard.html#"
        )));
        assert_eq!(url.fragment(), Some("secret=a%26b%23%3D%2B&language=en"));
    }
}
#[test]
fn remote_ambiguous_tls_and_foreign_dashboard_listeners_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path());
    for host in [
        "192.0.2.1",
        "example.test",
        "127.0.0.1@evil.invalid",
        "ff02::1",
    ] {
        assert_eq!(
            listener(&request(&assets, host), &assets).err().as_deref(),
            Some("dashboard_listener_unsupported")
        );
    }
    for (path, value, error) in [
        (
            "/services/0/dashboard/path",
            json!("/custom/dashboard"),
            "dashboard_custom_configuration",
        ),
        (
            "/services/0/listen_port",
            json!(0),
            "dashboard_listener_unsupported",
        ),
        (
            "/services/0/dashboard/enabled",
            json!(false),
            "dashboard_disabled",
        ),
    ] {
        let mut source = request(&assets, "127.0.0.1");
        let mut core: Value = serde_json::from_str(source.core_config.as_deref().unwrap()).unwrap();
        *core.pointer_mut(path).unwrap() = value;
        source.core_config = Some(core.to_string());
        assert_eq!(listener(&source, &assets).err().as_deref(), Some(error));
    }
    let mut source = request(&assets, "127.0.0.1");
    let mut core: Value = serde_json::from_str(source.core_config.as_deref().unwrap()).unwrap();
    core["services"][0]["tls"] = json!({"enabled":true});
    source.core_config = Some(core.to_string());
    assert!(listener(&source, &assets).is_err());
    let second = core["services"][0].clone();
    core["services"].as_array_mut().unwrap().push(second);
    source.core_config = Some(core.to_string());
    assert_eq!(
        listener(&source, &assets).err().as_deref(),
        Some("dashboard_custom_configuration")
    );
}
#[test]
fn disconnected_status_does_not_start_core_or_expose_saved_secret() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("/missing-core")).unwrap();
    engine
        .store
        .library
        .settings
        .insert("core_box_api_enabled".into(), json!(true));
    engine
        .store
        .library
        .settings
        .insert("core_box_api_dashboard".into(), json!(true));
    engine.store.library.settings.insert(
        "core_box_api_secret".into(),
        json!("private-status-canary62"),
    );
    let status = engine.dashboard_status().unwrap();
    assert!(!status.can_open && status.settings_enabled);
    assert_eq!(status.reason.as_deref(), Some("dashboard_disconnected"));
    assert!(engine.rpc.is_none());
    assert!(!serde_json::to_string(&status)
        .unwrap()
        .contains("private-status-canary62"));
    assert_eq!(
        engine.dashboard_open_url().err().as_deref(),
        Some("dashboard_disconnected")
    );
}
