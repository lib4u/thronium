use super::*;
#[test]
fn legacy_close_behavior_and_background_preference_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(store::Library::default()).unwrap();
    value["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("closeBehavior");
    let path = dir.path().join("library.json");
    let before = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &before).unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(engine.store.library.preferences.close_behavior == store::CloseBehavior::Quit);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut preferences = engine.store.library.preferences.clone();
    preferences.close_behavior = store::CloseBehavior::Background;
    engine.preferences(preferences).unwrap();
    drop(engine);
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(engine.store.library.preferences.close_behavior == store::CloseBehavior::Background);
    value["preferences"]["closeBehavior"] = json!("unknown");
    assert!(serde_json::from_value::<store::Library>(value).is_err());
}
#[test]
fn core_decode_errors_do_not_echo_the_entire_configuration() {
    let config = json!({"outbounds":[{"password":"error-secret-sentinel"}], "dns":{"servers":[{"password":"dns-secret"}]}});
    let result = core_result(proto::ErrorResp {
        error: Some(format!(
            "decode config at {config}: route.rules[0].port: invalid port"
        )),
    })
    .unwrap_err();
    assert_eq!(
        result,
        "invalid_configuration: route.rules[0].port: invalid port"
    );
    assert!(!result.contains("secret"));
    assert_eq!(
        core_result(proto::ErrorResp {
            error: Some("decode config at {incomplete secret".into())
        })
        .unwrap_err(),
        "invalid_configuration"
    );
}
#[test]
fn import_batch_is_atomic_and_preserves_existing_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let draft = |name: &str, group: &str| ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: group.into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks", "server":"127.0.0.1", "server_port":1080, "password":"secret"}),
    };
    let ids = engine
        .import_profiles(vec![draft("One", "personal"), draft("Two", "personal")])
        .unwrap();
    assert_eq!(engine.store.library.selected, Some(ids[0].clone()));
    let before = serde_json::to_value(&engine.store.library).unwrap();
    assert!(engine
        .import_profiles(vec![draft("Three", "personal"), draft("Bad", "missing")])
        .is_err());
    assert_eq!(serde_json::to_value(&engine.store.library).unwrap(), before);
    let mut replacement = draft("Replacement", "personal");
    replacement.id = Some(ids[0].clone());
    assert!(engine.import_profiles(vec![replacement]).is_err());
    assert!(engine.import_profiles(vec![]).is_err());
    drop(engine);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        serde_json::to_value(&reopened.store.library).unwrap(),
        before
    );
}

#[test]
fn snapshots_never_contain_profile_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    engine.save_profile(ProfileDraft { vpn_policy: Default::default(), id:None, name:"Test".into(), group_id:"personal".into(), kind:ProfileKind::SingBoxOutbound,
        config:json!({"type":"vless", "server":"example.org", "uuid":"secret-sentinel", "tls":{"reality":{"public_key":"key-sentinel"}}}) }).unwrap();
    engine.error = Some("invalid UUID: secret-sentinel".into());
    let snapshot = serde_json::to_string(&engine.snapshot()).unwrap();
    assert!(!snapshot.contains("secret-sentinel"));
    assert!(!snapshot.contains("key-sentinel"));
    assert_eq!(engine.snapshot().error.as_deref(), Some("core_error"));
    assert!(snapshot.contains("example.org"));
}
