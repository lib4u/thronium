use serde_json::{json, Value};
use thronium_engine::{profile_edit::EditRequest, store::ProfileKind, Engine, ProfileDraft};

fn engine() -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let draft: ProfileDraft = serde_json::from_value(json!({
        "name":"Original", "groupId":"personal", "kind":"sing-box-outbound",
        "config":{"type":"socks","server":"example.test","server_port":443,"future":{"keep":true}}
    }))
    .unwrap();
    let id = engine.save_profile(draft).unwrap();
    (dir, engine, id)
}

fn edit(engine: &Engine, id: &str) -> EditRequest {
    serde_json::from_value(json!(engine.editable_profile(id).unwrap())).unwrap()
}

#[test]
fn stale_form_cannot_overwrite_new_port_and_unknown_fields() {
    let (_dir, mut engine, id) = engine();
    let mut stale = edit(&engine, &id);
    stale.draft.name = "Stale".into();
    let current = engine.editable_profile(&id).unwrap();
    let mut config = current.profile.config;
    config["server_port"] = json!(8443);
    engine
        .save_profile_configuration(&id, &current.expected_revision, config.clone())
        .unwrap();
    assert_eq!(
        engine.save_profile_edit(stale, None).unwrap_err(),
        "profile_configuration_changed"
    );
    let saved = engine.profile(&id).unwrap();
    assert_eq!((saved.name.as_str(), saved.config), ("Original", config));
}

#[test]
fn configuration_editor_rejects_changes_to_name_policy_or_core() {
    let (_dir, mut engine, id) = engine();
    let stale = engine.editable_profile(&id).unwrap();
    let mut current = edit(&engine, &id);
    current.draft.name = "Renamed".into();
    engine.save_profile_edit(current, None).unwrap();
    assert_eq!(
        engine
            .save_profile_configuration(&id, &stale.expected_revision, stale.profile.config)
            .unwrap_err(),
        "profile_configuration_changed"
    );
}

#[test]
fn favorite_and_background_library_commits_do_not_invalidate_editor() {
    let (_dir, mut engine, id) = engine();
    let mut request = edit(&engine, &id);
    engine.favorite(&id).unwrap();
    let mut next = engine.store.library.clone();
    next.preferences.theme = "dark".into();
    engine.store.commit(next).unwrap();
    request.draft.config["server_port"] = json!(8443);
    engine.save_profile_edit(request, None).unwrap();
    let saved = engine.profile(&id).unwrap();
    assert!(saved.favorite);
    assert_eq!(saved.config["server_port"], 8443);
}

#[test]
fn existing_profile_requires_revision_but_create_and_clone_do_not() {
    let (_dir, mut engine, id) = engine();
    let mut request = edit(&engine, &id);
    request.expected_revision = None;
    assert_eq!(
        engine.save_profile_edit(request, None).unwrap_err(),
        "profile_configuration_changed"
    );
    let mut clone = edit(&engine, &id);
    clone.draft.id = None;
    clone.draft.name = "Copy".into();
    let cloned = engine.save_profile_edit(clone, None).unwrap();
    assert_ne!(cloned, id);
    assert_eq!(
        engine.profile(&cloned).unwrap().config,
        engine.profile(&id).unwrap().config
    );
}

#[test]
fn vpn_policy_and_vless_override_are_part_of_revision() {
    let (_dir, mut engine, id) = engine();
    let before = engine.editable_profile(&id).unwrap().expected_revision;
    // Check projection directly, independently of protocol-specific core validation.
    engine
        .store
        .library
        .preferences
        .vless_overrides
        .insert(id.clone(), thronium_engine::vless::Core::SingBox);
    assert_ne!(
        engine.editable_profile(&id).unwrap().expected_revision,
        before
    );
    engine.store.library.preferences.vless_overrides.remove(&id);
    engine.store.library.profiles[0].vpn_policy = Some(
        serde_json::from_value(
            json!({"onlyAdvertisedRoutes":true,"useTunnelDns":false,"blockOutsideDns":false}),
        )
        .unwrap(),
    );
    assert_ne!(
        engine.editable_profile(&id).unwrap().expected_revision,
        before
    );
}

#[test]
fn editor_revision_is_not_persisted_or_included_in_summary() {
    let (dir, mut engine, id) = engine();
    let dto = json!(engine.editable_profile(&id).unwrap());
    assert_eq!(dto["expectedRevision"].as_str().unwrap().len(), 64);
    let disk = std::fs::read_to_string(dir.path().join("library.json")).unwrap();
    assert!(!disk.contains("expectedRevision"));
    assert!(!engine.snapshot().profiles[0]
        .as_object()
        .unwrap()
        .contains_key("expectedRevision"));
}

fn descriptor(kind: ProfileKind, config: Value) -> (String, String, String) {
    let p = thronium_engine::store::Profile {
        id: "p".into(),
        name: "Name".into(),
        group_id: "personal".into(),
        kind,
        config,
        favorite: false,
        vpn_policy: None,
    };
    let d = thronium_engine::profile_descriptor::describe(&p);
    (d.protocol.into(), d.address.into(), d.security)
}

#[test]
fn xray_addresses_and_security_are_projected_without_exposing_authentication() {
    for (protocol, key) in [("vless", "vnext"), ("shadowsocks", "servers")] {
        let config = json!({"protocol":protocol,"settings":{key:[{"address":"2001:db8::1","port":443,"password":"hidden"}]},"streamSettings":{"security":"reality","network":"grpc"}});
        assert_eq!(
            descriptor(ProfileKind::XrayOutbound, config),
            (
                protocol.into(),
                "2001:db8::1".into(),
                "Reality · grpc".into()
            )
        );
    }
}

#[test]
fn wireguard_endpoint_and_single_full_config_have_display_addresses() {
    let wg =
        json!({"protocol":"wireguard","settings":{"peers":[{"endpoint":"[2001:db8::2]:51820"}]}});
    assert_eq!(descriptor(ProfileKind::XrayOutbound, wg).1, "2001:db8::2");
    let full = json!({"outbounds":[{"protocol":"freedom"},{"protocol":"socks","settings":{"servers":[{"address":"proxy.test","port":1080}]}}]});
    assert_eq!(descriptor(ProfileKind::XrayConfig, full).1, "proxy.test");
}

#[test]
fn multiple_servers_and_chains_do_not_invent_a_display_endpoint() {
    for (kind, config) in [
        (
            ProfileKind::XrayOutbound,
            json!({"protocol":"vless","settings":{"vnext":[{"address":"one"},{"address":"two"}]}}),
        ),
        (
            ProfileKind::SingBoxConfig,
            json!({"outbounds":[{"type":"socks","server":"one"},{"type":"socks","server":"two"}]}),
        ),
        (ProfileKind::Chain, json!({"hops":["one","two"]})),
    ] {
        assert_eq!(descriptor(kind, config).1, "");
    }
}
