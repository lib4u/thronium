//! Independent public API review. No network, executable lookup or real core.
use serde_json::{json, Value};
use thronium_engine::{
    exports::Format,
    store::ProfileKind,
    subscriptions::{metadata::Metadata, Download, GroupDraft},
    system_proxy::ConnectionMode,
    Engine, ProfileDraft,
};

fn source() -> Value {
    json!({"type":"extracore","name":"Opaque external 日本","socks_address":"127.0.0.1","socks_port":38171,
        "extra_core_path":"/missing/private-external-program","extra_core_args":"  --file '%s'  --literal '$HOME'  ",
        "extra_core_conf":" \r\n# private-external-secret\n  value: \"日本\"\n\t ","no_logs":true})
}
fn draft(config: Value) -> ProfileDraft {
    serde_json::from_value(json!({"name":"Reviewed external","groupId":"personal","kind":"external-core","config":config})).unwrap()
}
fn engine(path: &std::path::Path) -> Engine {
    Engine::open(path, &path.join("absent-core")).unwrap()
}
fn safe(value: impl serde::Serialize) {
    let text = serde_json::to_string(&value).unwrap();
    for secret in [
        "private-external-program",
        "private-external-secret",
        "$HOME",
    ] {
        assert!(!text.contains(secret));
    }
}

#[tokio::test]
async fn opaque_source_is_exact_across_public_save_preview_export_import_backup_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let input = source();
    let id = app.save_profile(draft(input.clone())).unwrap();
    assert_eq!(app.profile(&id).unwrap().config, input);
    safe(app.snapshot());
    assert!(app.owned_core_process().is_none());
    let preview = app.connection_configuration(&id, false).await.unwrap();
    let external = preview["parts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "external-core")
        .unwrap();
    for key in [
        "extra_core_path",
        "extra_core_args",
        "extra_core_conf",
        "socks_address",
        "socks_port",
        "no_logs",
    ] {
        assert_eq!(external["config"][key], input[key]);
    }
    assert!(app.owned_core_process().is_none());
    let exported: Value = serde_json::from_str(
        &app.export_profiles(vec![id.clone()], Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(exported["profiles"][0]["kind"], "external-core");
    assert_eq!(exported["profiles"][0]["config"], input);
    assert_eq!(
        serde_json::from_str::<Value>(
            &app.export_profiles(vec![id.clone()], Format::Configurations)
                .unwrap()
        )
        .unwrap(),
        input
    );
    let mut imported = exported["profiles"][0].clone();
    imported["groupId"] = json!("personal");
    let new_id = app
        .import_profiles(vec![serde_json::from_value(imported).unwrap()])
        .unwrap()
        .remove(0);
    assert_ne!(id, new_id);
    assert_eq!(app.profile(&new_id).unwrap().config, input);
    let saved = app.export_backup().unwrap();
    let before = json!(app.store.library);
    let mut empty = source();
    empty["extra_core_args"] = json!("");
    empty["extra_core_conf"] = json!("");
    app.save_profile(draft(empty)).unwrap();
    let review = app.preview_backup(&saved).unwrap();
    safe(&review);
    app.restore_backup(&review.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    drop(app);
    let mut reopened = engine(dir.path());
    assert_eq!(reopened.profile(&id).unwrap().config, input);
    assert!(reopened.owned_core_process().is_none());
    safe(reopened.snapshot());
}

#[test]
fn malformed_external_manual_batches_are_atomic_and_errors_never_reflect_source_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let before = json!(app.store.library);
    for (key, value) in [
        ("future-private-external-secret", json!(true)),
        ("socks_address", json!("private-external-secret.example")),
        ("socks_port", json!(53)),
        ("no_logs", Value::Null),
        ("extra_core_path", json!("relative/private-external-secret")),
    ] {
        let mut bad = source();
        bad[key] = value;
        let error = app
            .import_profiles(vec![draft(source()), draft(bad)])
            .unwrap_err();
        safe(&error);
        assert_eq!(json!(app.store.library), before);
        assert!(app.owned_core_process().is_none());
    }
}

/// TUN, the system proxy and WARP run an external core: the external
/// checks pass and only the absent core stops the attempt. What stays refused
/// (a clashing inbound port, legacy routing) fails before core discovery.
#[tokio::test]
async fn runtime_contexts_refuse_only_what_an_external_core_cannot_run() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let id = app.save_profile(draft(source())).unwrap();
    let base = app.store.library.clone();
    for mode in [ConnectionMode::Tun, ConnectionMode::SystemProxy] {
        let mut next = base.clone();
        next.preferences.connection_mode = mode;
        app.store.commit(next).unwrap();
        // The system proxy may also stop at a desktop without a proxy backend.
        let error = app.connect(&id).await.unwrap_err();
        assert!(!error.starts_with("external_"), "{error}");
        assert_eq!(
            app.check(&app.profile(&id).unwrap()).await.unwrap_err(),
            "core_missing"
        );
        // The external core's own traffic leaves directly, matched by its path.
        let configuration = app.connection_configuration(&id, false).await.unwrap();
        assert!(configuration.to_string().contains(
            r#""action":"route","outbound":"direct","process_path":["/missing/private-external-program"]"#
        ));
        assert!(app.owned_core_process().is_none());
        assert!(app.snapshot().running.is_none());
    }
    let mut next = base.clone();
    next.settings.insert("enable_warp".into(), json!(true));
    for key in ["warp_private_key", "warp_public_key"] {
        next.settings.insert(
            key.into(),
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        );
    }
    next.settings
        .insert("warp_ifc_addrs".into(), json!(["172.16.0.2/32"]));
    app.store.commit(next).unwrap();
    assert_eq!(app.connect(&id).await.unwrap_err(), "core_missing");
    assert!(app.owned_core_process().is_none());
    let mut next = base.clone();
    next.preferences.inbound_port = 38171;
    app.store.commit(next).unwrap();
    assert_eq!(
        app.connect(&id).await.unwrap_err(),
        "external_port_conflict"
    );
    assert!(app.owned_core_process().is_none());
    let mut next = base.clone();
    next.routing.profiles[0].legacy_constraints =
        Some(thronium_engine::routing::LegacyRoutingConstraints {
            warp_enabled: false,
            version: 2,
            xray_dns_strategy: Some("UseIP".into()),
            ..Default::default()
        });
    app.store.commit(next).unwrap();
    assert_eq!(
        app.connect(&id).await.unwrap_err(),
        "external_routing_unsupported"
    );
    assert!(app.owned_core_process().is_none());
    app.store.commit(base).unwrap();
}

/// A chain may start at an external core and nowhere else; pools, group
/// front and landing proxies never hold one, and dynamic pools skip it.
#[test]
fn external_cores_start_chains_only_and_dynamic_membership_excludes_them() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let id = app.save_profile(draft(source())).unwrap();
    let before = json!(app.store.library);
    let pool: ProfileDraft = serde_json::from_value(
        json!({"name":"Unsupported pool","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","members":[id]}}),
    )
    .unwrap();
    assert_eq!(
        app.save_profile(pool).unwrap_err(),
        "selector_member_unsupported"
    );
    assert_eq!(json!(app.store.library), before);
    for proxy_chain in [json!({"front":id}), json!({"landing":id})] {
        let group: GroupDraft = serde_json::from_value(
            json!({"name":"External in group chain","proxyChain":proxy_chain}),
        )
        .unwrap();
        assert_eq!(
            app.save_group(group).unwrap_err(),
            "group_chain_hop_unsupported"
        );
        assert_eq!(json!(app.store.library), before);
    }
    let ordinary = app
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Ordinary supported".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":9}),
        })
        .unwrap();
    let pool:ProfileDraft=serde_json::from_value(json!({"name":"Dynamic excludes external","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","member_source":{"group_id":"personal","name_regex":"","exclude_regex":""}}})).unwrap();
    let preview = app.preview_selector(pool).unwrap();
    assert_eq!(
        preview["members"],
        json!([{"id":ordinary,"name":"Ordinary supported"}])
    );
    for (hops, result) in [
        (json!([id, ordinary]), Ok(())),
        (json!([ordinary, id]), Err("external_chain_position")),
    ] {
        let chain: ProfileDraft = serde_json::from_value(
            json!({"name":"External chain","groupId":"personal","kind":"chain","config":{"type":"chain","hops":hops}}),
        )
        .unwrap();
        assert_eq!(
            app.save_profile(chain).map(|_| ()),
            result.map_err(String::from)
        );
    }
    assert!(app.owned_core_process().is_none());
}

#[test]
fn subscription_external_profiles_are_rejected_before_filters_and_cannot_be_applied_as_remote_code()
{
    let dir = tempfile::tempdir().unwrap();
    let mut app = engine(dir.path());
    let group=app.save_group(serde_json::from_value(json!({"name":"Subscription fixture","subscription":{"url":"http://127.0.0.1:9/never-requested","inheritDefaults":false,"nameRules":{"exclude":"Reviewed external"}}})).unwrap()).unwrap();
    let before = json!(app.store.library);
    let request = app.subscription_request(&group).unwrap();
    let downloaded = app
        .subscription_downloaded(
            request,
            Download {
                body: String::new(),
                metadata: Metadata::default(),
                usage: None,
            },
        )
        .unwrap();
    let token = downloaded["ticket"].as_str().unwrap();
    let mut remote = draft(source());
    remote.group_id = group;
    assert_eq!(
        app.preview_subscription(token, vec![remote]).err().unwrap(),
        "external_remote_import_unsupported"
    );
    assert!(app.apply_subscription(token).is_err());
    assert_eq!(json!(app.store.library), before);
    assert!(app.owned_core_process().is_none());
    safe(app.snapshot());
    // Explicit local JSON import remains a distinct reviewable storage action.
    assert_eq!(app.import_profiles(vec![draft(source())]).unwrap().len(), 1);
    assert!(app.owned_core_process().is_none());
}
