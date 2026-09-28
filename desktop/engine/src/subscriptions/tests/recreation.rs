use super::*;

fn recreate(engine: &mut Engine) {
    engine
        .store
        .library
        .settings
        .insert("sub_update_mode".into(), json!("recreate"));
}

#[test]
fn recreation_replaces_even_identical_remote_rows_but_preserves_manual_profiles() {
    let (dir, mut e, g) = setup();
    let first = apply(&mut e, &g, vec![draft(&g, "Same", 1080, "old")]);
    e.favorite(&first[0].id).unwrap();
    let manual = e.save_profile(draft(&g, "Manual", 9999, "local")).unwrap();
    recreate(&mut e);
    e.store
        .library
        .settings
        .insert("sub_clear".into(), json!(false));
    let next = apply(&mut e, &g, vec![draft(&g, "Same", 1080, "old")]);
    assert_eq!(
        next.iter().map(|c| c.action.as_str()).collect::<Vec<_>>(),
        ["added", "removed"]
    );
    assert_ne!(next[0].id, first[0].id);
    assert!(!e.profile(&next[0].id).unwrap().favorite);
    assert!(e.profile(&manual).is_ok());
    let after = state(&e);
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(state(&reopened), after);
}

#[test]
fn recreation_reconciles_protected_survivors_and_preserves_active_configuration() {
    let (_dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Active", 1080, "old"),
            draft(&g, "Routed", 1081, "old"),
            draft(&g, "Replace", 1082, "old"),
        ],
    );
    e.running = Some(first[0].id.clone());
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{}", first[1].id));
    recreate(&mut e);
    let next = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Active", 1080, "new"),
            draft(&g, "Routed", 1081, "new"),
            draft(&g, "Replace", 1082, "new"),
        ],
    );
    assert_eq!(next[0].id, first[0].id);
    assert_eq!(next[1].id, first[1].id);
    assert_ne!(next[2].id, first[2].id);
    assert_eq!(e.profile(&first[0].id).unwrap().config["password"], "old");
    assert_eq!(e.profile(&first[1].id).unwrap().config["password"], "old");
    assert_eq!(e.running.as_ref(), Some(&first[0].id));
}

#[test]
fn recreation_never_deletes_chain_dependencies_or_local_selectors() {
    let (_dir, mut e, g) = setup();
    let first = apply(&mut e, &g, vec![draft(&g, "Hop", 1080, "old")]);
    e.store.library.profiles.push(Profile {
        vpn_policy: None,
        id: "chain-fixture".into(),
        group_id: "personal".into(),
        name: "Chain".into(),
        kind: ProfileKind::Chain,
        config: json!({"hops":[first[0].id]}),
        favorite: false,
    });
    let mut selector = e.profile(&first[0].id).unwrap().clone();
    selector.id = "local-selector".into();
    selector.kind = ProfileKind::AutoSelector;
    selector.config = json!({"type":"auto-selector","members":[first[0].id]});
    // Older imported groups may still list local selectors as managed.
    e.store
        .library
        .groups
        .iter_mut()
        .find(|p| p.id == g)
        .unwrap()
        .subscription
        .as_mut()
        .unwrap()
        .managed_ids
        .push(selector.id.clone());
    e.store.library.profiles.push(selector);
    recreate(&mut e);
    apply(&mut e, &g, vec![draft(&g, "New", 7777, "new")]);
    assert!(e.profile(&first[0].id).is_ok());
    assert!(e.profile("local-selector").is_ok());
    assert!(!e
        .group(&g)
        .unwrap()
        .subscription
        .unwrap()
        .managed_ids
        .iter()
        .any(|id| id == "local-selector"));
}

#[test]
fn mode_change_invalidates_an_existing_preview() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "Old", 1080, "old")]);
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "New", 1080, "new")])
        .unwrap();
    recreate(&mut e);
    let before = state(&e);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(state(&e), before);
}

#[test]
fn failed_recreation_before_rename_preserves_memory_and_disk() {
    let (dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "Old", 1080, "old")]);
    recreate(&mut e);
    e.store.commit(e.store.library.clone()).unwrap();
    let before = state(&e);
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "New", 1080, "new")])
        .unwrap();
    e.store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert!(e.apply_subscription(&token).is_err());
    assert_eq!(state(&e), before);
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(state(&reopened), before);
}

#[test]
fn failure_after_rename_keeps_the_replaced_state_and_consumes_the_ticket() {
    let (dir, mut e, g) = setup();
    let first = apply(&mut e, &g, vec![draft(&g, "Old", 1080, "old")]);
    recreate(&mut e);
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "New", 1080, "new")])
        .unwrap();
    e.store
        .fail_next_commit(crate::store::CommitFault::AfterRename);
    assert!(e.apply_subscription(&token).is_err());
    assert!(e.profile(&first[0].id).is_err());
    assert!(e.store.durability_uncertain());
    let after = state(&e);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_expired")
    );
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(state(&reopened), after);
}

fn with_config(group: &str, kind: ProfileKind, config: Value) -> ProfileDraft {
    let mut p = draft(group, "Location", 443, "unused");
    p.kind = kind;
    p.config = config;
    p
}

#[test]
fn xray_credentials_rotate_with_same_id_for_standard_endpoint_layouts() {
    for (protocol, field) in [("vless", "vnext"), ("shadowsocks", "servers")] {
        let (_dir, mut e, g) = setup();
        let mut config = json!({"protocol":protocol,"settings":{field:[{"address":"example.test","port":443,"users":[{"id":"old"}],"password":"old"}]}});
        let first = apply(
            &mut e,
            &g,
            vec![with_config(&g, ProfileKind::XrayOutbound, config.clone())],
        );
        e.favorite(&first[0].id).unwrap();
        config["settings"][field][0]["password"] = json!("new");
        config["settings"][field][0]["users"][0]["id"] = json!("new");
        let next = apply(
            &mut e,
            &g,
            vec![with_config(&g, ProfileKind::XrayOutbound, config)],
        );
        assert_eq!(next[0].id, first[0].id);
        assert_eq!(next[0].action, "updated");
        assert!(e.profile(&first[0].id).unwrap().favorite);
    }
}

#[test]
fn wireguard_rotation_preserves_id_but_a_changed_peer_topology_does_not() {
    let (_dir, mut e, g) = setup();
    let mut config = json!({"type":"wireguard","private_key":"old","peers":[{"address":"example.test","port":51820,"public_key":"old","allowed_ips":["0.0.0.0/0"]},{"address":"backup.test","port":51820,"allowed_ips":["::/0"]}]});
    let first = apply(
        &mut e,
        &g,
        vec![with_config(
            &g,
            ProfileKind::SingBoxOutbound,
            config.clone(),
        )],
    );
    config["private_key"] = json!("new");
    config["peers"][0]["public_key"] = json!("new");
    let next = apply(
        &mut e,
        &g,
        vec![with_config(
            &g,
            ProfileKind::SingBoxOutbound,
            config.clone(),
        )],
    );
    assert_eq!(next[0].id, first[0].id);
    config["peers"][1]["address"] = json!("different.test");
    let changed = apply(
        &mut e,
        &g,
        vec![with_config(&g, ProfileKind::SingBoxOutbound, config)],
    );
    assert_ne!(changed[0].id, first[0].id);
}

#[test]
fn full_json_matches_its_egress_and_keeps_other_updated_configuration() {
    let (_dir, mut e, g) = setup();
    let mut config = json!({"dns":{"final":"old-dns"},"route":{"final":"pick"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"pick","outbounds":["vpn"]},{"type":"socks","tag":"vpn","server":"example.test","server_port":1080,"password":"old"}]});
    let first = apply(
        &mut e,
        &g,
        vec![with_config(&g, ProfileKind::SingBoxConfig, config.clone())],
    );
    config["outbounds"][2]["password"] = json!("new");
    config["dns"]["final"] = json!("new-dns");
    let next = apply(
        &mut e,
        &g,
        vec![with_config(&g, ProfileKind::SingBoxConfig, config.clone())],
    );
    assert_eq!(next[0].id, first[0].id);
    assert_eq!(e.profile(&first[0].id).unwrap().config, config);
}

#[test]
fn cyclic_full_json_and_multi_server_xray_keep_exact_content_identity() {
    for (kind, mut config) in [
        (
            ProfileKind::SingBoxConfig,
            json!({"outbounds":[{"type":"selector","tag":"self","outbounds":["self"]}],"opaque":"old"}),
        ),
        (
            ProfileKind::XrayOutbound,
            json!({"protocol":"vless","settings":{"vnext":[{"address":"one.test","port":443},{"address":"two.test","port":443}]},"opaque":"old"}),
        ),
    ] {
        let (_dir, mut e, g) = setup();
        let first = apply(&mut e, &g, vec![with_config(&g, kind, config.clone())]);
        config["opaque"] = json!("new");
        let next = apply(&mut e, &g, vec![with_config(&g, kind, config)]);
        assert_ne!(next[0].id, first[0].id);
    }
}
