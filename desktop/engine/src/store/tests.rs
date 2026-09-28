use super::*;
#[test]
fn preserves_complete_configuration_and_blocks_concurrent_writers() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    assert!(Store::open(dir.path()).is_err());
    let mut next = store.library.clone();
    next.profiles.push(Profile { vpn_policy: None, id: "awg".into(), name: "AWG".into(), group_id: "personal".into(), kind: ProfileKind::SingBoxOutbound, favorite: false,
        config: serde_json::json!({"type":"wireguard", "private_key":"sentinel", "amnezia_wg":{"h1":"10-20","random_trailers":true}, "future_option":{"value":7}}) });
    store.commit(next.clone()).unwrap();
    drop(store);
    let loaded = Store::open(dir.path()).unwrap();
    assert_eq!(loaded.library.profiles[0].config, next.profiles[0].config);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("library.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn library_without_routing_migrates_without_changing_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let mut old = serde_json::to_value(Library::default()).unwrap();
    old.as_object_mut().unwrap().remove("routing");
    old["profiles"] = serde_json::json!([{"id":"legacy", "name":"Existing", "groupId":"personal", "kind":"sing-box-outbound", "favorite":true,
        "config":{"type":"socks", "server":"127.0.0.1", "server_port":1080, "password":"migration-sentinel", "extension":{"preserve":true}}}]);
    old["selected"] = serde_json::json!("legacy");
    let bytes = serde_json::to_vec(&old).unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, &bytes).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    assert_eq!(
        serde_json::to_value(&store.library.profiles).unwrap(),
        old["profiles"]
    );
    assert_eq!(store.library.selected.as_deref(), Some("legacy"));
    assert!(store.library.routing.active().unwrap().rules.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    store.commit(store.library.clone()).unwrap();
    drop(store);
    let loaded = Store::open(dir.path()).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded.library.profiles).unwrap(),
        old["profiles"]
    );
    assert_eq!(
        loaded.library.routing.active().unwrap().route["final"],
        "proxy"
    );
}
#[test]
fn corrupt_data_is_not_silently_reset() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("library.json"), "{bad").unwrap();
    assert!(matches!(Store::open(dir.path()), Err(e) if e == "library_corrupt"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("library.json")).unwrap(),
        "{bad"
    );
}

#[test]
fn a_sealed_library_holds_nothing_in_the_open_and_is_refused_without_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = crate::secrets::Key::generate().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    // Without a key of this desktop the file stays exactly as it always was.
    store.commit(store.library.clone()).unwrap();
    let plain = std::fs::read(dir.path().join("library.json")).unwrap();
    assert!(!crate::secrets::sealed(&plain));
    // With one, the same library is written sealed and reads back unchanged.
    store.secrets = Ok(key.clone());
    let mut library = store.library.clone();
    library.profiles.push(crate::store::Profile {
        id: "sealed-profile".into(),
        name: "Sealed".into(),
        group_id: PERSONAL_GROUP.into(),
        kind: crate::store::ProfileKind::SingBoxOutbound,
        config: serde_json::json!({"type":"socks","password":"synthetic-store-secret"}),
        favorite: false,
        vpn_policy: None,
    });
    store.commit(library).unwrap();
    let bytes = std::fs::read(dir.path().join("library.json")).unwrap();
    assert!(crate::secrets::sealed(&bytes));
    assert!(!bytes
        .windows(b"synthetic-store-secret".len())
        .any(|window| window == b"synthetic-store-secret"));
    drop(store);
    // A copy of this installation without the key sees only that it is sealed.
    assert!(matches!(Store::open(dir.path()), Err(code) if code == "secrets_unavailable"));
    let mut reopened = Store::open_sealed_for_test(dir.path(), key).unwrap();
    assert!(reopened
        .library
        .profiles
        .iter()
        .any(|p| p.id == "sealed-profile"));
    // Losing the key later never rewrites the file in the open.
    reopened.commit(reopened.library.clone()).unwrap();
    assert!(crate::secrets::sealed(
        &std::fs::read(dir.path().join("library.json")).unwrap()
    ));
}

/// A library that travels between computers is not sealed; one sealed
/// earlier opens with this computer's key and is written plain from then on.
#[test]
fn a_travelling_library_is_read_with_the_old_key_and_written_plain() {
    let dir = tempfile::tempdir().unwrap();
    let key = crate::secrets::Key::generate().unwrap();
    let mut sealed = Store::open_sealed_for_test(dir.path(), key.clone()).unwrap();
    sealed.commit(sealed.library.clone()).unwrap();
    drop(sealed);
    assert!(crate::secrets::sealed(
        &std::fs::read(dir.path().join("library.json")).unwrap()
    ));
    crate::secrets::keyring::inject_for_test(Some(key));
    let mut portable = Store::open_with(dir.path(), false);
    crate::secrets::keyring::inject_for_test(None);
    let portable = portable.as_mut().unwrap();
    assert!(matches!(
        portable.secrets,
        Err(crate::secrets::keyring::Absent::Portable)
    ));
    portable.commit(portable.library.clone()).unwrap();
    assert!(!crate::secrets::sealed(
        &std::fs::read(dir.path().join("library.json")).unwrap()
    ));
}
