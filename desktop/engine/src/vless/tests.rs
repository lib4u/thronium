use super::*;
#[test]
fn legacy_libraries_keep_their_core_and_exports_backups_preserve_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let id=engine.save_profile(crate::ProfileDraft{ vpn_policy: Default::default(),id:None,name:"Fixture".into(),group_id:"personal".into(),kind:ProfileKind::SingBoxOutbound,config:json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"})}).unwrap();
    let mut legacy = serde_json::to_value(&engine.store.library).unwrap();
    legacy["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("vlessCore");
    legacy["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("vlessOverrides");
    migrate(&mut legacy);
    let library: Library = serde_json::from_value(legacy).unwrap();
    assert_eq!(library.preferences.vless_overrides[&id], Core::SingBox);
    assert_eq!(
        compile(
            &library.profiles[0],
            library.preferences.vless_core,
            &library.preferences.vless_overrides
        )
        .unwrap()
        .kind,
        ProfileKind::SingBoxOutbound
    );
    engine.vless_core(&id, Some(Core::SingBox)).unwrap();
    let export: Value = serde_json::from_str(
        &engine
            .export_profiles(vec![id.clone()], crate::exports::Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(export["profiles"][0]["vlessCore"], "sing-box");
    let mut imported = export["profiles"][0].clone();
    imported["groupId"] = json!("personal");
    let drafts = serde_json::from_value(json!([imported])).unwrap();
    let imported = engine.import_referenced_profiles(drafts).unwrap();
    assert_eq!(
        engine.store.library.preferences.vless_overrides[&imported[0]],
        Core::SingBox
    );
    let backup = engine.export_backup().unwrap();
    let preview = engine.preview_backup(&backup).unwrap();
    assert_eq!(preview.incoming.profiles, 2);
}
use std::path::Path;
#[test]
fn vless_conversion_is_lossless_for_supported_transport_and_rejects_extras() {
    let uri = json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","packet_encoding":"xudp"});
    assert!(to_xray(&uri).is_ok());
    let mut packetaddr = uri.clone();
    packetaddr["packet_encoding"] = json!("packetaddr");
    assert!(to_xray(&packetaddr).is_err());
    let c = json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","tls":{"enabled":true,"server_name":"example.test","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"key","short_id":"abcd"}},"transport":{"type":"grpc","service_name":"service"}});
    assert_eq!(to_singbox(&to_xray(&c).unwrap()).unwrap(), c);
    let mut c = to_xray(&c).unwrap();
    c["streamSettings"]["network"] = json!("xhttp");
    assert_eq!(to_singbox(&c).unwrap_err(), "vless_requires_xray");
    c["streamSettings"]["network"] = json!("grpc");
    c["streamSettings"]["grpcSettings"]["multiMode"] = json!(true);
    assert!(to_singbox(&c).is_err());
}
#[test]
fn websocket_and_httpupgrade_header_lists_become_single_xray_strings() {
    for kind in ["ws", "httpupgrade"] {
        let mut c = json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","transport":{"type":kind,"path":"/up","headers":{"X-Fixture":["one"]}}});
        let xray = to_xray(&c).unwrap();
        assert_eq!(
            xray["streamSettings"][format!("{kind}Settings")]["headers"]["X-Fixture"],
            "one",
            "{kind}"
        );
        c["transport"]["headers"]["X-Fixture"] = json!(["one", "two"]);
        assert_eq!(
            to_xray(&c).unwrap_err(),
            "vless_core_conversion_unsupported",
            "{kind}"
        );
    }
}
