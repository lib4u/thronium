//! Independent public URL-probe dispatch checks. No Core execution or network.
#![cfg(target_os = "linux")]
use serde_json::json;
use thronium_engine::{probes::Options, Engine, ProfileDraft};

fn ordinary(protocol: &str) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let config = if protocol == "openvpn-client" {
        json!({"type":protocol,"server":"127.0.0.1","server_port":1194,"system":false})
    } else {
        json!({"type":protocol,"server":"https://127.0.0.1:443/owned","flavor":"anyconnect","system":false})
    };
    let draft: ProfileDraft = serde_json::from_value(json!({
        "name":"Owned ordinary VPN probe","kind":"sing-box-outbound",
        "groupId":"personal","config":config
    }))
    .unwrap();
    let id = engine.save_profile(draft).unwrap();
    let bytes = std::fs::read(dir.path().join("library.json")).unwrap();
    let selected = engine.snapshot().selected;
    let run = engine
        .start_url_tests(Options {
            ids: vec![id],
            url: "http://127.0.0.1:9/never-executed".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    let probe = engine.next_url_test(&run.id);
    let status = engine.snapshot().url_tests.unwrap().entries[0].status;
    assert!(engine.owned_core_process().is_none());
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        bytes
    );
    assert_eq!(engine.snapshot().selected, selected);
    // The executable is intentionally absent, and execute() is never called.
    // Baseline35 fails here with Unsupported;36 must prepare disposable work.
    assert!(
        probe.is_some(),
        "ordinary {protocol} HTTP probe was {status:?}"
    );
    drop(probe);
    engine.cancel_url_tests();
    engine.clear_url_tests().unwrap();
}

#[test]
fn ordinary_openvpn_http_is_dispatched_without_starting_core() {
    ordinary("openvpn-client");
}

#[test]
fn ordinary_openconnect_http_is_dispatched_without_starting_core() {
    ordinary("openconnect");
}

fn profile(engine: &mut Engine, config: serde_json::Value) -> String {
    engine.save_profile(serde_json::from_value(json!({
        "name":"Public VPN guard","kind":"sing-box-outbound","groupId":"personal","config":config
    })).unwrap()).unwrap()
}
fn ovpn() -> serde_json::Value {
    json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,
        "username":"owned-static-user","password":"owned-static-password","system":false})
}
fn start(engine: &mut Engine, id: &str) -> thronium_engine::probes::Run {
    engine
        .start_url_tests(Options {
            ids: vec![id.into()],
            url: "http://127.0.0.1:9/never-executed".into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap()
}
fn refused(engine: &mut Engine, id: &str, directory: &std::path::Path) {
    let disk = std::fs::read(directory.join("library.json")).unwrap();
    let otp = engine.otp_list();
    let run = start(engine, id);
    assert!(engine.next_url_test(&run.id).is_none());
    let entry = engine.snapshot().url_tests.unwrap().entries.remove(0);
    assert_eq!(entry.status, thronium_engine::probes::Status::Unsupported);
    assert!(entry.latency_ms.is_none());
    assert!(engine.owned_core_process().is_none());
    assert_eq!(engine.otp_list(), otp);
    assert!(
        std::fs::read(directory.join("library.json")).unwrap() == disk,
        "refused probe changed Library"
    );
    engine.clear_url_tests().unwrap();
}

#[test]
fn unsafe_auth_and_system_contexts_are_refused_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    for (key, value) in [
        ("password", json!("prefix{otp}")),
        ("username", json!("{otp}")),
        ("system", json!(true)),
        ("name", json!("owned-interface")),
        ("detour", json!("direct")),
        ("token", json!({"mode":"totp","secret":"synthetic-token"})),
    ] {
        let mut config = ovpn();
        config[key] = value;
        let id = profile(&mut engine, config);
        refused(&mut engine, &id, dir.path());
    }
    for (key, value) in [
        ("flavor", json!("globalprotect")),
        ("cookie", json!("synthetic-cookie")),
        ("form_entries", json!([{"name":"otp","value":"{otp}"}])),
        ("password_authentication_disabled", json!(true)),
    ] {
        let mut config =
            json!({"type":"openconnect","server":"https://127.0.0.1/owned","flavor":"anyconnect"});
        config[key] = value;
        let id = profile(&mut engine, config);
        refused(&mut engine, &id, dir.path());
    }
    let full: ProfileDraft = serde_json::from_value(json!({
        "name":"Opaque VPN configuration","kind":"sing-box-config","groupId":"personal",
        "config":{"endpoints":[ovpn()],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    }))
    .unwrap();
    let id = engine.save_profile(full).unwrap();
    refused(&mut engine, &id, dir.path());
    let id = profile(&mut engine, ovpn());
    engine
        .connection_settings(thronium_engine::system_proxy::ConnectionMode::Tun, 2080)
        .unwrap();
    refused(&mut engine, &id, dir.path()); // Configured TUN context; no TUN/permission operation is performed.
}

#[test]
fn policy_changes_make_queued_probe_stale_but_name_change_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let id = profile(&mut engine, ovpn());
    let run = start(&mut engine, &id);
    let original = engine.profile(&id).unwrap();
    engine.save_profile(serde_json::from_value(json!({
        "id":id,"name":original.name,"kind":"sing-box-outbound","groupId":"personal","config":original.config,
        "vpnPolicy":{"onlyAdvertisedRoutes":true,"useTunnelDns":false,"blockOutsideDns":false}
    })).unwrap()).unwrap();
    assert!(engine.next_url_test(&run.id).is_none());
    assert_eq!(
        engine.snapshot().url_tests.unwrap().entries[0].status,
        thronium_engine::probes::Status::Stale
    );
    engine.clear_url_tests().unwrap();
    let run = start(&mut engine, &id);
    engine.save_profile(serde_json::from_value(json!({
        "id":id,"name":"Renamed without network change","kind":"sing-box-outbound","groupId":"personal","config":ovpn()
    })).unwrap()).unwrap();
    engine.select(&id).unwrap();
    let probe = engine.next_url_test(&run.id);
    assert!(
        probe.is_some(),
        "display name change incorrectly changed probe identity"
    );
    assert!(engine.owned_core_process().is_none());
    drop(probe);
    engine.cancel_url_tests();
    engine.clear_url_tests().unwrap();
}

#[test]
fn new_local_otp_binding_invalidates_queue_without_consuming_hotp() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let mut config = ovpn();
    config["static_challenge"] = json!("Owned challenge");
    let id = profile(&mut engine, config);
    let otp = engine
        .otp_save(
            "",
            "",
            thronium_engine::otp::Draft {
                name: "Unused probe OTP".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                kind: thronium_engine::otp::Kind::Hotp,
                counter: "9007199254740993".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let run = start(&mut engine, &id);
    let edit = engine.get_vpn_otp_binding(&id).unwrap();
    engine
        .save_vpn_otp_binding(thronium_engine::vpn_otp_bindings::SaveRequest {
            profile_id: id.clone(),
            edit_token: edit.edit_token,
            otp_id: Some(otp["id"].as_str().unwrap().into()),
            otp_revision: Some(otp["revision"].as_str().unwrap().into()),
            mode: None,
        })
        .unwrap();
    assert!(engine.next_url_test(&run.id).is_none());
    assert_eq!(
        engine.snapshot().url_tests.unwrap().entries[0].status,
        thronium_engine::probes::Status::Stale
    );
    engine.clear_url_tests().unwrap();
    // Nothing was spent while the queue went stale.
    assert_eq!(
        engine.store.library.otp[0].value.counter,
        "9007199254740993"
    );
    // A manual test of the now bound profile spends exactly one code, when
    // the probe is issued; automatic sources are refused (`bake_probe_otp`).
    let run = start(&mut engine, &id);
    assert!(engine.next_url_test(&run.id).is_some());
    assert_eq!(
        engine.store.library.otp[0].value.counter,
        "9007199254740994"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn issued_vpn_probe_blocks_tun_connect_before_build_or_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("core-does-not-exist");
    assert!(!absent.exists());
    let mut engine = Engine::open(dir.path(), &absent).unwrap();
    let vpn = profile(&mut engine, ovpn());
    let direct = profile(&mut engine, json!({"type":"direct"}));
    let run = start(&mut engine, &vpn);
    let issued = engine
        .next_url_test(&run.id)
        .expect("ordinary VPN should issue a Probe");
    engine
        .connection_settings(thronium_engine::system_proxy::ConnectionMode::Tun, 2080)
        .unwrap();
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    assert_eq!(engine.connect(&direct).await.unwrap_err(), "probe_busy");
    engine.cancel_url_tests();
    // Queue cancellation cannot release ownership of an issued, still-held Probe.
    assert_eq!(engine.connect(&direct).await.unwrap_err(), "probe_busy");
    assert!(engine.owned_core_process().is_none());
    assert!(std::fs::read(dir.path().join("library.json")).unwrap() == disk);
    drop(issued);
    engine.clear_url_tests().unwrap();
    // Source trace: CheckConfig -> ensure_rpc -> spawn canonicalize fails before
    // process creation; ensure_tun_rpc/pkexec is later. No Core path exists.
    assert_eq!(engine.connect(&direct).await.unwrap_err(), "core_missing");
    assert!(engine.owned_core_process().is_none());
    assert!(!absent.exists());
}
