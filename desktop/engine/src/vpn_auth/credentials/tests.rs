use super::*;
use std::sync::{Arc, Mutex};

pub(super) struct Wire {
    state: String,
    after_check: Option<String>,
    check_error: bool,
    start_error: bool,
    calls: Vec<String>,
    checks: Vec<proto::LoadConfigReq>,
    starts: Vec<proto::LoadConfigReq>,
}
impl Default for Wire {
    fn default() -> Self {
        Self {
            state: "error".into(),
            after_check: None,
            check_error: false,
            start_error: false,
            calls: vec![],
            checks: vec![],
            starts: vec![],
        }
    }
}
pub(super) fn response(state: &str) -> proto::VpnStatusResponse {
    proto::VpnStatusResponse {
        results: vec![proto::VpnEndpointStatus {
            tag: Some("proxy".into()),
            state: Some(state.into()),
            connected: Some(state == "connected"),
            auth_failed: Some(state == "error"),
            challenge: (state == "auth-pending").then(|| proto::VpnChallenge {
                endpoint_tag: Some("proxy".into()),
                id: Some("next".into()),
                kind: Some("secret".into()),
                ..Default::default()
            }),
            ..Default::default()
        }],
    }
}
pub(super) fn setup() -> (tempfile::TempDir, Engine, Arc<Mutex<Wire>>) {
    let state = Arc::new(Mutex::new(Wire::default()));
    let remote = state.clone();
    let rpc = crate::transport::Rpc::scripted_local_test_rpc(move |method, payload| {
        let mut wire = remote.lock().unwrap();
        wire.calls.push(method.into());
        match method {
            "QueryVPNStatus" => response(&wire.state).encode_to_vec(),
            "CheckConfig" => {
                wire.checks
                    .push(proto::LoadConfigReq::decode(payload).unwrap());
                if let Some(next) = wire.after_check.take() {
                    wire.state = next;
                }
                proto::ErrorResp {
                    error: wire
                        .check_error
                        .then(|| "sensitive-candidate-password".into()),
                }
                .encode_to_vec()
            }
            "Start" => {
                wire.starts
                    .push(proto::LoadConfigReq::decode(payload).unwrap());
                proto::ErrorResp {
                    error: wire
                        .start_error
                        .then(|| "ordinary_candidate_rejected".into()),
                }
                .encode_to_vec()
            }
            "Stop" => proto::ErrorResp::default().encode_to_vec(),
            _ => panic!("Unexpected credential RPC {method}"),
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
    engine
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                name: "Unspent".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                kind: crate::otp::Kind::Hotp,
                counter: i64::MAX.to_string(),
                ..Default::default()
            },
        )
        .unwrap();
    engine.rpc = Some(rpc);
    engine.running = Some("frozen-profile".into());
    engine.active_connection = Some(ActiveConnection {
        id: "frozen-profile".into(), profiles: HashSet::from(["frozen-profile".into()]),
        groups: HashSet::from(["personal".into()]),
        request: proto::LoadConfigReq { core_config: Some(json!({
            "endpoints":[{"type":"openvpn-client","tag":"proxy","username":"original-user","password":"original-password","server":"127.0.0.1","server_port":1194}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"proxy","rules":[{"domain":"held.fixture.invalid","action":"route","outbound":"direct"}]},
            "dns":{"servers":[{"type":"local","tag":"local"}]},
            "inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":12345}]
        }).to_string()), ..Default::default() },
        routing_revision: 17, system_port: None, tun: false, external_instance: None,
        vpn_primary: true, vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    engine.routing_revision = None;
    engine.reset_vpn_session();
    (dir, engine, state)
}
pub(super) fn get(engine: &Engine) -> CredentialRequest {
    CredentialRequest {
        session_id: engine.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
    }
}
pub(super) fn edit(view: &CredentialView) -> CredentialEditRequest {
    CredentialEditRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
    }
}
pub(super) fn restart(view: &CredentialView) -> RestartCredentialsRequest {
    RestartCredentialsRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
        username: " temporary user \n".into(),
        password: "sensitive-candidate-password".into(),
    }
}
fn assert_error<T>(result: Result<T, String>, expected: &str) {
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("Expected {expected}"),
    }
}

#[tokio::test]
async fn cancel_is_local_and_old_identity_cannot_consume_new_token() {
    let (_dir, mut engine, wire) = setup();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    let owner = engine.owned_core_process().unwrap();
    let public = serde_json::to_value(&view).unwrap();
    assert_eq!(public.as_object().unwrap().len(), 4);
    assert_eq!(view.username, "original-user");
    assert!(!public.to_string().contains("original-password"));
    let mut wrong = edit(&view);
    wrong.session_id = "old-session".into();
    assert_error(
        engine.cancel_vpn_credentials(wrong),
        "vpn_credentials_stale",
    );
    assert!(engine.vpn.credentials.0.contains_key(&view.edit_token));
    let calls = wire.lock().unwrap().calls.clone();
    engine.cancel_vpn_credentials(edit(&view)).unwrap();
    assert_error(
        engine.restart_vpn_credentials(restart(&view)).await,
        "vpn_credentials_stale",
    );
    assert_eq!(wire.lock().unwrap().calls, calls);
    assert_eq!(engine.owned_core_process().unwrap(), owner);
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn observed_connected_or_challenge_invalidates_even_if_error_returns_same_session() {
    for observed in ["connected", "auth-pending"] {
        let (_dir, mut engine, wire) = setup();
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        wire.lock().unwrap().state = observed.into();
        engine.query_vpn().await.unwrap();
        wire.lock().unwrap().state = "error".into();
        engine.query_vpn().await.unwrap();
        assert_eq!(
            engine.vpn.status.session_id.as_deref(),
            Some(view.session_id.as_str())
        );
        assert_error(
            engine.restart_vpn_credentials(restart(&view)).await,
            "vpn_credentials_stale",
        );
        assert!(!wire
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|m| matches!(m.as_str(), "CheckConfig" | "Stop" | "Start")));
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}

#[tokio::test]
async fn unsupported_contexts_refuse_before_any_rpc() {
    for variant in 0..7 {
        let (_dir, mut engine, wire) = setup();
        let active = engine.active_connection.as_mut().unwrap();
        match variant {
            0 => active.tun = true,
            1 => active.system_port = Some(12345),
            2 => active.external_instance = Some("external".into()),
            // A tag that names no endpoint of this connection.
            3 => {}
            _ => {
                let (mut config, _) = endpoint_config(&active.request, "proxy").unwrap();
                config["endpoints"][0]["type"] = json!("openconnect");
                let (key, value) = match variant {
                    4 => ("cookie", json!("opaque")),
                    5 => ("form_entries", json!([{"name":"answer","value":"fixed"}])),
                    _ => ("token", json!({"mode":"totp"})),
                };
                config["endpoints"][0][key] = value;
                active.request.core_config = Some(config.to_string());
            }
        }
        let expected = if variant < 4 {
            "vpn_credentials_unsupported"
        } else {
            "vpn_credentials_configuration_unsupported"
        };
        let mut request = get(&engine);
        if variant == 3 {
            request.endpoint_tag = "not-an-endpoint".into();
        }
        assert_error(engine.vpn_credentials(request).await, expected);
        assert!(wire.lock().unwrap().calls.is_empty());
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}

#[tokio::test]
async fn expired_and_invalid_answers_never_check_or_stop_and_require_new_token() {
    let (_dir, mut engine, wire) = setup();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    engine
        .vpn
        .credentials
        .0
        .get_mut(&view.edit_token)
        .unwrap()
        .created -= EDIT_TTL + Duration::from_secs(1);
    assert_error(
        engine.restart_vpn_credentials(restart(&view)).await,
        "vpn_credentials_expired",
    );
    for (username, password) in [
        ("".to_string(), "".to_string()),
        ("user".into(), "{otp}".into()),
        ("user".into(), "bad\0value".into()),
        ("x".repeat(4097), "password".into()),
    ] {
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        let mut answer = restart(&view);
        answer.username = username;
        answer.password = password;
        assert_error(
            engine.restart_vpn_credentials(answer).await,
            "vpn_credentials_invalid",
        );
        assert_error(
            engine.restart_vpn_credentials(restart(&view)).await,
            "vpn_credentials_stale",
        );
    }
    assert!(wire
        .lock()
        .unwrap()
        .calls
        .iter()
        .all(|m| m == "QueryVPNStatus"));
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn failed_check_and_new_challenge_during_check_preserve_old_request_and_owner() {
    for fail_check in [true, false] {
        let (_dir, mut engine, wire) = setup();
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        let owner = engine.owned_core_process().unwrap();
        let before = engine
            .active_connection
            .as_ref()
            .unwrap()
            .request
            .encode_to_vec();
        if fail_check {
            wire.lock().unwrap().check_error = true;
        } else {
            wire.lock().unwrap().after_check = Some("auth-pending".into());
        }
        assert_error(
            engine.restart_vpn_credentials(restart(&view)).await,
            if fail_check {
                "vpn_credentials_check_failed"
            } else {
                "vpn_credentials_unavailable"
            },
        );
        assert_eq!(engine.owned_core_process().unwrap(), owner);
        assert_eq!(
            engine
                .active_connection
                .as_ref()
                .unwrap()
                .request
                .encode_to_vec(),
            before
        );
        assert!(!wire
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|m| m == "Stop" || m == "Start"));
        assert_eq!(
            engine.vpn.status.session_id.as_deref(),
            Some(view.session_id.as_str())
        );
        assert!(!serde_json::to_string(&engine.snapshot())
            .unwrap()
            .contains("sensitive-candidate-password"));
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}

#[tokio::test]
async fn successful_restart_uses_frozen_request_preserves_pending_library_and_clears_tokens() {
    let (dir, mut engine, wire) = setup();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    let old = engine.active_connection.clone().unwrap();
    let library = serde_json::to_value(&engine.store.library).unwrap();
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    // Changing selection/settings cannot retarget this explicit session action.
    engine.store.library.selected = Some("other-selected".into());
    let expected_library = serde_json::to_value(&engine.store.library).unwrap();
    engine
        .restart_vpn_credentials(restart(&view))
        .await
        .unwrap();
    let mut expected = old.request.clone();
    let (mut config, index) = endpoint_config(&expected, "proxy").unwrap();
    config["endpoints"][index]["username"] = json!(" temporary user \n");
    config["endpoints"][index]["password"] = json!("sensitive-candidate-password");
    expected.core_config = Some(config.to_string());
    assert_eq!(
        engine
            .active_connection
            .as_ref()
            .unwrap()
            .request
            .encode_to_vec(),
        expected.encode_to_vec()
    );
    assert_eq!(engine.running.as_deref(), Some("frozen-profile"));
    assert_eq!(engine.routing_revision, None);
    assert_ne!(
        engine.vpn.status.session_id.as_deref(),
        Some(view.session_id.as_str())
    );
    assert_error(
        engine.cancel_vpn_credentials(edit(&view)),
        "vpn_credentials_stale",
    );
    assert_eq!(
        serde_json::to_value(&engine.store.library).unwrap(),
        expected_library
    );
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        disk
    );
    assert_eq!(library["otp"], expected_library["otp"]);
    {
        let state = wire.lock().unwrap();
        assert_eq!(
            state.calls,
            [
                "QueryVPNStatus",
                "QueryVPNStatus",
                "CheckConfig",
                "QueryVPNStatus",
                "Stop",
                "Start"
            ]
        );
        assert_eq!(state.starts.len(), 1);
        assert_eq!(state.starts[0].encode_to_vec(), expected.encode_to_vec());
    }
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn failed_start_reaps_candidate_and_keeps_library_when_restore_is_unavailable() {
    let (dir, mut engine, wire) = setup();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    wire.lock().unwrap().start_error = true;
    assert_error(
        engine.restart_vpn_credentials(restart(&view)).await,
        "connection_restore_failed",
    );
    assert!(engine.owned_core_process().is_none());
    assert!(engine.running.is_none());
    assert!(engine.vpn.status.session_id.is_none());
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        disk
    );
    assert_eq!(wire.lock().unwrap().starts.len(), 1);
}

#[tokio::test]
async fn later_generic_connect_rollback_redacts_error_echoing_temporary_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut engine, wire) = setup();
    let next = engine
        .save_profile(crate::ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Next ordinary".into(),
            group_id: "personal".into(),
            kind: crate::store::ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    engine
        .restart_vpn_credentials(restart(&view))
        .await
        .unwrap();
    // A real owned IPC child returns an error containing the former session's
    // transient password when the generic rollback tries to restore it.
    let helper = dir.path().join("restore-error-core");
    std::fs::write(
        &helper,
        r#"#!/usr/bin/python3
import os, socket, struct
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ['THRONE_CORE_SOCKET'])
def read(n):
    data = b''
    while len(data) < n:
        v = s.recv(n-len(data))
        if not v: raise SystemExit
        data += v
    return data
while True:
    ident = read(4)
    method = read(struct.unpack('<H', read(2))[0])
    data = read(struct.unpack('<I', read(4))[0])
    assert method == b'Start'
    assert b'sensitive-candidate-password' in data
    message = b'restore rejected sensitive-candidate-password'
    result = b'\x0a' + bytes([len(message)]) + message
    s.sendall(ident + b'\0' + struct.pack('<I', len(result)) + result)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    engine.core = helper;
    wire.lock().unwrap().start_error = true;
    assert_error(engine.connect(&next).await, "connection_restore_failed");
    let logs =
        serde_json::to_value(engine.logs.view(crate::logs::Filter::default()).unwrap()).unwrap();
    assert!(!logs.to_string().contains("sensitive-candidate-password"));
    assert!(logs
        .to_string()
        .contains("Connection restore: core_start_rejected"));
    assert!(engine.owned_core_process().is_none());
}

#[tokio::test]
async fn failed_second_manual_restart_restores_exact_first_ephemeral_request() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut engine, wire) = setup();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    engine
        .restart_vpn_credentials(restart(&view))
        .await
        .unwrap();
    let previous = engine
        .active_connection
        .as_ref()
        .unwrap()
        .request
        .encode_to_vec();
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    let otp = engine.otp_list();
    let helper = dir.path().join("successful-restore-core");
    std::fs::write(
        &helper,
        r#"#!/usr/bin/python3
import os, socket, struct
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ['THRONE_CORE_SOCKET'])
def read(n):
    data = b''
    while len(data) < n:
        value = s.recv(n-len(data))
        if not value: raise SystemExit
        data += value
    return data
while True:
    ident = read(4)
    method = read(struct.unpack('<H', read(2))[0])
    data = read(struct.unpack('<I', read(4))[0])
    assert method == b'Start'
    assert b'sensitive-candidate-password' in data
    assert b'second-candidate-password' not in data
    with open('restored-request.bin', 'wb') as output: output.write(data)
    s.sendall(ident + b'\0' + struct.pack('<I', 0))
"#,
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    engine.core = helper;
    // Scripted endpoint has now reached another terminal auth failure in the
    // same first manual session. Its fresh details yield a new one-use token.
    let second = engine.vpn_credentials(get(&engine)).await.unwrap();
    let mut request = restart(&second);
    request.password = "second-candidate-password".into();
    wire.lock().unwrap().start_error = true;
    assert_error(
        engine.restart_vpn_credentials(request).await,
        "connection_restored",
    );
    assert_eq!(
        engine
            .active_connection
            .as_ref()
            .unwrap()
            .request
            .encode_to_vec(),
        previous
    );
    assert_eq!(
        std::fs::read(dir.path().join("restored-request.bin")).unwrap(),
        previous
    );
    assert_ne!(
        engine.vpn.status.session_id.as_deref(),
        Some(second.session_id.as_str())
    );
    assert_eq!(engine.routing_revision, None);
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        disk
    );
    assert_eq!(engine.otp_list(), otp);
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn a_vpn_endpoint_that_is_not_the_exit_can_be_signed_in_to_again() {
    // Qt lets the person sign in again to any VPN node of the connection: a hop
    // of a chain, a member of a pool or an endpoint a route sends traffic to.
    let (_dir, mut engine, _wire) = setup();
    engine.active_connection.as_mut().unwrap().vpn_primary = false;
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    assert_eq!(view.endpoint_tag, "proxy");
    assert!(!view.edit_token.is_empty());
}
