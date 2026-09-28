use super::tests::{edit, get, response, restart};
use super::*;
use std::sync::{Arc, Mutex};

struct Wire {
    generation: u64,
    outcome: i32,
    code: String,
    malformed: bool,
    calls: Vec<String>,
    answers: Vec<proto::ManagedVpnReplaceCredentialsRequest>,
}
fn setup(outcome: i32, code: &str) -> (tempfile::TempDir, Engine, Arc<Mutex<Wire>>) {
    let (directory, mut engine, _) = super::tests::setup();
    let state = Arc::new(Mutex::new(Wire {
        generation: (1 << 53) + 1,
        outcome,
        code: code.into(),
        malformed: false,
        calls: vec![],
        answers: vec![],
    }));
    let remote = state.clone();
    engine.rpc = Some(crate::transport::Rpc::scripted_vpn_test_rpc(
        move |method, payload| {
            let mut wire = remote.lock().unwrap();
            wire.calls.push(method.into());
            match method {
                "ManagedVPN" => {
                    let request = proto::ManagedVpnRequest::decode(payload).unwrap();
                    assert!(matches!(
                        request.operation,
                        Some(proto::managed_vpn_request::Operation::Query(_))
                    ));
                    proto::ManagedVpnResponse {
                        version: Some(1),
                        generation: Some(wire.generation),
                        error_code: (request.generation != Some(wire.generation))
                            .then(|| "managed_vpn_stale_generation".into()),
                        result: Some(proto::managed_vpn_response::Result::Status(response(
                            "error",
                        ))),
                    }
                    .encode_to_vec()
                }
                "ManagedVPNReplaceCredentials" => {
                    let request =
                        proto::ManagedVpnReplaceCredentialsRequest::decode(payload).unwrap();
                    assert_eq!(request.generation, Some(wire.generation));
                    let previous = wire.generation;
                    wire.answers.push(request);
                    wire.generation += match wire.outcome {
                        1 => 0,
                        3 => 2,
                        _ => 1,
                    };
                    if wire.malformed {
                        return vec![8, 1];
                    }
                    proto::ManagedVpnReplaceCredentialsResponse {
                        version: Some(1),
                        previous_generation: Some(previous),
                        generation: Some(wire.generation),
                        outcome: Some(wire.outcome),
                        error_code: Some(wire.code.clone()),
                    }
                    .encode_to_vec()
                }
                _ => panic!("Unexpected managed credential RPC {method}"),
            }
        },
    ));
    engine.active_connection.as_mut().unwrap().tun = true;
    engine.reset_vpn_session();
    let generation = state.lock().unwrap().generation;
    engine.observe_vpn_generation(generation, 1);
    engine.observe_vpn_credentials_capability(1);
    engine.tun_generation = generation;
    (directory, engine, state)
}

#[tokio::test]
async fn managed_applied_commits_only_frozen_credentials_and_new_session() {
    let (_directory, mut engine, wire) = setup(2, "");
    let owner = engine.owned_core_process().unwrap();
    let source = engine.store.library.clone();
    let original = engine.active_connection.as_ref().unwrap().request.clone();
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    engine
        .restart_vpn_credentials(restart(&view))
        .await
        .unwrap();
    assert_eq!(engine.owned_core_process().unwrap(), owner);
    assert_ne!(
        engine.vpn.status.session_id.as_deref(),
        Some(view.session_id.as_str())
    );
    assert_eq!(engine.vpn.generation, Some((1 << 53) + 2));
    assert_eq!(engine.vpn.managed_credentials_version, 1);
    assert!(engine.vpn_credentials_transition.is_none());
    assert_eq!(engine.routing_revision, None);
    assert_eq!(
        serde_json::to_value(&engine.store.library).unwrap(),
        serde_json::to_value(source).unwrap()
    );
    let mut expected = original;
    let (mut config, index) = endpoint_config(&expected, "proxy").unwrap();
    config["endpoints"][index]["username"] = json!(" temporary user \n");
    config["endpoints"][index]["password"] = json!("sensitive-candidate-password");
    expected.core_config = Some(config.to_string());
    assert_eq!(engine.active_connection.as_ref().unwrap().request, expected);
    {
        let wire = wire.lock().unwrap();
        assert_eq!(
            wire.calls,
            ["ManagedVPN", "ManagedVPN", "ManagedVPNReplaceCredentials"]
        );
        assert_eq!(wire.answers.len(), 1);
        assert_eq!(
            wire.answers[0].username.as_deref(),
            Some(" temporary user \n")
        );
        assert_eq!(
            engine.cancel_vpn_credentials(edit(&view)).err().as_deref(),
            Some("vpn_credentials_stale")
        );
    }
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn managed_rejected_retains_request_and_restored_rebinds_exact_old_request() {
    for (outcome, code, expected_error, changed) in [
        (
            1,
            "managed_vpn_credentials_check_failed",
            "vpn_credentials_check_failed",
            false,
        ),
        (
            3,
            "managed_vpn_credentials_restart_failed",
            "connection_restored",
            true,
        ),
    ] {
        let (_directory, mut engine, wire) = setup(outcome, code);
        let original = engine.active_connection.as_ref().unwrap().request.clone();
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        assert_eq!(
            engine
                .restart_vpn_credentials(restart(&view))
                .await
                .err()
                .as_deref(),
            Some(expected_error)
        );
        assert_eq!(engine.active_connection.as_ref().unwrap().request, original);
        assert_eq!(engine.routing_revision, None);
        assert_eq!(
            engine.vpn.status.session_id.as_deref() != Some(view.session_id.as_str()),
            changed
        );
        assert!(engine.vpn_credentials_transition.is_none());
        assert_eq!(wire.lock().unwrap().answers.len(), 1);
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}

#[tokio::test]
async fn managed_missing_capability_and_stale_generation_never_send_replacement() {
    let (_directory, mut engine, wire) = setup(2, "");
    engine.observe_vpn_credentials_capability(0);
    assert_eq!(
        engine.vpn_credentials(get(&engine)).await.err().as_deref(),
        Some("vpn_credentials_managed_unsupported")
    );
    assert!(wire.lock().unwrap().calls.is_empty());
    engine.observe_vpn_credentials_capability(1);
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    wire.lock().unwrap().generation += 1;
    assert_eq!(
        engine
            .restart_vpn_credentials(restart(&view))
            .await
            .err()
            .as_deref(),
        Some("vpn_credentials_stale")
    );
    assert!(wire.lock().unwrap().answers.is_empty());
    assert!(engine.vpn_credentials_transition.is_none());
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn typed_failed_cleanup_complete_is_terminal_and_never_rolls_back_old_request() {
    let (_directory, mut engine, wire) = setup(4, "managed_vpn_credentials_restart_failed");
    let view = engine.vpn_credentials(get(&engine)).await.unwrap();
    assert_eq!(
        engine
            .restart_vpn_credentials(restart(&view))
            .await
            .err()
            .as_deref(),
        Some("connection_restore_failed")
    );
    assert!(engine.running.is_none());
    assert!(engine.active_connection.is_none());
    assert!(engine.vpn_credentials_transition.is_none());
    assert_eq!(wire.lock().unwrap().answers.len(), 1);
    assert!(!engine.recovery.pending());
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn malformed_reply_and_cleanup_failure_retain_exact_child_without_background_spawn() {
    for malformed in [false, true] {
        let (_directory, mut engine, wire) = setup(4, "managed_vpn_credentials_cleanup_failed");
        wire.lock().unwrap().malformed = malformed;
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        let owner = engine.owned_core_process().unwrap();
        assert_eq!(
            engine
                .restart_vpn_credentials(restart(&view))
                .await
                .err()
                .as_deref(),
            Some("tun_recovery_failed")
        );
        for _ in 0..3 {
            let _ = engine.snapshot();
            engine.poll().await;
            engine.recovery_tick().await;
            engine.vpn_tick().await;
            assert_eq!(engine.owned_core_process(), Some(owner));
            assert!(engine.vpn_credentials_transition.is_some());
            assert!(engine.active_connection.is_none());
            assert!(!engine.recovery.pending());
        }
        assert_eq!(
            engine.ensure_rpc().await.err().as_deref(),
            Some("tun_recovery_failed")
        );
        assert_eq!(
            engine.ensure_tun_rpc().await.err().as_deref(),
            Some("tun_recovery_failed")
        );
        let before = wire.lock().unwrap().calls.clone();
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
        engine.recovery_tick().await;
        assert!(engine.rpc.is_none());
        // A nonzero exact child exit and clean network do NOT release the marker.
        assert!(engine.vpn_credentials_transition.is_some());
        assert_eq!(wire.lock().unwrap().calls, before);
    }
}

#[tokio::test]
async fn cancelled_replace_future_requires_exact_exit_proof_and_keeps_failed_quit_blocked() {
    use std::os::unix::fs::PermissionsExt;
    for success in [true, false] {
        let (directory, mut engine, _) = setup(2, "");
        let query = proto::ManagedVpnResponse {
            version: Some(1),
            generation: engine.vpn.generation,
            error_code: None,
            result: Some(proto::managed_vpn_response::Result::Status(response(
                "error",
            ))),
        };
        std::fs::write(directory.path().join("query.bin"), query.encode_to_vec()).unwrap();
        std::fs::write(
            directory.path().join("exit-code"),
            if success { "0" } else { "1" },
        )
        .unwrap();
        let helper = directory.path().join("owned-ipc-child");
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
        if not value: raise SystemExit(3)
        data += value
    return data
while True:
    ident = read(4)
    method = read(struct.unpack('<H', read(2))[0])
    payload = read(struct.unpack('<I', read(4))[0])
    if method == b'ManagedVPNReplaceCredentials':
        with open('attempted', 'w') as output: output.write('1')
        assert s.recv(1) == b''
        with open('exit-code') as source: code = int(source.read())
        raise SystemExit(code)
    assert method == b'ManagedVPN'
    with open('query.bin', 'rb') as source: result = source.read()
    s.sendall(ident + b'\0' + struct.pack('<I', len(result)) + result)
"#,
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        engine.rpc = Some(
            crate::transport::Rpc::owned_managed_ipc_test_rpc(&helper, directory.path()).await,
        );
        engine.reset_vpn_session();
        engine.observe_vpn_generation((1 << 53) + 1, 1);
        engine.observe_vpn_credentials_capability(1);
        let view = engine.vpn_credentials(get(&engine)).await.unwrap();
        let owner = engine.owned_core_process().unwrap();
        let disk = std::fs::read(directory.path().join("library.json")).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                _ = engine.restart_vpn_credentials(restart(&view)) => panic!("Replacement replied before deliberate cancellation"),
                _ = async { while !directory.path().join("attempted").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }} => {},
            }
        }).await.unwrap();
        // No method completed, but the Engine-level obligation outlives its future.
        assert!(engine.vpn_credentials_transition.is_some());
        engine.snapshot();
        assert!(engine.active_connection.is_none());
        assert_eq!(engine.rpc.as_ref().unwrap().instance(), owner.instance);
        tokio::time::timeout(Duration::from_secs(3), async {
            while engine.rpc.is_some() {
                engine.recovery_tick().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            engine.vpn_credentials_transition.is_none(),
            success && crate::tun::network_clear().is_ok()
        );
        assert_eq!(
            std::fs::read(directory.path().join("library.json")).unwrap(),
            disk
        );
        assert!(!engine.recovery.pending());
        if !success {
            engine.core = directory.path().join("no-barrier-core");
            engine.store.library.preferences.tun.request_permission = false;
            assert_eq!(
                engine.shutdown_checked().await.err().as_deref(),
                Some("tun_recovery_failed")
            );
            assert_eq!(
                engine.connect("missing-profile").await.err().as_deref(),
                Some("tun_recovery_failed")
            );
            assert!(engine.vpn_credentials_transition.is_some());
            assert!(engine.rpc.is_none());
        }
    }
}
