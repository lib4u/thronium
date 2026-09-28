use super::*;
use crate::vpn_auth::credentials::{
    CredentialEditRequest, CredentialRequest, CredentialView, RestartCredentialsRequest,
};
use crate::{proto, store::ProfileKind, transport::Rpc, Engine, ProfileDraft};
use prost::Message;
use serde_json::{json, Value as Json};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};

const CLEANUP: &str = "vpn_credentials_proxy_cleanup_failed";
fn request(engine: &mut Engine) -> CredentialRequest {
    CredentialRequest {
        session_id: engine.snapshot().vpn.session_id.unwrap(),
        endpoint_tag: "proxy".into(),
    }
}
fn edit(view: &CredentialView) -> CredentialEditRequest {
    CredentialEditRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
    }
}
fn restart(view: &CredentialView) -> RestartCredentialsRequest {
    RestartCredentialsRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
        username: " temporary user ".into(),
        password: "temporary-private-password".into(),
    }
}
fn events(directory: &Path) -> Vec<String> {
    std::fs::read_to_string(directory.join("events"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}
async fn setup() -> (tempfile::TempDir, Engine, Arc<Mutex<State>>) {
    let directory = tempfile::tempdir().unwrap();
    let core = directory.path().join("owned-ipc-core");
    std::fs::write(
        &core,
        r#"#!/usr/bin/python3
import os, socket, struct, select, time
from pathlib import Path
count = Path('spawn-count')
stage = int(count.read_text()) if count.exists() else 0
count.write_text(str(stage+1))
Path('spawned-'+str(stage)).write_text(str(os.getpid()))
while Path('pause-handshake-'+str(stage)).exists(): time.sleep(.005)
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ['THRONE_CORE_SOCKET'])
def read(n):
    data = b''
    while len(data) < n:
        value = s.recv(n-len(data))
        if not value: raise SystemExit(0)
        data += value
    return data
while True:
    ident = read(4)
    method = read(struct.unpack('<H', read(2))[0]).decode()
    payload = read(struct.unpack('<I', read(4))[0])
    with Path('events').open('a') as output: output.write(str(stage)+':'+method+'\n')
    while Path('pause-'+method+'-'+str(stage)).exists():
        if select.select([s],[],[],.005)[0]:
            assert s.recv(1) == b''
            raise SystemExit(0)
    if method == 'QueryVPNStatus': result = Path('status.bin').read_bytes()
    elif method in ['CheckConfig','Start','Stop']:
        if method == 'Start': Path('start-'+str(stage)+'.bin').write_bytes(payload)
        reject = Path('reject-'+method+'-'+str(stage)).exists()
        result = b'\x0a\x08rejected' if reject else b''
        if Path('malformed-'+method+'-'+str(stage)).exists(): result = b'\x10\x01'
    else: raise AssertionError('unexpected method')
    s.sendall(ident+b'\0'+struct.pack('<I',len(result))+result)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&core, std::fs::Permissions::from_mode(0o700)).unwrap();
    let status = proto::VpnStatusResponse {
        results: vec![proto::VpnEndpointStatus {
            tag: Some("proxy".into()),
            state: Some("error".into()),
            auth_failed: Some(true),
            ..Default::default()
        }],
    };
    std::fs::write(directory.path().join("status.bin"), status.encode_to_vec()).unwrap();
    let shared = state();
    let mut engine = Engine::open(directory.path(), &core).unwrap();
    engine.system_proxy = open(&directory.path().join("proxy"), &shared);
    engine
        .connection_settings(ConnectionMode::SystemProxy, 2080)
        .unwrap();
    let id = engine.save_profile(ProfileDraft { vpn_policy: Default::default(), id: None, name: "Frozen primary".into(), group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound, config: json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"username":"old","password":"old-pass","system":false}) }).unwrap();
    let profile = engine.profile(&id).unwrap();
    let request = engine.build(&profile).unwrap();
    engine.rpc = Some(
        Rpc::spawn_logged(&core, directory.path(), None)
            .await
            .unwrap(),
    );
    engine.running = Some(id.clone());
    engine.active_connection = Some(crate::connection::ActiveConnection {
        id: id.clone(),
        profiles: std::collections::HashSet::from([id]),
        groups: Default::default(),
        request,
        routing_revision: 17,
        system_port: Some(2080),
        tun: false,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    engine.system_proxy.enable(2080).unwrap();
    engine.routing_revision = None;
    engine.reset_vpn_session();
    (directory, engine, shared)
}
fn journal(engine: &Engine) -> (Vec<u8>, u64, i64, i64) {
    let path = engine.system_proxy.path();
    let metadata = std::fs::metadata(&path).unwrap();
    (
        std::fs::read(path).unwrap(),
        metadata.ino(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}
async fn get(engine: &mut Engine) -> CredentialView {
    let req = request(engine);
    engine.vpn_credentials(req).await.unwrap()
}

#[tokio::test]
async fn details_cancel_and_preflight_refusals_preserve_listener_lease_and_all_settings() {
    let (directory, mut engine, shared) = setup().await;
    let owner = engine.owned_core_process().unwrap();
    let before = journal(&engine);
    let values = shared.lock().unwrap().values.clone();
    let view = get(&mut engine).await;
    let reads = shared.lock().unwrap().reads;
    let writes = shared.lock().unwrap().writes;
    let calls = events(directory.path());
    shared.lock().unwrap().read_error = true;
    engine.cancel_vpn_credentials(edit(&view)).unwrap();
    assert_eq!(shared.lock().unwrap().reads, reads);
    assert_eq!(events(directory.path()), calls);
    let req = CredentialRequest {
        session_id: view.session_id,
        endpoint_tag: "proxy".into(),
    };
    assert_eq!(
        engine.vpn_credentials(req).await.err().as_deref(),
        Some("system_proxy_read_failed")
    );
    assert_eq!(events(directory.path()), calls);
    shared.lock().unwrap().read_error = false;
    let view = get(&mut engine).await;
    std::fs::write(directory.path().join("reject-CheckConfig-0"), "").unwrap();
    assert_eq!(
        engine
            .restart_vpn_credentials(restart(&view))
            .await
            .err()
            .as_deref(),
        Some("vpn_credentials_check_failed")
    );
    assert_eq!(engine.owned_core_process(), Some(owner));
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert_eq!(journal(&engine), before);
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert_eq!(shared.lock().unwrap().values, values);
    assert!(!events(directory.path())
        .iter()
        .any(|event| event.ends_with(":Stop") || event.ends_with(":Start")));
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn retained_candidate_and_exact_single_rollback_never_acquire_or_rewrite_journal() {
    for rejected in [false, true] {
        let (directory, mut engine, shared) = setup().await;
        let original = engine.active_connection.as_ref().unwrap().request.clone();
        let before = journal(&engine);
        let writes = shared.lock().unwrap().writes;
        let disk = std::fs::read(directory.path().join("library.json")).unwrap();
        let view = get(&mut engine).await;
        if rejected {
            std::fs::write(directory.path().join("reject-Start-1"), "").unwrap();
        }
        let result = engine.restart_vpn_credentials(restart(&view)).await;
        assert_eq!(
            result.err().as_deref(),
            rejected.then_some("connection_restored")
        );
        assert!(engine.vpn_credentials_proxy_transition.is_none());
        assert_eq!(journal(&engine), before);
        assert_eq!(shared.lock().unwrap().writes, writes);
        assert_eq!(
            std::fs::read(directory.path().join("library.json")).unwrap(),
            disk
        );
        assert_eq!(engine.routing_revision, None);
        let bytes = std::fs::read(directory.path().join("start-1.bin")).unwrap();
        let candidate = proto::LoadConfigReq::decode(bytes.as_slice()).unwrap();
        let mut config: Json =
            serde_json::from_str(candidate.core_config.as_deref().unwrap()).unwrap();
        let proxy = config["endpoints"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|endpoint| endpoint["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["password"], "temporary-private-password");
        assert_eq!(proxy["username"], " temporary user ");
        if rejected {
            assert_eq!(
                std::fs::read(directory.path().join("start-2.bin")).unwrap(),
                original.encode_to_vec()
            );
            assert_eq!(engine.active_connection.as_ref().unwrap().request, original);
        } else {
            assert_eq!(
                engine.active_connection.as_ref().unwrap().request,
                candidate
            );
        }
        assert_eq!(
            events(directory.path())
                .iter()
                .filter(|e| e.ends_with(":Start"))
                .count(),
            if rejected { 2 } else { 1 }
        );
        let logs = serde_json::to_value(engine.logs.view(crate::logs::Filter::default()).unwrap())
            .unwrap()
            .to_string();
        assert!(!logs.contains("temporary-private-password"));
        engine.shutdown_checked().await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_details_preserve_restore_failure_journal_and_checked_quit_until_retry() {
    let (directory, mut engine, shared) = setup().await;
    let before = journal(&engine);
    std::fs::write(directory.path().join("pause-QueryVPNStatus-0"), "").unwrap();
    let req = request(&mut engine);
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            _ = engine.vpn_credentials(req) => panic!("details unexpectedly returned"),
            _ = async { while events(directory.path()).is_empty() { tokio::time::sleep(Duration::from_millis(5)).await; } } => {}
        }
    }).await.unwrap();
    assert!(engine.vpn_credentials_proxy_transition.is_some());
    shared.lock().unwrap().read_error = true;
    engine.snapshot();
    engine.recovery_tick().await;
    assert_eq!(journal(&engine), before);
    assert_eq!(
        engine.shutdown_checked().await.err().as_deref(),
        Some(CLEANUP)
    );
    assert_eq!(
        engine.retry_system_proxy_recovery().err().as_deref(),
        Some(CLEANUP)
    );
    assert_eq!(
        engine.restore_system_proxy().err().as_deref(),
        Some(CLEANUP)
    );
    assert_eq!(
        engine.connect("irrelevant").await.err().as_deref(),
        Some(CLEANUP)
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawn-count")).unwrap(),
        "1"
    );
    shared.lock().unwrap().read_error = false;
    engine.retry_system_proxy_cleanup().await.unwrap();
    assert!(engine.rpc.is_none());
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert!(!engine.system_proxy.path().exists());
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn cancellation_during_spawn_handshake_retains_exact_child_until_cleanup_reap() {
    let (directory, mut engine, shared) = setup().await;
    let view = get(&mut engine).await;
    std::fs::write(directory.path().join("pause-handshake-1"), "").unwrap();
    let old = engine.owned_core_process().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = engine.restart_vpn_credentials(restart(&view)) => panic!("restart unexpectedly returned"),
            _ = async { while !directory.path().join("spawned-1").exists() { tokio::time::sleep(Duration::from_millis(5)).await; } } => {}
        }
    }).await.unwrap();
    let candidate = engine
        .owned_core_process()
        .expect("Child retained before handshake");
    assert_ne!(old.instance, candidate.instance);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawned-1"))
            .unwrap()
            .parse::<u32>()
            .unwrap(),
        candidate.pid
    );
    assert!(engine.vpn_credentials_proxy_transition.is_some());
    shared.lock().unwrap().writable = false;
    let before = journal(&engine);
    engine.poll().await;
    engine.recovery_tick().await;
    assert_eq!(engine.owned_core_process(), Some(candidate));
    assert_eq!(journal(&engine), before);
    assert_eq!(
        engine.shutdown_checked().await.err().as_deref(),
        Some(CLEANUP)
    );
    shared.lock().unwrap().writable = true;
    engine.retry_system_proxy_cleanup().await.unwrap();
    assert!(engine.rpc.is_none());
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert!(!Path::new(&format!("/proc/{}", candidate.pid)).exists());
    assert!(!events(directory.path())
        .iter()
        .any(|event| event.ends_with(":Start")));
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawn-count")).unwrap(),
        "2"
    );
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn ownership_changes_after_await_preserve_foreign_values_without_acquire_or_rollback() {
    for after_start in [false, true] {
        let (directory, mut engine, shared) = setup().await;
        let view = get(&mut engine).await;
        let before_writes = shared.lock().unwrap().writes;
        let marker = if after_start {
            "pause-Start-1"
        } else {
            "pause-CheckConfig-0"
        };
        let event = if after_start {
            "1:Start"
        } else {
            "0:CheckConfig"
        };
        std::fs::write(directory.path().join(marker), "").unwrap();
        let operation = engine.restart_vpn_credentials(restart(&view));
        let writer = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !events(directory.path()).iter().any(|e| e == event) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            shared.lock().unwrap().values[0] = Value {
                effective: "'external-owner.example'".into(),
                user: Some("'external-owner.example'".into()),
            };
            let foreign = shared.lock().unwrap().values.clone();
            std::fs::remove_file(directory.path().join(marker)).unwrap();
            foreign
        };
        let (result, foreign) = tokio::join!(operation, writer);
        assert_eq!(result.err().as_deref(), Some("system_proxy_changed"));
        assert_eq!(shared.lock().unwrap().values, foreign);
        assert_eq!(shared.lock().unwrap().writes, before_writes);
        assert!(!engine.system_proxy.path().exists());
        assert!(engine.vpn_credentials_proxy_transition.is_none());
        assert_eq!(engine.running.is_none(), after_start);
        assert_eq!(
            events(directory.path())
                .iter()
                .filter(|event| event.ends_with(":Start"))
                .count(),
            usize::from(after_start)
        );
        engine.shutdown_checked().await.unwrap();
        assert_eq!(shared.lock().unwrap().values, foreign);
    }
}

#[tokio::test]
async fn foreign_change_during_handshake_is_checked_before_first_candidate_start() {
    let (directory, mut engine, shared) = setup().await;
    let view = get(&mut engine).await;
    let writes = shared.lock().unwrap().writes;
    std::fs::write(directory.path().join("pause-handshake-1"), "").unwrap();
    let operation = engine.restart_vpn_credentials(restart(&view));
    let writer = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !directory.path().join("spawned-1").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        shared.lock().unwrap().values[1] = Value {
            effective: "9099".into(),
            user: Some("9099".into()),
        };
        let foreign = shared.lock().unwrap().values.clone();
        std::fs::remove_file(directory.path().join("pause-handshake-1")).unwrap();
        foreign
    };
    let (result, foreign) = tokio::join!(operation, writer);
    assert_eq!(result.err().as_deref(), Some("system_proxy_changed"));
    assert!(!events(directory.path())
        .iter()
        .any(|e| e.ends_with(":Start")));
    assert_eq!(shared.lock().unwrap().values, foreign);
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(engine.rpc.is_none());
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn failed_rollback_preserves_failed_restore_obligation_until_explicit_retry() {
    let (directory, mut engine, shared) = setup().await;
    let view = get(&mut engine).await;
    let before = journal(&engine);
    for marker in ["reject-Start-1", "reject-Start-2", "pause-Start-2"] {
        std::fs::write(directory.path().join(marker), "").unwrap();
    }
    let operation = engine.restart_vpn_credentials(restart(&view));
    let fault = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !events(directory.path()).iter().any(|e| e == "2:Start") {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        shared.lock().unwrap().writable = false;
        std::fs::remove_file(directory.path().join("pause-Start-2")).unwrap();
    };
    let (result, _) = tokio::join!(operation, fault);
    assert_eq!(result.err().as_deref(), Some(CLEANUP));
    assert!(engine.vpn_credentials_proxy_transition.is_some());
    assert_eq!(journal(&engine), before);
    let child = engine.owned_core_process().unwrap();
    engine.snapshot();
    engine.recovery_tick().await;
    assert_eq!(engine.owned_core_process(), Some(child));
    assert_eq!(
        engine.shutdown_checked().await.err().as_deref(),
        Some(CLEANUP)
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawn-count")).unwrap(),
        "3"
    );
    shared.lock().unwrap().writable = true;
    engine.retry_system_proxy_cleanup().await.unwrap();
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert!(engine.rpc.is_none());
    assert!(engine.error.is_none());
    assert!(!engine.system_proxy.path().exists());
    assert!(engine.snapshot().error.is_none());
    assert_eq!(
        engine
            .connect("missing-after-cleanup")
            .await
            .err()
            .as_deref(),
        Some("profile_not_found")
    );
    assert_eq!(
        events(directory.path())
            .iter()
            .filter(|e| e.ends_with(":Start"))
            .count(),
        2
    );
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn read_failure_after_check_keeps_old_listener_without_destructive_calls() {
    let (directory, mut engine, shared) = setup().await;
    let view = get(&mut engine).await;
    let before = journal(&engine);
    let owner = engine.owned_core_process().unwrap();
    std::fs::write(directory.path().join("pause-CheckConfig-0"), "").unwrap();
    let operation = engine.restart_vpn_credentials(restart(&view));
    let fault = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !events(directory.path())
                .iter()
                .any(|e| e == "0:CheckConfig")
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        shared.lock().unwrap().read_error = true;
        std::fs::remove_file(directory.path().join("pause-CheckConfig-0")).unwrap();
    };
    let (result, _) = tokio::join!(operation, fault);
    assert_eq!(result.err().as_deref(), Some("system_proxy_read_failed"));
    assert_eq!(engine.owned_core_process(), Some(owner));
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert_eq!(journal(&engine), before);
    assert!(!events(directory.path())
        .iter()
        .any(|e| e.ends_with(":Stop") || e.ends_with(":Start")));
    shared.lock().unwrap().read_error = false;
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn malformed_start_acknowledgement_cleans_up_without_old_rollback() {
    let (directory, mut engine, _shared) = setup().await;
    let view = get(&mut engine).await;
    let disk = std::fs::read(directory.path().join("library.json")).unwrap();
    std::fs::write(directory.path().join("malformed-Start-1"), "").unwrap();
    assert_eq!(
        engine
            .restart_vpn_credentials(restart(&view))
            .await
            .err()
            .as_deref(),
        Some("vpn_credentials_restart_failed")
    );
    assert_eq!(
        events(directory.path())
            .iter()
            .filter(|e| e.ends_with(":Start"))
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawn-count")).unwrap(),
        "2"
    );
    assert!(engine.rpc.is_none());
    assert!(engine.running.is_none());
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert!(!engine.system_proxy.path().exists());
    assert_eq!(
        std::fs::read(directory.path().join("library.json")).unwrap(),
        disk
    );
    assert!(!engine.recovery.pending());
    engine.shutdown_checked().await.unwrap();
}

#[tokio::test]
async fn retained_handshake_timeout_returns_to_owned_cleanup_without_start_or_rollback() {
    let (directory, mut engine, _shared) = setup().await;
    let view = get(&mut engine).await;
    std::fs::write(directory.path().join("pause-handshake-1"), "").unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(12),
        engine.restart_vpn_credentials(restart(&view)),
    )
    .await
    .unwrap();
    assert_eq!(
        result.err().as_deref(),
        Some("vpn_credentials_restart_failed")
    );
    assert!(!events(directory.path())
        .iter()
        .any(|event| event.ends_with(":Start")));
    assert_eq!(
        std::fs::read_to_string(directory.path().join("spawn-count")).unwrap(),
        "2"
    );
    assert!(engine.rpc.is_none());
    assert!(engine.vpn_credentials_proxy_transition.is_none());
    assert!(!engine.system_proxy.path().exists());
    engine.shutdown_checked().await.unwrap();
}
