use super::*;
use crate::{connection::ActiveConnection, proto};
#[cfg(target_os = "linux")]
use crate::{store::ProfileKind, ProfileDraft};
use serde_json::json;
#[cfg(target_os = "linux")]
use serde_json::Value;

fn active(id: &str) -> ActiveConnection {
    ActiveConnection {
        id: id.into(),
        profiles: [id.into(), "frozen-member".into()].into(),
        groups: ["personal".into(), "frozen-group".into()].into(),
        request: proto::LoadConfigReq {
            core_config: Some(
                json!({"inbounds":[],"secret":"private-request-sentinel"}).to_string(),
            ),
            ..Default::default()
        },
        routing_revision: 7,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    }
}

fn pending(engine: &mut Engine) {
    engine.active_connection = Some(active("frozen"));
    engine.running = Some("frozen".into());
    engine.routing_revision = None;
    assert!(engine.recovery.arm(Instant::now()));
}

#[test]
fn upstream_delay_and_rapid_exit_boundary_use_monotonic_time() {
    let now = Instant::now();
    let mut recovery = Recovery::default();
    assert!(recovery.arm(now));
    assert_eq!(recovery.pending, Some(now + Duration::from_millis(200)));
    recovery.clear_pending(); // Successful automatic Start must retain last_exit.
    assert!(!recovery.arm(now + Duration::from_millis(9999)));
    assert!(!recovery.pending());
    let mut recovery = Recovery::default();
    assert!(recovery.arm(now));
    assert!(recovery.arm(now + Duration::from_secs(10)));
}

#[test]
fn background_failure_messages_do_not_echo_core_payloads_or_paths() {
    assert_eq!(
        safe_failure("decode config: private-request-sentinel"),
        "core_start_rejected"
    );
    assert_eq!(
        safe_failure("core_launch: /private/path"),
        "core_launch_failed"
    );
    assert_eq!(
        safe_failure("listen 127.0.0.1:private: address already in use"),
        "local_listener_busy"
    );
    assert_eq!(safe_failure("core_request_timeout"), "core_request_timeout");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_live_owned_child_with_lost_ipc_is_terminal_not_an_automatic_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
    engine.active_connection = Some(active("frozen"));
    engine.running = Some("frozen".into());
    engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(false));
    assert!(!engine.rpc.as_mut().unwrap().child_exited());
    assert!(!engine.rpc.as_mut().unwrap().is_alive());
    assert_eq!(engine.snapshot().phase, "reconnecting");
    assert!(engine.recovery.observing_exit.is_some());
    assert!(engine.recovery.pending.is_none());
    engine.recovery.observing_exit = Some(Instant::now());
    engine.recovery_tick().await;
    assert!(engine.rpc.is_none());
    assert!(!engine.recovery.pending());
    assert_eq!(
        engine.snapshot().error.as_deref(),
        Some("core_disconnected")
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn remote_eof_before_child_exit_preserves_the_request_until_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
    engine.active_connection = Some(active("frozen"));
    engine.running = Some("frozen".into());
    engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(true));
    let owner = engine.owned_core_process().unwrap();
    let cached = engine.active_connection.as_ref().unwrap().request.clone();
    // The fixture consumes an actual RPC frame and returns EOF, but keeps its
    // owned child alive. This used to terminate/reap and discard the request.
    assert_eq!(engine.poll().await.phase, "reconnecting");
    assert!(engine.recovery.observing_exit.is_some());
    assert!(engine.recovery.pending.is_none());
    assert!(!engine.rpc.as_mut().unwrap().child_exited());
    // Selector status bypasses ensure_rpc; a repeated call on the lost stream
    // must not relabel the earlier remote EOF as a local failure.
    assert_eq!(
        engine.auto_selectors().await.err().as_deref(),
        Some("selector_status_failed")
    );
    assert!(engine.rpc.as_ref().unwrap().remote_stream_lost());
    let deadline = engine.recovery.observing_exit;
    for _ in 0..3 {
        assert_eq!(engine.snapshot().phase, "reconnecting");
        assert_eq!(engine.owned_core_process(), Some(owner));
        assert_eq!(engine.recovery.observing_exit, deadline);
    }
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    engine.recovery_tick().await;
    assert!(engine.recovery.observing_exit.is_none());
    assert!(engine.recovery.pending.is_some());
    assert!(engine.rpc.is_none());
    assert_eq!(engine.active_connection.as_ref().unwrap().request, cached);
    engine.disconnect().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn disconnect_reaps_a_live_observed_child_before_returning() {
    for action in ["disconnect", "connect"] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
        engine.active_connection = Some(active("frozen"));
        engine.running = Some("frozen".into());
        engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(false));
        let owner = engine.owned_core_process().unwrap();
        assert_eq!(engine.snapshot().phase, "reconnecting");
        if action == "disconnect" {
            engine.disconnect().await.unwrap();
        } else {
            assert_eq!(
                engine.connect("missing-profile").await.err().as_deref(),
                Some("profile_not_found")
            );
        }
        assert!(engine.rpc.is_none());
        assert!(!std::path::Path::new(&format!("/proc/{}", owner.pid)).exists());
        engine.recovery_tick().await;
        assert!(!engine.recovery.pending());
        assert!(engine.running.is_none());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn only_local_internal_connections_are_eligible_even_for_raw_tun_configs() {
    for excluded in [
        "local",
        "system-mode",
        "tun-mode",
        "tun-connection",
        "proxy-lease",
        "external-instance",
        "external-request",
        "raw-tun",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
        engine.active_connection = Some(active("frozen"));
        engine.running = Some("frozen".into());
        engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(true));
        match excluded {
            "system-mode" => {
                engine.store.library.preferences.connection_mode = ConnectionMode::SystemProxy
            }
            "tun-mode" => engine.store.library.preferences.connection_mode = ConnectionMode::Tun,
            "tun-connection" => engine.active_connection.as_mut().unwrap().tun = true,
            "proxy-lease" => engine.active_connection.as_mut().unwrap().system_port = Some(2080),
            "external-instance" => {
                engine.active_connection.as_mut().unwrap().external_instance =
                    Some("owned-external".into())
            }
            "external-request" => {
                engine
                    .active_connection
                    .as_mut()
                    .unwrap()
                    .request
                    .need_extra_process = Some(true)
            }
            "raw-tun" => {
                engine
                    .active_connection
                    .as_mut()
                    .unwrap()
                    .request
                    .core_config = Some(json!({"inbounds":[{"type":"tun"}]}).to_string())
            }
            _ => (),
        }
        assert_eq!(
            engine.local_recovery_eligible(),
            excluded == "local",
            "{excluded}"
        );
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
        let snapshot = engine.snapshot();
        assert_eq!(
            snapshot.phase == "reconnecting",
            excluded == "local",
            "{excluded}"
        );
        engine.cancel_recovery().await.unwrap();
    }
}

#[tokio::test]
async fn synchronous_snapshot_and_check_preserve_pending_dependencies_without_spawning() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
    pending(&mut engine);
    let before = std::fs::read(dir.path().join("library.json")).ok();
    for _ in 0..3 {
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.phase, "reconnecting");
        assert_eq!(snapshot.running.as_deref(), Some("frozen"));
        assert_eq!(snapshot.since, None);
        assert!(!snapshot.traffic_available);
        assert!(snapshot.connections.is_empty());
        assert!(!serde_json::to_string(&snapshot)
            .unwrap()
            .contains("private-request-sentinel"));
        assert!(engine.running_uses("frozen-member"));
        assert!(engine.running_group_uses("frozen-group"));
        assert!(engine.rpc.is_none());
    }
    assert_eq!(
        engine.ensure_rpc().await.err().as_deref(),
        Some("core_reconnecting")
    );
    assert!(engine.rpc.is_none());
    assert_eq!(std::fs::read(dir.path().join("library.json")).ok(), before);
}

#[tokio::test]
async fn explicit_disconnect_shutdown_and_invalid_connect_cancel_before_deadline() {
    for action in ["disconnect", "shutdown", "connect"] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-spawn")).unwrap();
        pending(&mut engine);
        match action {
            "disconnect" => engine.disconnect().await.unwrap(),
            "shutdown" => engine.shutdown().await,
            _ => assert_eq!(
                engine.connect("missing-profile").await.err().as_deref(),
                Some("profile_not_found")
            ),
        }
        assert!(!engine.recovery.pending());
        engine.recovery_tick().await;
        assert!(engine.rpc.is_none());
        assert!(engine.running.is_none());
        assert!(engine.active_connection.is_none());
        assert_eq!(engine.snapshot().phase, "disconnected");
    }
}

#[tokio::test]
async fn failed_automatic_spawn_is_terminal_and_clears_the_private_request() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
    pending(&mut engine);
    engine.recovery.pending = Some(Instant::now());
    engine.recovery_tick().await;
    assert_eq!(
        engine.snapshot().error.as_deref(),
        Some("core_reconnect_failed")
    );
    assert!(!engine.recovery.pending());
    assert!(engine.active_connection.is_none());
    assert!(engine.running.is_none());
    for _ in 0..3 {
        engine.recovery_tick().await;
    }
    assert!(engine.rpc.is_none());
    assert_eq!(
        engine.snapshot().error.as_deref(),
        Some("core_reconnect_failed")
    );
}

#[cfg(target_os = "linux")]
fn add(engine: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> String {
    engine
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: name.into(),
            group_id: "personal".into(),
            kind,
            config,
        })
        .unwrap()
}

#[cfg(target_os = "linux")]
async fn http(port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut input = [0u8; 4096];
        assert!(socket.read(&mut input).await.unwrap() > 0);
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered",
            )
            .await
            .unwrap();
    });
    let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"recovered"));
    server.await.unwrap();
}

#[cfg(target_os = "linux")]
async fn kill_owned(engine: &mut Engine) -> crate::transport::OwnedProcess {
    let owner = engine.owned_core_process().unwrap();
    let exe = std::fs::read_link(format!("/proc/{}/exe", owner.pid)).unwrap();
    assert_eq!(exe, engine.core.canonicalize().unwrap());
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", owner.pid)).unwrap();
    let start = stat[stat.rfind(')').unwrap() + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(owner.start_time, Some(start));
    // Own Child handle, not a global name/port/PID search.
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    assert!(engine.rpc.as_mut().unwrap().child_exited());
    owner
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "requires THRONIUM_TEST_CORE; actual owned child crashes and loopback forwarding"]
async fn actual_core_recovery_preserves_request_and_cancels_or_limits_restarts() {
    const NAME: &str =
        "recovery::tests::actual_core_recovery_preserves_request_and_cancels_or_limits_restarts";
    if std::env::var_os("THRONIUM_LOCAL_RECOVERY_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let wrapper = tempfile::tempdir().unwrap();
        let exe = wrapper.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::copy(core, wrapper.path().join("ThroniumCore")).unwrap();
        let output = std::process::Command::new(exe)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_LOCAL_RECOVERY_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &core).unwrap();
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    engine.store.library.preferences.inbound_port = port;
    drop(reserve);
    let ordinary = add(
        &mut engine,
        "Ordinary",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let xray = add(
        &mut engine,
        "Xray",
        ProfileKind::XrayOutbound,
        json!({"protocol":"freedom","settings":{}}),
    );
    let raw = add(
        &mut engine,
        "Full sing-box",
        ProfileKind::SingBoxConfig,
        json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":port}],"outbounds":[{"type":"direct"}]}),
    );
    let raw_xray = add(
        &mut engine,
        "Full Xray",
        ProfileKind::XrayConfig,
        json!({"outbounds":[{"protocol":"freedom","settings":{}}]}),
    );
    let selected = add(
        &mut engine,
        "Selected but not active",
        ProfileKind::SingBoxOutbound,
        json!({"type":"block"}),
    );
    for id in [&ordinary, &xray, &raw, &raw_xray] {
        engine.connect(id).await.unwrap();
        http(port).await;
        engine.select(&selected).unwrap();
        engine.routing_revision = None;
        let previous = engine.active_connection.as_ref().unwrap().request.clone();
        let owner = kill_owned(&mut engine).await;
        for _ in 0..3 {
            assert_eq!(engine.snapshot().phase, "reconnecting");
        }
        assert_eq!(engine.snapshot().running.as_deref(), Some(id.as_str()));
        assert!(engine.owned_core_process().is_none());
        assert_eq!(
            engine.ensure_rpc().await.err().as_deref(),
            Some("core_reconnecting")
        );
        if id == &ordinary {
            let unchanged = std::fs::read(dir.path().join("library.json")).unwrap();
            assert_eq!(
                engine
                    .save_profile(ProfileDraft {
                        vpn_policy: Default::default(),
                        id: Some(id.clone()),
                        name: "Edited source must not replace active request".into(),
                        group_id: "personal".into(),
                        kind: ProfileKind::SingBoxOutbound,
                        config: json!({"type":"block"}),
                    })
                    .err()
                    .as_deref(),
                Some("stop_before_editing")
            );
            assert_eq!(
                std::fs::read(dir.path().join("library.json")).unwrap(),
                unchanged
            );
            assert_eq!(engine.profile(id).unwrap().config, json!({"type":"direct"}));
        }
        let before_library = std::fs::read(dir.path().join("library.json")).unwrap();
        tokio::time::sleep(RESTART_DELAY).await;
        engine.recovery_tick().await;
        assert_eq!(engine.snapshot().phase, "connected");
        assert_eq!(engine.snapshot().running.as_deref(), Some(id.as_str()));
        assert_eq!(
            engine.snapshot().selected.as_deref(),
            Some(selected.as_str())
        );
        assert!(engine.snapshot().since.is_some());
        assert_eq!(engine.routing_revision, None);
        assert_ne!(engine.owned_core_process().unwrap(), owner);
        assert_eq!(engine.active_connection.as_ref().unwrap().request, previous);
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            before_library
        );
        http(port).await;
        if id == &raw {
            assert_eq!(engine.poll().await.phase, "connected");
            http(port).await;
        }
        println!(
            "PASS exact {} request resumes real HTTP after owned core death",
            engine.profile(id).unwrap().name
        );
    }
    // The immediately following real death must exhaust Qt's rapid-exit guard.
    kill_owned(&mut engine).await;
    engine.recovery_tick().await;
    assert_eq!(engine.snapshot().phase, "disconnected");
    assert_eq!(
        engine.snapshot().error.as_deref(),
        Some("core_restart_limited")
    );
    for _ in 0..3 {
        engine.recovery_tick().await;
    }
    assert!(engine.owned_core_process().is_none());
    println!("PASS second actual death within 10 seconds stops retries");

    // A successful explicit connect resets the budget; Disconnect cancels a
    // pending automatic attempt even if its deadline has already become due.
    engine.connect(&ordinary).await.unwrap();
    http(port).await;
    kill_owned(&mut engine).await;
    assert_eq!(engine.snapshot().phase, "reconnecting");
    engine.disconnect().await.unwrap();
    tokio::time::sleep(RESTART_DELAY).await;
    engine.recovery_tick().await;
    assert!(engine.owned_core_process().is_none());
    assert_eq!(engine.snapshot().phase, "disconnected");
    assert!(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok());
    println!("PASS manual successful connect resets guard and Disconnect cancels queued recovery");

    engine.connect(&ordinary).await.unwrap();
    kill_owned(&mut engine).await;
    engine.snapshot();
    let foreign = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    tokio::time::sleep(RESTART_DELAY).await;
    engine.recovery_tick().await;
    assert_eq!(
        engine.snapshot().error.as_deref(),
        Some("core_reconnect_failed")
    );
    assert!(engine.owned_core_process().is_none());
    assert!(!engine.recovery.pending());
    assert_eq!(foreign.local_addr().unwrap().port(), port);
    for _ in 0..3 {
        engine.recovery_tick().await;
    }
    drop(foreign);
    assert!(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok());
    println!("PASS failed automatic Start reaps its candidate once and preserves foreign listener");
    engine.shutdown().await;
}
