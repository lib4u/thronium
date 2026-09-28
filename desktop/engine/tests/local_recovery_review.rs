//! Independent public-API recovery acceptance with the pinned, real local core.
//! Run only through tests/local_recovery_review.py (owned loopback fixtures).
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thronium_engine::{
    store::ProfileKind, system_proxy::ConnectionMode, transport::OwnedProcess, Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const DELAY: Duration = Duration::from_millis(320);

fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(
        exe.file_name().unwrap(),
        "Thronium",
        "use the explicit pinned-core runner"
    );
    exe.with_file_name("ThroniumCore").canonicalize().unwrap()
}

fn listener(port: u16) -> TcpListener {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .unwrap();
    socket.listen(16).unwrap()
}

struct App {
    engine: Engine,
    directory: tempfile::TempDir,
    port: u16,
}
impl App {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(directory.path(), &core()).unwrap();
        let reservation = listener(0);
        let port = reservation.local_addr().unwrap().port();
        engine
            .connection_settings(ConnectionMode::Local, port)
            .unwrap();
        drop(reservation);
        Self {
            engine,
            directory,
            port,
        }
    }
    fn add(&mut self, name: &str, config: Value) -> String {
        self.engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: name.into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config,
            })
            .unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.directory.path().join("library.json")).unwrap()
    }
    async fn close(&mut self) {
        self.engine.shutdown().await;
        assert!(self.engine.owned_core_process().is_none());
        assert_eq!(self.engine.snapshot().phase, "disconnected");
        let released = listener(self.port);
        assert_eq!(released.local_addr().unwrap().port(), self.port);
    }
}

async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 16384, "bounded fixture HTTP header");
            bytes.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .expect("owned HTTP header timeout");
    bytes
}

struct Origin {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Origin {
    fn from_listener(server: TcpListener, marker: &'static str) -> Self {
        let address = server.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, peer) = server.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let request = header(&mut stream).await;
                assert!(
                    request.starts_with(b"GET "),
                    "only the owned synthetic GET protocol"
                );
                seen.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{marker}",
                    marker.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            count,
            task,
        }
    }
    fn new(marker: &'static str) -> Self {
        Self::from_listener(listener(0), marker)
    }
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
    async fn close(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn get(port: u16, destination: SocketAddr, expected: &str) {
    let mut stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(format!("GET http://{destination}/recovery-fixture HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let body = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &response[body..],
        expected.as_bytes(),
        "actual destination marker"
    );
}

fn identity(pid: u32) -> Option<(char, u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    Some((
        fields.first()?.chars().next()?,
        fields.get(1)?.parse().ok()?,
        fields.get(19)?.parse().ok()?,
    ))
}

fn signal_owned(engine: &Engine, signal: i32) -> OwnedProcess {
    let owner = engine
        .owned_core_process()
        .expect("only the public authenticated owner can be targeted");
    // pidfd pins identity against reuse; additionally verify spawn start time,
    // direct parent and the exact private copied core before sending a signal.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, owner.pid, 0) };
    assert!(
        fd >= 0,
        "pidfd_open for our own core: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let (_, parent, start) = identity(owner.pid).unwrap();
    assert_eq!(parent, std::process::id());
    assert_eq!(Some(start), owner.start_time);
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/exe", owner.pid)).unwrap(),
        core()
    );
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    assert_eq!(sent, 0, "signal only this verified owned pidfd");
    owner
}

async fn crash(engine: &mut Engine) -> OwnedProcess {
    let owner = signal_owned(engine, libc::SIGKILL);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        engine.snapshot();
        if engine.owned_core_process().is_none() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "owned core was not observed exited"
        );
        sleep(Duration::from_millis(10)).await;
    }
    assert!(
        identity(owner.pid).is_none_or(|(_, _, start)| Some(start) != owner.start_time),
        "owned child must be reaped"
    );
    owner
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn locally_cancelled_ipc_causes_real_core_eof_exit_without_recovery() {
    let mut app = App::new();
    let selected = app.add("Locally cancelled IPC fixture", json!({"type":"direct"}));
    let origin = Origin::new("before-local-cancel");
    app.engine.connect(&selected).await.unwrap();
    get(app.port, origin.address, "before-local-cancel").await;
    let owner = signal_owned(&app.engine, libc::SIGSTOP);
    let stopped_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let (state, _, start) = identity(owner.pid).unwrap();
        assert_eq!(Some(start), owner.start_time);
        if state == 'T' {
            break;
        }
        assert!(Instant::now() < stopped_deadline);
        sleep(Duration::from_millis(5)).await;
    }
    // Actual pending QueryConnections, not a fake/disconnected stream. Dropping
    // this public poll future closes the taken IPC stream conservatively.
    assert!(timeout(Duration::from_millis(150), app.engine.poll())
        .await
        .is_err());
    assert_eq!(app.engine.owned_core_process(), Some(owner));
    assert_eq!(identity(owner.pid).unwrap().0, 'T');
    assert_eq!(signal_owned(&app.engine, libc::SIGCONT), owner);
    // Do not call snapshot/tick while waiting: the real Go child must first
    // observe our EOF and exit, before Engine classifies the confirmed death.
    let eof_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match identity(owner.pid) {
            None => break,
            Some((state, _, start)) => {
                assert_eq!(Some(start), owner.start_time);
                if state == 'Z' || state == 'X' {
                    break;
                }
            }
        }
        assert!(
            Instant::now() < eof_deadline,
            "real Go core did not exit after locally cancelled parent IPC"
        );
        sleep(Duration::from_millis(10)).await;
    }
    app.engine.recovery_tick().await;
    terminal_ticks(&mut app, Some("core_disconnected")).await;
    assert_eq!(origin.count(), 1);
    app.close().await;
    origin.close().await;
    report(
        "local-ipc-cancel",
        json!({"owner":owner.instance,"httpRequests":1,"publicPollFutureCancelled":true,"goExitedFromParentEof":true,"sigkillUsed":false,"startsAfterLocallyCausedDeath":0,"terminalError":"core_disconnected"}),
    );
}

async fn terminal_ticks(app: &mut App, expected_error: Option<&str>) {
    for _ in 0..4 {
        sleep(Duration::from_millis(90)).await;
        app.engine.recovery_tick().await;
        let snapshot = app.engine.poll().await;
        assert_eq!(snapshot.phase, "disconnected");
        assert_eq!(snapshot.running, None);
        assert_eq!(snapshot.error.as_deref(), expected_error);
        assert!(app.engine.owned_core_process().is_none());
    }
    let reservation = listener(app.port);
    assert_eq!(reservation.local_addr().unwrap().port(), app.port);
}

fn report(name: &str, value: Value) {
    println!(
        "LOCAL_RECOVERY_REVIEW_JSON {}",
        json!({"scenario":name,"evidence":value})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn dormant_selected_and_two_idle_core_paths_never_autoconnect() {
    let mut app = App::new();
    let selected = app.add("Dormant selected fixture", json!({"type":"direct"}));
    app.engine.select(&selected).unwrap();
    let baseline = app.bytes();
    terminal_ticks(&mut app, None).await;
    assert_eq!(
        app.engine.snapshot().selected.as_deref(),
        Some(selected.as_str())
    );
    assert_eq!(app.bytes(), baseline);
    app.engine
        .check(&app.engine.profile(&selected).unwrap())
        .await
        .unwrap();
    assert!(app.engine.owned_core_process().is_some());
    assert_eq!(app.engine.snapshot().running, None);
    let checked = crash(&mut app.engine).await;
    terminal_ticks(&mut app, Some("core_disconnected")).await;
    let origin = Origin::new("idle-before-disconnect");
    app.engine.connect(&selected).await.unwrap();
    get(app.port, origin.address, "idle-before-disconnect").await;
    app.engine.disconnect().await.unwrap();
    assert!(
        app.engine.owned_core_process().is_some(),
        "normal Disconnect retains the idle RPC core"
    );
    let disconnected = crash(&mut app.engine).await;
    terminal_ticks(&mut app, Some("core_disconnected")).await;
    assert_eq!(
        app.engine.snapshot().selected.as_deref(),
        Some(selected.as_str())
    );
    assert_eq!(app.bytes(), baseline);
    app.close().await;
    origin.close().await;
    report(
        "dormant-and-idle",
        json!({"checkOnlyOwner":checked.instance,"disconnectedIdleOwner":disconnected.instance,"httpRequests":1,"idleDeaths":2,"libraryUnchanged":true,"automaticStarts":0}),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn snapshots_do_not_spawn_and_recovery_uses_the_frozen_route_and_selection() {
    let mut app = App::new();
    let original = Origin::new("FROZEN-A");
    let changed = Origin::new("SAVED-B");
    let active = app.add("Applied A", json!({"type":"direct"}));
    let other = app.add("Selected B", json!({"type":"direct"}));
    let mut initial_routing = app.engine.routing();
    initial_routing.profiles[0].rules.push(thronium_engine::routing::Rule {
        id: "owned-marker-redirect".into(),
        name: "Fixture route to original marker".into(),
        enabled: true,
        config: json!({"port":changed.address.port(),"action":"route","outbound":"proxy","override_port":original.address.port()}),
        simple: None,
    });
    app.engine.save_routing(initial_routing).unwrap();
    app.engine.connect(&active).await.unwrap();
    get(app.port, changed.address, "FROZEN-A").await;
    assert_eq!(changed.count(), 0);
    // A permitted network setting marks the applied revision unknown while the
    // original request is active. That dirty state must survive restoration.
    let previous = thronium_engine::settings::section(&app.engine.store.library, "logging");
    let mut next = previous.clone();
    assert!(previous.get("log_level").is_some());
    next["log_level"] = json!("error");
    app.engine
        .save_settings("logging", previous, next)
        .await
        .unwrap();
    assert_eq!(app.engine.snapshot().routing["pending"], true);
    let before = crash(&mut app.engine).await;
    assert_eq!(
        app.engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: Some(active.clone()),
                name: "Forbidden applied edit".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"block"})
            })
            .unwrap_err(),
        "stop_before_editing"
    );
    app.add("Unrelated library addition", json!({"type":"direct"}));
    app.engine.select(&other).unwrap();
    let mut routing = app.engine.routing();
    let saved_route = routing
        .profiles
        .iter_mut()
        .find(|p| p.id == routing.active)
        .unwrap();
    saved_route.route["final"] = json!("direct");
    saved_route.rules.clear();
    app.engine.save_routing(routing).unwrap();
    let saved_bytes = app.bytes();
    sleep(DELAY).await;
    for _ in 0..3 {
        let pending = app.engine.poll().await;
        assert_eq!(pending.phase, "reconnecting");
        assert_eq!(pending.running.as_deref(), Some(active.as_str()));
        assert_eq!(pending.selected.as_deref(), Some(other.as_str()));
        assert_eq!(pending.since, None);
        assert!(!pending.traffic_available);
        assert!(pending.connections.is_empty());
        assert!(app.engine.owned_core_process().is_none());
    }
    assert_eq!(
        app.engine
            .check(&app.engine.profile(&other).unwrap())
            .await
            .unwrap_err(),
        "core_reconnecting"
    );
    assert!(app.engine.owned_core_process().is_none());
    let reservation = listener(app.port);
    drop(reservation);
    app.engine.recovery_tick().await;
    let restored = app.engine.snapshot();
    assert_eq!(restored.phase, "connected");
    assert_eq!(restored.running.as_deref(), Some(active.as_str()));
    assert_eq!(restored.selected.as_deref(), Some(other.as_str()));
    assert!(restored.since.is_some());
    assert_eq!(restored.routing["pending"], true);
    let after = app.engine.owned_core_process().unwrap();
    assert_ne!(before, after);
    get(app.port, changed.address, "FROZEN-A").await;
    assert_eq!(original.count(), 2);
    assert_eq!(
        changed.count(),
        0,
        "new saved routing or selected profile must not leak into automatic restore"
    );
    assert_eq!(app.bytes(), saved_bytes);
    app.close().await;
    original.close().await;
    changed.close().await;
    report(
        "frozen-request",
        json!({"owners":[before.instance,after.instance],"originalHttpRequests":2,"changedDestinationRequests":0,"snapshotAndPollNeverSpawned":true,"pendingCheckRefused":true,"activeEditGuard":true,"savedLibraryUnchangedByRestore":true,"savedRoutingRemainsPending":true}),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn explicit_disconnect_invalid_connect_and_shutdown_cancel_due_recovery() {
    let mut evidence = vec![];
    for action in ["disconnect", "invalid-connect", "shutdown"] {
        let mut app = App::new();
        let selected = app.add("Cancellation fixture", json!({"type":"direct"}));
        let origin = Origin::new("before-cancel");
        app.engine.connect(&selected).await.unwrap();
        get(app.port, origin.address, "before-cancel").await;
        let owner = crash(&mut app.engine).await;
        assert_eq!(app.engine.snapshot().phase, "reconnecting");
        sleep(DELAY).await; // Cancellation must work even after the deadline.
        match action {
            "disconnect" => app.engine.disconnect().await.unwrap(),
            "invalid-connect" => assert_eq!(
                app.engine
                    .connect("no-such-fixture-profile")
                    .await
                    .unwrap_err(),
                "profile_not_found"
            ),
            _ => app.engine.shutdown().await,
        }
        terminal_ticks(&mut app, None).await;
        assert_eq!(origin.count(), 1);
        app.close().await;
        origin.close().await;
        evidence.push(json!({"action":action,"crashedOwner":owner.instance,"httpRequests":1,"startsAfterCancellation":0}));
    }
    report("explicit-cancel", json!(evidence));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn failed_recovery_preserves_foreign_listener_and_release_does_not_retry() {
    let mut app = App::new();
    let selected = app.add("Failed recovery fixture", json!({"type":"direct"}));
    let origin = Origin::new("before-failed-recovery");
    app.engine.connect(&selected).await.unwrap();
    get(app.port, origin.address, "before-failed-recovery").await;
    crash(&mut app.engine).await;
    let foreign = Origin::from_listener(listener(app.port), "FOREIGN-STILL-OWNED");
    sleep(DELAY).await;
    app.engine.recovery_tick().await;
    assert_eq!(
        app.engine.snapshot().error.as_deref(),
        Some("core_reconnect_failed")
    );
    assert!(app.engine.owned_core_process().is_none());
    get(app.port, foreign.address, "FOREIGN-STILL-OWNED").await;
    assert_eq!(
        foreign.count(),
        1,
        "failed core Start cannot kill or replace a foreign listener"
    );
    foreign.close().await;
    terminal_ticks(&mut app, Some("core_reconnect_failed")).await;
    assert_eq!(origin.count(), 1);
    app.close().await;
    origin.close().await;
    report(
        "failed-recovery",
        json!({"initialHttpRequests":1,"foreignHttpRequestsAfterFailure":1,"foreignListenerPreserved":true,"startsAfterForeignPortRelease":0,"terminalError":"core_reconnect_failed"}),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned core and owned loopback runner"]
async fn two_real_exits_are_limited_and_explicit_connect_resets_the_budget() {
    let mut app = App::new();
    let selected = app.add("Rapid exit fixture", json!({"type":"direct"}));
    let origin = Origin::new("rapid-fixture");
    app.engine.connect(&selected).await.unwrap();
    get(app.port, origin.address, "rapid-fixture").await;
    let started = Instant::now();
    crash(&mut app.engine).await;
    sleep(DELAY).await;
    app.engine.recovery_tick().await;
    get(app.port, origin.address, "rapid-fixture").await;
    crash(&mut app.engine).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    terminal_ticks(&mut app, Some("core_restart_limited")).await;
    app.engine.connect(&selected).await.unwrap();
    crash(&mut app.engine).await;
    assert_eq!(
        app.engine.snapshot().phase,
        "reconnecting",
        "explicit successful connect resets the old rapid-exit budget"
    );
    sleep(DELAY).await;
    app.engine.recovery_tick().await;
    get(app.port, origin.address, "rapid-fixture").await;
    assert_eq!(origin.count(), 3);
    app.close().await;
    origin.close().await;
    report(
        "rapid-exit",
        json!({"httpRequests":3,"secondDeathLimited":true,"explicitConnectResetsBudget":true}),
    );
}
