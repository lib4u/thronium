//! Public Engine acceptance in an isolated GNOME keyfile backend and real core.
#![cfg(target_os = "linux")]
use fs2::FileExt;
use gio::{glib, prelude::*};
use serde_json::{json, Value};
use std::{
    fs::File,
    net::{Ipv4Addr, SocketAddr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thronium_engine::{
    logs::Filter, store::ProfileKind, system_proxy::ConnectionMode, transport::OwnedProcess,
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

const KEYS: &[(&str, &str)] = &[
    ("http", "host"),
    ("http", "port"),
    ("http", "enabled"),
    ("http", "use-authentication"),
    ("https", "host"),
    ("https", "port"),
    ("ftp", "host"),
    ("ftp", "port"),
    ("socks", "host"),
    ("socks", "port"),
    ("", "use-same-proxy"),
    ("", "mode"),
    ("", "autoconfig-url"),
    ("", "ignore-hosts"),
];
fn config() -> PathBuf {
    assert_eq!(std::env::var("GSETTINGS_BACKEND").unwrap(), "keyfile");
    assert_eq!(std::env::var("XDG_CURRENT_DESKTOP").unwrap(), "GNOME");
    let path = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap());
    assert!(
        path.is_absolute()
            && path
                .to_string_lossy()
                .contains("thronium-system-proxy-review-")
    );
    path
}
fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(exe.file_name().unwrap(), "Thronium");
    exe.with_file_name("ThroniumCore").canonicalize().unwrap()
}
fn settings(suffix: &str) -> gio::Settings {
    config();
    gio::Settings::new(&format!(
        "org.gnome.system.proxy{}{}",
        if suffix.is_empty() { "" } else { "." },
        suffix
    ))
}
fn drain() {
    let context = glib::MainContext::default();
    while context.pending() {
        context.iteration(false);
    }
    gio::Settings::sync();
}
fn values() -> Value {
    drain();
    json!(KEYS.iter().map(|(suffix,key)|{let s=settings(suffix);json!({"effective":s.value(key).print(true).to_string(),"user":s.user_value(key).map(|v|v.print(true).to_string())})}).collect::<Vec<_>>())
}
fn set(suffix: &str, key: &str, raw: &str) {
    let s = settings(suffix);
    let v = glib::Variant::parse(Some(s.value(key).type_()), raw).unwrap();
    s.set_value(key, &v).unwrap();
    gio::Settings::sync();
}
fn baseline() -> Value {
    assert!(
        !journal().exists(),
        "previous scenario must release its lease"
    );
    for (suffix, key) in KEYS {
        settings(suffix).reset(key);
    }
    gio::Settings::sync();
    set("http", "host", "'before.fixture.invalid'");
    set("http", "port", "14771");
    set("http", "use-authentication", "true");
    set("socks", "port", "14772");
    set("", "mode", "'none'");
    set(
        "",
        "autoconfig-url",
        "'http://127.0.0.1:9/untouched-fixture.pac'",
    );
    set("", "ignore-hosts", "['localhost']");
    let value = values();
    assert!(value.as_array().unwrap()[..12]
        .iter()
        .any(|v| v["user"].is_null()));
    assert!(value.as_array().unwrap()[..12]
        .iter()
        .any(|v| !v["user"].is_null()));
    value
}
fn journal() -> PathBuf {
    config().join("thronium-system-proxy/recovery.json")
}
fn fingerprint(path: &Path) -> Value {
    let meta = std::fs::metadata(path).unwrap();
    json!({"bytes":std::fs::read(path).unwrap(),"inode":meta.ino(),"mtime":meta.mtime(),"mtimeNsec":meta.mtime_nsec()})
}
fn lease_locked() {
    let f = File::open(config().join("thronium-system-proxy/owner.lock")).unwrap();
    assert!(
        f.try_lock_exclusive().is_err(),
        "an independent file description must not acquire the retained lock"
    );
}
fn lease_released() {
    assert!(!journal().exists());
    let path = config().join("thronium-system-proxy/owner.lock");
    if path.exists() {
        let f = File::open(path).unwrap();
        f.try_lock_exclusive().unwrap();
        FileExt::unlock(&f).unwrap();
    }
}
fn listen(ip: Ipv4Addr, port: u16) -> TcpListener {
    let s = TcpSocket::new_v4().unwrap();
    s.set_reuseaddr(true).unwrap();
    s.bind(SocketAddr::from((ip, port))).unwrap();
    s.listen(16).unwrap()
}
struct Origin {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Origin {
    fn from(listener: TcpListener, marker: &'static str) -> Self {
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let mut request = Vec::new();
                timeout(Duration::from_secs(5), async {
                    while !request.ends_with(b"\r\n\r\n") {
                        assert!(request.len() < 16384);
                        request.push(stream.read_u8().await.unwrap());
                    }
                })
                .await
                .unwrap();
                assert!(request.starts_with(b"GET "));
                seen.fetch_add(1, Ordering::SeqCst);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{marker}",marker.len()).as_bytes()).await.unwrap();
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
        Self::from(listen(Ipv4Addr::new(127, 0, 0, 2), 0), marker)
    }
    async fn close(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}
async fn http(port: u16, destination: SocketAddr, marker: &str) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    stream.write_all(format!("GET http://{destination}/proxy-recovery HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let pos = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&response[pos..], marker.as_bytes());
}
async fn through_gnome(app: &App, origin: &Origin, marker: &str) {
    drain();
    let proxies = gio::ProxyResolver::default()
        .lookup(
            &format!("http://{}/proxy-recovery", origin.address),
            None::<&gio::Cancellable>,
        )
        .unwrap();
    assert_eq!(
        proxies.first().unwrap().as_str(),
        format!("http://127.0.0.1:{}", app.port)
    );
    http(app.port, origin.address, marker).await;
}
struct App {
    engine: Engine,
    _dir: tempfile::TempDir,
    port: u16,
    id: String,
}
impl App {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &core()).unwrap();
        engine.initialize_system_proxy();
        let status = engine.snapshot().system_proxy;
        assert!(status.available && !status.active);
        let reserve = listen(Ipv4Addr::LOCALHOST, 0);
        let port = reserve.local_addr().unwrap().port();
        engine
            .connection_settings(ConnectionMode::SystemProxy, port)
            .unwrap();
        drop(reserve);
        let id = engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "System proxy recovery fixture".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"direct"}),
            })
            .unwrap();
        Self {
            engine,
            _dir: dir,
            port,
            id,
        }
    }
    async fn connect(&mut self) {
        self.engine.connect(&self.id).await.unwrap();
        assert!(self.engine.snapshot().system_proxy.active);
        lease_locked();
    }
    async fn close(&mut self) {
        self.engine.shutdown().await;
        assert!(self.engine.owned_core_process().is_none());
        lease_released();
        let _ = listen(Ipv4Addr::LOCALHOST, self.port);
    }
    fn starts(&self) -> usize {
        self.engine
            .logs
            .view(Filter {
                search: "Core process started".into(),
                source: "app".into(),
                ..Default::default()
            })
            .unwrap()
            .entries
            .iter()
            .filter(|e| e.text == "Core process started")
            .count()
    }
}
fn identity(pid: u32) -> Option<(char, u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = text[text.rfind(')')? + 1..].split_whitespace().collect();
    Some((
        fields[0].chars().next()?,
        fields[1].parse().ok()?,
        fields[19].parse().ok()?,
    ))
}
fn signal(owner: OwnedProcess, sig: i32) {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, owner.pid, 0) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let (_, parent, start) = identity(owner.pid).unwrap();
    assert_eq!(parent, std::process::id());
    assert_eq!(Some(start), owner.start_time);
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/exe", owner.pid)).unwrap(),
        core()
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}
async fn crash(app: &mut App) -> OwnedProcess {
    let owner = app.engine.owned_core_process().unwrap();
    signal(owner, libc::SIGKILL);
    let end = Instant::now() + Duration::from_secs(3);
    while app.engine.owned_core_process().is_some() {
        app.engine.snapshot();
        assert!(Instant::now() < end);
        sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(app.engine.snapshot().phase, "reconnecting");
    assert!(app.engine.snapshot().system_proxy.active);
    owner
}
async fn terminal(app: &mut App, error: Option<&str>) {
    let starts = app.starts();
    for _ in 0..4 {
        sleep(Duration::from_millis(90)).await;
        app.engine.recovery_tick().await;
        let view = app.engine.snapshot();
        assert_eq!(view.phase, "disconnected");
        assert_eq!(view.error.as_deref(), error);
        assert!(app.engine.owned_core_process().is_none());
    }
    assert_eq!(app.starts(), starts);
}
async fn external_write() -> Value {
    for (schema, key, value) in [
        (
            "org.gnome.system.proxy.http",
            "host",
            "external.fixture.invalid",
        ),
        ("org.gnome.system.proxy", "mode", "auto"),
    ] {
        let status = tokio::process::Command::new("gsettings")
            .args(["set", schema, key, value])
            .status()
            .await
            .unwrap();
        assert!(status.success());
    }
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        let current = values();
        if current[0]["effective"] == "'external.fixture.invalid'"
            && current[11]["effective"] == "'auto'"
        {
            return current;
        }
        assert!(
            Instant::now() < end,
            "private GSettings file notification did not settle"
        );
        sleep(Duration::from_millis(10)).await;
    }
}
fn new_owned_candidate(previous: OwnedProcess) -> Option<OwnedProcess> {
    for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let Ok(children) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for pid in children
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
        {
            let Some((_, parent, start)) = identity(pid) else {
                continue;
            };
            if parent != std::process::id()
                || Some(start) == previous.start_time && pid == previous.pid
            {
                continue;
            }
            if std::fs::read_link(format!("/proc/{pid}/exe")).ok().as_ref() == Some(&core()) {
                return Some(OwnedProcess {
                    pid,
                    start_time: Some(start),
                    instance: 0,
                });
            }
        }
    }
    None
}
fn report(name: &str, data: Value) {
    println!(
        "SYSTEM_PROXY_RECOVERY_REVIEW_JSON {}",
        json!({"scenario":name,"evidence":data})
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "explicit private GNOME keyfile and pinned-core runner"]
async fn actual_system_proxy_recovery_public_matrix() {
    config();
    // Successful recovery retains exact journal, keyfile and lock ownership.
    {
        let before = baseline();
        let mut app = App::new();
        let origin = Origin::new("retained");
        app.connect().await;
        through_gnome(&app, &origin, "retained").await;
        let journal_before = fingerprint(&journal());
        let parsed: Value = serde_json::from_slice(&std::fs::read(journal()).unwrap()).unwrap();
        assert_eq!(parsed["before"], json!(&before.as_array().unwrap()[..12]));
        assert_eq!(parsed["port"], app.port);
        let keyfile = config().join("glib-2.0/settings/keyfile");
        let active_file = fingerprint(&keyfile);
        let active = values();
        let owner = crash(&mut app).await;
        sleep(Duration::from_millis(320)).await;
        assert_eq!(fingerprint(&journal()), journal_before);
        lease_locked();
        app.engine.recovery_tick().await;
        assert_eq!(app.engine.snapshot().phase, "connected");
        assert_ne!(app.engine.owned_core_process().unwrap(), owner);
        assert_eq!(fingerprint(&journal()), journal_before);
        assert_eq!(fingerprint(&keyfile), active_file);
        assert_eq!(values(), active);
        lease_locked();
        through_gnome(&app, &origin, "retained").await;
        app.engine.disconnect().await.unwrap();
        assert_eq!(values(), before);
        lease_released();
        app.close().await;
        assert_eq!(origin.count.load(Ordering::SeqCst), 2);
        origin.close().await;
        report(
            "retained-success",
            json!({"http":2,"exactJournalAndKeyfileIncludingInodeMtime":true,"competingLockDenied":true,"originalUserAndDefaultValuesRestored":true}),
        );
    }
    // Disconnect and shutdown after deadline cancel and restore without tick help.
    for action in ["disconnect", "shutdown"] {
        let before = baseline();
        let mut app = App::new();
        app.connect().await;
        crash(&mut app).await;
        sleep(Duration::from_millis(320)).await;
        if action == "disconnect" {
            app.engine.disconnect().await.unwrap();
        } else {
            app.engine.shutdown().await;
        }
        assert_eq!(values(), before);
        lease_released();
        terminal(&mut app, None).await;
        app.close().await;
        report(
            action,
            json!({"originalValuesRestoredBeforeSnapshot":true,"noLaterStart":true}),
        );
    }
    // The rapid breaker must restore from the backend tick, without UI polling.
    {
        let before = baseline();
        let mut app = App::new();
        let origin = Origin::new("rapid-proxy");
        app.connect().await;
        crash(&mut app).await;
        sleep(Duration::from_millis(320)).await;
        app.engine.recovery_tick().await;
        through_gnome(&app, &origin, "rapid-proxy").await;
        let owner = app.engine.owned_core_process().unwrap();
        signal(owner, libc::SIGKILL);
        let end = Instant::now() + Duration::from_secs(3);
        while identity(owner.pid).is_some_and(|(state, _, _)| state != 'Z' && state != 'X') {
            assert!(Instant::now() < end);
            sleep(Duration::from_millis(5)).await;
        }
        // A multithreaded process leader may be Z before waitpid observes the
        // whole Child exit. Drive the real periodic backend, without snapshots,
        // until it has reaped that exact instance; do not wait on proxy values.
        let mut exit_ticks = 0;
        while app.engine.owned_core_process().is_some() {
            assert_eq!(app.engine.owned_core_process(), Some(owner));
            assert!(Instant::now() < end);
            app.engine.recovery_tick().await;
            exit_ticks += 1;
            sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(values(), before);
        lease_released();
        terminal(&mut app, Some("core_restart_limited")).await;
        app.close().await;
        origin.close().await;
        report(
            "rapid-breaker",
            json!({"http":1,"exitObservationTicks":exit_ticks,"tickRestoredBeforeAnySnapshot":true,"noLaterStart":true}),
        );
    }
    // Failed Start must restore our lease while preserving a foreign listener.
    {
        let before = baseline();
        let mut app = App::new();
        app.connect().await;
        crash(&mut app).await;
        let foreign = Origin::from(listen(Ipv4Addr::LOCALHOST, app.port), "FOREIGN");
        sleep(Duration::from_millis(320)).await;
        app.engine.recovery_tick().await;
        assert_eq!(values(), before);
        lease_released();
        http(app.port, foreign.address, "FOREIGN").await;
        foreign.close().await;
        terminal(&mut app, Some("core_reconnect_failed")).await;
        app.close().await;
        report(
            "failed-start",
            json!({"http":1,"originalValuesRestoredBeforeSnapshot":true,"foreignListenerSurvived":true,"releaseDoesNotRetry":true}),
        );
    }
    // An external writer before retained-check blocks spawning, with no reacquire.
    {
        baseline();
        let mut app = App::new();
        app.connect().await;
        crash(&mut app).await;
        let external = external_write().await;
        let starts = app.starts();
        sleep(Duration::from_millis(320)).await;
        app.engine.recovery_tick().await;
        assert_eq!(app.starts(), starts);
        assert_eq!(values(), external);
        lease_released();
        let state = app.engine.snapshot();
        assert!(!state.system_proxy.active);
        assert_eq!(
            state.system_proxy.error.as_deref(),
            Some("system_proxy_changed")
        );
        terminal(&mut app, Some("core_reconnect_failed")).await;
        app.close().await;
        assert_eq!(values(), external);
        report(
            "external-before-start",
            json!({"candidateSpawns":0,"externalUserValuesPreserved":true,"leaseRelinquished":true}),
        );
    }
    // Pre-check occurs before spawn. Stop the exact new owned child while its
    // real handshake is pending, change the private backend, then let Start run.
    {
        baseline();
        let mut app = App::new();
        app.connect().await;
        let old = crash(&mut app).await;
        let starts = app.starts();
        sleep(Duration::from_millis(320)).await;
        let finished = AtomicBool::new(false);
        let (_, external) = tokio::join!(
            async {
                app.engine.recovery_tick().await;
                finished.store(true, Ordering::SeqCst);
            },
            async {
                let end = Instant::now() + Duration::from_secs(4);
                let candidate = loop {
                    if let Some(candidate) = new_owned_candidate(old) {
                        break candidate;
                    }
                    assert!(!finished.load(Ordering::SeqCst));
                    assert!(Instant::now() < end);
                    sleep(Duration::from_millis(1)).await;
                };
                assert!(!finished.load(Ordering::SeqCst));
                signal(candidate, libc::SIGSTOP);
                let external = external_write().await;
                assert!(
                    !finished.load(Ordering::SeqCst),
                    "external change must precede Start completion"
                );
                signal(candidate, libc::SIGCONT);
                external
            }
        );
        assert_eq!(app.starts(), starts + 1);
        assert!(app.engine.owned_core_process().is_none());
        assert_eq!(values(), external);
        lease_released();
        let state = app.engine.snapshot();
        assert_eq!(state.error.as_deref(), Some("core_reconnect_failed"));
        assert_eq!(
            state.system_proxy.error.as_deref(),
            Some("system_proxy_changed")
        );
        terminal(&mut app, Some("core_reconnect_failed")).await;
        app.close().await;
        assert_eq!(values(), external);
        report(
            "external-during-start",
            json!({"candidateSpawns":1,"ownedCandidateReaped":true,"externalChangeAfterPrecheckBeforeStartCompletion":true,"externalUserValuesPreserved":true}),
        );
    }
}
