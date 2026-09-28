//! Genuine owned VPN URL probes; private GNOME, immutable Core, no OTP answers.
#![cfg(target_os = "linux")]
use fs2::FileExt;
use gio::{glib, prelude::*};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use thronium_engine::{
    logs::Filter,
    probes::{Method, Options, Outcome},
    system_proxy::ConnectionMode,
    transport::OwnedProcess,
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
    assert!(path.is_absolute() && path.to_string_lossy().contains("thronium-vpn-probes36-"));
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
struct Held {
    stream: TcpStream,
    task: tokio::task::JoinHandle<()>,
    count: usize,
}
impl Held {
    async fn new(proxy: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            loop {
                let mut header = Vec::new();
                loop {
                    let Ok(byte) = stream.read_u8().await else {
                        return;
                    };
                    header.push(byte);
                    assert!(header.len() < 4096);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\nowned36").await.is_err() { return; }
            }
        });
        let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
        stream
            .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = vec![];
        timeout(Duration::from_secs(3), async {
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 4096);
            }
        })
        .await
        .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        Self {
            stream,
            task,
            count: 0,
        }
    }
    async fn http(&mut self) {
        self.stream
            .write_all(b"GET /proof HTTP/1.1\r\nHost: owned.fixture.invalid\r\n\r\n")
            .await
            .unwrap();
        let mut head = vec![];
        timeout(Duration::from_secs(3), async {
            while !head.ends_with(b"\r\n\r\n") {
                head.push(self.stream.read_u8().await.unwrap());
                assert!(head.len() < 4096);
            }
        })
        .await
        .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let mut body = [0u8; 7];
        self.stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"owned36");
        self.count += 1;
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        self.task.abort();
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

#[derive(Clone)]
struct Observed {
    pid: u32,
    start: u64,
    directory: PathBuf,
    socket: PathBuf,
    private_ca: bool,
}
struct Observer {
    stop: Arc<AtomicBool>,
    records: Arc<Mutex<Vec<Observed>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Observer {
    fn start(main: OwnedProcess, private_ca: Option<PathBuf>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let records = Arc::new(Mutex::new(Vec::<Observed>::new()));
        let (done, found) = (stop.clone(), records.clone());
        let executable = core();
        let expected_ca_directory = std::env::var_os("SSL_CERT_DIR").map(PathBuf::from);
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
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
                            || pid == main.pid && Some(start) == main.start_time
                        {
                            continue;
                        }
                        if found
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|r| r.pid == pid && r.start == start)
                        {
                            continue;
                        }
                        let path = PathBuf::from(format!("/proc/{pid}"));
                        if std::fs::metadata(&path)
                            .ok()
                            .is_none_or(|m| m.uid() != unsafe { libc::geteuid() })
                        {
                            continue;
                        }
                        if std::fs::read_link(path.join("exe")).ok().as_ref() != Some(&executable) {
                            continue;
                        }
                        let Ok(directory) = std::fs::read_link(path.join("cwd")) else {
                            continue;
                        };
                        let Ok(environment) = std::fs::read(path.join("environ")) else {
                            continue;
                        };
                        let variable = |name: &str| {
                            environment
                                .split(|b| *b == 0)
                                .find_map(|entry| entry.strip_prefix(name.as_bytes()))
                                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                        };
                        let Some(socket) = variable("THRONE_CORE_SOCKET=") else {
                            continue;
                        };
                        let ca = variable("SSL_CERT_FILE=");
                        let directory_value = variable("SSL_CERT_DIR=");
                        let private_ca = match &private_ca {
                            Some(expected) => {
                                ca.as_deref() == expected.to_str()
                                    && directory_value.as_deref()
                                        == expected_ca_directory.as_ref().and_then(|p| p.to_str())
                            }
                            None => ca.is_none() && directory_value.is_none(),
                        };
                        found.lock().unwrap().push(Observed {
                            pid,
                            start,
                            directory,
                            socket: socket.into(),
                            private_ca,
                        });
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        Self {
            stop,
            records,
            thread: Some(thread),
        }
    }
    fn finish(mut self) -> Vec<Observed> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        let records = self.records.lock().unwrap().clone();
        records
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
async fn reaped(records: &[Observed], expected: usize) {
    assert_eq!(
        records.len(),
        expected,
        "wrong number of exact disposable Core children"
    );
    for record in records {
        assert!(
            record.private_ca,
            "probe child inherited unexpected CA environment"
        );
        assert!(
            !identity(record.pid).is_some_and(
                |(_, parent, start)| parent == std::process::id() && start == record.start
            ),
            "disposable Core remained owned after execute returned"
        );
        assert!(!record.socket.exists(), "disposable IPC socket remains");
        assert!(
            !record.socket.parent().unwrap().exists(),
            "disposable IPC directory remains"
        );
        assert!(
            !record.directory.exists(),
            "disposable private directory remains"
        );
    }
}

struct Fixture {
    child: Child,
    stdout: BufReader<ChildStdout>,
    _root: tempfile::TempDir,
    ready: Value,
    stopped: bool,
}
impl Fixture {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::copy(
            std::env::var_os("THRONIUM_PROBE_PYTHON").unwrap(),
            root.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(core(), root.path().join("ThroniumCore")).unwrap();
        let mut child = Command::new(root.path().join("Thronium"))
            .arg(std::env::var_os("THRONIUM_PROBE_FIXTURE").unwrap())
            .arg(root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(root.path().join("fixture-private.log")).unwrap())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "owned fixture failed to initialize");
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["systemTun"], false);
        assert_eq!(ready["openconnectBoundary"], "auth-exchange-only-no-cstp");
        Self {
            child,
            stdout,
            _root: root,
            ready,
            stopped: false,
        }
    }
    fn text(&self, key: &str) -> &str {
        self.ready[key].as_str().unwrap()
    }
    fn count(&self, event: &str) -> usize {
        std::fs::read_to_string(self.text("events"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["event"] == event)
            .count()
    }
    fn auth_count(&self, event: &str) -> usize {
        self.auth_rows()
            .into_iter()
            .filter(|row| row["event"] == event)
            .count()
    }
    fn auth_rows(&self) -> Vec<Value> {
        std::fs::read_to_string(self.text("authEvents"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    }
    fn command(&mut self, operation: &str) {
        writeln!(
            self.child.stdin.as_mut().unwrap(),
            "{}",
            json!({"op":operation})
        )
        .unwrap();
        self.child.stdin.as_mut().unwrap().flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let result: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(result["done"], true);
    }
    async fn wait_count(&self, event: &str, before: usize) {
        let until = Instant::now() + Duration::from_secs(12);
        while self.count(event) <= before {
            assert!(Instant::now() < until, "owned HTTP stage was not observed");
            sleep(Duration::from_millis(10)).await;
        }
    }
    fn close(&mut self) {
        if self.stopped {
            return;
        }
        self.child.stdin.take();
        let until = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.stopped = true;
                assert!(status.success(), "fixture cleanup failed");
                assert!(!Path::new(&format!(
                    "/proc/{}",
                    self.ready["serverCorePid"].as_u64().unwrap()
                ))
                .exists());
                assert_eq!(self.count("http-handler-error"), 0);
                return;
            }
            if Instant::now() >= until {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.stopped = true;
                panic!("fixture cleanup timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.stopped {
            if !std::thread::panicking() {
                self.close();
            } else {
                self.child.stdin.take();
                let until = Instant::now() + Duration::from_secs(12);
                while self.child.try_wait().ok().flatten().is_none() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if self.child.try_wait().ok().flatten().is_none() {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                }
            }
        }
    }
}

fn save(engine: &mut Engine, name: &str, config: Value) -> String {
    let draft: ProfileDraft = serde_json::from_value(json!({
        "name":name,"kind":"sing-box-outbound","groupId":"personal","config":config
    }))
    .unwrap();
    engine.save_profile(draft).unwrap()
}
struct App {
    engine: Engine,
    dir: tempfile::TempDir,
    main: String,
    profiles: std::collections::HashMap<String, String>,
    owner: OwnedProcess,
    frozen: Value,
    held: Held,
    proxy_before: Value,
    retained: Option<Value>,
}
impl App {
    async fn start(mode: ConnectionMode, fixture: &Fixture) -> Self {
        let proxy_before = baseline();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &core()).unwrap();
        engine.initialize_system_proxy();
        assert!(engine.snapshot().system_proxy.available);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        engine.connection_settings(mode, port).unwrap();
        let main = save(
            &mut engine,
            "Main direct connection",
            json!({"type":"direct"}),
        );
        let mut profiles = std::collections::HashMap::new();
        for key in [
            "openvpn",
            "openvpnRejected",
            "openconnectForm",
            "openconnectRejected",
        ] {
            profiles.insert(
                key.into(),
                save(&mut engine, key, fixture.ready[key].clone()),
            );
        }
        engine
            .otp_save(
                "",
                "",
                thronium_engine::otp::Draft {
                    name: "Unused HOTP probe control".into(),
                    secret: "JBSWY3DPEHPK3PXP".into(),
                    kind: thronium_engine::otp::Kind::Hotp,
                    counter: "19".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        // Explicit global direct routing must not bypass the tested VPN endpoint.
        let mut routing = engine.routing();
        routing.profiles[0]
            .rules
            .push(thronium_engine::routing::Rule {
                id: "owned-probe-global-direct".into(),
                name: "Owned probe global direct".into(),
                enabled: true,
                config: json!({"ip_cidr":["10.79.36.1/32"],"action":"route","outbound":"direct"}),
                simple: None,
            });
        engine.save_routing(routing).unwrap();
        engine.connect(&main).await.unwrap();
        let owner = engine.owned_core_process().unwrap();
        let environment = std::fs::read(format!("/proc/{}/environ", owner.pid)).unwrap();
        assert!(!environment
            .split(|b| *b == 0)
            .any(|e| e.starts_with(b"SSL_CERT_FILE=")));
        let frozen = engine.connection_configuration(&main, true).await.unwrap();
        let mut held = Held::new(port).await;
        held.http().await;
        let retained = if mode == ConnectionMode::SystemProxy {
            lease_locked();
            Some(json!({"journal":fingerprint(&journal()),"values":values(),
                "keyfile":fingerprint(&config().join("glib-2.0/settings/keyfile"))}))
        } else {
            assert!(!journal().exists());
            None
        };
        Self {
            engine,
            dir,
            main,
            profiles,
            owner,
            frozen,
            held,
            proxy_before,
            retained,
        }
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("library.json")).unwrap()
    }
    fn privacy(&mut self) {
        let snapshot = serde_json::to_string(&self.engine.snapshot()).unwrap();
        let logs = self.engine.logs.view(Filter::default()).unwrap();
        for secret in [
            " credentials-fixture-new-user ",
            " credentials-fixture-new-password-31 ",
            "credentials-fixture-rejected-password",
        ] {
            assert!(
                !snapshot.contains(secret),
                "source auth appeared in snapshot"
            );
            assert!(
                logs.entries
                    .iter()
                    .all(|entry| !entry.text.contains(secret)),
                "source auth appeared in app logs"
            );
        }
        assert!(
            self.engine.snapshot().vpn.endpoints.is_empty(),
            "probe auth form entered main panel"
        );
    }
    async fn retained(&mut self) {
        let current = self.engine.owned_core_process().unwrap();
        assert_eq!(
            (current.pid, current.start_time, current.instance),
            (self.owner.pid, self.owner.start_time, self.owner.instance)
        );
        assert!(
            self.engine
                .connection_configuration(&self.main, true)
                .await
                .unwrap()
                == self.frozen
        );
        assert_eq!(
            self.engine.snapshot().running.as_deref(),
            Some(self.main.as_str())
        );
        if let Some(before) = &self.retained {
            assert_eq!(fingerprint(&journal()), before["journal"]);
            assert_eq!(values(), before["values"]);
            assert_eq!(
                fingerprint(&config().join("glib-2.0/settings/keyfile")),
                before["keyfile"]
            );
            lease_locked();
        }
        self.held.http().await;
        self.privacy();
    }
    async fn close(mut self) {
        self.engine.shutdown_checked().await.unwrap();
        assert!(self.engine.owned_core_process().is_none());
        assert!(identity(self.owner.pid).is_none());
        lease_released();
        assert_eq!(values(), self.proxy_before);
        self.held.task.abort();
        let _ = (&mut self.held.task).await;
    }
}

struct Trust {
    file: Option<std::ffi::OsString>,
    directory: Option<std::ffi::OsString>,
    _empty: tempfile::TempDir,
}
impl Trust {
    fn install(certificate: &Path) -> Self {
        let file = std::env::var_os("SSL_CERT_FILE");
        let directory = std::env::var_os("SSL_CERT_DIR");
        assert!(file.is_none() && directory.is_none());
        let empty = tempfile::tempdir().unwrap();
        std::env::set_var("SSL_CERT_FILE", certificate);
        std::env::set_var("SSL_CERT_DIR", empty.path());
        Self {
            file,
            directory,
            _empty: empty,
        }
    }
}
impl Drop for Trust {
    fn drop(&mut self) {
        for (key, value) in [
            ("SSL_CERT_FILE", &self.file),
            ("SSL_CERT_DIR", &self.directory),
        ] {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    app: &mut App,
    fixture: &mut Fixture,
    scenario: &str,
    profile: &str,
    url: &str,
    expected: &str,
    auto: bool,
    action: &str,
) {
    if matches!(action, "cancel" | "stale") {
        fixture.command("reset-holds");
    }
    let id = app.profiles[profile].clone();
    let timeout_ms = if matches!(action, "cancel" | "stale") {
        5000
    } else {
        3000
    };
    if auto {
        app.engine
            .save_ping_settings(thronium_engine::probes::PingSettings {
                method: Method::Auto,
                url: url.into(),
                timeout_ms,
            })
            .unwrap();
    }
    let selected_other = app.profiles["openconnectRejected"].clone();
    app.engine.select(&selected_other).unwrap();
    let mut disk = app.disk();
    let otp = app.engine.otp_list();
    let main_vpn = serde_json::to_value(app.engine.snapshot().vpn).unwrap();
    let held_before = fixture.count("http-held");
    let closed_before = fixture.count("http-held-peer-closed");
    let http_before = fixture.count("http-success");
    let https_before = fixture.count("https-success");
    let failed_before = fixture.count("http-closed-before-headers");
    let auth_before = fixture.auth_count("credentials");
    let auth_rows_before = fixture.auth_rows().len();
    let run = if auto {
        app.engine.start_ping(vec![id.clone()]).unwrap()
    } else {
        app.engine
            .start_url_tests(Options {
                ids: vec![id.clone()],
                url: url.into(),
                timeout_ms,
                concurrency: None,
            })
            .unwrap()
    };
    let probe = app
        .engine
        .next_url_test(&run.id)
        .expect("supported VPN probe not dispatched");
    let ca = (scenario == "local-https").then(|| PathBuf::from(fixture.text("httpsCertificate")));
    let trust = ca.as_ref().map(|path| Trust::install(path));
    let observer = Observer::start(app.owner, ca);
    if action == "cancel-before" {
        app.engine.cancel_url_tests();
    }
    let mut cancellation = run.cancelled.clone();
    let task = tokio::spawn(async move { probe.execute_detailed(&mut cancellation).await });
    if matches!(action, "cancel" | "stale") {
        fixture.wait_count("http-held", held_before).await;
        app.retained().await;
        if action == "cancel" {
            app.engine.cancel_url_tests();
        } else {
            let original = app.engine.profile(&id).unwrap();
            let draft: ProfileDraft = serde_json::from_value(json!({
                "id":id,"name":original.name,"kind":"sing-box-outbound","groupId":original.group_id,
                "config":original.config,"vpnPolicy":{"onlyAdvertisedRoutes":true,"useTunnelDns":false,"blockOutsideDns":false}
            })).unwrap();
            app.engine.save_profile(draft).unwrap();
            disk = app.disk();
            fixture.command("release-holds");
        }
    }
    let result = timeout(Duration::from_secs(35), task)
        .await
        .expect("probe execution exceeded contract")
        .expect("probe worker panicked");
    let records = observer.finish();
    reaped(&records, usize::from(action != "cancel-before")).await;
    drop(trust);
    let verdict = match &result {
        Ok(Outcome::Latency(_)) => "latency",
        Ok(Outcome::ConnectedOnly) => "connected-only",
        Ok(Outcome::AuthRequired) => "auth-required",
        Ok(Outcome::HttpFailed(_)) => "http-failed",
        Ok(Outcome::Ip { .. }) | Ok(Outcome::Speed(_)) => "isolated-test",
        Err(code) => code.as_str(), // Public runtime returns finite, redacted codes.
    };
    println!(
        "VPN_PROBES36_OBSERVATION {}",
        json!({"scenario":scenario,"verdict":verdict,
        "httpRequests":fixture.count("http-success")-http_before,
        "httpsRequests":fixture.count("https-success")-https_before,
        "httpFailures":fixture.count("http-closed-before-headers")-failed_before,
        "authExchanges":fixture.auth_count("credentials")-auth_before,"reaped":records.len()})
    );
    let mut cancelled_peer_eof = None;
    let mut cancelled_server_release = false;
    if matches!(action, "cancel" | "cancel-before") {
        assert!(
            result.as_ref().is_err_and(|e| e == "probe_cancelled"),
            "cancel returned unexpected result"
        );
        if action == "cancel" {
            // Exact local child/IPC cleanup is asserted above. A killed UDP VPN
            // client cannot promise that this independent server's TCP origin
            // receives a FIN. Record that separately and release our own held
            // handler explicitly; never claim release was caused by Cancel.
            let peer_eof = fixture.count("http-held-peer-closed") > closed_before;
            cancelled_peer_eof = Some(peer_eof);
            if !peer_eof {
                let releases = fixture.count("http-hold-released");
                fixture.command("release-holds");
                fixture.wait_count("http-hold-released", releases).await;
                cancelled_server_release = true;
            }
        }
    } else if expected == "ok" || expected == "stale" {
        assert!(
            matches!(result, Ok(Outcome::Latency(ms)) if ms >= 0),
            "real HTTP result was not latency"
        );
    } else if expected == "connected-only" {
        assert!(
            matches!(result, Ok(Outcome::ConnectedOnly)),
            "VPN connected-only outcome absent"
        );
    } else {
        assert!(
            matches!(result, Ok(Outcome::AuthRequired)),
            "genuine VPN auth-required outcome absent"
        );
    }
    app.engine.finish_url_test_detailed(&run.id, &id, result);
    assert!(
        app.engine.next_url_test(&run.id).is_none(),
        "terminal VPN outcome fell through to a later method"
    );
    let batch = app.engine.snapshot().url_tests.unwrap();
    assert_eq!(batch.entries.len(), 1);
    let entry = serde_json::to_value(&batch.entries[0]).unwrap();
    assert_eq!(entry["status"], expected);
    if expected != "ok" {
        assert!(entry["latencyMs"].is_null());
    }
    if matches!(expected, "connected-only" | "auth-required") {
        assert_eq!(entry["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(entry["effectiveMethod"], "http");
        assert!(!entry["firstHop"].as_bool().unwrap());
    }
    if expected == "auth-required" {
        assert_eq!(entry["error"], "probe_vpn_auth_required");
    }
    if expected == "connected-only" {
        assert!(entry["error"].is_null());
    }
    if scenario.ends_with("http") {
        assert!(fixture.count("http-success") > http_before);
    }
    if scenario == "local-https" {
        assert!(fixture.count("https-success") > https_before);
    }
    if expected == "connected-only" {
        assert!(fixture.count("http-closed-before-headers") > failed_before);
    }
    if profile.starts_with("openconnect") {
        let rows = fixture.auth_rows();
        let delta = &rows[auth_rows_before..];
        let credentials: Vec<_> = delta
            .iter()
            .filter(|r| r["event"] == "credentials")
            .collect();
        assert!(
            !credentials.is_empty(),
            "OpenConnect credentials were never received"
        );
        assert!(delta.iter().any(|r| r["event"] == "initial-form"));
        if profile == "openconnectForm" {
            assert!(
                credentials.iter().all(|r| r["newExact"] == true
                    && r["oldExact"] == false
                    && r["accepted"] == true
                    && r["httpStatus"] == 200),
                "operator-form control did not receive exact accepted new credentials"
            );
            assert!(!delta.iter().any(|r| r["event"] == "initial-lockout"));
        } else {
            assert!(
                credentials.iter().all(|r| r["oldExact"] == true
                    && r["newExact"] == false
                    && r["accepted"] == false
                    && r["httpStatus"] == 403),
                "terminal rejection control did not receive exact rejected old credentials"
            );
            assert!(
                delta.iter().any(|r| r["event"] == "initial-lockout"
                    && r["accepted"] == false
                    && r["httpStatus"] == 403),
                "terminal rejection did not reach real initial lockout"
            );
        }
    }
    if expected == "auth-required" || action == "cancel-before" {
        assert_eq!(fixture.count("http-success"), http_before);
        assert_eq!(fixture.count("https-success"), https_before);
    }
    assert_eq!(
        app.engine.snapshot().selected.as_deref(),
        Some(selected_other.as_str())
    );
    assert!(
        app.disk() == disk,
        "persistent library changed unexpectedly"
    );
    assert!(
        app.engine.otp_list() == otp,
        "OTP rows changed unexpectedly"
    );
    assert_eq!(
        serde_json::to_value(app.engine.snapshot().vpn).unwrap(),
        main_vpn
    );
    app.retained().await;
    app.engine.clear_url_tests().unwrap();
    println!(
        "VPN_PROBES36_JSON {}",
        json!({"scenario":scenario,"status":expected,
        "actualHttpRequests":fixture.count("http-success")-http_before,
        "actualHttpsRequests":fixture.count("https-success")-https_before,
        "actualAuthExchanges":fixture.auth_count("credentials")-auth_before,
        "cancelRemotePeerEofBeforeRelease":cancelled_peer_eof,
        "cancelServerReleaseUsed":cancelled_server_release,
        "authEventContract":if profile=="openconnectForm" {"new-exact-http200-operator-form"}
            else if profile=="openconnectRejected" {"old-exact-http403-plus-initial-lockout"}
            else {"not-openconnect"},
        "disposableChildren":records.len(),"allExactChildrenReaped":true,"temporaryIpcRemoved":true,
        "mainPidRequestHeldConnectPreserved":true,"proxyLeasePreserved":app.retained.is_some(),
        "libraryUnchanged":action!="stale","onlyExplicitPolicyEdit":action=="stale",
        "hotpSelectedPreserved":true,"noOtpAnswer":true,
        "boundary":if profile.starts_with("openconnect") {"auth-only-no-cstp"} else {"actual-owned-openvpn-userspace"}})
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires private DBus/GNOME/XDG, immutable Core and owned synthetic fixture"]
async fn vpn_http_probe_actual_public_matrix() {
    config();
    assert!(std::env::var_os("SSL_CERT_FILE").is_none());
    assert!(std::env::var_os("SSL_CERT_DIR").is_none());
    let mut fixture = Fixture::start();
    let urls: std::collections::HashMap<String, String> =
        ["httpUrl", "httpsUrl", "closedUrl", "holdUrl"]
            .into_iter()
            .map(|key| (key.into(), fixture.text(key).into()))
            .collect();
    let mut local = App::start(ConnectionMode::Local, &fixture).await;
    for (scenario, profile, url, expected, auto, action) in [
        ("local-http", "openvpn", "httpUrl", "ok", false, "none"),
        ("local-https", "openvpn", "httpsUrl", "ok", false, "none"),
        (
            "local-connected-only",
            "openvpn",
            "closedUrl",
            "connected-only",
            true,
            "none",
        ),
        (
            "local-ovpn-auth",
            "openvpnRejected",
            "httpUrl",
            "auth-required",
            true,
            "none",
        ),
        (
            "local-oc-form",
            "openconnectForm",
            "httpUrl",
            "auth-required",
            false,
            "none",
        ),
        (
            "local-oc-rejected",
            "openconnectRejected",
            "httpUrl",
            "auth-required",
            false,
            "none",
        ),
        (
            "local-cancel-before",
            "openvpn",
            "httpUrl",
            "cancelled",
            false,
            "cancel-before",
        ),
        (
            "local-cancel",
            "openvpn",
            "holdUrl",
            "cancelled",
            false,
            "cancel",
        ),
        ("local-stale", "openvpn", "holdUrl", "stale", false, "stale"),
    ] {
        run_case(
            &mut local,
            &mut fixture,
            scenario,
            profile,
            &urls[url],
            expected,
            auto,
            action,
        )
        .await;
    }
    local.close().await;
    let mut system = App::start(ConnectionMode::SystemProxy, &fixture).await;
    run_case(
        &mut system,
        &mut fixture,
        "system-http",
        "openvpn",
        &urls["httpUrl"],
        "ok",
        false,
        "none",
    )
    .await;
    run_case(
        &mut system,
        &mut fixture,
        "system-cancel",
        "openvpn",
        &urls["holdUrl"],
        "cancelled",
        false,
        "cancel",
    )
    .await;
    system.close().await;
    fixture.close();
    println!("VPN_PROBES36_CLEANUP true");
}
