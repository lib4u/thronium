//! Actual Local selector continuity with owned, allowlisted loopback relays.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use thronium_engine::{store::ProfileKind, subscriptions::GroupDraft, Engine, ProfileDraft};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::{timeout, Duration},
};

#[derive(Default)]
struct Counts {
    health: usize,
    health_head: usize,
    health_get: usize,
    echo: usize,
    relays: Vec<(usize, u16)>,
    denied: usize,
}
type Seen = Arc<Mutex<Counts>>;
#[derive(Clone, Copy)]
enum Role {
    Http,
    Echo,
    Socks(usize),
}
struct Server {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Server {
    async fn start(role: Role, allowed: Vec<u16>, seen: Seen) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    _=clients.join_next(),if !clients.is_empty()=>{},
                    incoming=listener.accept()=>{
                        let (client,peer)=incoming.unwrap();assert!(peer.ip().is_loopback());let allowed=allowed.clone();let seen=seen.clone();
                        clients.spawn(async move {let _=serve(client,role,&allowed,seen).await;});
                    }
                }
            }
            drop(listener);
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        });
        Self {
            port,
            stop: Some(stop),
            task: Some(task),
        }
    }
    async fn close(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn header(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(client.read_u8().await?);
        if bytes.len() > 8192 {
            return Err(std::io::Error::other("owned_header_limit"));
        }
    }
    Ok(bytes)
}
async fn serve(
    mut client: TcpStream,
    role: Role,
    allowed: &[u16],
    seen: Seen,
) -> std::io::Result<()> {
    match role {
        Role::Http => {
            let request = header(&mut client).await?;
            let head = request.starts_with(b"HEAD /health HTTP/1.1\r\n");
            let get = request.starts_with(b"GET /health HTTP/1.1\r\n");
            if !head && !get {
                seen.lock().unwrap().denied += 1;
                return Err(std::io::Error::other("owned_health_request"));
            }
            {
                let mut counts = seen.lock().unwrap();
                counts.health += 1;
                counts.health_head += usize::from(head);
                counts.health_get += usize::from(get);
            }
            client
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
        }
        Role::Echo => {
            seen.lock().unwrap().echo += 1;
            let (mut input, mut output) = client.split();
            tokio::io::copy(&mut input, &mut output).await?;
        }
        Role::Socks(index) => {
            let mut hello = [0; 2];
            client.read_exact(&mut hello).await?;
            if hello[0] != 5 || hello[1] == 0 {
                seen.lock().unwrap().denied += 1;
                return Err(std::io::Error::other("owned_socks_hello"));
            }
            let mut methods = vec![0; hello[1] as usize];
            client.read_exact(&mut methods).await?;
            client.write_all(&[5, 0]).await?;
            let mut request = [0; 4];
            client.read_exact(&mut request).await?;
            if request != [5, 1, 0, 1] {
                seen.lock().unwrap().denied += 1;
                return Err(std::io::Error::other("owned_ipv4_connect_only"));
            }
            let mut address = [0; 4];
            client.read_exact(&mut address).await?;
            let port = client.read_u16().await?;
            if address != [127, 0, 0, 1] || !allowed.contains(&port) {
                seen.lock().unwrap().denied += 1;
                return Err(std::io::Error::other("outside_owned_fixture"));
            }
            let mut target = TcpStream::connect(("127.0.0.1", port)).await?;
            seen.lock().unwrap().relays.push((index, port));
            client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
            tokio::io::copy_bidirectional(&mut client, &mut target).await?;
        }
    }
    Ok(())
}
async fn tunnel(proxy: u16, echo: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    stream
        .write_all(
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let response = timeout(Duration::from_secs(5), header(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    stream
}
async fn echo(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    let mut result = vec![0; bytes.len()];
    timeout(Duration::from_secs(4), stream.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, bytes);
}
fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(exe.file_name().unwrap(), "Thronium");
    exe.parent().unwrap().join("ThroniumCore")
}
fn owned_ipc(owner: thronium_engine::transport::OwnedProcess) -> PathBuf {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let process = PathBuf::from(format!("/proc/{}", owner.pid));
    assert_eq!(
        std::fs::read_link(process.join("exe")).unwrap(),
        core().canonicalize().unwrap()
    );
    assert_eq!(std::fs::metadata(&process).unwrap().uid(), unsafe {
        libc::geteuid()
    });
    let stat = std::fs::read_to_string(process.join("stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(fields[1].parse::<u32>().unwrap(), std::process::id());
    assert_eq!(Some(fields[19].parse::<u64>().unwrap()), owner.start_time);
    let environment = std::fs::read(process.join("environ")).unwrap();
    let bytes = environment
        .split(|b| *b == 0)
        .find_map(|entry| entry.strip_prefix(b"THRONE_CORE_SOCKET="))
        .unwrap();
    let socket = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
    assert!(socket.is_absolute() && socket.exists());
    println!(
        "PROFILE_ORDER37_PROCESS {}",
        json!({"pid":owner.pid,"startTime":owner.start_time,"instance":owner.instance,"parentExeUidVerified":true})
    );
    socket
}
fn group(e: &mut Engine, name: &str) -> String {
    e.save_group(GroupDraft {
        id: None,
        name: name.into(),
        subscription: None,
        proxy_chain: None,
        auto_clear_unavailable: None,
    })
    .unwrap()
}
fn save(e: &mut Engine, name: &str, gid: &str, kind: ProfileKind, config: Value) -> String {
    e.save_profile(ProfileDraft {
        id: None,
        name: name.into(),
        group_id: gid.into(),
        kind,
        config,
        vpn_policy: Default::default(),
    })
    .unwrap()
}
fn members(status: &Value) -> Vec<String> {
    status["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["profileId"].as_str().unwrap().into())
        .collect()
}
async fn status(e: &mut Engine) -> Value {
    let groups = e.auto_selectors().await.unwrap();
    groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["tag"] == "proxy")
        .unwrap()
        .clone()
}
async fn ready(e: &mut Engine) -> Value {
    timeout(Duration::from_secs(15), async {
        loop {
            let s = status(e).await;
            if s["membersAlive"] == 2 {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}
async fn select(e: &mut Engine, id: &str) {
    let tag = thronium_engine::auto_selector::member_tag("proxy", id);
    e.auto_selector_action("proxy", "select", &tag)
        .await
        .unwrap();
    assert_eq!(status(e).await["selected"], tag);
}
fn session(e: &mut Engine) -> Value {
    let s = e.snapshot();
    assert!(s.since.is_some());
    json!({"running":s.running,"since":s.since,"phase":s.phase,"selected":s.selected,"vpn":s.vpn})
}
fn profiles(e: &Engine) -> BTreeMap<String, Value> {
    e.store
        .library
        .profiles
        .iter()
        .map(|p| (p.id.clone(), json!(p)))
        .collect()
}
fn rest(e: &Engine) -> Value {
    let mut v = json!(e.store.library);
    v.as_object_mut().unwrap().remove("profiles");
    v
}
fn ports(config: &Value) -> Vec<u64> {
    let out = config["parts"][0]["config"]["outbounds"]
        .as_array()
        .unwrap();
    let selector = out.iter().find(|v| v["tag"] == "proxy").unwrap();
    selector["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| {
            out.iter().find(|o| o["tag"] == *tag).unwrap()["server_port"]
                .as_u64()
                .unwrap()
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "owned loopback sockets, immutable Core and parent Thronium required"]
async fn actual_reorder_keeps_held_main_and_changes_only_next_selector_build() {
    let seen: Seen = Default::default();
    let mut http = Server::start(Role::Http, vec![], seen.clone()).await;
    let mut origin = Server::start(Role::Echo, vec![], seen.clone()).await;
    let allowed = vec![http.port, origin.port];
    let mut socks_a = Server::start(Role::Socks(0), allowed.clone(), seen.clone()).await;
    let mut socks_b = Server::start(Role::Socks(1), allowed, seen.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let mut e = Engine::open(directory.path(), &core()).unwrap();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = reserved.local_addr().unwrap().port();
    drop(reserved);
    e.connection_settings(thronium_engine::system_proxy::ConnectionMode::Local, proxy)
        .unwrap();
    let source = group(&mut e, "Source");
    let owner = group(&mut e, "Owner");
    let a = save(
        &mut e,
        "Owned A",
        &source,
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":socks_a.port,"version":"5"}),
    );
    let foreign = save(
        &mut e,
        "Foreign slot",
        "personal",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let b = save(
        &mut e,
        "Owned B",
        &source,
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":socks_b.port,"version":"5"}),
    );
    let selector = save(
        &mut e,
        "Live dynamic",
        &owner,
        ProfileKind::AutoSelector,
        json!({"type":"auto-selector","member_source":{"group_id":source,"name_regex":"^Owned [AB]$"},"url":format!("http://127.0.0.1:{}/health",http.port),"interval":"1s","bench_interval":"2s","watch_interval":"500ms","timeout":"800ms","sampling":2,"expected":2,"active_size":2,"concurrency":2,"interrupt_exist_connections":false}),
    );
    e.otp_save(
        "",
        "",
        thronium_engine::otp::Draft {
            name: "Unused order37 HOTP".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            kind: thronium_engine::otp::Kind::Hotp,
            counter: "9007199254740993".into(),
            ..Default::default()
        },
    )
    .unwrap();
    e.connect(&selector).await.unwrap();
    let owner_before = e.owned_core_process().unwrap();
    let ipc_before = owned_ipc(owner_before);
    let first = ready(&mut e).await;
    assert_eq!(members(&first), [a.clone(), b.clone()]);
    select(&mut e, &a).await;
    let mut held = tunnel(proxy, origin.port).await;
    echo(&mut held, b"order37-before").await;
    assert!(seen.lock().unwrap().relays.contains(&(0, origin.port)));
    let active = e.connection_configuration(&selector, true).await.unwrap();
    assert_eq!(ports(&active), [socks_a.port as u64, socks_b.port as u64]);
    let session_before = session(&mut e);
    let selected_tag = status(&mut e).await["selected"].clone();
    let payloads = profiles(&e);
    let remaining = rest(&e);
    let otp = e.otp_list();
    let foreign_index = e
        .store
        .library
        .profiles
        .iter()
        .position(|p| p.id == foreign)
        .unwrap();
    let connects_before = seen
        .lock()
        .unwrap()
        .relays
        .iter()
        .filter(|(_, p)| *p == origin.port)
        .count();
    e.reorder_profile(&b, &a, false).unwrap();
    assert_eq!(e.store.library.profiles[foreign_index].id, foreign);
    assert!(profiles(&e) == payloads);
    assert!(rest(&e) == remaining);
    assert!(e.otp_list() == otp);
    assert_eq!(e.owned_core_process().unwrap(), owner_before);
    assert_eq!(session(&mut e), session_before);
    assert!(e.connection_configuration(&selector, true).await.unwrap() == active);
    let still = status(&mut e).await;
    assert_eq!(members(&still), [a.clone(), b.clone()]);
    assert_eq!(still["selected"], selected_tag);
    echo(&mut held, b"order37-after-reorder").await;
    assert_eq!(
        seen.lock()
            .unwrap()
            .relays
            .iter()
            .filter(|(_, p)| *p == origin.port)
            .count(),
        connects_before,
        "held stream was replaced by a new fixture CONNECT"
    );
    let next = e.connection_configuration(&selector, false).await.unwrap();
    assert_eq!(ports(&next), [socks_b.port as u64, socks_a.port as u64]);
    assert!(e.connection_configuration(&selector, true).await.unwrap() == active);
    echo(&mut held, b"order37-after-preview").await;
    let stored = std::fs::read(directory.path().join("library.json")).unwrap();
    e.reorder_profile(&b, &a, false).unwrap(); // Adjacent current anchor is a no-op.
    assert!(std::fs::read(directory.path().join("library.json")).unwrap() == stored);
    assert_eq!(e.owned_core_process().unwrap(), owner_before);
    assert_eq!(session(&mut e), session_before);
    echo(&mut held, b"order37-after-noop").await;
    println!(
        "PROFILE_ORDER37_LIVE {}",
        json!({"stage":"retained","samePidStartInstance":true,"sameSessionAndActiveConfig":true,"sameCoreMemberOrder":true,"storedAndPreviewOrderChanged":true,"heldConnectUnchanged":true,"profilePayloadsOtpSelectionUnchanged":true})
    );
    drop(held);
    e.connect(&selector).await.unwrap();
    let final_owner = e.owned_core_process().unwrap();
    let ipc_after = owned_ipc(final_owner);
    let next_status = ready(&mut e).await;
    assert_eq!(members(&next_status), [b.clone(), a.clone()]);
    assert_eq!(
        ports(&e.connection_configuration(&selector, true).await.unwrap()),
        [socks_b.port as u64, socks_a.port as u64]
    );
    select(&mut e, &b).await;
    let prior_b = seen
        .lock()
        .unwrap()
        .relays
        .iter()
        .filter(|(i, p)| *i == 1 && *p == origin.port)
        .count();
    let mut after = tunnel(proxy, origin.port).await;
    echo(&mut after, b"order37-explicit-reconnect").await;
    assert_eq!(
        seen.lock()
            .unwrap()
            .relays
            .iter()
            .filter(|(i, p)| *i == 1 && *p == origin.port)
            .count(),
        prior_b + 1
    );
    assert!(profiles(&e) == payloads);
    assert!(rest(&e) == remaining);
    assert!(e.otp_list() == otp);
    println!(
        "PROFILE_ORDER37_LIVE {}",
        json!({"stage":"explicit-connect","newCoreMemberOrder":true,"newActiveConfigOrder":true,"actualEchoThroughB":true,"sameCoreProcessAllowed":final_owner==owner_before,"noAutomaticBestServerClaim":true})
    );
    drop(after);
    e.shutdown_checked().await.unwrap();
    assert!(e.owned_core_process().is_none());
    for pid in [owner_before.pid, final_owner.pid] {
        assert!(
            !PathBuf::from(format!("/proc/{pid}")).exists(),
            "owned Core not reaped"
        );
    }
    for socket in [ipc_before, ipc_after] {
        assert!(!socket.exists(), "owned Core IPC socket remains");
        assert!(
            !socket.parent().unwrap().exists(),
            "owned Core IPC directory remains"
        );
    }
    for server in [&mut socks_a, &mut socks_b, &mut http, &mut origin] {
        server.close().await;
    }
    let counts = seen.lock().unwrap();
    assert_eq!(counts.denied, 0);
    assert!(counts.health >= 2 && counts.echo >= 2);
    assert!(counts.health_head >= 2);
    println!(
        "PROFILE_ORDER37_CLEANUP {}",
        json!({"ownedCoreReaped":true,"ownedPidStartParentExeUidVerified":true,"ownedIpcSocketAndDirectoryRemoved":true,"allServerTasksJoined":true,"deniedTargets":counts.denied,"healthRequests":counts.health,"healthHeadRequests":counts.health_head,"healthGetRequests":counts.health_get,"echoConnections":counts.echo,"boundary":"actual-local-only; no-system-proxy-tun-otp-network"})
    );
}
