//! Real pinned Core packet proof via public Engine generation, owned loopback only.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
use thronium_engine::{system_proxy::ConnectionMode, Engine, ProfileDraft};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};
fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(exe.file_name().unwrap(), "Thronium");
    exe.with_file_name("ThroniumCore").canonicalize().unwrap()
}
fn policy(g: bool, d: bool, b: bool) -> Value {
    json!({"onlyAdvertisedRoutes":g,"useTunnelDns":d,"blockOutsideDns":b})
}
struct Fixture {
    child: Child,
    stdout: BufReader<ChildStdout>,
    _root: tempfile::TempDir,
    ready: Value,
}
impl Fixture {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::copy(
            std::env::var_os("THRONIUM_POLICY_PYTHON").unwrap(),
            root.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(core(), root.path().join("ThroniumCore")).unwrap();
        let mut child = Command::new(root.path().join("Thronium"))
            .arg(std::env::var_os("THRONIUM_POLICY_FIXTURE").unwrap())
            .arg(root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(root.path().join("fixture-private.log")).unwrap())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "owned packet fixture failed to start");
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["systemTun"], false);
        Self {
            child,
            stdout,
            _root: root,
            ready,
        }
    }
    fn port(&self, name: &str) -> u16 {
        self.ready[name].as_u64().unwrap() as u16
    }
    fn count(&self, event: &str) -> usize {
        std::fs::read_to_string(self.ready["events"].as_str().unwrap())
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str::<Value>(s).unwrap())
            .filter(|v| v["event"] == event)
            .count()
    }
    fn check(&mut self, configs: Vec<Value>) -> Value {
        let input = self.child.stdin.as_mut().unwrap();
        writeln!(input, "{}", json!({"op":"check","configs":configs})).unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(
            !line.is_empty(),
            "Core CheckConfig rejected generated matrix"
        );
        let result: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(result["checked"], 32);
        assert_eq!(result["startCalls"], 0);
        assert_eq!(result["checkerReaped"], true);
        result
    }
    fn close(mut self) {
        self.stop();
    }
    fn stop(&mut self) {
        self.child.stdin.take();
        let end = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "fixture owned cleanup failed");
                assert!(!std::path::Path::new(&format!(
                    "/proc/{}",
                    self.ready["serverCorePid"].as_u64().unwrap()
                ))
                .exists());
                return;
            }
            if Instant::now() > end {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("fixture cleanup timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.stop();
        } else {
            self.child.stdin.take();
            for _ in 0..600 {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
struct App {
    engine: Engine,
    dir: tempfile::TempDir,
    id: String,
    port: u16,
    source: Value,
    flags: Value,
}
impl App {
    fn new(f: &Fixture, source: Value, flags: Value) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &core()).unwrap();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        engine
            .connection_settings(ConnectionMode::Local, port)
            .unwrap();
        let draft:ProfileDraft=serde_json::from_value(json!({"name":"Synthetic packet policy34","kind":"sing-box-outbound","groupId":"personal","config":source,"vpnPolicy":flags})).unwrap();
        let id = engine.save_profile(draft).unwrap();
        let mut routing = engine.routing();
        let active = &mut routing.profiles[0];
        active.route = json!({"final":"proxy","default_domain_resolver":"dns-direct"});
        active.rules=vec![
    serde_json::from_value(json!({"id":"dns-probe","name":"Owned DNS probe","enabled":true,"config":{"port":53,"action":"hijack-dns"}})).unwrap(),
    serde_json::from_value(json!({"id":"direct-control","name":"Owned direct exception","enabled":true,"config":{"ip_cidr":["127.0.0.1/32"],"port":f.port("directHttpPort"),"action":"route","outbound":"direct"}})).unwrap()
  ];
        active.dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":f.port("directDnsPort")}],"rules":[],"final":"dns-direct","disable_cache":true});
        engine.save_routing(routing).unwrap();
        Self {
            engine,
            dir,
            id,
            port,
            source,
            flags,
        }
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("library.json")).unwrap()
    }
    async fn preview(&mut self) -> Value {
        self.engine
            .connection_configuration(&self.id, false)
            .await
            .unwrap()["parts"][0]["config"]
            .clone()
    }
    async fn connected(&mut self) {
        self.engine.connect(&self.id).await.unwrap();
        let end = Instant::now() + Duration::from_secs(12);
        loop {
            self.engine.vpn_tick().await;
            if self.engine.snapshot().vpn.endpoints.iter().any(|e| {
                e.tag == "proxy"
                    && e.state == "connected"
                    && !e.auth_failed
                    && e.challenge_id.is_none()
            }) {
                return;
            }
            assert!(Instant::now() < end, "actual VPN connected timeout");
            sleep(Duration::from_millis(25)).await;
        }
    }
    async fn close(&mut self) {
        let owned = self.engine.owned_core_process();
        self.engine.disconnect().await.unwrap();
        self.engine.shutdown_checked().await.unwrap();
        assert!(self.engine.owned_core_process().is_none());
        if let Some(owner) = owned {
            assert!(!std::path::Path::new(&format!("/proc/{}", owner.pid)).exists());
        }
    }
}
async fn socks(
    proxy: u16,
    command: u8,
    address: Ipv4Addr,
    port: u16,
) -> Result<(TcpStream, std::net::SocketAddr), String> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .map_err(|_| "proxy_socket")?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|_| "greeting_write")?;
    let mut greeting = [0; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|_| "greeting_read")?;
    if greeting != [5, 0] {
        return Err("greeting_rejected".into());
    }
    let mut request = vec![5, command, 0, 1];
    request.extend(address.octets());
    request.extend(port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| "request_write")?;
    let mut head = [0; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| "reply_read")?;
    if head[1] != 0 {
        return Err(format!("socks_rejected_{}", head[1]));
    }
    if head[3] != 1 {
        return Err("non_ipv4_reply".into());
    }
    let mut address = [0; 4];
    stream
        .read_exact(&mut address)
        .await
        .map_err(|_| "reply_addr")?;
    let port = stream.read_u16().await.map_err(|_| "reply_port")?;
    Ok((stream, (Ipv4Addr::from(address), port).into()))
}
async fn http(proxy: u16, address: Ipv4Addr, port: u16) -> Result<String, String> {
    timeout(Duration::from_secs(4),async {
  let (mut stream,_)=socks(proxy,1,address,port).await?;stream.write_all(b"GET /owned-policy34 HTTP/1.1\r\nHost: owned.fixture.invalid\r\nConnection: close\r\n\r\n").await.map_err(|_|"http_write")?;
  let mut response=Vec::new();stream.read_to_end(&mut response).await.map_err(|_|"http_read")?;if response.len()>8192{return Err("http_oversize".into());}let text=String::from_utf8(response).map_err(|_|"http_utf8")?;if !text.starts_with("HTTP/1.0 200"){return Err("http_no_success".into());}Ok(text)
 }).await.map_err(|_|"http_timeout".to_string())?
}
async fn dns(proxy: u16, name: &str) -> (u8, Option<Ipv4Addr>) {
    timeout(Duration::from_secs(5), async {
        let (_hold, relay) = socks(proxy, 3, Ipv4Addr::UNSPECIFIED, 0).await.unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut query = vec![0x34, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend(label.as_bytes());
        }
        query.extend([0, 0, 1, 0, 1]);
        let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 53, 0, 53];
        packet.extend(&query);
        let relay = if relay.ip().is_unspecified() {
            (Ipv4Addr::LOCALHOST, relay.port()).into()
        } else {
            relay
        };
        socket.send_to(&packet, relay).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(peer, relay);
        assert!(n >= 22 && buf[..4] == [0, 0, 0, 1]);
        let body = &buf[10..n];
        assert_eq!(&body[..2], &query[..2]);
        let code = body[3] & 15;
        let answers = u16::from_be_bytes([body[6], body[7]]);
        let ip = if code == 0 && answers == 1 {
            assert!(body.ends_with(&[10, 79, 34, 1]) || body.ends_with(&[192, 0, 2, 34]));
            Some(Ipv4Addr::new(
                body[body.len() - 4],
                body[body.len() - 3],
                body[body.len() - 2],
                body[body.len() - 1],
            ))
        } else {
            None
        };
        (code, ip)
    })
    .await
    .expect("bounded owned DNS response required")
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "owned pinned Core, private DBus/XDG runner required"]
async fn vpn_policy_packets_public_matrix() {
    assert_eq!(std::env::var("GSETTINGS_BACKEND").unwrap(), "keyfile");
    assert!(std::env::var("XDG_CONFIG_HOME")
        .unwrap()
        .contains("thronium-policy34-"));
    let mut fixture = Fixture::start();
    let mut configs = vec![];
    for protocol in ["openvpn-client", "openconnect"] {
        for gate in [false, true] {
            for use_dns in [false, true] {
                for block in [false, true] {
                    let source = if protocol == "openvpn-client" {
                        fixture.ready["endpoint"].clone()
                    } else {
                        json!({"type":"openconnect","server":"https://127.0.0.1:9","flavor":"anyconnect","system":false,"no_udp":true,"username":"public-check","password":"public-check","tls":{"certificate_authority_path":fixture.ready["certificate"]}})
                    };
                    let mut app = App::new(&fixture, source, policy(gate, use_dns, block));
                    configs.push(app.preview().await);
                    app.engine
                        .connection_settings(ConnectionMode::Tun, app.port)
                        .unwrap();
                    configs.push(app.preview().await);
                    assert!(app.engine.owned_core_process().is_none());
                }
            }
        }
    }
    let checked = fixture.check(configs);
    println!(
        "VPN_POLICY34_JSON {}",
        json!({"scenario":"core-check32","checked":checked["checked"],"startCalls":0,"checkerReaped":true})
    );
    for (gate, use_dns, block) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let mut app = App::new(
            &fixture,
            fixture.ready["endpoint"].clone(),
            policy(gate, use_dns, block),
        );
        let preview = app.preview().await;
        let before = app.disk();
        app.connected().await;
        let advertised = fixture.count("advertised-http");
        let text = http(
            app.port,
            Ipv4Addr::new(10, 79, 34, 1),
            fixture.port("advertisedHttpPort"),
        )
        .await
        .unwrap();
        assert!(text.ends_with("policy34-advertised-http"));
        assert_eq!(fixture.count("advertised-http"), advertised + 1);
        let rejected_before = fixture.count("unadvertised-http");
        let unadvertised = http(
            app.port,
            Ipv4Addr::new(192, 0, 2, 44),
            fixture.port("unadvertisedHttpPort"),
        )
        .await;
        if gate {
            assert!(unadvertised.is_err());
            assert_eq!(fixture.count("unadvertised-http"), rejected_before);
        } else {
            assert!(unadvertised
                .unwrap()
                .ends_with("policy34-unadvertised-http"));
            assert_eq!(fixture.count("unadvertised-http"), rejected_before + 1);
        }
        let direct_before = fixture.count("direct-http");
        assert!(http(
            app.port,
            Ipv4Addr::LOCALHOST,
            fixture.port("directHttpPort")
        )
        .await
        .unwrap()
        .ends_with("policy34-direct-http"));
        assert_eq!(fixture.count("direct-http"), direct_before + 1);
        let vpn_before = fixture.count("vpn-dns");
        let dns_before = fixture.count("direct-dns");
        let (claimed_code, claimed) = dns(app.port, "test.corp.fixture.invalid").await;
        assert_eq!(claimed_code, 0);
        if gate || use_dns {
            assert_eq!(claimed, Some(Ipv4Addr::new(10, 79, 34, 1)));
            assert_eq!(fixture.count("vpn-dns"), vpn_before + 1);
            assert_eq!(fixture.count("direct-dns"), dns_before);
        } else {
            assert_eq!(claimed, Some(Ipv4Addr::new(192, 0, 2, 34)));
            assert_eq!(fixture.count("vpn-dns"), vpn_before);
            assert_eq!(fixture.count("direct-dns"), dns_before + 1);
        }
        let dns_before = fixture.count("direct-dns");
        let vpn_before = fixture.count("vpn-dns");
        let (unclaimed_code, unclaimed) = dns(app.port, "unclaimed.fixture.invalid").await;
        if gate && block {
            assert!(unclaimed_code != 0 && unclaimed.is_none());
            assert_eq!(fixture.count("direct-dns"), dns_before);
        } else {
            assert_eq!(unclaimed_code, 0);
            assert_eq!(unclaimed, Some(Ipv4Addr::new(192, 0, 2, 34)));
            assert_eq!(fixture.count("direct-dns"), dns_before + 1);
        }
        assert_eq!(fixture.count("vpn-dns"), vpn_before);
        assert_eq!(app.disk(), before);
        let profile = serde_json::to_value(app.engine.profile(&app.id).unwrap()).unwrap();
        assert_eq!(profile["config"], app.source);
        assert_eq!(profile["vpnPolicy"], app.flags);
        assert_eq!(
            app.engine
                .connection_configuration(&app.id, true)
                .await
                .unwrap()["parts"][0]["config"],
            preview
        );
        app.close().await;
        assert_eq!(app.disk(), before);
        println!(
            "VPN_POLICY34_JSON {}",
            json!({"scenario":format!("packets-{}{}{}",u8::from(gate),u8::from(use_dns),u8::from(block)),"advertisedHttp":true,"unadvertisedRejected":gate,"unadvertisedControlAccepted":!gate,"explicitDirectHttp":true,"pushedDnsAnswer":gate||use_dns,"directDnsFallback":!(gate&&block),"unclaimedRcode":unclaimed_code,"blockedDnsDirectQueries":if gate&&block {Some(0)}else{None},"sourceUnchanged":true,"ownedClientReaped":true})
        );
    }
    fixture.close();
    println!("VPN_POLICY34_CLEANUP true");
}
