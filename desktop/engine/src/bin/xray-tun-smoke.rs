//! Non-loopback Xray egress, three VLESS transports, DNS and recovery in private namespaces.
#[cfg(target_os = "linux")]
mod fixtures;
#[cfg(target_os = "linux")]
mod linux {
    use serde_json::{json, Value};
    use std::{path::Path, process::Command, time::Duration};
    use thronium_engine::{
        proto, store::ProfileKind, system_proxy::ConnectionMode, transport::Rpc, Engine,
        ProfileDraft,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const UUID: &str = "00000000-0000-0000-0000-000000000001";
    fn ip(args: &[&str]) -> Value {
        let r = Command::new("ip").args(args).output().unwrap();
        assert!(
            r.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        serde_json::from_slice(&r.stdout).unwrap_or(Value::Null)
    }
    fn rules() -> Value {
        json!([ip(&["-4", "-j", "rule"]), ip(&["-6", "-j", "rule"])])
    }
    async fn http() {
        let mut socket = tokio::net::TcpStream::connect("198.18.0.80:80")
            .await
            .unwrap();
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: tun.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        let mut chunk = [0; 1024];
        while !reply.ends_with(b"xray-over-tun") {
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0, "response truncated");
            reply.extend_from_slice(&chunk[..n]);
            assert!(reply.len() < 4096);
        }
        assert!(reply.starts_with(b"HTTP/1.1 200 OK"));
    }
    async fn dns() {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let q =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tun\x04test\x00\x00\x01\x00\x01";
        socket.send_to(q, "198.18.0.53:53").await.unwrap();
        let mut bytes = [0; 512];
        let (len, _) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..2], &q[..2]);
        assert_eq!(&bytes[len - 4..len], &[198, 18, 0, 81]);
    }
    async fn traffic() {
        http().await;
        dns().await;
    }
    async fn dns_answer(name: &str, expected: [u8; 4], tcp: bool) {
        let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend([0, 0, 1, 0, 1]);
        tokio::time::timeout(Duration::from_secs(7), async {
            let response = if tcp {
                let mut socket = tokio::net::TcpStream::connect("198.18.0.53:53")
                    .await
                    .unwrap();
                socket.write_u16(query.len() as u16).await.unwrap();
                socket.write_all(&query).await.unwrap();
                let len = socket.read_u16().await.unwrap();
                let mut data = vec![0; len as usize];
                socket.read_exact(&mut data).await.unwrap();
                data
            } else {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
                socket.send_to(&query, "198.18.0.53:53").await.unwrap();
                let mut bytes = [0; 512];
                let (len, _) = socket.recv_from(&mut bytes).await.unwrap();
                bytes[..len].to_vec()
            };
            assert_eq!(&response[..2], &query[..2]);
            assert_eq!(&response[response.len() - 4..], &expected);
        })
        .await
        .expect("DNS policy timed out");
    }
    fn child(pid: u32) -> u32 {
        String::from_utf8(
            Command::new("pgrep")
                .args(["-P", &pid.to_string()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .parse()
        .unwrap()
    }
    async fn serve(folder: &Path, core: &Path) {
        for _ in 0..100 {
            if folder.join("network-ready").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "set", "peer", "up"]);
        ip(&["addr", "add", "192.0.2.1/24", "dev", "peer"]);
        ip(&["addr", "add", "203.0.113.9/32", "dev", "lo"]);
        ip(&["route", "add", "default", "via", "192.0.2.2", "dev", "peer"]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:18080")
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    crate::fixtures::read_http_headers(&mut s).await.unwrap();
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nxray-over-tun").await.unwrap();
                });
            }
        });
        for (address, answer) in [
            ("203.0.113.9:53", [198, 18, 0, 81]),
            ("127.0.0.1:18080", [198, 18, 0, 80]),
        ] {
            let dns = tokio::net::UdpSocket::bind(address).await.unwrap();
            tokio::spawn(async move {
                loop {
                    let mut bytes = [0; 512];
                    let (n, peer) = dns.recv_from(&mut bytes).await.unwrap();
                    let mut out = bytes[..n].to_vec();
                    out[2] = 0x81;
                    out[3] = 0x80;
                    out[7] = 1;
                    let ip = if bytes[..n].windows(4).any(|w| w == b"\x03vpn") {
                        [198, 18, 0, 99]
                    } else {
                        answer
                    };
                    out.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    out.extend(ip);
                    dns.send_to(&out, peer).await.unwrap();
                }
            });
        }
        let listener = tokio::net::TcpListener::bind("203.0.113.9:18081")
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    crate::fixtures::read_http_headers(&mut s).await.unwrap();
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\ndirect-path").await.unwrap();
                });
            }
        });
        let mut inbounds = vec![];
        for (i, network) in ["raw", "grpc", "xhttp"].iter().enumerate() {
            let mut stream = json!({"network":network,"security":"none"});
            if *network == "grpc" {
                stream["grpcSettings"] = json!({"serviceName":"fixture"})
            }
            if *network == "xhttp" {
                stream["xhttpSettings"] = json!({"path":"/fixture","mode":"packet-up"})
            }
            inbounds.push(json!({"tag":network,"listen":"203.0.113.9","port":18800+i,"protocol":"vless","settings":{"clients":[{"id":UUID}],"decryption":"none"},"streamSettings":stream}));
        }
        std::fs::create_dir_all(folder.join("server")).unwrap();
        let logs = thronium_engine::logs::Logs::default();
        let mut rpc = Rpc::spawn_logged(core, &folder.join("server"), Some(logs.clone()))
            .await
            .unwrap();
        let request=proto::LoadConfigReq{core_config:Some(json!({"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"auto_detect_interface":true,"final":"direct"}}).to_string()),need_xray:Some(true),need_extra_process:Some(false),extra_no_out:Some(false),disable_stats:Some(false),xray_config:Some(json!({"log":{"loglevel":"debug"},"inbounds":inbounds,"outbounds":[{"protocol":"freedom","settings":{"redirect":"127.0.0.1:18080","finalRules":[{"action":"allow","ip":["127.0.0.1/32"],"port":18080}]}}]}).to_string()),..Default::default()};
        let response: proto::ErrorResp = rpc.call("Start", request).await.unwrap();
        assert!(
            response.error.as_deref().unwrap_or("").is_empty(),
            "server: {:?}",
            response.error
        );
        std::fs::write(folder.join("server-ready"), b"ready").unwrap();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            std::fs::write(
                folder.join("server-log"),
                logs.view(Default::default())
                    .unwrap()
                    .entries
                    .iter()
                    .map(|e| e.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .unwrap();
        }
    }
    pub async fn main() {
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_str()
                .unwrap(),
            std::env::var("THRONIUM_TEST_ORIGINAL_NETNS").expect("Use the isolated runner")
        );
        let exe = std::env::current_exe().unwrap();
        let core = exe.parent().unwrap().join("ThroniumCore");
        if std::env::args().nth(1).as_deref() == Some("--serve") {
            serve(Path::new(&std::env::args().nth(2).unwrap()), &core).await;
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut server = Command::new("unshare")
            .args([
                "--net",
                exe.to_str().unwrap(),
                "--serve",
                dir.path().to_str().unwrap(),
            ])
            .spawn()
            .unwrap();
        ip(&["link", "set", "lo", "up"]);
        ip(&[
            "link", "add", "uplink", "type", "veth", "peer", "name", "peer",
        ]);
        ip(&["link", "set", "peer", "netns", &server.id().to_string()]);
        ip(&["addr", "add", "192.0.2.2/24", "dev", "uplink"]);
        ip(&["link", "set", "uplink", "up"]);
        ip(&[
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "uplink",
        ]);
        std::fs::write(dir.path().join("network-ready"), b"ready").unwrap();
        for _ in 0..150 {
            if dir.path().join("server-ready").exists() {
                break;
            }
            assert!(server.try_wait().unwrap().is_none(), "server exited");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dir.path().join("server-ready").exists());
        let baseline = rules();
        let mut engine = Engine::open(&dir.path().join("client"), &core).unwrap();
        let mut prefs = engine.store.library.preferences.clone();
        prefs.connection_mode = ConnectionMode::Tun;
        prefs.inbound_port = 22880;
        prefs.tun.exclude_addresses.clear();
        engine.preferences(prefs).unwrap();
        let mut routing = engine.routing();
        routing.profiles[0].dns = json!({"servers":[{"tag":"dns-direct","type":"udp","server":"203.0.113.9","server_port":53}],"final":"dns-direct"});
        engine.save_routing(routing).unwrap();
        for (i, network) in ["raw", "grpc", "xhttp"].iter().enumerate() {
            let mut stream = json!({"network":network,"security":"none"});
            if *network == "grpc" {
                stream["grpcSettings"] = json!({"serviceName":"fixture"})
            }
            if *network == "xhttp" {
                stream["xhttpSettings"] = json!({"path":"/fixture","mode":"packet-up"})
            }
            let id=engine.save_profile(ProfileDraft{ vpn_policy: Default::default(),id:None,name:network.to_string(),group_id:"personal".into(),kind:ProfileKind::XrayOutbound,config:json!({"protocol":"vless","settings":{"address":"203.0.113.9","port":18800+i,"id":UUID,"encryption":"none"},"streamSettings":stream})}).unwrap();
            engine.connect(&id).await.unwrap();
            if tokio::time::timeout(Duration::from_secs(14), traffic())
                .await
                .is_err()
            {
                eprintln!(
                    "client log: {}",
                    engine
                        .logs
                        .view(Default::default())
                        .unwrap()
                        .entries
                        .iter()
                        .map(|e| e.text.clone())
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                eprintln!(
                    "server log: {}",
                    std::fs::read_to_string(dir.path().join("server-log")).unwrap_or_default()
                );
                eprintln!("rules: {}", rules());
                eprintln!(
                    "connections: {}",
                    serde_json::to_value(engine.poll().await).unwrap()
                );
                eprintln!("link counters: {}", ip(&["-j", "-s", "link"]));
                panic!("traffic timeout");
            }

            let runtime = engine.connection_configuration(&id, true).await.unwrap();
            let tun = runtime["parts"][0]["config"]["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["type"] == "tun")
                .unwrap();
            assert!(tun["iproute2_table_index"].as_u64().is_some());
            if *network == "xhttp" {
                let helper = std::fs::read_to_string(format!(
                    "/proc/{}/task/{}/children",
                    std::process::id(),
                    std::process::id()
                ))
                .unwrap()
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .find(|pid| *pid != server.id())
                .unwrap();
                let worker = child(helper);
                assert_eq!(unsafe { libc::kill(worker as i32, libc::SIGKILL) }, 0);
                for _ in 0..150 {
                    engine.poll().await;
                    if engine.snapshot().phase == "connected" && child(helper) != worker {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                assert_eq!(engine.snapshot().phase, "connected");
                traffic().await;
            }
            engine.disconnect().await.unwrap();
            assert_eq!(rules(), baseline);
            assert!(!ip(&["-j", "link"])
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["ifname"] == "thronium-tun"));
            println!("PASS VLESS {network}: non-loopback core egress, HTTP through TUN, UDP DNS, effective table and complete cleanup");
            if *network == "raw" {
                engine
                    .vless_core(&id, Some(thronium_engine::vless::Core::SingBox))
                    .unwrap();
                engine.connect(&id).await.unwrap();
                traffic().await;
                let active = engine.connection_configuration(&id, true).await.unwrap();
                assert_eq!(active["parts"].as_array().unwrap().len(), 1);
                engine.disconnect().await.unwrap();
                assert_eq!(rules(), baseline);
                println!("PASS same VLESS server through sing-box after switching the per-profile core: TUN HTTP and UDP DNS");
            }
        }
        let mut routing = engine.routing();
        routing.profiles = vec![Default::default()];
        routing.active = "default".into();
        engine.save_routing(routing).unwrap();
        let group=engine.save_group(thronium_engine::subscriptions::GroupDraft{ auto_clear_unavailable: None, proxy_chain: None,id:None,name:"Policy fixture".into(),subscription:Some(serde_json::from_value(json!({"url":"https://example.test/subscription","headers":{},"userAgent":"fixture","viaProxy":false,"useProviderRouting":true})).unwrap())}).unwrap();
        let provider = thronium_engine::subscriptions::provider_routing::ProviderRouting {
            action: "add".into(),
            error: None,
            config: json!({"DomainStrategy":"IPIfNonMatch","RouteOrder":"block-proxy-direct","DnsHosts":{"vpn.test":"203.0.113.9"},"DirectSites":["full:direct.test"],"DirectIp":["203.0.113.9/32"],"BlockIp":["198.18.0.82/32"],"RemoteDNSType":"DoU","RemoteDNSIP":"203.0.113.9","DomesticDNSType":"DoU","DomesticDNSIP":"203.0.113.9"}),
        };
        let req = engine.subscription_request(&group).unwrap();
        let metadata = thronium_engine::subscriptions::metadata::Metadata {
            routing: Some(provider),
            ..Default::default()
        };
        let ticket = engine
            .subscription_downloaded(
                req,
                thronium_engine::subscriptions::Download {
                    body: "fixture".into(),
                    metadata,
                    usage: None,
                },
            )
            .unwrap();
        let token = ticket["ticket"].as_str().unwrap();
        let outbound = json!({"protocol":"vless","settings":{"address":"vpn.test","port":18800,"id":UUID,"encryption":"none"},"streamSettings":{"network":"raw","security":"none"}});
        engine
            .preview_subscription(
                token,
                vec![ProfileDraft {
                    vpn_policy: Default::default(),
                    id: None,
                    name: "Policy".into(),
                    group_id: group.clone(),
                    kind: ProfileKind::XrayOutbound,
                    config: outbound.clone(),
                }],
            )
            .unwrap();
        engine
            .prepare_subscription_apply(token, Some(true))
            .await
            .unwrap();
        engine
            .apply_subscription_routing(token, Some(true))
            .unwrap();
        let id = engine
            .store
            .library
            .profiles
            .iter()
            .find(|p| p.group_id == group)
            .unwrap()
            .id
            .clone();
        engine.connect(&id).await.unwrap();
        tokio::time::timeout(Duration::from_secs(12), http())
            .await
            .unwrap();
        let direct = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap()
            .get("http://203.0.113.9:18081/")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(direct, "direct-path");
        let blocked = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap()
            .get("http://198.18.0.82/")
            .send()
            .await;
        assert!(blocked.is_err());
        assert!(!blocked.unwrap_err().is_timeout());
        for (name, expected) in [
            ("tun.test", [198, 18, 0, 80]),
            ("direct.test", [198, 18, 0, 81]),
        ] {
            dns_answer(name, expected, false).await;
            dns_answer(name, expected, true).await;
        }
        engine.disconnect().await.unwrap();
        assert_eq!(rules(), baseline);
        println!("PASS provider policy: real direct/proxy/block, separate DNS answers over UDP/TCP and VPN hostname bootstrap through Xray in TUN");
        let mut full_outbound = outbound;
        full_outbound["settings"]["address"] = json!("203.0.113.9");
        full_outbound["tag"] = json!("proxy");
        let full = json!({"inbounds":[{"protocol":"socks","port":10900,"tag":"socks","settings":{"udp":true},"sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}}],"outbounds":[full_outbound,{"protocol":"blackhole","tag":"block"}],"dns":{"servers":[{"address":"203.0.113.9","port":53}]},"routing":{"rules":[{"type":"field","domain":["full:blocked.test"],"outboundTag":"block"}]}});
        let id = engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Full Xray".into(),
                group_id: "personal".into(),
                kind: ProfileKind::XrayConfig,
                config: full,
            })
            .unwrap();
        engine.connect(&id).await.unwrap();
        tokio::time::timeout(Duration::from_secs(12), http())
            .await
            .unwrap();
        dns_answer("tun.test", [198, 18, 0, 80], false).await;
        dns_answer("tun.test", [198, 18, 0, 80], true).await;
        let denied = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get("http://198.18.0.80/")
            .header("Host", "blocked.test")
            .send()
            .await;
        assert!(denied.is_err());
        engine.disconnect().await.unwrap();
        assert_eq!(rules(), baseline);
        println!("PASS full Xray JSON in TUN: original DNS, SOCKS bridge sniffing and domain blocking own the connection policy");
        engine.shutdown().await;
        server.kill().unwrap();
        server.wait().unwrap();
        println!("PASS XHTTP TUN worker recovery restores real traffic in the same network lease");
    }
}
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    linux::main().await
}
#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("Linux only")
}
