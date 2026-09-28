//! Real TUN traffic. The runner must create a disposable Linux user/network namespace.
#[cfg(target_os = "linux")]
mod fixtures;
#[cfg(target_os = "linux")]
mod linux {
    use serde_json::{json, Value};
    use std::{path::Path, process::Command, time::Duration};
    use thronium_engine::{
        store::ProfileKind,
        system_proxy::ConnectionMode,
        tun::{self, Stack},
        Engine, ProfileDraft,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ip(args: &[&str]) -> Value {
        let output = Command::new("ip").args(args).output().unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
    }
    fn rules() -> Value {
        json!([ip(&["-4", "-j", "rule"]), ip(&["-6", "-j", "rule"])])
    }
    fn links() -> Value {
        ip(&["-j", "link"])
    }
    fn has_tun() -> bool {
        links()
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["ifname"] == tun::INTERFACE)
    }
    fn add(engine: &mut Engine, name: &str, config: Value) -> String {
        engine
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
    fn child_pid(parent: u32) -> u32 {
        maybe_child_pid(parent).expect("Expected a supervised child")
    }
    fn maybe_child_pid(parent: u32) -> Option<u32> {
        let output = Command::new("pgrep")
            .args(["-P", &parent.to_string()])
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .ok()
    }
    async fn settled(mut accept: impl FnMut() -> bool) {
        for _ in 0..100 {
            if accept() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("network state did not settle: {}", rules());
    }
    async fn wait_phase(engine: &mut Engine, wanted: &str) {
        for _ in 0..300 {
            let status = engine.poll().await;
            if status.phase == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let status = engine.snapshot();
        panic!("Expected {wanted}, got {} {:?}", status.phase, status.error);
    }
    fn kill_worker(helper: u32) -> u32 {
        let worker = child_pid(helper);
        assert_eq!(unsafe { libc::kill(worker as i32, libc::SIGKILL) }, 0);
        worker
    }
    async fn http(destination: &str) {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(destination),
        )
        .await
        .unwrap()
        .unwrap();
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: tun.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_to_string(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.ends_with("real-tun"), "{reply}");
    }
    async fn rejected_http(destination: &str) {
        let Ok(Ok(mut socket)) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(destination),
        )
        .await
        else {
            return;
        };
        let _ = socket
            .write_all(b"GET / HTTP/1.1\r\nHost: tun.test\r\nConnection: close\r\n\r\n")
            .await;
        let mut reply = String::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), socket.read_to_string(&mut reply)).await;
        assert!(
            !reply.ends_with("real-tun"),
            "a rejected host reached the proxy"
        );
    }
    async fn socks_client(mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; greeting[1] as usize];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[5, 0]).await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        assert_eq!(header[1], 1);
        let size = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await? as usize,
            _ => panic!("SOCKS address"),
        };
        let mut address = vec![0; size + 2];
        stream.read_exact(&mut address).await?;
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
        crate::fixtures::read_http_headers(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nreal-tun")
            .await?;
        Ok(())
    }
    async fn dns() {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let query =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tun\x04test\x00\x00\x01\x00\x01";
        socket.send_to(query, "198.18.0.53:53").await.unwrap();
        let mut response = [0; 512];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(&response[len - 4..len], &[198, 18, 0, 80]);
    }

    pub async fn main() {
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_str()
                .unwrap(),
            std::env::var("THRONIUM_TEST_ORIGINAL_NETNS").expect("Run scripts/test_tun.py"),
            "Refusing TUN tests in the host network namespace"
        );
        let exe = std::env::current_exe().unwrap();
        let core = exe.parent().unwrap().join("ThroniumCore");
        if let Some(directory) = std::env::args().nth(1) {
            let mut engine = Engine::open(Path::new(&directory), &core).unwrap();
            engine
                .connect(&engine.store.library.selected.clone().unwrap())
                .await
                .unwrap();
            std::fs::write(
                Path::new(&directory).join("ready"),
                child_pid(std::process::id()).to_string(),
            )
            .unwrap();
            std::future::pending::<()>().await;
            return;
        }
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "uplink", "type", "dummy"]);
        ip(&["addr", "add", "192.0.2.2/24", "dev", "uplink"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8::2/64",
            "dev",
            "uplink",
            "nodad",
        ]);
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
        ip(&[
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8::1",
            "dev",
            "uplink",
        ]);
        let baseline = rules();
        let routes = json!([
            ip(&["-4", "-j", "route", "show", "table", "all"]),
            ip(&["-6", "-j", "route", "show", "table", "all"])
        ]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let proxy = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    socks_client(stream).await.unwrap();
                });
            }
        });
        let dns_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = dns_server.local_addr().unwrap().port();
        let dns_task = tokio::spawn(async move {
            loop {
                let mut data = [0; 512];
                let (len, peer) = dns_server.recv_from(&mut data).await.unwrap();
                let mut reply = data[..len].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[7] = 1;
                reply.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 80]);
                dns_server.send_to(&reply, peer).await.unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        let mut preferences = engine.store.library.preferences.clone();
        preferences.connection_mode = ConnectionMode::Tun;
        preferences.tun.ipv6 = true;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        preferences.inbound_port = port;
        engine.preferences(preferences.clone()).unwrap();
        let id = add(
            &mut engine,
            "TUN proxy",
            json!({"type":"socks","server":"127.0.0.1","server_port":proxy_port,"version":"5"}),
        );
        let mut routing = engine.routing();
        routing.profiles[0].dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":dns_port}],"final":"dns-direct"});
        engine.save_routing(routing).unwrap();

        ip(&["rule", "add", "priority", "18905", "table", "main"]);
        let foreign = rules();
        assert_eq!(engine.connect(&id).await.unwrap_err(), "tun_conflict");
        assert_eq!(rules(), foreign);
        ip(&["rule", "del", "priority", "18905", "table", "main"]);
        ip(&["link", "add", tun::INTERFACE, "type", "dummy"]);
        assert_eq!(engine.connect(&id).await.unwrap_err(), "tun_conflict");
        assert!(has_tun());
        ip(&["link", "del", tun::INTERFACE]);
        ip(&["addr", "add", "172.19.0.2/30", "dev", "uplink"]);
        assert_eq!(engine.connect(&id).await.unwrap_err(), "tun_conflict");
        assert_eq!(rules(), baseline);
        ip(&["addr", "del", "172.19.0.2/30", "dev", "uplink"]);
        println!("PASS foreign interface, overlapping addresses and policy rules are preserved before Start");

        for stack in [Stack::Gvisor, Stack::System, Stack::Mixed] {
            preferences.tun.stack = stack;
            preferences.tun.mtu = 1400;
            engine.preferences(preferences.clone()).unwrap();
            if let Err(error) = engine.connect(&id).await {
                eprintln!("TUN Start {stack:?}: {error}");
                std::process::exit(1);
            }
            let device = links()
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["ifname"] == tun::INTERFACE)
                .unwrap()
                .clone();
            assert_eq!(device["mtu"], 1400);
            assert_ne!(rules(), baseline);
            http("198.18.0.80:80").await;
            http("[2001:db8:1::80]:80").await;
            dns().await;
            engine.generate_wg_keys().await.unwrap();
            http("198.18.0.80:80").await;
            assert!(engine.poll().await.traffic_down > 0);
            let mut edit = preferences.clone();
            edit.tun.mtu = 1500;
            assert_eq!(engine.preferences(edit).unwrap_err(), "stop_before_editing");
            if let Err(error) = engine.disconnect().await {
                eprintln!(
                    "Disconnect failed: {error}; rules={}; links={}",
                    rules(),
                    links()
                );
                for entry in engine.logs.view(Default::default()).unwrap().entries {
                    eprintln!("{}", entry.text);
                }
                panic!("TUN did not release its network state");
            }
            settled(|| !has_tun()).await;
            assert!(!has_tun());
            assert_eq!(rules(), baseline);
            println!("PASS {stack:?}: actual IPv4/IPv6 HTTP, UDP DNS, MTU, counters, editing guard and complete Disconnect");
        }
        // TUN traffic arrives as addresses; the route's sniff names the site, so a
        // domain rule decides it instead of the proxy (Qt parity).
        let mut routing = engine.routing();
        routing.profiles[0]
            .rules
            .push(thronium_engine::routing::Rule {
                id: "sniffed-host".into(),
                name: "Sniffed host".into(),
                enabled: true,
                simple: None,
                config: json!({"domain":["tun.test"],"action":"reject"}),
            });
        engine.save_routing(routing).unwrap();
        engine.connect(&id).await.unwrap();
        rejected_http("198.18.0.80:80").await;
        engine.disconnect().await.unwrap();
        settled(|| !has_tun()).await;
        let mut routing = engine.routing();
        routing.profiles[0]
            .rules
            .retain(|rule| rule.id != "sniffed-host");
        engine.save_routing(routing).unwrap();
        println!("PASS a domain rule decides TUN traffic to an address by its sniffed host");
        // A complete sing-box JSON keeps its own outbounds, routing and DNS and
        // receives the managed TUN listener like any compiled profile.
        preferences.tun.stack = Stack::Mixed;
        engine.preferences(preferences.clone()).unwrap();
        let full = |extra: Value| ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Complete sing-box".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxConfig,
            config: {
                let mut config = json!({
                    "outbounds":[{"type":"socks","tag":"user-proxy","server":"127.0.0.1","server_port":proxy_port,"version":"5"}],
                    "route":{"final":"user-proxy","rules":[{"ip_cidr":["198.18.0.80/32"],"action":"route","outbound":"user-proxy"}]},
                    "dns":{"servers":[{"type":"udp","tag":"user-dns","server":"127.0.0.1","server_port":dns_port}],"final":"user-dns"}
                });
                config
                    .as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().cloned().unwrap_or_default());
                config
            },
        };
        let owned = engine
            .save_profile(full(
                json!({"inbounds":[{"type":"tun","tag":"mine","address":["172.19.9.1/30"]}]}),
            ))
            .unwrap();
        assert_eq!(
            engine.connect(&owned).await.unwrap_err(),
            "tun_full_config_inbound_unsupported"
        );
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        let raw = engine.save_profile(full(json!({}))).unwrap();
        if let Err(error) = engine.connect(&raw).await {
            eprintln!("TUN Start of complete sing-box JSON: {error}");
            std::process::exit(1);
        }
        let running: Value = serde_json::from_str(
            engine.connection_configuration(&raw, true).await.unwrap()["parts"][0]["config"]
                .to_string()
                .as_str(),
        )
        .unwrap();
        assert_eq!(running["route"]["final"], "user-proxy");
        assert_eq!(running["dns"]["final"], "user-dns");
        assert_eq!(running["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(running["inbounds"][0]["type"], "tun");
        http("198.18.0.80:80").await;
        dns().await;
        // A verbatim JSON declares no managed stats service, so counters stay
        // unavailable; the HTTP and DNS exchanges above are the proof of traffic.
        engine.disconnect().await.unwrap();
        settled(|| !has_tun()).await;
        assert_eq!(rules(), baseline);
        println!("PASS complete sing-box JSON: managed TUN listener added, own routing/DNS kept, own tun inbound refused before Start");
        preferences.tun.stack = Stack::Gvisor;
        // Separate data directories still share ownership of one network.
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = Engine::open(other_dir.path(), &core).unwrap();
        let mut other_preferences = preferences.clone();
        other_preferences.inbound_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        other.preferences(other_preferences).unwrap();
        let other_id = add(
            &mut other,
            "Concurrent TUN",
            json!({"type":"socks","server":"127.0.0.1","server_port":proxy_port,"version":"5"}),
        );
        engine.preferences(preferences.clone()).unwrap();
        let (first, second) = tokio::join!(engine.connect(&id), other.connect(&other_id));
        assert_ne!(first.is_ok(), second.is_ok());
        assert_eq!(first.err().or(second.err()).unwrap(), "tun_conflict");
        http("198.18.0.80:80").await;
        if let Err(error) = engine.disconnect().await {
            eprintln!(
                "Disconnect failed: {error}; rules={}; links={}",
                rules(),
                links()
            );
            for entry in engine.logs.view(Default::default()).unwrap().entries {
                eprintln!("{}", entry.text);
            }
            panic!("TUN did not release its network state");
        }
        other.shutdown().await;
        assert_eq!(rules(), baseline);
        println!("PASS concurrent libraries admit one TUN owner and preserve its traffic");

        preferences.tun.ipv6 = false;
        preferences
            .tun
            .exclude_addresses
            .push("198.18.0.80/32".into());
        engine.preferences(preferences.clone()).unwrap();
        engine.connect(&id).await.unwrap();
        assert_eq!(
            ip(&["-j", "route", "get", "198.18.0.80"])[0]["dev"],
            "uplink"
        );
        assert_eq!(
            ip(&["-6", "-j", "route", "get", "2001:db8:1::80"])[0]["dev"],
            "uplink"
        );
        http("198.18.0.81:80").await;
        if let Err(error) = engine.disconnect().await {
            eprintln!(
                "Disconnect failed: {error}; rules={}; links={}",
                rules(),
                links()
            );
            for entry in engine.logs.view(Default::default()).unwrap().entries {
                eprintln!("{}", entry.text);
            }
            panic!("TUN did not release its network state");
        }
        println!("PASS configured CIDR bypass and IPv6-off preserve the original route while IPv4 TUN still works");

        preferences.tun.strict_route = true;
        let mut routing = engine.routing();
        routing.profiles[0]
            .rules
            .push(thronium_engine::routing::Rule {
                id: "dns-block".into(),
                name: "DNS fallback rejection".into(),
                enabled: true,
                simple: None,
                config: json!({"port":53,"action":"reject"}),
            });
        engine.save_routing(routing).unwrap();
        engine.preferences(preferences.clone()).unwrap();
        engine.connect(&id).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect("[2001:db8:1::80]:80")
        )
        .await
        .unwrap()
        .is_err());
        dns().await;
        if let Err(error) = engine.disconnect().await {
            eprintln!(
                "Disconnect failed: {error}; rules={}; links={}",
                rules(),
                links()
            );
            for entry in engine.logs.view(Default::default()).unwrap().entries {
                eprintln!("{}", entry.text);
            }
            panic!("TUN did not release its network state");
        }
        preferences.tun.dns_hijack = false;
        engine.preferences(preferences.clone()).unwrap();
        engine.connect(&id).await.unwrap();
        http("198.18.0.81:80").await;
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket.send_to(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tun\x04test\x00\x00\x01\x00\x01", "198.18.0.53:53").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut [0; 512]))
                .await
                .is_err()
        );
        if let Err(error) = engine.disconnect().await {
            eprintln!(
                "Disconnect failed: {error}; rules={}; links={}",
                rules(),
                links()
            );
            for entry in engine.logs.view(Default::default()).unwrap().entries {
                eprintln!("{}", entry.text);
            }
            panic!("TUN did not release its network state");
        }
        assert_eq!(rules(), baseline);
        println!("PASS strict routing blocks disabled IPv6 and DNS interception can be turned off independently");
        preferences.tun.ipv6 = true;
        preferences.tun.strict_route = false;
        preferences.tun.dns_hijack = true;
        preferences.tun.exclude_addresses.pop();
        engine.preferences(preferences).unwrap();
        engine.connect(&id).await.unwrap();
        let library = dir.path().join("library.json");
        let saved = dir.path().join("library.saved");
        std::fs::rename(&library, &saved).unwrap();
        std::fs::create_dir(&library).unwrap();
        let result = engine.connect(&id).await;
        std::fs::remove_dir(&library).unwrap();
        std::fs::rename(&saved, &library).unwrap();
        assert_eq!(result.unwrap_err(), "connection_restored");
        http("198.18.0.80:80").await;
        if let Err(error) = engine.disconnect().await {
            eprintln!(
                "Disconnect failed: {error}; rules={}; links={}",
                rules(),
                links()
            );
            for entry in engine.logs.view(Default::default()).unwrap().entries {
                eprintln!("{}", entry.text);
            }
            panic!("TUN did not release its network state");
        }
        assert_eq!(rules(), baseline);
        println!(
            "PASS post-Start persistence failure cleans the new TUN and restores working traffic"
        );
        engine.shutdown().await;
        drop(engine);

        let mut engine = Engine::open(dir.path(), &core).unwrap();
        engine.connect(&id).await.unwrap();
        let helper = child_pid(std::process::id());
        let original = kill_worker(helper);
        // Do not poll the engine until traffic has returned: the supervisor
        // must also reconnect while the webview is hidden or suspended.
        settled(|| maybe_child_pid(helper).is_some_and(|p| p != original) && has_tun()).await;
        http("198.18.0.80:80").await;
        assert_eq!(engine.poll().await.phase, "connected");
        assert_eq!(child_pid(std::process::id()), helper);
        println!("PASS TUN restarts a killed worker without GUI polling or another authorization");

        let mut route_before = engine.routing();
        let mut changed = route_before.clone();
        changed.profiles[0].mode = "direct".into();
        engine.save_routing(changed).unwrap();
        kill_worker(helper);
        wait_phase(&mut engine, "reconnecting").await;
        let pending = engine.snapshot();
        assert_eq!(pending.running.as_deref(), Some(id.as_str()));
        assert!(!pending.traffic_available);
        let mut edit = engine.store.library.preferences.clone();
        edit.tun.mtu = 1500;
        assert_eq!(engine.preferences(edit).unwrap_err(), "stop_before_editing");
        wait_phase(&mut engine, "connected").await;
        http("198.18.0.80:80").await;
        assert_eq!(engine.snapshot().routing["pending"], true);
        route_before.revision = engine.routing().revision;
        engine.save_routing(route_before).unwrap();
        println!("PASS reconnect restores the exact active request, retains pending routing and locks editing");

        kill_worker(helper);
        wait_phase(&mut engine, "reconnecting").await;
        engine.disconnect().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(engine.poll().await.phase, "disconnected");
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        assert!(maybe_child_pid(helper).is_none());
        println!(
            "PASS manual Disconnect cancels a pending retry and releases the worker and network"
        );

        engine.connect(&id).await.unwrap();
        kill_worker(helper);
        wait_phase(&mut engine, "reconnecting").await;
        let occupied = std::net::TcpListener::bind((
            "127.0.0.1",
            engine.store.library.preferences.inbound_port,
        ))
        .unwrap();
        wait_phase(&mut engine, "disconnected").await;
        assert_eq!(
            engine.snapshot().error.as_deref(),
            Some("tun_reconnect_failed")
        );
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        assert!(std::fs::read_dir("/run/thronium-tun")
            .unwrap()
            .next()
            .is_none());
        drop(occupied);
        engine.connect(&id).await.unwrap();
        http("198.18.0.80:80").await;
        assert_eq!(child_pid(std::process::id()), helper);
        engine.disconnect().await.unwrap();
        println!("PASS three failed retries stop cleanly; manual retry reuses authorization and restores HTTP");

        engine.connect(&id).await.unwrap();
        kill_worker(helper);
        wait_phase(&mut engine, "reconnecting").await;
        ip(&["addr", "add", "172.19.0.2/30", "dev", "uplink"]);
        wait_phase(&mut engine, "disconnected").await;
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        ip(&["addr", "del", "172.19.0.2/30", "dev", "uplink"]);
        println!("PASS retries refuse a TUN address claimed by another interface during backoff");

        engine.connect(&id).await.unwrap();
        for _ in 0..3 {
            kill_worker(helper);
            wait_phase(&mut engine, "reconnecting").await;
            wait_phase(&mut engine, "connected").await;
        }
        kill_worker(helper);
        wait_phase(&mut engine, "disconnected").await;
        assert_eq!(
            engine.snapshot().error.as_deref(),
            Some("tun_reconnect_failed")
        );
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        println!("PASS repeated crashes after successful starts exhaust the same retry budget");

        let mut disabled = engine.store.library.preferences.clone();
        disabled.tun.auto_reconnect = false;
        engine.preferences(disabled.clone()).unwrap();
        engine.connect(&id).await.unwrap();
        kill_worker(helper);
        wait_phase(&mut engine, "disconnected").await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(maybe_child_pid(helper).is_none());
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        println!("PASS disabling automatic reconnect leaves a crashed session disconnected");
        disabled.tun.auto_reconnect = true;
        engine.preferences(disabled).unwrap();
        engine.connect(&id).await.unwrap();
        let frozen = child_pid(helper);
        assert_eq!(unsafe { libc::kill(frozen as i32, libc::SIGSTOP) }, 0);
        // Do not poll the engine: a hidden WebView must not be required for
        // detecting and replacing a live-but-frozen worker.
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if maybe_child_pid(helper).is_some_and(|pid| pid != frozen) && has_tun() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("background watchdog did not recover a frozen worker");
        wait_phase(&mut engine, "connected").await;
        http("198.18.0.80:80").await;
        engine.disconnect().await.unwrap();
        engine.shutdown().await;
        drop(engine);
        println!("PASS a frozen worker recovers without GUI polling and restores real HTTP");

        let mut crashed = tokio::process::Command::new(&exe)
            .arg(dir.path())
            .spawn()
            .unwrap();
        settled(|| dir.path().join("ready").exists()).await;
        assert!(has_tun());
        let helper: u32 = std::fs::read_to_string(dir.path().join("ready"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            unsafe { libc::kill(child_pid(helper) as i32, libc::SIGSTOP) },
            0
        );
        crashed.kill().await.unwrap();
        settled(|| !has_tun() && rules() == baseline).await;
        println!("PASS abrupt GUI death reaps a frozen worker and removes the owned TUN and rules");

        for kill_helper in [false, true] {
            std::fs::remove_file(dir.path().join("ready")).unwrap();
            let mut owner = tokio::process::Command::new(&exe)
                .arg(dir.path())
                .spawn()
                .unwrap();
            settled(|| dir.path().join("ready").exists()).await;
            let helper: u32 = std::fs::read_to_string(dir.path().join("ready"))
                .unwrap()
                .parse()
                .unwrap();
            let worker = child_pid(helper);
            // A stopped worker cannot react to EOF. Recovery must identify and
            // reap this exact process from the protected journal after helper death.
            if kill_helper {
                assert_eq!(unsafe { libc::kill(worker as i32, libc::SIGSTOP) }, 0);
            }
            assert_eq!(
                unsafe {
                    libc::kill(
                        if kill_helper { helper } else { worker } as i32,
                        libc::SIGKILL,
                    )
                },
                0
            );
            if !kill_helper {
                settled(|| !has_tun() && rules() == baseline).await;
            }
            owner.kill().await.unwrap();
            let mut engine = Engine::open(dir.path(), &core).unwrap();
            engine.connect(&id).await.unwrap();
            http("198.18.0.80:80").await;
            engine.disconnect().await.unwrap();
            engine.shutdown().await;
            assert_eq!(rules(), baseline);
            assert!(!has_tun());
            println!(
                "PASS {} death recovers the owned network state and reconnects with real HTTP",
                if kill_helper {
                    "helper with a frozen worker"
                } else {
                    "core worker"
                }
            );
        }
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        let occupied = std::net::TcpListener::bind((
            "127.0.0.1",
            engine.store.library.preferences.inbound_port,
        ))
        .unwrap();
        assert!(engine.connect(&id).await.is_err());
        assert!(!has_tun());
        assert_eq!(rules(), baseline);
        assert!(std::fs::read_dir("/run/thronium-tun")
            .unwrap()
            .next()
            .is_none());
        drop(occupied);
        println!("PASS failed core Start removes its recovery journal and leaves network state unchanged");
        engine.connect(&id).await.unwrap();
        ip(&[
            "rule",
            "add",
            "priority",
            "18905",
            "to",
            "203.0.113.0/24",
            "table",
            "main",
        ]);
        engine.disconnect().await.unwrap();
        assert!(ip(&["-j", "rule"])
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["priority"] == 18905));
        ip(&[
            "rule",
            "del",
            "priority",
            "18905",
            "to",
            "203.0.113.0/24",
            "table",
            "main",
        ]);
        assert_eq!(rules(), baseline);
        println!("PASS disconnect preserves a foreign policy rule added during the TUN session");
        for (redirect, bridge) in [(false, false), (true, false), (false, true), (true, true)] {
            engine
                .store
                .library
                .settings
                .insert("vpn_l3_bridge".into(), json!(bridge));
            engine
                .store
                .library
                .settings
                .insert("vpn_tun_ipv4_cidr".into(), json!("10.71.0.1/30"));
            engine
                .store
                .library
                .settings
                .insert("vpn_tun_ipv6_cidr".into(), json!("fd72::1/126"));
            engine
                .store
                .library
                .settings
                .insert("vpn_auto_redirect".into(), json!(redirect));
            engine.store.library.preferences.tun.auto_reconnect = false;
            if let Err(error) = engine.connect(&id).await {
                for entry in engine.logs.view(Default::default()).unwrap().entries {
                    eprintln!("{}", entry.text);
                }
                panic!("settings TUN redirect={redirect}: {error}");
            }
            assert!(ip(&["-j", "address", "show", "dev", tun::INTERFACE])
                .to_string()
                .contains("10.71.0.1"));
            http("198.18.0.80:80").await;
            dns().await;
            if redirect || bridge {
                kill_worker(child_pid(std::process::id()));
                wait_phase(&mut engine, "disconnected").await;
            } else {
                engine.disconnect().await.unwrap();
            }
            assert_eq!(rules(), baseline);
            assert!(!has_tun());
            let nft = std::process::Command::new("/usr/sbin/nft")
                .args(["-j", "list", "tables"])
                .output()
                .unwrap();
            assert!(nft.status.success());
            assert!(!String::from_utf8_lossy(&nft.stdout).contains("thronium-auto-redirect"));
            assert!(!String::from_utf8_lossy(&nft.stdout).contains("sing-box-thronium-br0"));
            println!("PASS custom TUN addresses, redirect={redirect}, L3={bridge}: traffic, DNS and crash-safe route/firewall cleanup");
        }
        let mut local = engine.store.library.preferences.clone();
        local.connection_mode = ConnectionMode::Local;
        engine.preferences(local).unwrap();
        engine.connect(&id).await.unwrap();
        assert!(!has_tun());
        engine.disconnect().await.unwrap();
        engine.shutdown().await;
        println!("PASS switching back to local mode releases the authorized helper");
        assert_eq!(
            json!([
                ip(&["-4", "-j", "route", "show", "table", "all"]),
                ip(&["-6", "-j", "route", "show", "table", "all"])
            ]),
            routes
        );
        proxy.abort();
        dns_task.abort();
        println!("PASS original namespace routes preserved; no host networking or DNS changes");
    }
}

#[tokio::main]
async fn main() {
    #[cfg(target_os = "linux")]
    linux::main().await;
    #[cfg(not(target_os = "linux"))]
    panic!("Linux only");
}
