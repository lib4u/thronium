//! Real systemd-resolved and managed TUN inside the runner's private namespaces.
#[cfg(target_os = "linux")]
mod linux {
    use serde_json::{json, Value};
    use std::{
        path::Path,
        process::{Child, Command},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use thronium_engine::{
        store::ProfileKind,
        system_proxy::ConnectionMode,
        tun::{Stack, SystemDns},
        Engine, ProfileDraft,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn run(program: &str, args: &[&str]) -> String {
        let o = Command::new(program).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "{program} {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }
    fn ip(args: &[&str]) -> Value {
        serde_json::from_str(&run("ip", args)).unwrap_or(Value::Null)
    }
    fn rules() -> Value {
        json!([ip(&["-4", "-j", "rule"]), ip(&["-6", "-j", "rule"])])
    }
    fn exists() -> bool {
        Path::new("/sys/class/net/thronium-tun").exists()
    }
    fn child(parent: u32) -> u32 {
        let expected = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("ThroniumCore");
        let matches: Vec<u32> = run("pgrep", &["-P", &parent.to_string()])
            .lines()
            .filter_map(|line| line.parse::<u32>().ok())
            .filter(|pid| {
                std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe == expected)
            })
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected one owned core child of {parent}: {matches:?}"
        );
        matches[0]
    }
    struct Resolver(Child);
    impl Drop for Resolver {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    async fn resolver() -> Resolver {
        let r = Resolver(
            Command::new("/usr/lib/systemd/systemd-resolved")
                .spawn()
                .unwrap(),
        );
        for _ in 0..100 {
            if Command::new("resolvectl")
                .arg("status")
                .output()
                .unwrap()
                .status
                .success()
            {
                for args in [
                    ["dns", "uplink", "192.0.2.53"],
                    ["dnsovertls", "uplink", "no"],
                    ["dnssec", "uplink", "no"],
                ] {
                    run("resolvectl", &args);
                }
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("private resolver did not start");
    }
    fn response(query: &[u8]) -> Vec<u8> {
        assert!(query.len() > 16);
        // resolved adds an EDNS OPT record after the question. Decode the
        // question itself and omit that additional record from our answer.
        let mut end = 12;
        while query[end] != 0 {
            let length = query[end] as usize;
            assert!(length < 64 && end + length + 1 < query.len());
            end += length + 1;
        }
        end += 1;
        let kind = u16::from_be_bytes([query[end], query[end + 1]]);
        let mut v = query[..end + 4].to_vec();
        v[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        v[2] = 0x81;
        v[3] = 0x80;
        if kind == 1 || kind == 28 {
            v[7] = 1;
            v.extend([0xc0, 0x0c]);
            v.extend(kind.to_be_bytes());
            v.extend([0, 1, 0, 0, 0, 0]);
            if kind == 1 {
                v.extend([0, 4, 198, 18, 0, 80]);
            } else {
                v.extend([0, 16]);
                v.extend(
                    "2001:db8:1::80"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
            }
        }
        v
    }
    async fn query(tcp: bool, aaaa: bool, n: u32) {
        let label = format!("dns{n}");
        let mut q = vec![0x59, 0x59, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
        q.extend([
            4,
            b't',
            b'e',
            b's',
            b't',
            0,
            0,
            if aaaa { 28 } else { 1 },
            0,
            1,
        ]);
        let reply = tokio::time::timeout(Duration::from_secs(8), async {
            if tcp {
                let mut s = tokio::net::TcpStream::connect("127.0.0.53:53")
                    .await
                    .unwrap();
                s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
                s.write_all(&q).await.unwrap();
                let len = s.read_u16().await.unwrap();
                let mut r = vec![0; len as usize];
                s.read_exact(&mut r).await.unwrap();
                r
            } else {
                let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                s.send_to(&q, "127.0.0.53:53").await.unwrap();
                let mut r = vec![0; 4096];
                let len = s.recv(&mut r).await.unwrap();
                r.truncate(len);
                r
            }
        })
        .await
        .expect("system DNS query timed out");
        assert_eq!(&reply[..2], &q[..2]);
        assert_eq!(reply[3] & 15, 0, "DNS response {reply:?}");
        assert!(reply[7] > 0, "no DNS answer {reply:?}");
        let expected = if aaaa {
            "2001:db8:1::80"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        } else {
            vec![198, 18, 0, 80]
        };
        assert!(
            reply.windows(expected.len()).any(|v| v == expected),
            "unexpected answer {reply:?}"
        );
    }
    async fn connected(engine: &mut Engine) {
        for _ in 0..300 {
            if engine.poll().await.phase == "connected" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "not connected: {}",
            engine.snapshot().error.unwrap_or_default()
        );
    }
    async fn clean(engine: &mut Engine, baseline: &Value, physical: &str) {
        engine.disconnect().await.unwrap();
        for _ in 0..100 {
            if !exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!exists());
        assert_eq!(&rules(), baseline);
        assert_eq!(run("resolvectl", &["dns", "uplink"]), physical);
        assert!(std::fs::read_dir("/run/thronium-tun")
            .unwrap()
            .next()
            .is_none());
    }
    pub async fn main() {
        for kind in ["net", "mnt"] {
            assert_ne!(
                std::fs::read_link(format!("/proc/self/ns/{kind}"))
                    .unwrap()
                    .to_str()
                    .unwrap(),
                std::env::var(format!("THRONIUM_TEST_ORIGINAL_{}NS", kind.to_uppercase())).unwrap(),
                "host namespace forbidden"
            );
        }
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let exe = std::env::current_exe().unwrap();
        let core = exe.parent().unwrap().join("ThroniumCore");
        if std::env::args().nth(1).as_deref() == Some("--legacy-capability") {
            let dir = tempfile::tempdir().unwrap();
            let mut old = Engine::open(dir.path(), &core).unwrap();
            let mut prefs = old.store.library.preferences.clone();
            prefs.connection_mode = ConnectionMode::Tun;
            prefs.tun.system_dns = SystemDns::Resolved;
            old.preferences(prefs).unwrap();
            let id = old
                .save_profile(ProfileDraft {
                    id: None,
                    name: "Legacy capability".into(),
                    group_id: "personal".into(),
                    kind: ProfileKind::SingBoxOutbound,
                    config: json!({"type":"direct"}),
                    vpn_policy: Default::default(),
                })
                .unwrap();
            assert_eq!(
                old.connect(&id).await.unwrap_err(),
                "tun_system_dns_core_unsupported"
            );
            assert!(!exists());
            old.shutdown().await;
            println!("PASS older Core refuses system DNS before TUN Start or resolver mutation");
            return;
        }
        if let Some(dir) = std::env::args().nth(1) {
            let mut e = Engine::open(Path::new(&dir), &core).unwrap();
            let id = e.store.library.selected.clone().unwrap();
            e.connect(&id).await.unwrap();
            std::fs::write(Path::new(&dir).join("ready"), "ready").unwrap();
            std::future::pending::<()>().await;
            return;
        }
        ip(&["link", "set", "lo", "up"]);
        ip(&["link", "add", "uplink", "type", "dummy"]);
        ip(&["addr", "add", "192.0.2.53/24", "dev", "uplink"]);
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
        let udp_count = Arc::new(AtomicUsize::new(0));
        let tcp_count = Arc::new(AtomicUsize::new(0));
        let udp = tokio::net::UdpSocket::bind("192.0.2.53:53").await.unwrap();
        let count = udp_count.clone();
        let udp_task = tokio::spawn(async move {
            loop {
                let mut q = [0; 4096];
                let (n, p) = udp.recv_from(&mut q).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                udp.send_to(&response(&q[..n]), p).await.unwrap();
            }
        });
        let tcp = tokio::net::TcpListener::bind("192.0.2.53:53")
            .await
            .unwrap();
        let count = tcp_count.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                let (mut s, _) = tcp.accept().await.unwrap();
                let count = count.clone();
                tokio::spawn(async move {
                    while let Ok(n) = s.read_u16().await {
                        let mut q = vec![0; n as usize];
                        s.read_exact(&mut q).await.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let r = response(&q);
                        s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
                        s.write_all(&r).await.unwrap();
                    }
                });
            }
        });
        let mut resolved = resolver().await;
        let physical = run("resolvectl", &["dns", "uplink"]);
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), &core).unwrap();
        let mut p = e.store.library.preferences.clone();
        p.connection_mode = ConnectionMode::Tun;
        p.tun.ipv6 = true;
        p.tun.system_dns = SystemDns::Resolved;
        p.inbound_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        e.preferences(p.clone()).unwrap();
        let id = e
            .save_profile(ProfileDraft {
                id: None,
                name: "System DNS fixture".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"direct"}),
                vpn_policy: Default::default(),
            })
            .unwrap();
        let legacy = exe.parent().unwrap().join("legacy/Thronium");
        if legacy.exists() {
            assert!(Command::new(legacy)
                .arg("--legacy-capability")
                .status()
                .unwrap()
                .success());
            assert!(!exists());
            assert_eq!(rules(), baseline);
        }
        let mut routing = e.routing();
        routing.profiles[0].dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"192.0.2.53"}],"final":"dns-direct"});
        e.save_routing(routing).unwrap();
        for (n, stack) in [Stack::Gvisor, Stack::System, Stack::Mixed]
            .into_iter()
            .enumerate()
        {
            p.tun.stack = stack;
            e.preferences(p.clone()).unwrap();
            if let Err(err) = e.connect(&id).await {
                for entry in e.logs.view(Default::default()).unwrap().entries {
                    eprintln!("{}", entry.text);
                }
                panic!("DNS Start {err}");
            }
            let policy = run("resolvectl", &["dns", "thronium-tun"]);
            assert!(policy.contains("172.19.0.2") && policy.contains("fdfe:dcba:9876::2"));
            assert!(run("resolvectl", &["domain", "thronium-tun"]).contains("~."));
            query(false, false, n as u32 * 2).await;
            query(true, true, n as u32 * 2 + 1).await;
            clean(&mut e, &baseline, &physical).await;
            println!("PASS {stack:?}: actual resolved UDP A and TCP AAAA through managed TUN; per-link cleanup preserves physical DNS");
        }
        p.tun.stack = Stack::Gvisor;
        e.preferences(p.clone()).unwrap();
        e.connect(&id).await.unwrap();
        let supervisor = child(std::process::id());
        let old = child(supervisor);
        assert_eq!(unsafe { libc::kill(old as i32, libc::SIGKILL) }, 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        connected(&mut e).await;
        assert_ne!(child(supervisor), old);
        query(false, false, 10).await;
        println!("PASS killed worker restores the exact system DNS policy and real resolution");
        drop(resolved);
        resolved = resolver().await;
        let old = child(supervisor);
        tokio::time::sleep(Duration::from_secs(7)).await;
        connected(&mut e).await;
        assert_ne!(child(supervisor), old);
        query(true, true, 11).await;
        println!("PASS resolved service restart invalidates its old owner and restores resolution with a new worker");
        clean(&mut e, &baseline, &physical).await;
        let mut r = e.routing();
        r.profiles[0].dns = json!({"servers":[{"type":"tcp","tag":"dns-direct","server":"192.0.2.53"}],"final":"dns-direct"});
        e.save_routing(r).unwrap();
        e.connect(&id).await.unwrap();
        let before = tcp_count.load(Ordering::SeqCst);
        query(false, false, 12).await;
        assert!(tcp_count.load(Ordering::SeqCst) > before);
        let library = dir.path().join("library.json");
        let backup = dir.path().join("library.saved");
        std::fs::rename(&library, &backup).unwrap();
        std::fs::create_dir(&library).unwrap();
        let switched = e.connect(&id).await;
        std::fs::remove_dir(&library).unwrap();
        std::fs::rename(&backup, &library).unwrap();
        assert_eq!(switched.unwrap_err(), "connection_restored");
        query(true, true, 15).await;
        println!(
            "PASS post-Start persistence failure restores previous TUN DNS and actual resolution"
        );
        clean(&mut e, &baseline, &physical).await;
        println!("PASS client DNS transport rules select actual upstream TCP");
        let mut r = e.routing();
        r.profiles[0].dns =
            json!({"servers":[{"type":"local","tag":"dns-direct"}],"final":"dns-direct"});
        e.save_routing(r).unwrap();
        e.connect(&id).await.unwrap();
        let before = udp_count.load(Ordering::SeqCst);
        query(false, false, 13).await;
        assert!(udp_count.load(Ordering::SeqCst) > before);
        clean(&mut e, &baseline, &physical).await;
        println!("PASS local DNS uses the physical resolver without recursing into its TUN policy");
        e.shutdown().await;
        drop(e);
        let mut gui = Command::new(&exe).arg(dir.path()).spawn().unwrap();
        for _ in 0..200 {
            if dir.path().join("ready").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dir.path().join("ready").exists());
        query(false, false, 14).await;
        gui.kill().unwrap();
        gui.wait().unwrap();
        for _ in 0..200 {
            if !exists()
                && rules() == baseline
                && std::fs::read_dir("/run/thronium-tun")
                    .unwrap()
                    .next()
                    .is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!exists());
        assert_eq!(rules(), baseline);
        assert_eq!(run("resolvectl", &["dns", "uplink"]), physical);
        println!("PASS GUI SIGKILL closes supervised TUN and its resolved policy without another application start");
        // Journal recovery must reap a frozen worker after the supervisor dies.
        std::fs::remove_file(dir.path().join("ready")).unwrap();
        let mut gui = Command::new(&exe).arg(dir.path()).spawn().unwrap();
        for _ in 0..200 {
            if dir.path().join("ready").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dir.path().join("ready").exists());
        let helper = child(gui.id());
        let worker = child(helper);
        assert_eq!(unsafe { libc::kill(worker as i32, libc::SIGSTOP) }, 0);
        assert_eq!(unsafe { libc::kill(helper as i32, libc::SIGKILL) }, 0);
        gui.kill().unwrap();
        gui.wait().unwrap();
        let mut restored = Engine::open(dir.path(), &core).unwrap();
        restored.connect(&id).await.unwrap();
        query(false, false, 16).await;
        clean(&mut restored, &baseline, &physical).await;
        restored.shutdown().await;
        println!(
            "PASS supervisor SIGKILL with a frozen worker recovers its DNS journal and reconnects"
        );
        println!(
            "COUNTS upstream UDP={} TCP={}",
            udp_count.load(Ordering::SeqCst),
            tcp_count.load(Ordering::SeqCst)
        );
        drop(resolved);
        udp_task.abort();
        tcp_task.abort();
        let _ = udp_task.await;
        let _ = tcp_task.await;
    }
}
#[tokio::main]
async fn main() {
    #[cfg(target_os = "linux")]
    linux::main().await;
}
