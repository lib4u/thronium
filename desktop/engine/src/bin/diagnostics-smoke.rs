//! Isolated diagnostics against recording loopback SOCKS/TLS fixtures and the real core.
//! Run with scripts/test_diagnostics_core.py; no public endpoint receives a request.
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
use thronium_engine::{
    settings::{self, tests_runtime::ProfileTest},
    store::ProfileKind,
    subscriptions::GroupDraft,
    Engine, ProfileDraft, Snapshot,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{sleep, timeout},
};

struct Fixture {
    info: Value,
    client: reqwest::Client,
}
impl Fixture {
    async fn state(&self) -> Value {
        let body = self
            .client
            .get(self.info["admin"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str(&body).unwrap()
    }
    async fn configure(&self, value: Value) {
        self.client
            .post(self.info["admin"].as_str().unwrap())
            .header("Content-Type", "application/json")
            .body(value.to_string())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    async fn idle(&self) {
        timeout(Duration::from_secs(5), async {
            loop {
                if self.state().await["active"] == 0 {
                    break;
                }
                sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("diagnostic left fixture sockets open");
    }
    async fn started(&self) {
        timeout(Duration::from_secs(5), async {
            loop {
                if self.state().await["seen"].as_array().unwrap().len() >= 3 {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("diagnostic did not start its proxy chain");
    }
    async fn order(&self, ip: bool) {
        let entries = self.state().await["seen"].as_array().unwrap().clone();
        let ports = self.info["ports"].as_array().unwrap();
        let destination = if ip {
            443
        } else {
            reqwest::Url::parse(self.info["download"].as_str().unwrap())
                .unwrap()
                .port()
                .unwrap()
        };
        // Every connection must traverse front -> server -> landing; permit core retries.
        assert!(!entries.is_empty(), "no proxy traffic recorded");
        assert_eq!(
            entries.len() % 3,
            0,
            "incomplete proxy traversal: {entries:?}"
        );
        for traversal in entries.chunks(3) {
            assert_eq!(traversal[0], json!([0, "127.0.0.1", ports[1]]));
            assert_eq!(traversal[1], json!([1, "127.0.0.1", ports[2]]));
            assert_eq!(traversal[2][0], 2);
            assert_eq!(traversal[2][2], destination);
            assert_eq!(
                traversal[2][1],
                if ip {
                    "api.ip2location.io"
                } else {
                    "127.0.0.1"
                }
            );
        }
    }
}
fn add(
    e: &mut Engine,
    group: &str,
    name: &str,
    kind: ProfileKind,
    config: Value,
) -> Result<String, String> {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: group.into(),
        kind,
        config,
    })
}
fn pass(count: &mut usize, label: &str) {
    *count += 1;
    println!("PASS {label}");
}
async fn execute(test: &ProfileTest) -> Result<Value, String> {
    let (_sender, mut receiver) = watch::channel(false);
    test.execute(&mut receiver).await
}
async fn echo(socket: &mut TcpStream) {
    socket.write_all(b"still-open").await.unwrap();
    let mut response = [0; 10];
    timeout(Duration::from_secs(3), socket.read_exact(&mut response))
        .await
        .expect("active tunnel no longer forwards")
        .unwrap();
    assert_eq!(&response, b"still-open");
}
async fn connected_socket(port: u16) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = socket.split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket
        .write_all(format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut header = Vec::new();
    timeout(Duration::from_secs(3), async {
        while !header.ends_with(b"\r\n\r\n") {
            header.push(socket.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8(header).unwrap().contains(" 200 "));
    echo(&mut socket).await;
    (socket, server)
}
async fn preserved(e: &mut Engine, before: &Snapshot, socket: &mut TcpStream) {
    let after = e.snapshot();
    assert_eq!(after.running, before.running);
    assert_eq!(after.selected, before.selected);
    assert_eq!(after.since, before.since);
    assert_eq!(after.local_proxy, before.local_proxy);
    assert_eq!(after.phase, before.phase);
    assert_eq!(after.error, before.error);
    echo(socket).await;
}
async fn run(e: &mut Engine, fixture: &Fixture) -> Result<usize, String> {
    let mut count = 0;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut preferences = e.store.library.preferences.clone();
    preferences.inbound_port = port;
    preferences.ping.timeout_ms = 3000;
    e.preferences(preferences)?;
    let old = settings::section(&e.store.library, "testing");
    let mut next = old.clone();
    next["speed_test_mode"] = json!("simple");
    next["simple_dl_url"] = fixture.info["download"].clone();
    next["speed_test_timeout_ms"] = json!(3000);
    e.save_settings("testing", old, next).await?;
    let mut route = e.routing();
    route.profiles[0].route["final"] = json!("direct");
    e.save_routing(route)?;
    let active = add(
        e,
        "personal",
        "Active direct",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    )?;
    e.connect(&active).await?;
    let (mut socket, echo_server) = connected_socket(port).await;
    let before = e.snapshot();
    let group = e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        id: None,
        name: "Diagnostic chain".into(),
        subscription: None,
        proxy_chain: None,
    })?;
    let mut sing = Vec::new();
    let mut xray = Vec::new();
    for (i, port) in fixture.info["ports"].as_array().unwrap().iter().enumerate() {
        let owner = if i == 1 { &group } else { "personal" };
        sing.push(add(
            e,
            owner,
            "Sing",
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"127.0.0.1","server_port":port,"version":"5"}),
        )?);
        xray.push(add(
            e,
            owner,
            "Xray",
            ProfileKind::XrayOutbound,
            json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":port}}),
        )?);
    }
    for pattern in ["SSS", "SXS", "XSX"] {
        let hops: Vec<_> = pattern
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c == 'S' {
                    sing[i].clone()
                } else {
                    xray[i].clone()
                }
            })
            .collect();
        e.save_group(serde_json::from_value(json!({"id":group,"name":"Diagnostic chain","proxyChain":{"front":hops[0],"landing":hops[2]}})).unwrap())?;
        for ip in [false, true] {
            fixture.idle().await;
            fixture
                .configure(json!({"clear":true,"ipMode":"ok","downloadMode":"ok"}))
                .await;
            let test = if ip {
                e.ip_test(&hops[1])?
            } else {
                e.speed_test(&hops[1])?
            };
            assert!(e.test_matches(&test));
            let result = execute(&test).await?;
            if ip {
                assert_eq!(
                    result,
                    json!({"ip":"203.0.113.9","countryCode":"JP","provider":"IP2Location"})
                );
            } else {
                assert_eq!(result["downloadBytes"], 8192 * 30);
                assert!(!result["download"].as_str().unwrap_or("").is_empty());
                assert_eq!(result["uploadBytes"], 0);
            }
            fixture.order(ip).await;
            fixture.idle().await;
            preserved(e, &before, &mut socket).await;
            pass(&mut count,&format!("{pattern} {} follows group chain despite global Direct; active socket survives",if ip {"IP"} else {"speed"}));
        }
    }
    let chain = add(
        e,
        &group,
        "Explicit chain",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing[1]]}),
    )?;
    for ip in [false, true] {
        fixture.configure(json!({"clear":true})).await;
        let result = execute(&if ip {
            e.ip_test(&chain)?
        } else {
            e.speed_test(&chain)?
        })
        .await?;
        assert!(result.is_object());
        fixture.order(ip).await;
        fixture.idle().await;
        preserved(e, &before, &mut socket).await;
        pass(
            &mut count,
            &format!(
                "explicit chain supports isolated {} and group wrappers",
                if ip { "IP" } else { "speed" }
            ),
        );
    }
    for (mode, expected) in [
        (
            "ipv6",
            json!({"ip":"2001:db8::9","countryCode":"DE","provider":"IP2Location"}),
        ),
        (
            "unknown",
            json!({"ip":"203.0.113.9","countryCode":null,"provider":"IP2Location"}),
        ),
    ] {
        fixture.configure(json!({"clear":true,"ipMode":mode})).await;
        assert_eq!(execute(&e.ip_test(&sing[1])?).await?, expected);
        fixture.order(true).await;
        fixture.idle().await;
        preserved(e, &before, &mut socket).await;
        pass(&mut count, &format!("IP result accepts {mode} response"));
    }
    for (ip, mode) in [
        (true, "invalid"),
        (true, "oversize"),
        (true, "http-error"),
        (false, "http-error"),
        (false, "truncated"),
        (false, "empty"),
    ] {
        fixture.configure(json!({"clear":true,"ipMode":if ip {mode} else {"ok"},"downloadMode":if ip {"ok"} else {mode}})).await;
        let result = execute(&if ip {
            e.ip_test(&sing[1])?
        } else {
            e.speed_test(&sing[1])?
        })
        .await;
        assert_eq!(
            result.unwrap_err(),
            "probe_failed",
            "unexpected error for {mode}"
        );
        fixture.order(ip).await;
        fixture.idle().await;
        preserved(e, &before, &mut socket).await;
        pass(
            &mut count,
            &format!(
                "{} rejects {mode}; active socket survives and test sockets close",
                if ip { "IP" } else { "speed" }
            ),
        );
    }
    for ip in [false, true] {
        fixture
            .configure(json!({"clear":true,"ipMode":"slow","downloadMode":"slow"}))
            .await;
        let test = if ip {
            e.ip_test(&sing[1])?
        } else {
            e.speed_test(&sing[1])?
        };
        let (sender, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move { test.execute(&mut receiver).await });
        fixture.started().await;
        sender.send(true).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err(),
            "probe_cancelled"
        );
        fixture.order(ip).await;
        fixture.idle().await;
        preserved(e, &before, &mut socket).await;
        pass(
            &mut count,
            &format!(
                "running {} cancels promptly, closes sidecar sockets, keeps active tunnel",
                if ip { "IP" } else { "speed" }
            ),
        );
        fixture.configure(json!({"clear":true})).await;
        let (_sender, mut receiver) = watch::channel(true);
        let test = if ip {
            e.ip_test(&sing[1])?
        } else {
            e.speed_test(&sing[1])?
        };
        assert_eq!(
            test.execute(&mut receiver).await.unwrap_err(),
            "probe_cancelled"
        );
        assert!(fixture.state().await["seen"].as_array().unwrap().is_empty());
        pass(
            &mut count,
            &format!(
                "pre-cancelled {} starts no traffic",
                if ip { "IP" } else { "speed" }
            ),
        );
    }
    fixture
        .configure(json!({"ipMode":"ok","downloadMode":"ok","clear":true}))
        .await;
    let old = settings::section(&e.store.library, "testing");
    let mut next = old.clone();
    next["speed_test_timeout_ms"] = json!(31000);
    e.save_settings("testing", old, next).await?;
    fixture
        .configure(json!({"downloadMode":"long","clear":true}))
        .await;
    let start = std::time::Instant::now();
    let result = execute(&e.speed_test(&sing[1])?).await?;
    assert!(
        start.elapsed() >= Duration::from_secs(30),
        "fixture did not exercise old RPC deadline"
    );
    assert!(result["downloadBytes"].as_u64().unwrap() > 0);
    assert!(!result["download"].as_str().unwrap_or("").is_empty());
    fixture.order(false).await;
    fixture.idle().await;
    preserved(e, &before, &mut socket).await;
    pass(
        &mut count,
        "31-second speed window exceeds old RPC deadline and keeps active tunnel",
    );
    let old = settings::section(&e.store.library, "testing");
    let mut next = old.clone();
    next["speed_test_timeout_ms"] = json!(3000);
    e.save_settings("testing", old, next).await?;
    fixture
        .configure(json!({"downloadMode":"ok","clear":true}))
        .await;
    let speed = e.speed_test(&sing[1])?;
    let ip = e.ip_test(&sing[1])?;
    e.save_group(serde_json::from_value(json!({"id":group,"name":"Diagnostic chain","proxyChain":{"front":sing[0],"landing":sing[2]}})).unwrap())?;
    assert!(!e.test_matches(&speed));
    assert!(!e.test_matches(&ip));
    pass(
        &mut count,
        "changing group wrappers invalidates previously prepared speed and IP results",
    );
    let speed = e.speed_test(&sing[1])?;
    let ip = e.ip_test(&sing[1])?;
    let profile = e.profile(&sing[0])?;
    let mut changed = profile.config.clone();
    changed["username"] = json!("changed-fixture-user");
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(profile.id),
        name: profile.name,
        group_id: profile.group_id,
        kind: profile.kind,
        config: changed,
    })?;
    assert!(!e.test_matches(&speed));
    assert!(!e.test_matches(&ip));
    pass(
        &mut count,
        "changing wrapper credentials invalidates both diagnostic results",
    );
    preserved(e, &before, &mut socket).await;
    drop(socket);
    echo_server.await.unwrap();
    Ok(count)
}
#[tokio::main]
async fn main() -> Result<(), String> {
    let argument = std::env::args().nth(1).ok_or("fixture path required")?;
    let info: Value = serde_json::from_slice(&std::fs::read(argument).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let fixture = Fixture {
        info,
        client: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap(),
    };
    let executable = std::env::current_exe().unwrap();
    let core = executable.parent().unwrap().join(if cfg!(windows) {
        "ThroniumCore.exe"
    } else {
        "ThroniumCore"
    });
    assert!(Path::new(&core).is_file());
    let directory = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(directory.path(), &core)?;
    let result = run(&mut engine, &fixture).await;
    engine.shutdown().await;
    let count = result?;
    fixture.idle().await;
    println!("PASS TOTAL: {count} diagnostics core checks (loopback only)");
    Ok(())
}
