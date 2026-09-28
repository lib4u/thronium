//! Imported Qt route/DNS policies exercised with real loopback-only packet flow.
use serde_json::json;
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
use thronium_engine::{
    legacy_backup::{
        self, Parts, SourceArchive, SourceDatabase, SourceGroup, SourceProfile, SourceRoute,
        SourceRule, SourceSetting, SourceValue,
    },
    routing::RoutingProfile,
    settings, Engine,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{timeout, Duration},
};
type Result<T> = std::result::Result<T, String>;
#[derive(Default)]
struct Seen {
    exits: [usize; 2],
    targets: usize,
    dns: Vec<(String, String)>,
}
type Observations = Arc<Mutex<Seen>>;
fn io_error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn text(value: impl Into<String>) -> SourceValue {
    SourceValue::Text(value.into())
}
fn number(value: i64) -> SourceValue {
    SourceValue::Integer(value)
}
fn counters(seen: &Observations) -> ([usize; 2], usize) {
    let s = seen.lock().unwrap();
    (s.exits, s.targets)
}
fn unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn dns_answer(query: &[u8], transport: &str, seen: &Observations) -> io::Result<Vec<u8>> {
    if query.len() < 17 || query[2] & 0x80 != 0 || query[4..6] != [0, 1] {
        return Err(io::Error::other("invalid fixture DNS query"));
    }
    let mut end = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query
            .get(end)
            .ok_or_else(|| io::Error::other("short DNS"))? as usize;
        end += 1;
        if len == 0 {
            break;
        }
        if len > 63 || end + len > query.len() {
            return Err(io::Error::other("invalid DNS label"));
        }
        labels.push(
            std::str::from_utf8(&query[end..end + len])
                .map_err(io::Error::other)?
                .to_owned(),
        );
        end += len;
    }
    if end + 4 > query.len() {
        return Err(io::Error::other("short DNS question"));
    }
    let domain = labels.join(".");
    if !domain.ends_with(".fixture.invalid") {
        return Err(io::Error::other("DNS outside fixture"));
    }
    let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
    end += 4;
    seen.lock().unwrap().dns.push((transport.into(), domain));
    let mut response = query[..end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..12].fill(0);
    if qtype == 1 {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    }
    Ok(response)
}
async fn dns_fixtures(seen: Observations) -> (u16, u16, Vec<tokio::task::JoinHandle<()>>) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let udp_seen = seen.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
            assert!(peer.ip().is_loopback());
            if let Ok(response) = dns_answer(&buf[..len], "udp", &udp_seen) {
                let _ = udp.send_to(&response, peer).await;
            }
        }
    });
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, peer) = tcp.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            let seen = seen.clone();
            tokio::spawn(async move {
                let result: io::Result<()> = async {
                    loop {
                        let length = stream.read_u16().await? as usize;
                        if length > 4096 {
                            return Err(io::Error::other("large DNS query"));
                        }
                        let mut query = vec![0; length];
                        stream.read_exact(&mut query).await?;
                        let answer = dns_answer(&query, "tcp", &seen)?;
                        stream.write_u16(answer.len() as u16).await?;
                        stream.write_all(&answer).await?;
                    }
                }
                .await;
                let _ = result;
            });
        }
    });
    (udp_port, tcp_port, vec![udp_task, tcp_task])
}
async fn socks(
    index: usize,
    target: u16,
    seen: Observations,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            let seen = seen.clone();
            tokio::spawn(async move {
                let result: io::Result<()> = async {
                    let mut hello = [0; 2];
                    client.read_exact(&mut hello).await?;
                    if hello[0] != 5 {
                        return Err(io::Error::other("not SOCKS5"));
                    }
                    let mut methods = vec![0; hello[1] as usize];
                    client.read_exact(&mut methods).await?;
                    client.write_all(&[5, 0]).await?;
                    let mut header = [0; 4];
                    client.read_exact(&mut header).await?;
                    if header[..3] != [5, 1, 0] {
                        return Err(io::Error::other("not CONNECT"));
                    }
                    match header[3] {
                        1 => {
                            let mut address = [0; 4];
                            client.read_exact(&mut address).await?;
                            if address != [127, 0, 0, 1] {
                                return Err(io::Error::other("nonlocal SOCKS address"));
                            }
                        }
                        3 => {
                            let length = client.read_u8().await? as usize;
                            let mut address = vec![0; length];
                            client.read_exact(&mut address).await?;
                            if !String::from_utf8_lossy(&address).ends_with(".fixture.invalid") {
                                return Err(io::Error::other("nonfixture SOCKS domain"));
                            }
                        }
                        _ => return Err(io::Error::other("unsupported fixture address")),
                    }
                    if client.read_u16().await? != target {
                        return Err(io::Error::other("nonfixture SOCKS port"));
                    }
                    seen.lock().unwrap().exits[index] += 1;
                    let mut upstream = TcpStream::connect(("127.0.0.1", target)).await?;
                    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok(())
                }
                .await;
                let _ = result;
            });
        }
    });
    (port, task)
}
async fn tunnel(proxy: u16, domain: &str, target: u16) -> Result<TcpStream> {
    let mut socket = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(io_error)?;
    socket
        .write_all(
            format!("CONNECT {domain}:{target} HTTP/1.1\r\nHost: {domain}:{target}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .map_err(io_error)?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(4), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(socket.read_u8().await?);
            if response.len() > 8192 {
                return Err(io::Error::other("large CONNECT response"));
            }
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| "CONNECT timeout")?
    .map_err(io_error)?;
    if !response.starts_with(b"HTTP/1.1 200") {
        return Err("CONNECT rejected".into());
    }
    Ok(socket)
}
async fn echo(socket: &mut TcpStream, message: &str) -> Result<()> {
    socket
        .write_all(message.as_bytes())
        .await
        .map_err(io_error)?;
    let mut response = vec![0; message.len()];
    timeout(Duration::from_secs(4), socket.read_exact(&mut response))
        .await
        .map_err(|_| "echo timeout")?
        .map_err(io_error)?;
    if response != message.as_bytes() {
        return Err("echo differs".into());
    }
    Ok(())
}
async fn probe(
    proxy: u16,
    target: u16,
    name: &str,
    exit: Option<usize>,
    seen: &Observations,
) -> Result<TcpStream> {
    let before = counters(seen);
    let mut socket = tunnel(proxy, name, target).await?;
    echo(&mut socket, name).await?;
    let after = counters(seen);
    let mut expected = before.0;
    if let Some(index) = exit {
        expected[index] += 1;
    }
    assert_eq!(
        after,
        (expected, before.1 + 1),
        "wrong packet path for {name}"
    );
    Ok(socket)
}
async fn rejected(proxy: u16, target: u16, name: &str, seen: &Observations) -> Result<()> {
    let before = counters(seen);
    let result = match tunnel(proxy, name, target).await {
        Ok(mut socket) => echo(&mut socket, "must-not-reach-target").await,
        Err(e) => Err(e),
    };
    assert!(result.is_err(), "rejected route reached echo");
    assert_eq!(counters(seen), before);
    Ok(())
}
fn source(ports: [u16; 2], udp: u16, tcp: u16) -> SourceArchive {
    let profiles=ports.into_iter().enumerate().map(|(i,port)|SourceProfile{id:i as i64+11,group_id:8,kind:"socks".into(),name:Some(format!("Synthetic exit {i}")),outbound:json!({"type":"socks","tag":format!("Synthetic exit {i}"),"server":"127.0.0.1","server_port":port,"version":"5"}),columns:BTreeMap::new()}).collect();
    let dns = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":udp},{"type":"tcp","tag":"dns-tcp","server":"127.0.0.1","server_port":tcp}],"rules":[{"domain":["priority.nested.fixture.invalid"],"server":"dns-tcp"},{"domain_suffix":["nested.fixture.invalid"],"server":"dns-direct"}],"final":"dns-direct","strategy":"ipv4_only","disable_cache":true});
    let settings = vec![
        ("use_dns_object", "true".into()),
        ("dns_object", dns.to_string()),
        ("domain_strategy", "ipv4_only".into()),
        ("outbound_domain_strategy", "ipv4_only".into()),
    ]
    .into_iter()
    .map(|(key, value)| SourceSetting {
        key: key.into(),
        value,
        columns: BTreeMap::new(),
    })
    .collect();
    let rules = [
        ("direct.fixture.invalid", -2),
        ("aux.fixture.invalid", 12),
        ("reject.fixture.invalid", -3),
    ]
    .into_iter()
    .enumerate()
    .map(|(order, (domain, target))| SourceRule {
        route_id: 1,
        order: order as i64,
        kind: 0,
        columns: BTreeMap::from([
            ("domain_json".into(), text(json!([domain]).to_string())),
            ("outbound_id".into(), number(target)),
        ]),
    })
    .collect();
    let raw = json!({"rules":[{"action":"resolve","strategy":"ipv4_only"},{"domain":["blocked.nested.fixture.invalid"],"action":"reject"},{"type":"logical","mode":"and","rules":[{"domain_suffix":["nested.fixture.invalid"]},{"type":"logical","mode":"or","rules":[{"domain":["aux.nested.fixture.invalid"]},{"domain_keyword":["alternate"]}]}],"outbound":12},{"type":"logical","mode":"and","rules":[{"domain_suffix":["nested.fixture.invalid"]},{"domain":["proxy.nested.fixture.invalid"],"invert":true}],"outbound":-2},{"domain":["priority.nested.fixture.invalid"],"outbound":-2}],"final":-1,"find_process":false,"default_domain_resolver":"dns-direct"});
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            profiles: true,
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            profiles,
            groups: vec![SourceGroup {
                id: 8,
                name: "Synthetic imported routes".into(),
                columns: BTreeMap::from([("profiles_json".into(), text("[11,12]"))]),
            }],
            routes: vec![
                SourceRoute {
                    id: 1,
                    name: "Structured imported fixture".into(),
                    columns: BTreeMap::new(),
                },
                SourceRoute {
                    id: 2,
                    name: "Nested imported fixture".into(),
                    columns: BTreeMap::from([
                        ("is_raw".into(), number(1)),
                        ("raw_route".into(), text(raw.to_string())),
                    ]),
                },
            ],
            rules,
            settings,
            ..Default::default()
        }),
    }
}
fn activate(engine: &mut Engine, id: &str) -> Result<()> {
    let mut routing = engine.routing();
    routing.active = id.into();
    engine.save_routing(routing)?;
    Ok(())
}
async fn follow(engine: &mut Engine, enabled: bool) -> Result<()> {
    let field = settings::fields()
        .iter()
        .find(|field| field.id == "enable_dns_routing")
        .unwrap()
        .section
        .clone();
    let old = settings::section(&engine.store.library, &field);
    let mut next = old.clone();
    next["enable_dns_routing"] = json!(enabled);
    engine.save_settings(&field, old, next).await?;
    Ok(())
}
fn expect_guard(result: Result<()>) {
    assert_eq!(result.unwrap_err(), "legacy_routing_dns_follow_conflict");
}

async fn scenario(
    engine: &mut Engine,
    seen: Observations,
    target: u16,
    exits: [u16; 2],
    udp: u16,
    tcp: u16,
) -> Result<()> {
    let source = source(exits, udp, tcp);
    let profiles = legacy_backup::profiles::convert(source.database.as_ref().unwrap())
        .map_err(|e| serde_json::to_string(&e).unwrap())?;
    let route_plan = legacy_backup::routes::convert(&source, Some(&profiles))
        .map_err(|e| serde_json::to_string(&e).unwrap())?;
    let selected = profiles.profile_ids[&11].clone();
    let structured = route_plan.route_ids[&1].clone();
    let nested = route_plan.route_ids[&2].clone();
    let mut library = engine.store.library.clone();
    library.profiles.extend(profiles.profiles);
    library.groups.extend(profiles.groups);
    library.preferences.inbound_port = unused_port();
    library.selected = Some(selected.clone());
    engine.store.commit(library)?;
    let proxy = engine.store.library.preferences.inbound_port;
    let mut routing = engine.routing();
    routing.profiles.extend(route_plan.presets);
    routing.active = structured.clone();
    engine.save_routing(routing)?;
    engine
        .check_routing(engine.routing().active()?.clone())
        .await?;
    engine.connect(&selected).await?;
    probe(proxy, target, "direct.fixture.invalid", None, &seen).await?;
    probe(proxy, target, "proxy.fixture.invalid", Some(0), &seen).await?;
    probe(proxy, target, "aux.fixture.invalid", Some(1), &seen).await?;
    rejected(proxy, target, "reject.fixture.invalid", &seen).await?;
    println!("PASS converted structured direct/proxy/mapped auxiliary/reject routes carry real CONNECT traffic");
    activate(engine, &nested)?;
    engine.apply_routing().await?;
    probe(proxy, target, "aux.nested.fixture.invalid", Some(1), &seen).await?;
    probe(
        proxy,
        target,
        "alternate.nested.fixture.invalid",
        Some(1),
        &seen,
    )
    .await?;
    probe(
        proxy,
        target,
        "alternate.other.fixture.invalid",
        Some(0),
        &seen,
    )
    .await?;
    probe(proxy, target, "direct.nested.fixture.invalid", None, &seen).await?;
    probe(
        proxy,
        target,
        "proxy.nested.fixture.invalid",
        Some(0),
        &seen,
    )
    .await?;
    rejected(proxy, target, "blocked.nested.fixture.invalid", &seen).await?;
    println!("PASS converted nested AND, both OR branches, invert and first-match reject priority choose distinct packet paths");
    let mut held = probe(
        proxy,
        target,
        "priority.nested.fixture.invalid",
        None,
        &seen,
    )
    .await?;
    {
        let s = seen.lock().unwrap();
        assert!(s
            .dns
            .contains(&("tcp".into(), "priority.nested.fixture.invalid".into())));
        assert!(!s
            .dns
            .contains(&("udp".into(), "priority.nested.fixture.invalid".into())));
        assert!(s
            .dns
            .contains(&("udp".into(), "direct.fixture.invalid".into())));
    }
    println!(
        "PASS ordered imported DNS rules choose local TCP before overlapping UDP suffix, with UDP final fallback"
    );
    let before = engine.settings();
    expect_guard(follow(engine, true).await);
    assert_eq!(engine.settings(), before);
    echo(&mut held, "after-refused-settings").await?;
    println!("PASS conflicting DNS-follow settings are refused atomically while existing CONNECT survives");
    activate(engine, "default")?;
    follow(engine, true).await?;
    activate(engine, &nested)?;
    expect_guard(
        engine
            .check_routing(engine.routing().active()?.clone())
            .await,
    );
    echo(&mut held, "after-refused-check").await?;
    expect_guard(engine.apply_routing().await);
    echo(&mut held, "after-refused-reapply").await?;
    expect_guard(engine.connect(&selected).await);
    echo(&mut held, "after-refused-reconnect").await?;
    assert_eq!(engine.snapshot().running, Some(selected.clone()));
    println!("PASS selecting an imported preset under an existing DNS-follow conflict preserves the live socket through Check/reapply/reconnect refusal");
    follow(engine, false).await?;
    let mut invalid: RoutingProfile = engine.routing().active()?.clone();
    invalid.id = "synthetic-invalid-preset".into();
    invalid.rules[0].config = json!({"domain_regex":["["],"outbound":"direct"});
    let mut routing = engine.routing();
    routing.profiles.push(invalid.clone());
    routing.active = invalid.id.clone();
    engine.save_routing(routing)?;
    echo(&mut held, "after-invalid-preset-selection").await?;
    assert!(engine.check_routing(invalid).await.is_err());
    assert!(engine.apply_routing().await.is_err());
    echo(&mut held, "after-core-invalid-regex-refusal").await?;
    println!("PASS core-invalid regex in the selected saved preset is rejected before the existing CONNECT is interrupted");
    activate(engine, &nested)?;
    engine.apply_routing().await?;
    probe(proxy, target, "aux.nested.fixture.invalid", Some(1), &seen).await?;
    println!("PASS repairing the pending preset allows reconnect and restores the converted auxiliary route");
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let core = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "ThroniumCore.exe"
        } else {
            "ThroniumCore"
        });
    let seen: Observations = Default::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
    let target = listener.local_addr().unwrap().port();
    let target_seen = seen.clone();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut socket, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            target_seen.lock().unwrap().targets += 1;
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let (udp, tcp, mut tasks) = dns_fixtures(seen.clone()).await;
    tasks.push(echo_task);
    let (first, task) = socks(0, target, seen.clone()).await;
    tasks.push(task);
    let (second, task) = socks(1, target, seen.clone()).await;
    tasks.push(task);
    let folder = tempfile::tempdir().map_err(io_error)?;
    let mut engine = Engine::open(folder.path(), &core)?;
    let result = scenario(&mut engine, seen.clone(), target, [first, second], udp, tcp).await;
    engine.shutdown().await;
    for task in tasks {
        task.abort();
    }
    if result.is_ok() {
        let s = seen.lock().unwrap();
        println!(
            "OBSERVATIONS {}",
            json!({"proxyConnects":s.exits[0],"auxiliaryConnects":s.exits[1],"targetConnections":s.targets,"dnsQueries":s.dns,"loopbackOnly":true})
        );
    }
    result
}
