//! Real packets through Qt-derived generated DNS; every socket stays on loopback.
use serde_json::json;
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
use thronium_engine::{
    legacy_backup::{
        routes::{self, generated_dns},
        Parts, SourceArchive, SourceDatabase, SourceRoute, SourceRule, SourceSetting, SourceValue,
    },
    routing::{LegacyRoutingConstraints, RoutingProfile, Rule},
    store::ProfileKind,
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{timeout, Duration},
};
type Result<T> = std::result::Result<T, String>;
#[derive(Default)]
struct Seen {
    queries: Vec<(String, String, u16)>,
}
type Observations = Arc<Mutex<Seen>>;
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn question(query: &[u8]) -> io::Result<(String, u16, usize)> {
    if query.len() < 17 || query[2] & 0x80 != 0 || query[4..6] != [0, 1] {
        return Err(io::Error::other("bad question"));
    }
    let mut pos = 12;
    let mut labels = vec![];
    loop {
        let size = *query
            .get(pos)
            .ok_or_else(|| io::Error::other("short label"))? as usize;
        pos += 1;
        if size == 0 {
            break;
        }
        if size > 63 || pos + size > query.len() {
            return Err(io::Error::other("label bound"));
        }
        labels.push(std::str::from_utf8(&query[pos..pos + size]).map_err(io::Error::other)?);
        pos += size;
    }
    if pos + 4 > query.len() {
        return Err(io::Error::other("short type"));
    }
    let name = labels.join(".");
    if !name.ends_with(".fixture.invalid") {
        return Err(io::Error::other("nonfixture DNS"));
    }
    Ok((
        name,
        u16::from_be_bytes([query[pos], query[pos + 1]]),
        pos + 4,
    ))
}
fn answer(query: &[u8], transport: &str, seen: &Observations) -> io::Result<Vec<u8>> {
    let (name, kind, end) = question(query)?;
    seen.lock()
        .unwrap()
        .queries
        .push((transport.into(), name.clone(), kind));
    let mut response = query[..end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..12].fill(0);
    let data = match kind {
        1 => vec![
            127,
            0,
            0,
            if name == "xray.fixture.invalid" {
                1
            } else if transport == "udp" {
                11
            } else {
                12
            },
        ],
        28 => {
            let mut a = vec![0; 16];
            a[15] = if transport == "udp" { 11 } else { 12 };
            a
        }
        _ => vec![],
    };
    if !data.is_empty() {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend(data)
    }
    Ok(response)
}
async fn fixtures(seen: Observations) -> (u16, u16, Vec<tokio::task::JoinHandle<()>>) {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let up = udp.local_addr().unwrap().port();
    let us = seen.clone();
    let ut = tokio::spawn(async move {
        let mut data = [0; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut data).await.unwrap();
            assert!(peer.ip().is_loopback());
            if let Ok(reply) = answer(&data[..n], "udp", &us) {
                udp.send_to(&reply, peer).await.unwrap();
            }
        }
    });
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tp = tcp.local_addr().unwrap().port();
    let tt = tokio::spawn(async move {
        loop {
            let (mut client, peer) = tcp.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            let seen = seen.clone();
            tokio::spawn(async move {
                let result: io::Result<()> = async {
                    loop {
                        let size = client.read_u16().await? as usize;
                        if size > 4096 {
                            return Err(io::Error::other("DNS bound"));
                        }
                        let mut query = vec![0; size];
                        client.read_exact(&mut query).await?;
                        let response = answer(&query, "tcp", &seen)?;
                        client.write_u16(response.len() as u16).await?;
                        client.write_all(&response).await?;
                    }
                }
                .await;
                let _ = result;
            });
        }
    });
    (up, tp, vec![ut, tt])
}
async fn socks_dns(target: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            tokio::spawn(async move {
                let result: io::Result<()> = async {
                    let mut hello = [0; 2];
                    client.read_exact(&mut hello).await?;
                    if hello[0] != 5 {
                        return Err(io::Error::other("SOCKS hello"));
                    };
                    let mut methods = vec![0; hello[1] as usize];
                    client.read_exact(&mut methods).await?;
                    client.write_all(&[5, 0]).await?;
                    let mut head = [0; 8];
                    client.read_exact(&mut head).await?;
                    if head != [5, 1, 0, 1, 127, 0, 0, 1] || client.read_u16().await? != target {
                        return Err(io::Error::other("nonfixture SOCKS target"));
                    };
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
struct Association {
    _control: TcpStream,
    socket: UdpSocket,
    relay: std::net::SocketAddr,
}
impl Association {
    async fn open(port: u16) -> Result<Self> {
        let mut control = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(error)?;
        control.write_all(&[5, 1, 0]).await.map_err(error)?;
        let mut hello = [0; 2];
        control.read_exact(&mut hello).await.map_err(error)?;
        if hello != [5, 0] {
            return Err("SOCKS auth".into());
        }
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(error)?;
        let mut head = [0; 4];
        control.read_exact(&mut head).await.map_err(error)?;
        if head[..3] != [5, 0, 0] {
            return Err("SOCKS associate".into());
        }
        match head[3] {
            1 => {
                let mut bytes = [0; 4];
                control.read_exact(&mut bytes).await.map_err(error)?;
                if bytes != [0, 0, 0, 0] && bytes != [127, 0, 0, 1] {
                    return Err("nonlocal relay".into());
                }
            }
            4 => {
                let mut bytes = [0; 16];
                control.read_exact(&mut bytes).await.map_err(error)?;
                let ip = std::net::Ipv6Addr::from(bytes);
                if !ip.is_unspecified() && !ip.is_loopback() {
                    return Err("nonlocal relay".into());
                }
            }
            _ => return Err("unknown relay".into()),
        }
        let relay =
            std::net::SocketAddr::from(([127, 0, 0, 1], control.read_u16().await.map_err(error)?));
        let socket = UdpSocket::bind("127.0.0.1:0").await.map_err(error)?;
        Ok(Self {
            _control: control,
            socket,
            relay,
        })
    }
    async fn query(&self, name: &str, kind: u16) -> Result<Vec<u8>> {
        assert!(name.ends_with(".fixture.invalid") || name == "localhost");
        let mut query = vec![0x51, 0x23, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes())
        }
        query.push(0);
        query.extend_from_slice(&kind.to_be_bytes());
        query.extend_from_slice(&[0, 1]);
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1, 0, 53];
        packet.extend(query);
        self.socket
            .send_to(&packet, self.relay)
            .await
            .map_err(error)?;
        let mut response = [0; 4096];
        let (size, peer) = timeout(Duration::from_secs(4), self.socket.recv_from(&mut response))
            .await
            .map_err(|_| "DNS relay timeout")?
            .map_err(error)?;
        if !peer.ip().is_loopback() || size < 22 || response[..3] != [0, 0, 0] {
            return Err("DNS relay response".into());
        }
        let offset = match response[3] {
            1 => 10,
            4 => 22,
            _ => return Err("DNS relay address".into()),
        };
        let dns = response[offset..size].to_vec();
        if dns[..2] != [0x51, 0x23] || dns[2] & 0x80 == 0 {
            return Err("DNS response id".into());
        }
        Ok(dns)
    }
}
fn setting(db: &mut SourceDatabase, key: &str, value: impl Into<String>) {
    db.settings.retain(|s| s.key != key);
    db.settings.push(SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: BTreeMap::new(),
    });
}
fn source(udp: u16, tcp: u16) -> (SourceDatabase, SourceRoute) {
    let route = SourceRoute {
        id: 1,
        name: "Generated DNS fixture".into(),
        columns: BTreeMap::new(),
    };
    let mut db = SourceDatabase::default();
    for (name, value) in [
        ("remote_dns", format!("tcp://127.0.0.1:{tcp}")),
        ("direct_dns", format!("127.0.0.1:{udp}")),
        ("core_box_underlying_dns", format!("127.0.0.1:{udp}")),
        ("dns_final_out", "direct".into()),
        ("dns_disable_cache", "true".into()),
        (
            "dns_predefined_rules",
            json!([
                "127.0.0.21 override.fixture.invalid alias.fixture.invalid",
                "::1 v6.fixture.invalid",
                "127.0.0.22 dual.fixture.invalid",
                "::2 dual.fixture.invalid"
            ])
            .to_string(),
        ),
    ] {
        setting(&mut db, name, value)
    }
    for (order, target, domain) in [
        (0, -2, "direct.fixture.invalid"),
        (1, -1, "remote.fixture.invalid"),
    ] {
        db.rules.push(SourceRule {
            route_id: 1,
            order,
            kind: 0,
            columns: BTreeMap::from([
                ("outbound_id".into(), SourceValue::Integer(target)),
                ("action".into(), SourceValue::Text("route".into())),
                (
                    "domain_json".into(),
                    SourceValue::Text(json!([domain]).to_string()),
                ),
                ("port_json".into(), SourceValue::Text("[\"443\"]".into())),
                ("invert".into(), SourceValue::Integer(1)),
            ]),
        });
    }
    (db, route)
}
fn policy(db: &SourceDatabase, route: &SourceRoute) -> Result<RoutingProfile> {
    let dns = generated_dns::build(db, route, &mut vec![]).map_err(error)?;
    let adaptive =
        dns["servers"].as_array().into_iter().flatten().any(|s| {
            s["tag"] == "dns-remote" && matches!(s["type"].as_str(), Some("udp" | "quic"))
        });
    Ok(RoutingProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name: route.name.clone(),
        mode: "rules".into(),
        rules: vec![
            Rule {
                id: "sniff".into(),
                name: "Sniff".into(),
                enabled: true,
                config: json!({"action":"sniff"}),
                simple: None,
            },
            Rule {
                id: "dns".into(),
                name: "DNS".into(),
                enabled: true,
                config: json!({"protocol":"dns","action":"hijack-dns"}),
                simple: None,
            },
        ],
        route: json!({"final":"direct","default_domain_resolver":{"server":"dns-direct","strategy":generated_dns::direct_strategy(db).map_err(error)?}}),
        dns,
        source: None,
        legacy_constraints: Some(LegacyRoutingConstraints {
            warp_enabled: false,
            version: if adaptive { 4 } else { 2 },
            xray_dns_strategy: Some(generated_dns::xray_strategy(db).map_err(error)?),
            ..Default::default()
        }),
    })
}
async fn activate(
    engine: &mut Engine,
    selected: &str,
    db: &SourceDatabase,
    source: &SourceRoute,
) -> Result<Association> {
    let preset = policy(db, source)?;
    activate_preset(engine, selected, preset).await
}
async fn activate_preset(
    engine: &mut Engine,
    selected: &str,
    preset: RoutingProfile,
) -> Result<Association> {
    engine.check_routing(preset.clone()).await?;
    let mut routing = engine.routing();
    routing.active = preset.id.clone();
    routing.profiles.push(preset);
    engine.save_routing(routing)?;
    engine.connect(selected).await?;
    Association::open(engine.store.library.preferences.inbound_port).await
}
fn response(dns: &[u8], rcode: u8, answers: u16) {
    assert_eq!(dns[3] & 15, rcode);
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), answers)
}
async fn verify(
    association: &Association,
    seen: &Observations,
    name: &str,
    kind: u16,
    transport: Option<&str>,
    rcode: u8,
    answers: u16,
) -> Result<Vec<u8>> {
    let count = seen.lock().unwrap().queries.len();
    let dns = association.query(name, kind).await?;
    response(&dns, rcode, answers);
    tokio::time::sleep(Duration::from_millis(80)).await;
    let observations = seen.lock().unwrap();
    if let Some(expected) = transport {
        let added: Vec<_> = observations.queries[count..]
            .iter()
            .filter(|row| row.1 == name)
            .collect();
        assert!(
            added
                .iter()
                .any(|row| **row == (expected.into(), name.into(), kind)),
            "missing intended query: {added:?}"
        );
        assert!(
            added.iter().all(|row| row.0 == expected && row.1 == name),
            "query escaped intended DNS transport: {added:?}"
        );
    } else {
        assert_eq!(
            observations.queries[count..]
                .iter()
                .filter(|row| row.1 == name)
                .count(),
            0,
            "unexpected upstream query for {name}"
        )
    };
    Ok(dns)
}
async fn scenario(
    engine: &mut Engine,
    seen: &Observations,
    udp: u16,
    tcp: u16,
    socks: u16,
) -> Result<()> {
    let selected = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Loopback DNS direct".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":socks,"version":"5"}),
    })?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    engine.store.library.preferences.inbound_port = port;
    let (mut db, source) = source(udp, tcp);
    let association = activate(engine, &selected, &db, &source).await?;
    verify(
        &association,
        seen,
        "direct.fixture.invalid",
        1,
        Some("udp"),
        0,
        1,
    )
    .await?;
    verify(
        &association,
        seen,
        "remote.fixture.invalid",
        1,
        Some("tcp"),
        0,
        1,
    )
    .await?;
    verify(
        &association,
        seen,
        "fallback.fixture.invalid",
        1,
        Some("udp"),
        0,
        1,
    )
    .await?;
    println!("PASS generated route projection selects direct UDP and remote TCP despite stored port/invert, with direct final fallback");
    let answer = verify(
        &association,
        seen,
        "override.fixture.invalid",
        1,
        None,
        0,
        1,
    )
    .await?;
    assert!(answer.ends_with(&[127, 0, 0, 21]));
    verify(
        &association,
        seen,
        "override.fixture.invalid",
        28,
        None,
        3,
        0,
    )
    .await?;
    verify(&association, seen, "alias.fixture.invalid", 1, None, 0, 1).await?;
    verify(&association, seen, "v6.fixture.invalid", 28, None, 0, 1).await?;
    verify(&association, seen, "v6.fixture.invalid", 1, None, 3, 0).await?;
    verify(&association, seen, "dual.fixture.invalid", 1, None, 0, 1).await?;
    verify(&association, seen, "dual.fixture.invalid", 28, None, 0, 1).await?;
    println!("PASS predefined A/AAAA, aliases and missing-family NXDOMAIN answer without contacting either upstream");
    drop(association);
    setting(&mut db, "direct_dns_disable_ipv6", "true");
    setting(&mut db, "remote_dns_disable_ipv6", "true");
    let association = activate(engine, &selected, &db, &source).await?;
    for name in [
        "direct.fixture.invalid",
        "remote.fixture.invalid",
        "fallback.fixture.invalid",
    ] {
        verify(&association, seen, name, 28, None, 0, 0).await?;
    }
    verify(
        &association,
        seen,
        "remote.fixture.invalid",
        1,
        Some("tcp"),
        0,
        1,
    )
    .await?;
    println!("PASS direct, remote and final AAAA guards return empty answers without falling through or blocking A queries");
    drop(association);
    setting(&mut db, "dns_final_out", "remote");
    setting(&mut db, "direct_dns_disable_ipv6", "false");
    setting(&mut db, "remote_dns_disable_ipv6", "false");
    let association = activate(engine, &selected, &db, &source).await?;
    verify(
        &association,
        seen,
        "fallback.fixture.invalid",
        1,
        Some("tcp"),
        0,
        1,
    )
    .await?;
    verify(
        &association,
        seen,
        "direct.fixture.invalid",
        1,
        Some("udp"),
        0,
        1,
    )
    .await?;
    println!(
        "PASS remote final fallback switches to TCP while the direct DNS exception stays on UDP"
    );
    let original = engine.routing();
    setting(&mut db, "enable_redirect", "true");
    assert_eq!(
        policy(&db, &source).err().unwrap(),
        "legacy_dns_generated_dependency_unsupported"
    );
    assert_eq!(
        serde_json::to_value(engine.routing()).unwrap(),
        serde_json::to_value(original).unwrap()
    );
    verify(
        &association,
        seen,
        "fallback.fixture.invalid",
        1,
        Some("tcp"),
        0,
        1,
    )
    .await?;
    println!("PASS unsupported source dependency rejects before any policy mutation and the same SOCKS UDP association keeps working");
    drop(association);
    setting(&mut db, "enable_redirect", "false");
    setting(&mut db, "remote_dns", format!("127.0.0.1:{udp}"));
    let selected = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Owned direct UDP DNS".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct","udp_fragment":true}),
    })?;
    let association = activate(engine, &selected, &db, &source).await?;
    verify(
        &association,
        seen,
        "remote-udp.fixture.invalid",
        1,
        Some("udp"),
        0,
        1,
    )
    .await?;
    println!("PASS imported remote UDP DNS retains UDP through the selected direct outbound when no Xray path exists");
    drop(association);
    setting(&mut db, "fakedns", "true");
    setting(&mut db, "dns_use_hosts", "true");
    for disable_v6 in [false, true] {
        setting(
            &mut db,
            "fakeip_disable_ipv6",
            if disable_v6 { "true" } else { "false" },
        );
        let association = activate(engine, &selected, &db, &source).await?;
        let v4 = verify(&association, seen, "fake.fixture.invalid", 1, None, 0, 1).await?;
        assert_eq!(v4[v4.len() - 4], 198);
        assert!([18, 19].contains(&v4[v4.len() - 3]));
        let v6 = verify(
            &association,
            seen,
            "fake.fixture.invalid",
            28,
            None,
            0,
            if disable_v6 { 0 } else { 1 },
        )
        .await?;
        if !disable_v6 {
            assert_eq!(&v6[v6.len() - 16..v6.len() - 14], &[0xfc, 0x00]);
        }
        let pinned = verify(
            &association,
            seen,
            "override.fixture.invalid",
            1,
            None,
            0,
            1,
        )
        .await?;
        assert!(pinned.ends_with(&[127, 0, 0, 21]));
        let hosts = verify(&association, seen, "localhost", 1, None, 0, 1).await?;
        assert!(hosts.ends_with(&[127, 0, 0, 1]));
        println!("PASS imported FakeIP v6-disabled={disable_v6}: synthetic answers, hosts and predefined precedence without upstream DNS traffic");
    }
    explicit_dns_packets(engine, seen, udp).await
}
async fn explicit_dns_packets(engine: &mut Engine, seen: &Observations, udp: u16) -> Result<()> {
    let selected = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Owned explicit DNS".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(error)?;
    engine.store.library.preferences.inbound_port = listener.local_addr().map_err(error)?.port();
    drop(listener);
    let (_, source) = source(udp, udp);
    // Exercise the explicit JSON converter too; generated policies use a separate path.
    let dns = json!({"servers":[
        {"tag":"local","type":"local","prefer_go":true},
        {"tag":"hosts","type":"hosts","predefined":{"inline.fixture.invalid":["127.0.0.31","::31"]}},
        {"tag":"fake","type":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},
        {"tag":"dns-direct","type":"udp","server":"127.0.0.1","server_port":udp}
    ],"rules":[
        {"rule_set":"record-sites","query_type":"A","action":"predefined","rcode":"NOERROR","answer":"*. 120 IN A 127.0.0.53","ns":[],"extra":[]},
        {"rule_set":"record-sites","query_type":"AAAA","action":"predefined","answer":[]},
        {"preferred_by":["hosts"],"query_type":["A","AAAA"],"server":"hosts"},
        {"domain":["synthetic.fixture.invalid"],"query_type":["A","AAAA"],"server":"fake"}
    ],"final":"dns-direct","independent_cache":true,"disable_cache":true});
    let mut db = SourceDatabase {
        routes: vec![source],
        ..Default::default()
    };
    db.routes[0]
        .columns
        .insert("is_raw".into(), SourceValue::Integer(1));
    db.routes[0].columns.insert("raw_route".into(), SourceValue::Text(json!({
        "rule_set":[{"type":"inline","tag":"record-sites","rules":[{"domain":["records.fixture.invalid"]}]}],
        "rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}],"final":-2
    }).to_string()));
    setting(&mut db, "use_dns_object", "true");
    setting(&mut db, "dns_object", dns.to_string());
    let archive = SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: Default::default(),
        database: Some(db),
    };
    let mut converted = routes::convert(&archive, None).map_err(|issues| format!("{issues:?}"))?;
    let preset = converted.presets.remove(0);
    assert_eq!(preset.dns, dns);
    let association = activate_preset(engine, &selected, preset).await?;
    let record = verify(&association, seen, "records.fixture.invalid", 1, None, 0, 1).await?;
    assert!(record.ends_with(&[127, 0, 0, 53]));
    verify(
        &association,
        seen,
        "records.fixture.invalid",
        28,
        None,
        0,
        0,
    )
    .await?;
    let a = verify(&association, seen, "inline.fixture.invalid", 1, None, 0, 1).await?;
    assert!(a.ends_with(&[127, 0, 0, 31]));
    let aaaa = verify(&association, seen, "inline.fixture.invalid", 28, None, 0, 1).await?;
    assert!(aaaa.ends_with(&[0, 0x31]));
    let fake = verify(
        &association,
        seen,
        "synthetic.fixture.invalid",
        1,
        None,
        0,
        1,
    )
    .await?;
    assert_eq!(fake[fake.len() - 4], 198);
    verify(
        &association,
        seen,
        "fallback.fixture.invalid",
        1,
        Some("udp"),
        0,
        1,
    )
    .await?;
    println!("PASS explicit local/hosts/FakeIP, imported inline rule-set DNS conditions and predefined RR JSON imports, serves A/AAAA, NODATA and synthetic records, and falls through hosts to owned UDP");
    Ok(())
}
async fn xray_strategy_packets(
    engine: &mut Engine,
    seen: &Observations,
    udp: u16,
    tcp: u16,
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(error)?;
    let port = listener.local_addr().map_err(error)?.port();
    let selected = engine.save_profile(ProfileDraft { vpn_policy: Default::default(),
        id: None, name: "Loopback Xray DNS family".into(), group_id: "personal".into(),
        kind: ProfileKind::XrayOutbound,
        config: json!({"protocol":"vless","settings":{"address":"xray.fixture.invalid","port":port,"id":"00000000-0000-0000-0000-000000000051","encryption":"none"},"streamSettings":{"network":"raw","security":"none"}}),
    })?;
    engine
        .store
        .library
        .preferences
        .vless_overrides
        .insert(selected.clone(), thronium_engine::vless::Core::Xray);
    for (source_strategy, expected) in [("", "UseIPv4"), ("ipv4_only", "ForceIPv4")] {
        let (mut db, source) = source(udp, tcp);
        setting(&mut db, "direct_dns_disable_ipv6", "true");
        setting(&mut db, "outbound_domain_strategy", source_strategy);
        let mut preset = policy(&db, &source)?;
        assert_eq!(
            preset
                .legacy_constraints
                .as_ref()
                .unwrap()
                .xray_dns_strategy
                .as_deref(),
            Some(expected)
        );
        preset.route["final"] = json!("proxy");
        engine.check_routing(preset.clone()).await?;
        let mut routing = engine.routing();
        routing.active = preset.id.clone();
        routing.profiles.push(preset);
        engine.save_routing(routing)?;
        let before = seen.lock().unwrap().queries.len();
        engine.connect(&selected).await?;
        let mut client =
            TcpStream::connect(("127.0.0.1", engine.store.library.preferences.inbound_port))
                .await
                .map_err(error)?;
        client
            .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\nfixture")
            .await
            .map_err(error)?;
        let (mut upstream, peer) = timeout(Duration::from_secs(8), listener.accept())
            .await
            .map_err(error)?
            .map_err(error)?;
        assert!(peer.ip().is_loopback());
        let mut handshake = [0; 17];
        timeout(Duration::from_secs(4), upstream.read_exact(&mut handshake))
            .await
            .map_err(error)?
            .map_err(error)?;
        assert_eq!(handshake[0], 0, "VLESS version");
        assert_eq!(
            handshake[16], 0x51,
            "fixture UUID confirms selected Xray VLESS"
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        let all = seen.lock().unwrap();
        let queries: Vec<_> = all.queries[before..]
            .iter()
            .filter(|q| q.1 == "xray.fixture.invalid")
            .collect();
        assert!(!queries.is_empty(), "Xray server hostname was not resolved");
        assert!(
            queries.iter().all(|q| q.0 == "udp" && q.2 == 1),
            "{expected} server lookup must send A only via direct DNS: {queries:?}"
        );
        drop(all);
        drop(upstream);
        drop(client);
    }
    println!("PASS generated source IPv6 cap reaches Xray UseIPv4 and ForceIPv4 server hostname resolution with actual A-only UDP queries and local VLESS handshakes");
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
    let (udp, tcp, mut tasks) = fixtures(seen.clone()).await;
    let (socks, task) = socks_dns(tcp).await;
    tasks.push(task);
    let folder = tempfile::tempdir().map_err(error)?;
    let mut engine = Engine::open(folder.path(), &core)?;
    let result = async {
        if std::env::args().any(|argument| argument == "--explicit-only") {
            explicit_dns_packets(&mut engine, &seen, udp).await
        } else {
            scenario(&mut engine, &seen, udp, tcp, socks).await?;
            xray_strategy_packets(&mut engine, &seen, udp, tcp).await
        }
    }
    .await;
    engine.shutdown().await;
    for task in tasks {
        task.abort()
    }
    if result.is_ok() {
        println!(
            "OBSERVATIONS {}",
            json!({"queries":seen.lock().unwrap().queries,"loopbackOnly":true,"udpClientViaSocks5":true})
        );
    }
    result
}
