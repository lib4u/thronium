//! Verify actual dial order through local recording SOCKS servers and the real core.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use thronium_engine::{
    probes, store::ProfileKind, subscriptions::GroupDraft, Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
type Seen = Arc<Mutex<Vec<(usize, u16)>>>;
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
async fn proxy(index: usize, seen: Seen) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let result: std::io::Result<()> = async {
                    let mut header = [0u8; 2];
                    client.read_exact(&mut header).await?;
                    assert_eq!(header[0], 5);
                    let mut methods = vec![0; header[1] as usize];
                    client.read_exact(&mut methods).await?;
                    client.write_all(&[5, 0]).await?;
                    let mut request = [0u8; 4];
                    client.read_exact(&mut request).await?;
                    assert_eq!(&request, [5, 1, 0, 1].as_slice());
                    let mut address = [0u8; 4];
                    client.read_exact(&mut address).await?;
                    assert_eq!(address, [127, 0, 0, 1]);
                    let destination = client.read_u16().await?;
                    seen.lock().unwrap().push((index, destination));
                    let mut upstream = TcpStream::connect(("127.0.0.1", destination)).await?;
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
async fn exchange(proxy: u16, origin: u16) -> Result<(), String> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(format!("GET http://127.0.0.1:{origin}/test HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(5), s.read_to_string(&mut response))
        .await
        .map_err(|_| "HTTP timeout")?
        .map_err(|e| e.to_string())?;
    assert!(response.ends_with("group-chain"));
    Ok(())
}
fn order(seen: &Seen, ports: &[u16], origin: u16) {
    let entries = seen.lock().unwrap();
    for entry in [(0, ports[1]), (1, ports[2]), (2, origin)] {
        assert!(
            entries.contains(&entry),
            "missing {entry:?}, actual {entries:?}"
        );
    }
    assert!(
        entries
            .iter()
            .all(|e| [(0, ports[1]), (1, ports[2]), (2, origin)].contains(e)),
        "unexpected dial: {entries:?}"
    );
}
#[tokio::main]
async fn main() -> Result<(), String> {
    let core = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "ThroniumCore.exe"
        } else {
            "ThroniumCore"
        });
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        loop {
            let (mut s, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _=s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\ngroup-chain").await;
            });
        }
    });
    let seen: Seen = Default::default();
    let mut ports = vec![];
    let mut tasks = vec![];
    for i in 0..3 {
        let (p, t) = proxy(i, seen.clone()).await;
        ports.push(p);
        tasks.push(t);
    }
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &core)?;
    let proxy_port = port();
    let mut prefs = e.store.library.preferences.clone();
    prefs.inbound_port = proxy_port;
    e.preferences(prefs)?;
    let group = e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: None,
        name: "Wrapped".into(),
        subscription: None,
    })?;
    let mut sing = vec![];
    let mut xray = vec![];
    for (i, p) in ports.iter().enumerate() {
        sing.push(add(
            &mut e,
            if i == 1 { &group } else { "personal" },
            "Sing",
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"127.0.0.1","server_port":p,"version":"5"}),
        )?);
        xray.push(add(
            &mut e,
            if i == 1 { &group } else { "personal" },
            "Xray",
            ProfileKind::XrayOutbound,
            json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":p}}),
        )?);
    }
    for pattern in ["SSS", "XXX", "SXS", "XSX"] {
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
        e.save_group(serde_json::from_value(json!({"id":group,"name":"Wrapped","proxyChain":{"front":hops[0],"landing":hops[2]}})).unwrap())?;
        seen.lock().unwrap().clear();
        e.check(&e.profile(&hops[1])?).await?;
        e.connect(&hops[1]).await?;
        exchange(proxy_port, origin_port).await?;
        order(&seen, &ports, origin_port);
        e.disconnect().await?;
        println!("PASS {pattern}: real front -> selected -> landing dial order");
    }
    let full_front = add(
        &mut e,
        "personal",
        "Complete Xray front",
        ProfileKind::XrayConfig,
        json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
               "outbounds":[{"tag":"exit","protocol":"socks","settings":{"address":"127.0.0.1","port":ports[0]}}],
               "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]}}),
    )?;
    e.save_group(serde_json::from_value(json!({"id":group,"name":"Wrapped","proxyChain":{"front":full_front,"landing":sing[2]}})).unwrap())?;
    seen.lock().unwrap().clear();
    e.check(&e.profile(&sing[1])?).await?;
    e.connect(&sing[1]).await?;
    exchange(proxy_port, origin_port).await?;
    order(&seen, &ports, origin_port);
    let view = e.connection_configuration(&sing[1], true).await?;
    assert!(view["parts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "Xray 2"));
    e.disconnect().await?;
    println!("PASS complete Xray front -> selected -> landing dial order through its own instance");
    assert_eq!(
        e.save_group(serde_json::from_value(json!({"id":group,"name":"Wrapped","proxyChain":{"front":sing[0],"landing":full_front}})).unwrap())
            .unwrap_err(),
        "group_chain_hop_unsupported"
    );
    println!("PASS complete Xray configuration is refused as a landing proxy");
    let full_member = add(
        &mut e,
        &group,
        "Complete Xray member",
        ProfileKind::XrayConfig,
        json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
               "outbounds":[{"tag":"exit","protocol":"socks","settings":{"address":"127.0.0.1","port":ports[1]}}],
               "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]}}),
    )?;
    e.save_group(
        serde_json::from_value(
            json!({"id":group,"name":"Wrapped","proxyChain":{"landing":sing[2]}}),
        )
        .unwrap(),
    )?;
    seen.lock().unwrap().clear();
    e.connect(&full_member).await?;
    exchange(proxy_port, origin_port).await?;
    {
        let entries = seen.lock().unwrap();
        assert!(entries.contains(&(1, ports[2])) && entries.contains(&(2, origin_port)));
        assert!(
            entries.iter().all(|e| e.0 != 0),
            "no front proxy: {entries:?}"
        );
    }
    e.disconnect().await?;
    println!("PASS complete Xray member without a front proxy dials the landing proxy from its own instance");
    e.save_group(
        serde_json::from_value(
            json!({"id":group,"name":"Wrapped","proxyChain":{"front":sing[0],"landing":sing[2]}}),
        )
        .unwrap(),
    )?;
    let chain = add(
        &mut e,
        &group,
        "Chain",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing[1]]}),
    )?;
    seen.lock().unwrap().clear();
    e.connect(&chain).await?;
    exchange(proxy_port, origin_port).await?;
    order(&seen, &ports, origin_port);
    println!("PASS group proxies wrap an explicit chain");
    let active = e.snapshot();
    assert_eq!(
        e.save_group(
            serde_json::from_value(json!({"id":group,"name":"Wrapped","proxyChain":{}})).unwrap()
        )
        .unwrap_err(),
        "stop_before_editing"
    );
    let mut run = e.start_url_tests(probes::Options {
        ids: vec![sing[1].clone()],
        url: format!("http://127.0.0.1:{origin_port}/probe"),
        timeout_ms: 3000,
        concurrency: None,
    })?;
    seen.lock().unwrap().clear();
    let probe = e.next_url_test(&run.id).unwrap();
    let result = probe.execute(&mut run.cancelled).await;
    assert!(result.is_ok(), "{result:?}");
    e.finish_url_test(&run.id, &sing[1], result);
    order(&seen, &ports, origin_port);
    assert_eq!(e.snapshot().since, active.since);
    assert_eq!(e.snapshot().running, active.running);
    println!("PASS isolated URL probe follows group proxies and preserves active connection");
    let bad = add(
        &mut e,
        &group,
        "Full JSON",
        ProfileKind::SingBoxConfig,
        json!({"outbounds":[{"type":"direct"}]}),
    )?;
    assert_eq!(
        e.connect(&bad).await.unwrap_err(),
        "group_chain_hop_unsupported"
    );
    assert_eq!(e.snapshot().running, active.running);
    exchange(proxy_port, origin_port).await?;
    println!("PASS incompatible wrapped profile leaves working connection intact");
    e.disconnect().await?;
    let unavailable = add(
        &mut e,
        "personal",
        "Unavailable",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":port()}),
    )?;
    let mut routing = e.routing();
    routing.profiles[0].route["final"] = json!(format!("profile:{}", sing[1]));
    e.save_routing(routing.clone())?;
    seen.lock().unwrap().clear();
    e.connect(&unavailable).await?;
    exchange(proxy_port, origin_port).await?;
    order(&seen, &ports, origin_port);
    e.disconnect().await?;
    println!("PASS auxiliary routing target uses its own group proxies");
    routing = e.routing();
    routing.profiles[0].route["final"] = json!("proxy");
    e.save_routing(routing)?;
    let pool = add(
        &mut e,
        &group,
        "Pool",
        ProfileKind::AutoSelector,
        json!({"type":"auto-selector","members":[sing[1],xray[1]],"pinned_profile":xray[1],"url":format!("http://127.0.0.1:{origin_port}/probe"),"interval":"1s","bench_interval":"1s","watch_interval":"500ms","timeout":"1s","sampling":2,"expected":1,"active_size":2,"concurrency":2}),
    )?;
    seen.lock().unwrap().clear();
    e.connect(&pool).await?;
    timeout(Duration::from_secs(12), async {
        loop {
            let status = e.auto_selectors().await.unwrap();
            if status[0]["membersAlive"].as_i64().unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "selector not ready")?;
    exchange(proxy_port, origin_port).await?;
    order(&seen, &ports, origin_port);
    let status = e.auto_selectors().await?;
    assert_eq!(
        status[0]["pinned"],
        thronium_engine::auto_selector::member_tag("proxy", &xray[1])
    );
    assert!(status[0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["profileId"] == sing[1] || m["profileId"] == xray[1]));
    println!(
        "PASS selector probes and forwarding wrap every member and preserve diagnostic IDs and pin"
    );
    e.shutdown().await;
    server.abort();
    for t in tasks {
        t.abort();
    }
    Ok(())
}
