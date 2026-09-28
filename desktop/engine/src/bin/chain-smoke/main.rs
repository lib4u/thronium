//! Local HTTP through real multi-hop sing-box/Xray chains; no external servers.
//! With `_THRONIUM_WG_FIXTURE` set, an independent wireguard-go peer proves
//! WireGuard endpoints as chain hops in both positions.
mod vpn;
mod warp_routes;
mod wireguard;
use serde_json::{json, Value};
use thronium_engine::{exports, probes, routing::Rule, store::ProfileKind, Engine, ProfileDraft};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn add(e: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> Result<String, String> {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind,
        config,
    })
}
async fn exchange(proxy: u16, origin: u16) -> Result<(), String> {
    let mut client = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    client.write_all(format!("GET http://127.0.0.1:{origin}/chain HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(4), client.read_to_string(&mut response))
        .await
        .map_err(|_| "chain HTTP timeout")?
        .map_err(|e| e.to_string())?;
    if !response.ends_with("chained") {
        return Err(format!("chain HTTP did not reach origin: {response}"));
    }
    Ok(())
}
async fn counts(nodes: &mut [Engine]) -> Vec<(i64, i64)> {
    let mut result = vec![];
    for node in nodes {
        let s = node.poll().await;
        result.push((s.traffic_up, s.traffic_down));
    }
    result
}
#[tokio::main]
async fn main() -> Result<(), String> {
    let exe = std::env::current_exe().unwrap();
    let core = exe.parent().unwrap().join(if cfg!(windows) {
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
                let mut b = [0; 4096];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nchained",
                    )
                    .await;
            });
        }
    });
    let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut nodes = vec![];
    let mut ports = vec![];
    for dir in &dirs[..3] {
        let mut node = Engine::open(dir.path(), &core)?;
        let p = port();
        let mut prefs = node.store.library.preferences.clone();
        prefs.inbound_port = p;
        node.preferences(prefs)?;
        let id = add(
            &mut node,
            "Local hop",
            ProfileKind::SingBoxOutbound,
            json!({"type":"direct"}),
        )?;
        node.connect(&id).await?;
        nodes.push(node);
        ports.push(p);
    }
    let node_ports = ports.clone();
    let mut e = Engine::open(dirs[3].path(), &core)?;
    let proxy = port();
    let mut prefs = e.store.library.preferences.clone();
    prefs.inbound_port = proxy;
    e.preferences(prefs)?;
    let mut sing = vec![];
    let mut xray = vec![];
    let mut full = vec![];
    for p in ports {
        // The user's inbound tag and rule survive; only the listener is replaced.
        full.push(add(
            &mut e,
            "Complete Xray",
            ProfileKind::XrayConfig,
            json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
                   "outbounds":[{"tag":"exit","protocol":"socks","settings":{"address":"127.0.0.1","port":p}}],
                   "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]}}),
        )?);
        sing.push(add(
            &mut e,
            "sing-box hop",
            ProfileKind::SingBoxOutbound,
            json!({"type":"socks","server":"127.0.0.1","server_port":p,"version":"5"}),
        )?);
        xray.push(add(
            &mut e,
            "Xray hop",
            ProfileKind::XrayOutbound,
            json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":p}}),
        )?);
    }
    if std::env::args().any(|arg| arg == "--vpn-hops") {
        // Only the OpenVPN hop patterns, for iterating on that stand under load.
        let root = std::env::var_os("_THRONIUM_OVPN_FIXTURE").ok_or("OpenVPN fixture required")?;
        let result = vpn::vpn_hops(
            &mut e,
            &mut nodes,
            &node_ports,
            proxy,
            origin_port,
            std::path::Path::new(&root),
        )
        .await;
        e.shutdown().await;
        for node in &mut nodes {
            node.shutdown().await;
        }
        server.abort();
        return result;
    }
    if std::env::args().any(|arg| matches!(arg.as_str(), "--warp-routes" | "--warp-import")) {
        let fixture = std::env::var_os("_THRONIUM_WG_FIXTURE").ok_or("WARP fixture required")?;
        let result = warp_routes::run(&mut e, proxy, &sing[0], origin_port, &fixture).await;
        e.shutdown().await;
        for node in &mut nodes {
            node.shutdown().await;
        }
        server.abort();
        return result;
    }
    for pattern in [
        "SS", "XX", "SX", "XS", "SXS", "XSX", "SXSX", "F", "FS", "FX", "FSX",
    ] {
        // The four-hop case visits the first local proxy twice; F is a complete
        // Xray configuration running as its own instance in front of the chain.
        let hops: Vec<_> = pattern
            .chars()
            .enumerate()
            .map(|(i, c)| match c {
                'S' => sing[i % 3].clone(),
                'X' => xray[i % 3].clone(),
                _ => full[i % 3].clone(),
            })
            .collect();
        let id = add(
            &mut e,
            pattern,
            ProfileKind::Chain,
            json!({"type":"chain","hops":hops}),
        )?;
        e.check(&e.profile(&id)?)
            .await
            .map_err(|err| format!("{pattern} validation: {err}"))?;
        let before = counts(&mut nodes).await;
        e.connect(&id)
            .await
            .map_err(|err| format!("{pattern} start: {err}"))?;
        exchange(proxy, origin_port)
            .await
            .map_err(|err| format!("{pattern}: {err}"))?;
        // EOF at the client can precede the final counter update at an upstream
        // hop. Wait for that observation without sending extra test traffic.
        let after = timeout(Duration::from_secs(2), async {
            loop {
                let after = counts(&mut nodes).await;
                if (0..pattern.len().min(3))
                    .all(|i| after[i].0 > before[i].0 && after[i].1 > before[i].1)
                {
                    break after;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{pattern}: traffic counters did not reach every hop"));
        for i in 0..pattern.len().min(3) {
            assert!(
                after[i].0 > before[i].0 && after[i].1 > before[i].1,
                "{pattern} skipped hop {i}"
            );
        }
        if pattern.starts_with('F') {
            let view = e.connection_configuration(&id, true).await?;
            assert!(
                view["parts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "Xray 2"),
                "{pattern}: the complete configuration runs as its own instance"
            );
        }
        println!("PASS {pattern}: real HTTP and increasing traffic counters at every hop");
    }
    for (pattern, hops, code) in [
        (
            "SF",
            vec![sing[0].clone(), full[1].clone()],
            "chain_full_config_position",
        ),
        (
            "FF",
            vec![full[0].clone(), full[1].clone()],
            "chain_full_config_limit",
        ),
    ] {
        // Reference validation refuses the chain at save time, before any core change.
        let refused = add(
            &mut e,
            pattern,
            ProfileKind::Chain,
            json!({"type":"chain","hops":hops}),
        );
        assert_eq!(refused.unwrap_err(), code, "{pattern}");
        println!("PASS {pattern}: refused with {code} at save time");
    }
    let inner = add(
        &mut e,
        "Inner",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing[0],xray[1]]}),
    )?;
    let outer = add(
        &mut e,
        "Nested",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[inner,sing[2]]}),
    )?;
    e.connect(&outer).await?;
    exchange(proxy, origin_port).await?;
    let since = e.snapshot().since;
    let text = e.export_profiles(vec![outer.clone()], exports::Format::Profiles)?;
    let mut bundle: Value = serde_json::from_str(&text).unwrap();
    for p in bundle["profiles"].as_array_mut().unwrap() {
        p["groupId"] = json!("personal");
    }
    let index = bundle["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .position(|p| p["name"] == "Nested")
        .unwrap();
    let before = e.store.library.profiles.len();
    e.check_import_profile(
        serde_json::from_value(bundle["profiles"].clone()).unwrap(),
        index,
    )
    .await?;
    assert_eq!(e.store.library.profiles.len(), before);
    assert_eq!(e.snapshot().since, since);
    exchange(proxy, origin_port).await?;
    let imported =
        e.import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())?;
    e.connect(&imported[index]).await?;
    exchange(proxy, origin_port).await?;
    println!(
        "PASS nested chain export, isolated preview and import retain forwarding with new IDs"
    );
    let since = e.snapshot().since;
    let mut run = e.start_url_tests(probes::Options {
        ids: vec![outer.clone()],
        url: format!("http://127.0.0.1:{origin_port}/probe"),
        timeout_ms: 2000,
        concurrency: None,
    })?;
    let probe = e.next_url_test(&run.id).unwrap();
    let result = probe.execute(&mut run.cancelled).await;
    assert!(result.is_ok(), "mixed chain URL probe: {result:?}");
    e.finish_url_test(&run.id, &outer, result);
    assert_eq!(e.snapshot().since, since);
    exchange(proxy, origin_port).await?;
    println!(
        "PASS isolated mixed-chain URL probe retains internal bridges and the active connection"
    );
    let unavailable = add(
        &mut e,
        "Unavailable selected",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":port()}),
    )?;
    let mut routing = e.routing();
    routing.profiles[0].rules = vec![Rule {
        id: "chain-target".into(),
        name: "Chain target".into(),
        enabled: true,
        simple: None,
        config: json!({"ip_cidr":["127.0.0.0/8"],"action":"route","outbound":format!("profile:{outer}")}),
    }];
    e.check_routing(routing.profiles[0].clone()).await?;
    e.save_routing(routing)?;
    e.connect(&unavailable).await?;
    let before = counts(&mut nodes).await;
    exchange(proxy, origin_port).await?;
    let after = counts(&mut nodes).await;
    for i in 0..3 {
        assert!(after[i].0 > before[i].0 && after[i].1 > before[i].1);
    }
    println!(
        "PASS auxiliary mixed chain routing visits every hop without looping through global rules"
    );
    e.disconnect().await?;
    // The auxiliary rule above steers loopback destinations away from the
    // selected chain; the WireGuard patterns need the plain final route.
    let mut routing = e.routing();
    routing.profiles[0].rules.clear();
    e.save_routing(routing)?;
    if let Some(fixture) = std::env::var_os("_THRONIUM_WG_FIXTURE") {
        wireguard::wireguard_hops(
            &mut e,
            &mut nodes,
            &node_ports,
            proxy,
            origin_port,
            &fixture,
        )
        .await?;
    }
    if let Some(root) = std::env::var_os("_THRONIUM_OVPN_FIXTURE") {
        vpn::vpn_hops(
            &mut e,
            &mut nodes,
            &node_ports,
            proxy,
            origin_port,
            std::path::Path::new(&root),
        )
        .await?;
    }
    e.shutdown().await;
    for node in &mut nodes {
        node.shutdown().await;
    }
    server.abort();
    Ok(())
}
