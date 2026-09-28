//! Local HTTP through real multi-hop sing-box/Xray chains; no external servers.
use serde_json::{json, Value};
use thronium_engine::{exports, routing::Rule, store::ProfileKind, Engine, ProfileDraft};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

#[path = "selector-smoke/warp.rs"]
mod warp;

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
    let mut e = Engine::open(dirs[3].path(), &core)?;
    let proxy = port();
    let mut prefs = e.store.library.preferences.clone();
    prefs.inbound_port = proxy;
    e.preferences(prefs)?;
    let mut sing = vec![];
    let mut xray = vec![];
    let node_ports = ports.clone();
    for p in ports {
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

    let unavailable = add(
        &mut e,
        "Unavailable fixture",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":port(),"password":"synthetic-selector-secret"}),
    )?;
    let mut config = json!({"type":"auto-selector","members":[unavailable,sing[0],xray[1]],"url":format!("http://127.0.0.1:{origin_port}/probe"),"interval":"1s","bench_interval":"2s","watch_interval":"500ms","timeout":"500ms","sampling":2,"expected":2,"active_size":3,"concurrency":3,"dial_retries":2,"interrupt_exist_connections":false});
    let id = add(
        &mut e,
        "Automatic fixture",
        ProfileKind::AutoSelector,
        config.clone(),
    )?;
    e.check(&e.profile(&id)?).await?;
    e.connect(&id).await?;
    let ready = wait(&mut e, |g| g["membersAlive"].as_i64().unwrap_or(0) >= 2).await?;
    assert_eq!(ready["membersTotal"], 3);
    assert!(!ready.to_string().contains("synthetic-selector-secret"));
    assert!(ready["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p.get("lastError").is_none()));
    exchange(proxy, origin_port).await?;
    println!("PASS automatic pool finds healthy sing-box/Xray members, rejects an unavailable member and forwards real HTTP");
    let first = thronium_engine::auto_selector::member_tag("proxy", &sing[0]);
    let second = thronium_engine::auto_selector::member_tag("proxy", &xray[1]);
    e.auto_selector_action("proxy", "select", &second).await?;
    wait(&mut e, |g| g["selected"] == second && g["pinned"] == second).await?;
    let before = counts(&mut nodes).await;
    exchange(proxy, origin_port).await?;
    let after = counts(&mut nodes).await;
    assert!(after[1].0 > before[1].0 && after[1].1 > before[1].1);
    println!("PASS pinning chooses the actual Xray member and forwards through its local proxy");
    e.auto_selector_action("proxy", "select", "").await?;
    wait(&mut e, |g| g["pinned"] == "").await?;
    assert!(e
        .auto_selector_action("proxy", "select", "not-a-member")
        .await
        .is_err());
    assert!(e
        .auto_selector_action("proxy", "unknown", "")
        .await
        .is_err());
    let since = e.snapshot().since;
    let rounds = e.auto_selectors().await?[0]["roundsCompleted"]
        .as_i64()
        .unwrap_or(0);
    e.auto_selector_action("proxy", "recheck", "").await?;
    wait(&mut e, |g| {
        g["roundsCompleted"].as_i64().unwrap_or(0) > rounds
    })
    .await?;
    assert_eq!(e.snapshot().since, since);
    exchange(proxy, origin_port).await?;
    println!("PASS release-pin and recheck preserve the running core while invalid actions fail explicitly");
    e.auto_selector_action("proxy", "select", &first).await?;
    wait(&mut e, |g| g["selected"] == first).await?;
    nodes[0].disconnect().await?;
    wait(&mut e, |g| g["selected"] == second && g["pinned"] == first).await?;
    exchange(proxy, origin_port).await?;
    assert_eq!(e.snapshot().since, since);
    println!("PASS an unavailable pinned member fails over to a healthy Xray member without restarting the session");
    let text = e.export_profiles(vec![id.clone()], exports::Format::Profiles)?;
    let mut bundle: Value = serde_json::from_str(&text).unwrap();
    for p in bundle["profiles"].as_array_mut().unwrap() {
        p["groupId"] = json!("personal");
    }
    let index = bundle["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .position(|p| p["kind"] == "auto-selector")
        .unwrap();
    let before = e.store.library.profiles.len();
    e.check_import_profile(
        serde_json::from_value(bundle["profiles"].clone()).unwrap(),
        index,
    )
    .await?;
    assert_eq!(e.store.library.profiles.len(), before);
    assert_eq!(e.snapshot().since, since);
    let imported =
        e.import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())?;
    e.connect(&imported[index]).await?;
    wait(&mut e, |g| g["membersAlive"].as_i64().unwrap_or(0) >= 1).await?;
    exchange(proxy, origin_port).await?;
    println!("PASS portable pool preview and import resolve all member references without saving preview data");
    e.disconnect().await?;
    config["members"] = json!([sing[1], xray[1]]);
    config["balance"] = json!(true);
    config["balance_mode"] = json!("connection");
    config["pinned_profile"] = json!(xray[1]);
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(id.clone()),
        name: "Balanced".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: config.clone(),
    })?;
    e.connect(&id).await?;
    wait(&mut e, |g| {
        g["membersAlive"] == 2
            && g["balance"] == true
            && g["balanceMode"] == "connection"
            && g["pinned"] == second
    })
    .await?;
    exchange(proxy, origin_port).await?;
    e.auto_selector_action("proxy", "select", "").await?;
    for _ in 0..8 {
        exchange(proxy, origin_port).await?;
    }
    println!("PASS connection balancing, saved preferred member and healthy pool forwarding use the upstream core");
    e.disconnect().await?;
    let mut routing = e.routing();
    routing.profiles[0].rules = vec![Rule {
        id: "pool-target".into(),
        name: "Pool target".into(),
        enabled: true,
        simple: None,
        config: json!({"ip_cidr":["127.0.0.0/8"],"action":"route","outbound":format!("profile:{id}")}),
    }];
    e.check_routing(routing.profiles[0].clone()).await?;
    e.save_routing(routing)?;
    e.connect(&unavailable).await?;
    let tag = format!("thronium-route-{id}");
    wait(&mut e, |g| g["tag"] == tag && g["membersAlive"] == 2).await?;
    exchange(proxy, origin_port).await?;
    e.auto_selector_action(
        &tag,
        "select",
        &thronium_engine::auto_selector::member_tag(&tag, &sing[1]),
    )
    .await?;
    exchange(proxy, origin_port).await?;
    println!("PASS routing selects an auxiliary mixed automatic pool and its runtime controls address the correct group");
    warp::run(&mut e, &id, &sing[1]).await?;
    full_member(
        &mut e,
        &mut nodes,
        &node_ports,
        proxy,
        origin_port,
        &sing[1],
    )
    .await?;
    e.shutdown().await;
    for node in &mut nodes {
        node.shutdown().await;
    }
    server.abort();
    Ok(())
}
async fn wait(e: &mut Engine, condition: impl Fn(&Value) -> bool) -> Result<Value, String> {
    for _ in 0..120 {
        let groups = e.auto_selectors().await?;
        if let Some(g) = groups.as_array().unwrap().iter().find(|g| condition(g)) {
            return Ok(g.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "selector status timeout: {}",
        e.auto_selectors().await?
    ))
}

/// A complete Xray configuration is a pool member running as its own instance
/// behind the member tag (Qt parity); selecting it forwards real HTTP through
/// the local proxy that instance dials.
async fn full_member(
    e: &mut Engine,
    nodes: &mut [Engine],
    node_ports: &[u16],
    proxy: u16,
    origin_port: u16,
    sing0: &str,
) -> Result<(), String> {
    if e.snapshot().running.is_some() {
        e.disconnect().await?;
    }
    let mut routing = e.routing();
    routing.profiles[0].rules.clear();
    e.save_routing(routing)?;
    let full = add(
        e,
        "Complete Xray member",
        ProfileKind::XrayConfig,
        json!({"inbounds":[{"tag":"user-in","protocol":"socks","listen":"127.0.0.1","port":1}],
               "outbounds":[{"tag":"exit","protocol":"socks","settings":{"address":"127.0.0.1","port":node_ports[2]}}],
               "routing":{"rules":[{"type":"field","inboundTag":["user-in"],"outboundTag":"exit"}]}}),
    )?;
    let pool = add(
        e,
        "Pool with a complete Xray member",
        ProfileKind::AutoSelector,
        json!({"type":"auto-selector","members":[sing0,full],"url":format!("http://127.0.0.1:{origin_port}/probe"),"interval":"1s","bench_interval":"2s","watch_interval":"500ms","timeout":"500ms","sampling":2,"expected":2,"active_size":2,"concurrency":2,"dial_retries":2,"interrupt_exist_connections":false}),
    )?;
    e.check(&e.profile(&pool)?).await?;
    e.connect(&pool).await?;
    if let Err(error) = wait(e, |g| g["membersAlive"].as_i64().unwrap_or(0) >= 2).await {
        for entry in e.logs.view(Default::default()).unwrap().entries {
            eprintln!("{} [{}] {}", entry.source, entry.level, entry.text);
        }
        return Err(error);
    }
    let view = e.connection_configuration(&pool, true).await?;
    assert!(
        view["parts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "Xray 2"),
        "the complete configuration runs as its own instance"
    );
    // Pin the ordinary member first, then the instance: both directions of the
    // pin change the real forwarding path.
    let ordinary = thronium_engine::auto_selector::member_tag("proxy", sing0);
    e.auto_selector_action("proxy", "select", &ordinary).await?;
    wait(e, |g| g["selected"] == ordinary && g["pinned"] == ordinary).await?;
    let before = counts(nodes).await;
    exchange(proxy, origin_port).await?;
    grew(nodes, 1, &before, "the ordinary member").await?;
    let tag = thronium_engine::auto_selector::member_tag("proxy", &full);
    e.auto_selector_action("proxy", "select", &tag).await?;
    wait(e, |g| g["selected"] == tag && g["pinned"] == tag).await?;
    let before = counts(nodes).await;
    exchange(proxy, origin_port).await?;
    grew(nodes, 2, &before, "the instance's own exit").await?;
    e.disconnect().await?;
    println!("PASS a complete Xray configuration is a pool member with its own instance and forwards real HTTP when selected");
    Ok(())
}

/// EOF at the client can precede the final counter update at the hop; observe
/// it without sending extra traffic.
async fn grew(
    nodes: &mut [Engine],
    index: usize,
    before: &[(i64, i64)],
    what: &str,
) -> Result<(), String> {
    timeout(Duration::from_secs(2), async {
        loop {
            let after = counts(nodes).await;
            if after[index].0 > before[index].0 && after[index].1 > before[index].1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| format!("HTTP did not go through {what} (hop {index})"))
}
