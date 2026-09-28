//! Real sing-box defaults and persistent DNS/FakeIP/rule sets in disposable data.
use serde_json::{json, Value};
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use thronium_engine::{settings, store::ProfileKind, Engine, ProfileDraft};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn question(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    q
}
fn skip_name(packet: &[u8], mut at: usize) -> usize {
    loop {
        let n = packet[at] as usize;
        at += 1;
        if n == 0 {
            return at;
        }
        if n & 0xc0 == 0xc0 {
            return at + 1;
        }
        at += n;
    }
}
async fn lookup(port: u16, name: &str) -> Result<Ipv4Addr, String> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    socket
        .send_to(&question(name), (Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| e.to_string())?;
    let mut packet = [0; 4096];
    let (size, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut packet))
        .await
        .map_err(|_| "dns_timeout")?
        .map_err(|e| e.to_string())?;
    assert!(size > 12 && packet[3] & 15 == 0 && packet[7] > 0);
    let mut at = 12;
    for _ in 0..u16::from_be_bytes([packet[4], packet[5]]) {
        at = skip_name(&packet, at) + 4;
    }
    at = skip_name(&packet, at);
    assert_eq!(&packet[at..at + 2], &[0, 1]);
    assert_eq!(&packet[at + 8..at + 10], &[0, 4]);
    Ok(Ipv4Addr::new(
        packet[at + 10],
        packet[at + 11],
        packet[at + 12],
        packet[at + 13],
    ))
}

async fn run(engine: &mut Engine) -> Result<(), String> {
    let queries = Arc::new(AtomicUsize::new(0));
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let count = queries.clone();
    let dns_task = tokio::spawn(async move {
        let mut packet = [0; 4096];
        loop {
            let (size, peer) = upstream.recv_from(&mut packet).await.unwrap();
            let end = skip_name(&packet, 12) + 4;
            assert!(size >= end);
            count.fetch_add(1, Ordering::SeqCst);
            let mut reply = packet[..end].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[6] = 0;
            reply[7] = 1;
            reply[10] = 0;
            reply[11] = 0;
            reply.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 127, 0, 0, 1]);
            upstream.send_to(&reply, peer).await.unwrap();
        }
    });
    let downloads = Arc::new(AtomicUsize::new(0));
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let count = downloads.clone();
    let http_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = http.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let rules = String::from_utf8_lossy(&request[..n]).contains("/rules.json");
            let body = if rules {
                count.fetch_add(1, Ordering::SeqCst);
                r#"{"version":3,"rules":[{"domain_suffix":["never.invalid"]}]}"#
            } else {
                "singbox-ok"
            };
            let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",body.len());
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let dns_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns_port = dns_reservation.local_addr().unwrap().port();
    let tcp_reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, dns_port)).unwrap();
    let before = settings::section(&engine.store.library, "core");
    let mut next = before.clone();
    for (key, value) in [
        ("core_dns_in_port", json!(dns_port)),
        ("singbox_connect_timeout", json!(12)),
        ("singbox_tcp_fast_open", json!("disabled")),
        ("singbox_tcp_multi_path", json!("disabled")),
        ("singbox_tcp_keep_alive", json!("enabled")),
        ("singbox_tcp_keep_alive_idle", json!(30)),
        ("singbox_tcp_keep_alive_interval", json!(5)),
        ("singbox_udp_fragment", json!("disabled")),
        ("singbox_cache_enabled", json!(true)),
        ("singbox_cache_store_dns", json!(true)),
        ("singbox_cache_store_fakeip", json!(true)),
        ("singbox_mux_limits", json!("connections")),
        ("singbox_mux_max_connections", json!(3)),
        ("singbox_mux_min_streams", json!(5)),
    ] {
        next[key] = value;
    }
    engine.save_settings("core", before, next).await?;
    engine
        .store
        .library
        .settings
        .insert("random_inbound_port".into(), json!(true));
    let mut routing = engine.routing();
    routing.profiles[0].dns = json!({"servers":[
        {"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":upstream_port},
        {"type":"fakeip","tag":"dns-fake","inet4_range":"198.18.0.0/15"}],
        "rules":[{"domain_suffix":["fake.test"],"action":"route","server":"dns-fake"}],
        "final":"dns-direct","strategy":"ipv4_only"});
    routing.profiles[0].route["rule_set"] = json!([{"tag":"fixture","type":"remote","format":"source","url":format!("http://127.0.0.1:{http_port}/rules.json"),"update_interval":"24h"}]);
    engine.save_routing(routing)?;
    let id = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "sing-box cache fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    let profile = engine.profile(&id)?;
    engine.check(&profile).await?;
    let preview = engine.connection_configuration(&id, false).await?;
    let core = &preview["parts"][0]["config"];
    let cache = core["experimental"]["cache_file"]["path"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!std::path::Path::new(&cache).exists());
    let outbound = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert_eq!(outbound["connect_timeout"], "12s");
    assert_eq!(outbound["tcp_keep_alive"], "30s");
    assert_eq!(outbound["tcp_fast_open"], false);
    println!("PASS saved TCP/UDP options pass the real core checker; previews create no cache");
    let mux=engine.save_profile(ProfileDraft { vpn_policy: Default::default(),id:None,name:"Mux validation".into(),group_id:"personal".into(),kind:ProfileKind::SingBoxOutbound,config:json!({"type":"trojan","server":"127.0.0.1","server_port":443,"password":"fixture","multiplex":{"enabled":true}})})?;
    engine.check(&engine.profile(&mux)?).await?;
    let generated = engine.connection_configuration(&mux, false).await?;
    let outbound = generated["parts"][0]["config"]["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert_eq!(outbound["multiplex"]["max_connections"], 3);
    assert!(outbound["multiplex"].get("max_streams").is_none());
    println!("PASS connection-limited Mux passes the real core checker without conflicting stream limits");
    drop(dns_reservation);
    drop(tcp_reservation);
    engine.connect(&id).await?;
    let proxy = engine.application_proxy()?.unwrap();
    let body = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{http_port}/data"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(body, "singbox-ok");
    assert_eq!(
        lookup(dns_port, "cache-fixture.test").await?,
        Ipv4Addr::LOCALHOST
    );
    let fake_a = lookup(dns_port, "a.fake.test").await?;
    let fake_b = lookup(dns_port, "b.fake.test").await?;
    assert_ne!(fake_a, fake_b);
    assert_eq!(fake_a.octets()[0], 198);
    let query_count = queries.load(Ordering::SeqCst);
    let download_count = downloads.load(Ordering::SeqCst);
    assert!(query_count > 0 && download_count > 0);
    println!("PASS real HTTP forwarding, upstream DNS, FakeIP and remote rule-set loading");
    engine.check(&profile).await?;
    let before = settings::section(&engine.store.library, "core");
    let mut next = before.clone();
    next["singbox_connect_timeout"] = json!(18);
    engine.save_settings("core", before, next).await?;
    assert_eq!(
        engine.connection_configuration(&id, true).await?["parts"][0]["config"]["experimental"]
            ["cache_file"]["path"],
        cache
    );
    engine.connect(&id).await?;
    assert_eq!(
        lookup(dns_port, "cache-fixture.test").await?,
        Ipv4Addr::LOCALHOST
    );
    // Ask for the second FakeIP first: a fresh allocator would return A's address.
    assert_eq!(lookup(dns_port, "b.fake.test").await?, fake_b);
    assert_eq!(lookup(dns_port, "a.fake.test").await?, fake_a);
    assert_eq!(queries.load(Ordering::SeqCst), query_count);
    assert_eq!(downloads.load(Ordering::SeqCst), download_count);
    assert!(std::fs::metadata(&cache).unwrap().len() > 0);
    println!("PASS reconnect restores DNS, FakeIP and rule sets without upstream requests or database locks");
    engine.shutdown().await;
    engine.connect(&id).await?;
    assert_eq!(
        lookup(dns_port, "cache-fixture.test").await?,
        Ipv4Addr::LOCALHOST
    );
    assert_eq!(lookup(dns_port, "b.fake.test").await?, fake_b);
    assert_eq!(queries.load(Ordering::SeqCst), query_count);
    assert_eq!(downloads.load(Ordering::SeqCst), download_count);
    println!("PASS persistent data survives termination and restart of the core process");
    engine.disconnect().await?;
    let before = settings::section(&engine.store.library, "core");
    let mut next = before.clone();
    next["singbox_cache_enabled"] = json!(false);
    engine.save_settings("core", before, next).await?;
    engine.connect(&id).await?;
    let current: Value =
        engine.connection_configuration(&id, true).await?["parts"][0]["config"].clone();
    assert!(current["experimental"].get("cache_file").is_none());
    assert_eq!(
        lookup(dns_port, "cache-fixture.test").await?,
        Ipv4Addr::LOCALHOST
    );
    assert!(queries.load(Ordering::SeqCst) > query_count);
    assert!(downloads.load(Ordering::SeqCst) > download_count);
    engine.disconnect().await?;
    println!("PASS disabling the cache restores ordinary loading on the next connection");
    dns_task.abort();
    http_task.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("ThroniumCore");
    let mut engine = Engine::open(dir.path(), &core)?;
    let result = run(&mut engine).await;
    engine.shutdown().await;
    result
}
