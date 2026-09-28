//! Execute as Thronium beside ThroniumCore to exercise the real parent check.
use serde_json::json;
use thronium_engine::{store::ProfileKind, Engine, ProfileDraft};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let core = executable.parent().unwrap().join(if cfg!(windows) {
        "ThroniumCore.exe"
    } else {
        "ThroniumCore"
    });
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut engine = Engine::open(directory.path(), &core)?;
    if let Some(path) = std::env::args().nth(1) {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let fixtures: Vec<serde_json::Value> =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let mut failures = Vec::new();
        for fixture in fixtures {
            let profile = thronium_engine::store::Profile {
                vpn_policy: None,
                id: String::new(),
                name: fixture["name"].as_str().unwrap().into(),
                group_id: "personal".into(),
                kind: serde_json::from_value(fixture["kind"].clone()).unwrap(),
                config: fixture["config"].clone(),
                favorite: false,
            };
            // These fixtures exercise each editor's source core. Core selection
            // and cross-core conversion have separate runtime tests.
            engine.store.library.preferences.vless_core =
                if profile.kind == ProfileKind::XrayOutbound {
                    thronium_engine::vless::Core::Xray
                } else {
                    thronium_engine::vless::Core::SingBox
                };
            match engine.check(&profile).await {
                Ok(()) => println!("PASS core validates editor configuration: {}", profile.name),
                Err(error) => failures.push(format!("{}: {}", profile.name, error)),
            }
        }
        engine.shutdown().await;
        return if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n"))
        };
    }
    let port_guard = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = port_guard.local_addr().unwrap().port();
    let mut preferences = engine.store.library.preferences.clone();
    preferences.inbound_port = port;
    engine.preferences(preferences)?;
    drop(port_guard);
    let id = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Loopback smoke".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    assert_eq!(engine.snapshot().phase, "disconnected");
    engine.connect(&id).await?;
    assert_eq!(engine.snapshot().running.as_deref(), Some(id.as_str()));

    send_http(port).await?;
    // Connection-close accounting reaches the tracker asynchronously. Observe
    // the actual counters until they are published instead of assuming the
    // first RPC after HTTP EOF is already up to date.
    let measured = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let snapshot = engine.poll().await;
            if snapshot.traffic_up > 0 && snapshot.traffic_down > 0 {
                break snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("completed HTTP traffic must reach the core counters within two seconds");
    assert!(measured.traffic_up > 0 && measured.traffic_down > 0);
    let repeated = engine.poll().await;
    assert_eq!(
        (measured.traffic_up, measured.traffic_down),
        (repeated.traffic_up, repeated.traffic_down)
    );
    println!("PASS real connection byte counters do not reset or double-count");
    let bad = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Invalid protocol".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"does-not-exist"}),
    })?;
    assert!(engine.connect(&bad).await.is_err());
    assert_eq!(engine.snapshot().running.as_deref(), Some(id.as_str()));
    println!("PASS rejected configuration leaves active connection running");

    // Keep an actual forwarded connection open, then close it by its core ID.
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (_upstream, _) = origin.accept().await.unwrap();
    let mut header = [0; 1024];
    let n = client.read(&mut header).await.unwrap();
    assert!(String::from_utf8_lossy(&header[..n]).contains("200"));
    let live = engine.poll().await;
    let connection = live
        .connections
        .iter()
        .find(|c| c.destination == address.to_string())
        .unwrap();
    assert_eq!(
        engine
            .close_connections(vec![connection.id.clone()])
            .await?,
        1
    );
    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut header))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    println!("PASS QueryConnections reports a live socket and CloseConnections closes it");

    // Xray is embedded in the same Go core; exercise the generated sing-box bridge.
    let xray = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Xray bridge".into(),
        group_id: "personal".into(),
        kind: ProfileKind::XrayOutbound,
        config: json!({"protocol":"freedom", "settings":{}}),
    })?;
    engine.connect(&xray).await?;
    send_http(port).await?;
    println!("PASS real HTTP forwarding through the Xray bridge");
    let raw = engine.save_profile(ProfileDraft { vpn_policy: Default::default(),
        id: None, name: "Opaque full configuration".into(), group_id: "personal".into(),
        kind: ProfileKind::SingBoxConfig,
        config: json!({"inbounds":[{"type":"mixed", "listen":"127.0.0.1", "listen_port":port}], "outbounds":[{"type":"direct"}]}),
    })?;
    engine.connect(&raw).await?;
    let snapshot = engine.poll().await;
    assert_eq!(snapshot.running.as_deref(), Some(raw.as_str()));
    assert!(!snapshot.traffic_available);
    assert_eq!(snapshot.local_proxy, Some(format!("127.0.0.1:{port}")));
    send_http(port).await?;
    println!("PASS complete config keeps its inbound and runs without optional statistics");
    engine.disconnect().await?;
    assert_eq!(engine.snapshot().phase, "disconnected");
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err());
    assert!(engine.snapshot().connections.is_empty());
    engine.shutdown().await;
    drop(engine);
    let mut reopened = Engine::open(directory.path(), &core)?;
    assert_eq!(reopened.snapshot().profiles.len(), 4);
    assert_eq!(reopened.snapshot().phase, "disconnected");
    println!("PASS shutdown closes listener; library survives restart without auto-connect");
    Ok(())
}

async fn send_http(port: u16) -> Result<(), String> {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut data = [0; 4096];
        let n = socket.read(&mut data).await.unwrap();
        assert!(String::from_utf8_lossy(&data[..n]).starts_with("GET /test"));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\nthronium-core-works").await.unwrap();
    });
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    client.write_all(format!("GET http://{address}/test HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|e|e.to_string())?;
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_string(&mut response),
    )
    .await
    .map_err(|_| "origin_timeout")?
    .map_err(|e| e.to_string())?;
    assert!(response.contains("thronium-core-works"));
    server.await.unwrap();
    println!("PASS real HTTP forwarding through ThroneCore");
    Ok(())
}
