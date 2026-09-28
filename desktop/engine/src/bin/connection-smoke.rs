//! Start failures against the real core, using disposable storage and loopback only.
mod fixtures;
use serde_json::{json, Value};
use std::{net::TcpListener, path::Path, time::Duration};
use thronium_engine::{routing::Rule, store::ProfileKind, Engine, ProfileDraft};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn add(engine: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> String {
    engine
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: name.into(),
            group_id: "personal".into(),
            kind,
            config,
        })
        .unwrap()
}

async fn http(port: u16) {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        fixtures::read_http_headers(&mut socket).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrestored")
            .await
            .unwrap();
    });
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    socket
        .write_all(
            format!("GET http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with("restored"));
    server.await.unwrap();
}

async fn run(engine: &mut Engine, dir: &Path, core: &Path) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut preferences = engine.store.library.preferences.clone();
    preferences.inbound_port = port;
    engine.preferences(preferences)?;
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = occupied.local_addr().unwrap().port();
    let bad = add(
        engine,
        "Start failure",
        ProfileKind::SingBoxConfig,
        json!({
            "inbounds":[
                {"type":"mixed", "tag":"partial", "listen":"127.0.0.1", "listen_port":port},
                {"type":"mixed", "tag":"occupied", "listen":"127.0.0.1", "listen_port":busy_port}
            ], "outbounds":[{"type":"direct"}]
        }),
    );
    engine.check(&engine.profile(&bad)?).await?;
    drop(listener);
    let direct = add(
        engine,
        "Direct",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let xray = add(
        engine,
        "Xray",
        ProfileKind::XrayOutbound,
        json!({"protocol":"freedom", "settings":{}}),
    );
    let raw = add(
        engine,
        "Full JSON",
        ProfileKind::SingBoxConfig,
        json!({
            "inbounds":[{"type":"mixed", "listen":"127.0.0.1", "listen_port":port}],
            "outbounds":[{"type":"direct"}]
        }),
    );
    for id in [&direct, &xray, &raw] {
        engine.connect(id).await?;
        http(port).await;
        assert_eq!(
            engine.connect(&bad).await.unwrap_err(),
            "connection_restored"
        );
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.running.as_deref(), Some(id.as_str()));
        assert_eq!(snapshot.selected.as_deref(), Some(id.as_str()));
        assert_eq!(snapshot.error.as_deref(), Some("connection_restored"));
        assert!(snapshot.since.is_some());
        assert!(!snapshot.traffic_available && snapshot.connections.is_empty());
        http(port).await;
        println!(
            "PASS Start failure restores {} and real HTTP forwarding",
            engine.profile(id)?.name
        );
    }

    engine.connect(&direct).await?;
    let invalid = add(
        engine,
        "Check failure",
        ProfileKind::SingBoxOutbound,
        json!({"type":"unknown-protocol"}),
    );
    let before = engine.poll().await;
    assert!(engine.connect(&invalid).await.is_err());
    let after = engine.snapshot();
    assert_eq!(after.running, before.running);
    assert_eq!(after.since, before.since);
    http(port).await;
    println!("PASS CheckConfig failure preserves the running session without restart");

    let original_routing = engine.routing();
    let mut next = original_routing.clone();
    next.profiles[0].rules.push(Rule {
        id: "block-new".into(),
        name: "New pending block".into(),
        enabled: true,
        simple: None,
        config: json!({"action":"reject"}),
    });
    engine.save_routing(next)?;
    assert_eq!(
        engine.connect(&bad).await.unwrap_err(),
        "connection_restored"
    );
    assert_eq!(engine.snapshot().routing["pending"], true);
    http(port).await;
    println!("PASS rollback retains the old routing while saved rules stay pending");
    let mut reset = original_routing.clone();
    reset.revision = engine.routing().revision;
    engine.save_routing(reset)?;
    engine.apply_routing().await?;

    // Remote rule sets download at Start, after structural CheckConfig validation.
    let resource = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = resource.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = resource.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });
    let mut next = engine.routing();
    next.profiles[0].route["rule_set"] = json!([{
        "type":"remote", "tag":"missing", "format":"source",
        "url":format!("http://{address}/missing.json"), "download_detour":"direct"
    }]);
    engine.check_routing(next.profiles[0].clone()).await?;
    engine.save_routing(next)?;
    let result = engine.apply_routing().await;
    server.abort();
    assert_eq!(result.unwrap_err(), "connection_restored");
    assert_eq!(engine.snapshot().routing["pending"], true);
    http(port).await;
    println!("PASS failed Apply and reconnect restores the prior working routing");
    let mut reset = original_routing;
    reset.revision = engine.routing().revision;
    engine.save_routing(reset)?;

    // Persisting the new selection is part of a successful switch.
    let library = dir.join("library.json");
    let saved = dir.join("saved-library.json");
    std::fs::rename(&library, &saved).unwrap();
    std::fs::create_dir(&library).unwrap();
    let result = engine.connect(&xray).await;
    std::fs::remove_dir(&library).unwrap();
    std::fs::rename(&saved, &library).unwrap();
    assert_eq!(result.unwrap_err(), "connection_restored");
    assert_eq!(engine.snapshot().running.as_deref(), Some(direct.as_str()));
    assert_eq!(engine.snapshot().selected.as_deref(), Some(direct.as_str()));
    http(port).await;
    println!("PASS a selection write failure rolls back without another library write");

    // The running process still serves CheckConfig, but cannot be relaunched.
    #[cfg(unix)]
    {
        let hidden = core.with_extension("unavailable");
        std::fs::rename(core, &hidden).unwrap();
        let result = engine.connect(&bad).await;
        std::fs::rename(&hidden, core).unwrap();
        assert_eq!(result.unwrap_err(), "connection_restore_failed");
        let snapshot = engine.snapshot();
        assert!(snapshot.running.is_none() && snapshot.since.is_none());
        assert!(!snapshot.traffic_available && snapshot.connections.is_empty());
        assert_eq!(snapshot.error.as_deref(), Some("connection_restore_failed"));
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err());
        println!("PASS a failed recovery reports disconnected and closes partial listeners");
    }
    #[cfg(not(unix))]
    let _ = core;
    engine.connect(&xray).await?;
    assert!(engine.snapshot().error.is_none());
    http(port).await;
    engine.disconnect().await?;
    assert!(engine.connect(&bad).await.is_err());
    assert!(engine.snapshot().running.is_none());
    assert_ne!(
        engine.snapshot().error.as_deref(),
        Some("connection_restored")
    );
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err());
    println!(
        "PASS manual retry succeeds; a later disconnected failure never revives an old session"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let exe = std::env::current_exe().unwrap();
    let core = exe.parent().unwrap().join(if cfg!(windows) {
        "ThroniumCore.exe"
    } else {
        "ThroniumCore"
    });
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &core)?;
    let result = run(&mut engine, dir.path(), &core).await;
    engine.shutdown().await;
    result
}
