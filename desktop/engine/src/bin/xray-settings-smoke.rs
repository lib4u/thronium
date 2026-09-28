//! Real Xray configuration, forwarding and gRPC statistics in disposable storage.
mod fixtures;
use serde_json::json;
use thronium_engine::{settings, store::ProfileKind, Engine, ProfileDraft};
use tokio::io::AsyncWriteExt;

async fn run(engine: &mut Engine) -> Result<(), String> {
    let api_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api_port = api_listener.local_addr().unwrap().port();
    engine.store.library.settings.extend([
        ("random_inbound_port".into(), json!(true)),
        ("xray_api_enabled".into(), json!(true)),
        ("xray_api_port".into(), json!(api_port)),
        ("xray_policy_enabled".into(), json!(true)),
        ("xray_policy_conn_idle".into(), json!(45)),
        ("xray_policy_buffer_size".into(), json!(256)),
        ("xray_access_log".into(), json!(false)),
        ("xray_dns_log".into(), json!(true)),
        ("xray_log_mask_address".into(), json!("half")),
        ("xray_tcp_fast_open".into(), json!("disabled")),
        ("xray_tcp_keep_alive_idle".into(), json!(30)),
        ("xray_tcp_keep_alive_interval".into(), json!(5)),
        ("xray_tcp_user_timeout".into(), json!(10000)),
    ]);
    let id = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Xray settings fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::XrayOutbound,
        config: json!({"protocol":"freedom","settings":{}}),
    })?;
    let profile = engine.profile(&id)?;
    engine.check(&profile).await?;
    println!("PASS installed core accepts Xray log, policy, TCP and statistics API settings");
    let preview = engine.connection_configuration(&id, false).await?;
    let config = &preview["parts"][1]["config"];
    assert_eq!(config["api"]["listen"], format!("127.0.0.1:{api_port}"));
    assert_eq!(config["policy"]["levels"]["0"]["connIdle"], 45);
    drop(api_listener);
    engine.connect(&id).await?;
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        fixtures::read_http_headers(&mut socket).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nxray-ok")
            .await
            .unwrap();
    });
    let proxy = engine.application_proxy()?.unwrap();
    let response = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(&proxy).unwrap())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(response, "xray-ok");
    server.await.unwrap();
    println!("PASS Xray forwards HTTP with the saved connection limits and TCP options");
    let checker = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("check-xray-api");
    let status = tokio::process::Command::new(checker)
        .arg(api_port.to_string())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("xray_api_check_failed".into());
    }
    let old = settings::section(&engine.store.library, "core");
    let mut next = old.clone();
    next["xray_policy_conn_idle"] = json!(120);
    engine.save_settings("core", old, next).await?;
    assert_eq!(
        engine.connection_configuration(&id, true).await?["parts"][1]["config"]["policy"]["levels"]
            ["0"]["connIdle"],
        45
    );
    assert_eq!(
        engine.connection_configuration(&id, false).await?["parts"][1]["config"]["policy"]
            ["levels"]["0"]["connIdle"],
        120
    );
    engine.connect(&id).await?;
    assert_eq!(
        engine.connection_configuration(&id, true).await?["parts"][1]["config"]["policy"]["levels"]
            ["0"]["connIdle"],
        120
    );
    engine.disconnect().await?;
    assert!(std::net::TcpListener::bind(("127.0.0.1", api_port)).is_ok());
    println!("PASS changes apply after reconnect and disconnect releases the API port");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &exe.parent().unwrap().join("ThroniumCore"))?;
    let result = run(&mut engine).await;
    engine.shutdown().await;
    result
}
