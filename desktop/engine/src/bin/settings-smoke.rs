//! Real-core settings checks. Run renamed to Thronium next to its sidecar.
mod fixtures;
use serde_json::{json, Value};
use thronium_engine::{
    settings,
    store::{Profile, ProfileKind},
    Engine, ProfileDraft,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn profile(config: Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: "check".into(),
        name: "Fixture".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: ProfileKind::SingBoxOutbound,
        config,
    }
}
#[tokio::main]
async fn main() -> Result<(), String> {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &exe.parent().unwrap().join("ThroniumCore"))?;
    let base = e.store.library.clone();
    let trojan = json!({"type":"trojan","server":"127.0.0.1","server_port":443,"password":"fixture","tls":{"enabled":true,"server_name":"example.test"}});
    let fixtures = vec![
        (
            "TLS, mux and certificate defaults",
            trojan.clone(),
            json!({"mux_default_on":true,"mux_padding":true,"skip_cert":true,"utlsFingerprint":"chrome","use_mozilla_certs":true}),
        ),
        (
            "TLS built-in fragmentation",
            trojan.clone(),
            json!({"fragment_default_on":true}),
        ),
        (
            "TLS custom fragmentation",
            trojan.clone(),
            json!({"fragment_default_on":true,"fragment_implementation":"custom"}),
        ),
        (
            "TLS tricks and spoof",
            trojan.clone(),
            json!({"tls_tricks_default_on":true,"tls_spoof_default_on":true,"tls_spoof":"cover.test","tls_spoof_method":"wrong-sequence"}),
        ),
        (
            "HTTP/2 presets",
            json!({"type":"trojan","server":"127.0.0.1","server_port":443,"password":"fixture","tls":{"enabled":true},"transport":{"type":"http"}}),
            json!({"h2_idle_timeout":"20s","h2_keep_alive_period":"5s","h2_stream_receive_window":"1MB","h2_connection_receive_window":"4MB","h2_max_concurrent_streams":10}),
        ),
        (
            "QUIC presets",
            json!({"type":"hysteria2","server":"127.0.0.1","server_port":443,"password":"fixture","tls":{"enabled":true}}),
            json!({"h2_idle_timeout":"20s","h2_keep_alive_period":"5s","h2_stream_receive_window":"1MB","h2_connection_receive_window":"4MB","h2_max_concurrent_streams":10,"quic_initial_packet_size":1200,"quic_disable_path_mtu_discovery":true}),
        ),
        (
            "Clash and sing-box API",
            json!({"type":"direct"}),
            json!({"core_box_clash_enabled":true,"core_box_clash_api_secret":"fixture","core_box_api_enabled":true,"core_box_api_secret":"fixture","core_box_api_dashboard":true}),
        ),
        ("NTP", json!({"type":"direct"}), json!({"enable_ntp":true})),
        (
            "DNS interception",
            json!({"type":"direct"}),
            json!({"enable_dns_server":true,"dns_server_listen_port":15353,"dns_server_rules":["domain:blocked.test"],"core_dns_in_port":15354}),
        ),
        (
            "Redirect",
            json!({"type":"direct"}),
            json!({"enable_redirect":true,"redirect_listen_port":15443}),
        ),
        (
            "WARP endpoint",
            json!({"type":"direct"}),
            json!({"enable_warp":true,"warp_private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","warp_public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","warp_ifc_addrs":["172.16.0.2/32"],"warp_reserved":["1","2","3"]}),
        ),
    ];
    let mut failures = vec![];
    for (name, config, settings) in fixtures {
        e.store.library = base.clone();
        e.store.library.settings.extend(
            settings
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        match e.check(&profile(config)).await {
            Ok(()) => println!("PASS {name}"),
            Err(error) => {
                println!("FAIL {name}: {error}");
                failures.push(name);
            }
        }
    }
    if !failures.is_empty() {
        e.shutdown().await;
        return Err(format!("{} configuration groups failed", failures.len()));
    }
    e.store.library = base;
    let id = e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Loopback".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    e.select(&id)?;
    let initial = settings::section(&e.store.library, "inbound");
    let mut next = initial.clone();
    next["random_inbound_port"] = json!(true);
    next["inbound_auth"] = json!(true);
    next["inbound_user"] = json!("fixture");
    next["inbound_pass"] = json!("secret");
    e.save_settings("inbound", initial, next).await?;
    e.connect(&id).await?;
    let proxy = e.application_proxy()?.unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        fixtures::read_http_headers(&mut socket).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfixture")
            .await
            .unwrap();
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy).unwrap())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .map_err(|_| "authenticated_proxy_failed")?;
    assert_eq!(response.text().await.unwrap(), "fixture");
    server.await.unwrap();
    println!("PASS random port and authenticated proxy forward real loopback HTTP");
    e.disconnect().await?;
    // Speed and direct tests remain on loopback and use an isolated core.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let _ = socket.read(&mut bytes).await;
                let body = vec![b'x'; 65536];
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    let initial = settings::section(&e.store.library, "testing");
    let mut next = initial.clone();
    next["speed_test_mode"] = json!("simple");
    next["simple_dl_url"] = json!(format!("http://{address}/file"));
    next["test_concurrent"] = json!(2);
    e.save_settings("testing", initial, next).await?;
    let (cancel, mut receiver) = tokio::sync::watch::channel(false);
    let result = e.speed_test(&id)?.execute(&mut receiver).await?;
    assert_eq!(result["downloadBytes"], 65536);
    println!("PASS speed test downloads the configured file through the selected profile");
    let result =
        settings::tests_runtime::direct(format!("http://{address}/"), 3000, &mut receiver).await?;
    assert_eq!(result["online"], true);
    println!("PASS direct internet test uses the saved HTTP destination");
    cancel.send(true).unwrap();
    assert_eq!(
        e.speed_test(&id)?.execute(&mut receiver).await.unwrap_err(),
        "probe_cancelled"
    );
    assert_eq!(
        settings::tests_runtime::direct(format!("http://{address}/"), 3000, &mut receiver)
            .await
            .unwrap_err(),
        "probe_cancelled"
    );
    println!("PASS cancelled tests do not launch a core or a request");
    server.abort();
    let backup = e.export_backup()?;
    let expected = e.settings();
    e.store
        .library
        .settings
        .insert("test_concurrent".into(), json!(5));
    let preview = e.preview_backup(&backup)?;
    e.restore_backup(&preview.token)?;
    assert_eq!(expected, e.settings());
    println!("PASS backup restores all categorized settings and preferences");
    e.shutdown().await;
    Ok(())
}
