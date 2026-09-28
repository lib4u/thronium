use crate::{store::ProfileKind, Engine, ProfileDraft};
use serde_json::json;

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; actual running versus selected validation"]
async fn network_settings_validate_running_profile_and_keep_idle_selected_validation() {
    use base64::Engine as _;
    const NAME:&str="connection::tests::network_settings_validate_running_profile_and_keep_idle_selected_validation";
    if std::env::var_os("THRONIUM_SETTINGS_CONTEXT_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(core, dir.path().join("ThroniumCore")).unwrap();
        let output = std::process::Command::new(executable)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_SETTINGS_CONTEXT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let dir = tempfile::tempdir().unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let mut e = Engine::open(dir.path(), &core).unwrap();
    e.store.library.preferences.inbound_port = port;
    let ordinary = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Active ordinary".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();
    // The selected external profile is checked whole with WARP,
    // its program included: it must exist, though it is never started here.
    let program = dir.path().join("external-core");
    std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let external=e.save_profile(ProfileDraft{ vpn_policy: Default::default(),id:None,name:"Selected external".into(),group_id:"personal".into(),kind:ProfileKind::ExternalCore,
        config:json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":39173,"extra_core_path":program,"extra_core_args":"","extra_core_conf":"","no_logs":true})}).unwrap();
    e.connect(&ordinary).await.unwrap();
    e.select(&external).unwrap();
    let owner = e.owned_core_process().unwrap();
    let request = e.active_connection.as_ref().unwrap().request.clone();
    let previous = crate::settings::section(&e.store.library, "intercept");
    let mut next = previous.clone();
    next["enable_warp"] = json!(true);
    next["warp_private_key"] = json!(base64::engine::general_purpose::STANDARD.encode([1u8; 32]));
    next["warp_public_key"] = json!(base64::engine::general_purpose::STANDARD.encode([2u8; 32]));
    next["warp_ep"] = json!("127.0.0.1:39174");
    next["warp_ifc_addrs"] = json!(["10.66.0.2/32"]);
    e.save_settings("intercept", previous, next).await.unwrap();
    assert_eq!(e.store.library.selected.as_deref(), Some(external.as_str()));
    assert_eq!(e.running.as_deref(), Some(ordinary.as_str()));
    assert_eq!(e.owned_core_process().unwrap(), owner);
    assert_eq!(
        e.active_connection.as_ref().unwrap().request.core_config,
        request.core_config
    );
    assert_eq!(e.snapshot().routing["pending"], true);
    let current = crate::settings::section(&e.store.library, "intercept");
    let mut disabled = current.clone();
    disabled["enable_warp"] = json!(false);
    e.save_settings("intercept", current, disabled)
        .await
        .unwrap();
    e.disconnect().await.unwrap();
    // WARP is what gives a connection through an external core its UDP, so the
    // idle validation of the selected external profile accepts it.
    let previous = crate::settings::section(&e.store.library, "intercept");
    let mut next = previous.clone();
    next["enable_warp"] = json!(true);
    e.save_settings("intercept", previous, next).await.unwrap();
    assert_eq!(
        crate::settings::section(&e.store.library, "intercept")["enable_warp"],
        json!(true)
    );
    e.shutdown().await;
    println!("PASS actual ordinary Check validates WARP despite selected external; WARP over a selected external core is saved");
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; real loopback core Start/rollback"]
async fn failed_adblock_start_restores_old_request_but_keeps_saved_settings_pending() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const NAME:&str="connection::tests::failed_adblock_start_restores_old_request_but_keeps_saved_settings_pending";
    if std::env::var_os("THRONIUM_ROUTING_ROLLBACK_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(core, dir.path().join("ThroniumCore")).unwrap();
        let output = std::process::Command::new(executable)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_ROUTING_ROLLBACK_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let response_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = server.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                seen.fetch_add(1, Ordering::SeqCst);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-srs!").await.unwrap();
            });
        }
    });
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let dir = tempfile::tempdir().unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let mut e = Engine::open(dir.path(), &core).unwrap();
    e.store.library.preferences.inbound_port = port;
    let id = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Local direct".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();
    e.connect(&id).await.unwrap();
    let before = e.active_connection.as_ref().unwrap().request.clone();
    let previous = crate::settings::section(&e.store.library, "intercept");
    let mut next = previous.clone();
    next["adblock_enable"] = json!(true);
    next["adblock_ruleset_url"] = json!(format!("http://127.0.0.1:{server_port}/invalid.srs"));
    e.save_settings("intercept", previous, next).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "CheckConfig must not perform Start's ruleset download"
    );
    assert_eq!(e.snapshot().routing["pending"], true);
    assert_eq!(
        e.apply_routing().await.err().as_deref(),
        Some("connection_restored")
    );
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "failure must reach actual Start"
    );
    assert_eq!(e.running.as_deref(), Some(id.as_str()));
    assert_eq!(
        e.active_connection.as_ref().unwrap().request.core_config,
        before.core_config
    );
    assert!(crate::settings::boolean(&e.store.library, "adblock_enable"));
    assert_eq!(
        e.snapshot().routing["pending"],
        true,
        "saved checkbox must remain visibly unapplied after old request is restored"
    );
    // Restored listener transfers real traffic, not merely a connected snapshot.
    let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client.write_all(format!("GET http://127.0.0.1:{server_port}/echo HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut bytes = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(bytes.ends_with(b"not-srs!"));
    e.shutdown().await;
    response_task.abort();
    println!(
        "PASS actual AdBlock Start failure restores old traffic while saved flag remains pending"
    );
}
