use super::*;
use crate::{store::ProfileKind, Engine, ProfileDraft};
use serde_json::json;
use std::{os::unix::fs::MetadataExt, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn http(port: u16) {
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut input = [0u8; 4096];
        assert!(stream.read(&mut input).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nretained")
            .await
            .unwrap();
    });
    let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = vec![];
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"retained"));
    server.await.unwrap();
}

fn starts(engine: &Engine) -> usize {
    engine
        .logs
        .view(crate::logs::Filter::default())
        .unwrap()
        .entries
        .iter()
        .filter(|entry| entry.source == "app" && entry.text == "Core process started")
        .count()
}

async fn kill(engine: &mut Engine) {
    let owner = engine.owned_core_process().unwrap();
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/exe", owner.pid)).unwrap(),
        engine.core.canonicalize().unwrap()
    );
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", owner.pid)).unwrap();
    let start = stat[stat.rfind(')').unwrap() + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(Some(start), owner.start_time);
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    assert_eq!(engine.snapshot().phase, "reconnecting");
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; actual owned core with synthetic OS proxy backend"]
async fn actual_core_retains_proxy_and_rejects_lost_ownership_before_and_after_start() {
    const NAME: &str = "system_proxy::tests::real_recovery::actual_core_retains_proxy_and_rejects_lost_ownership_before_and_after_start";
    if std::env::var_os("THRONIUM_RETAINED_PROXY_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let wrapper = tempfile::tempdir().unwrap();
        let exe = wrapper.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::copy(core, wrapper.path().join("ThroniumCore")).unwrap();
        let result = std::process::Command::new(exe)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_RETAINED_PROXY_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        println!("{}", String::from_utf8_lossy(&result.stdout));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let shared = state();
    let original = shared.lock().unwrap().values.clone();
    let mut engine = Engine::open(&dir.path().join("library"), &core).unwrap();
    engine.system_proxy = open(&dir.path().join("proxy"), &shared);
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    engine
        .connection_settings(ConnectionMode::SystemProxy, port)
        .unwrap();
    drop(reserved);
    let id = engine
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Owned system proxy".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();

    engine.connect(&id).await.unwrap();
    http(port).await;
    let request = engine.active_connection.as_ref().unwrap().request.clone();
    let path = engine.system_proxy.path();
    let journal = std::fs::read(&path).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let writes = shared.lock().unwrap().writes;
    kill(&mut engine).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    engine.recovery_tick().await;
    assert_eq!(engine.snapshot().phase, "connected");
    assert_eq!(engine.active_connection.as_ref().unwrap().request, request);
    assert_eq!(
        engine.active_connection.as_ref().unwrap().system_port,
        Some(port)
    );
    assert!(engine.system_proxy.status().active);
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert_eq!(std::fs::read(&path).unwrap(), journal);
    let retained = std::fs::metadata(&path).unwrap();
    assert_eq!(
        (retained.ino(), retained.mtime(), retained.mtime_nsec()),
        (metadata.ino(), metadata.mtime(), metadata.mtime_nsec())
    );
    let competitor = open(&dir.path().join("proxy"), &shared);
    assert_eq!(
        competitor.preflight().err().as_deref(),
        Some("system_proxy_busy")
    );
    http(port).await;
    engine.disconnect().await.unwrap();
    assert_eq!(shared.lock().unwrap().values, original);
    println!("PASS actual HTTP resumes with the same proxy journal and no additional OS writes");

    engine.connect(&id).await.unwrap();
    http(port).await;
    kill(&mut engine).await;
    let writes = shared.lock().unwrap().writes;
    let previous_starts = starts(&engine);
    // This exact read sequence straddles the awaited real Core Start:
    // first read validates the retained lease, second read changes its values.
    {
        let mut s = shared.lock().unwrap();
        s.change_at_read = Some(s.reads + 2);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    engine.recovery_tick().await;
    assert_eq!(starts(&engine), previous_starts + 1);
    assert_eq!(engine.error.as_deref(), Some("core_reconnect_failed"));
    assert!(engine.running.is_none());
    assert!(engine.rpc.is_none());
    assert_eq!(
        engine.system_proxy.status().error.as_deref(),
        Some("system_proxy_changed")
    );
    assert_eq!(
        shared.lock().unwrap().values[0].effective,
        "'outside.proxy.test'"
    );
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(!path.exists());
    assert!(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok());
    println!("PASS ownership loss after actual Start reaps its candidate and preserves outside proxy values");

    shared.lock().unwrap().change_at_read = None;
    engine.connect(&id).await.unwrap();
    http(port).await;
    kill(&mut engine).await;
    let previous_starts = starts(&engine);
    let writes = shared.lock().unwrap().writes;
    shared.lock().unwrap().values[0] = Value {
        effective: "'prestart.proxy.test'".into(),
        user: Some("'prestart.proxy.test'".into()),
    };
    let outside = shared.lock().unwrap().values.clone();
    tokio::time::sleep(Duration::from_millis(200)).await;
    engine.recovery_tick().await;
    assert_eq!(engine.error.as_deref(), Some("core_reconnect_failed"));
    assert_eq!(starts(&engine), previous_starts);
    assert!(engine.rpc.is_none());
    assert_eq!(shared.lock().unwrap().values, outside);
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(!path.exists());
    println!("PASS ownership lost before Start prevents spawning and performs no OS writes");
    engine.shutdown().await;
}
