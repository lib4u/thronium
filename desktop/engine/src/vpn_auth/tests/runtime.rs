use super::*;
use crate::{store::ProfileKind, ProfileDraft};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn identity(e: &mut Engine) -> ChallengeRequest {
    let view = e.snapshot().vpn;
    let endpoint = view.endpoints.iter().find(|v| v.tag == "proxy").unwrap();
    ChallengeRequest {
        session_id: view.session_id.unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: endpoint.challenge_id.clone().unwrap(),
    }
}
async fn wait_state(e: &mut Engine, state: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        e.vpn_tick().await;
        if e.snapshot()
            .vpn
            .endpoints
            .iter()
            .any(|v| v.tag == "proxy" && v.state == state)
        {
            return;
        }
        assert!(Instant::now() < deadline, "endpoint state {state}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn profile(e: &mut Engine, kind: ProfileKind, config: serde_json::Value, name: &str) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind,
        config,
    })
    .unwrap()
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE, actual owned userspace OpenVPN/auth and held direct connection"]
async fn actual_openvpn_pending_submit_cancel_full_json_and_session_guards() {
    const TEST:&str="vpn_auth::tests::runtime::actual_openvpn_pending_submit_cancel_full_json_and_session_guards";
    if std::env::var_os("THRONIUM_VPN_AUTH_TEST_CHILD").is_none() {
        let core =
            PathBuf::from(std::env::var_os("THRONIUM_TEST_CORE").expect("preserved core required"));
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            dir.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(core, dir.path().join("ThroniumCore")).unwrap();
        let result = std::process::Command::new(dir.path().join("Thronium"))
            .args(["--ignored", "--exact", TEST, "--nocapture"])
            .env("THRONIUM_VPN_AUTH_TEST_CHILD", "1")
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
    let root = tempfile::tempdir().unwrap();
    let cert = root.path().join("cert.pem");
    let key = root.path().join("key.pem");
    let cert_result = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "1",
            "-subj",
            "/CN=vpn.fixture.invalid",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:vpn.fixture.invalid",
            "-addext",
            "keyUsage=digitalSignature,keyEncipherment,keyCertSign",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .unwrap();
    assert!(cert_result.status.success());
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let outbound = json!({"type":"openvpn-client","server":"127.0.0.1","server_port":sink.local_addr().unwrap().port(),"network":"udp","system":false,"static_challenge":"Synthetic answer","static_challenge_echo":false,"tls":{"certificate_path":cert,"server_name":"vpn.fixture.invalid"}});
    let data = root.path().join("data");
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let mut e = Engine::open(&data, &core).unwrap();
    e.store.library.preferences.inbound_port = port;
    let id = profile(
        &mut e,
        ProfileKind::SingBoxOutbound,
        outbound.clone(),
        "Fixture primary",
    );
    e.check(&e.profile(&id).unwrap()).await.unwrap();
    assert!(e.snapshot().vpn.session_id.is_none());
    e.connect(&id).await.unwrap();
    assert_eq!(e.snapshot().phase, "connecting");
    wait_state(&mut e, "auth-pending").await;
    assert_eq!(e.snapshot().phase, "auth-pending");
    let owned = e.owned_core_process().unwrap();
    let request = identity(&mut e);
    let view = e.vpn_challenge(request.clone()).await.unwrap();
    assert_eq!(view.kind, "credentials");
    assert_eq!(view.message, "Synthetic answer");
    assert!(!view.echo);
    assert_eq!(view.deadline, 0);
    let mut buf = [0u8; 2048];
    assert!(
        sink.try_recv(&mut buf).is_err(),
        "pending must not have dialled UDP"
    );
    let before = serde_json::to_value(&e.store.library).unwrap();
    let mut stale = request.clone();
    stale.challenge_id = "stale".into();
    assert_eq!(
        e.cancel_vpn_challenge(stale).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    e.cancel_vpn_challenge(request.clone()).await.unwrap();
    wait_state(&mut e, "error").await;
    assert_eq!(e.snapshot().phase, "error");
    assert_eq!(e.owned_core_process().unwrap(), owned);
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    e.disconnect().await.unwrap();
    assert!(e.snapshot().vpn.session_id.is_none());
    e.connect(&id).await.unwrap();
    wait_state(&mut e, "auth-pending").await;
    assert_ne!(identity(&mut e).session_id, request.session_id);
    assert_eq!(
        e.vpn_challenge(request).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    let mut secret = outbound.clone();
    secret["username"] = json!("fixture-user");
    secret["password"] = json!("fixture-password");
    let secret_id = profile(
        &mut e,
        ProfileKind::SingBoxOutbound,
        secret,
        "Fixture secret",
    );
    e.connect(&secret_id).await.unwrap();
    wait_state(&mut e, "auth-pending").await;
    let request = identity(&mut e);
    assert_eq!(
        e.vpn_challenge(request.clone()).await.unwrap().kind,
        "secret"
    );
    let before = serde_json::to_value(&e.store.library).unwrap();
    e.submit_vpn_challenge(SubmitRequest {
        session_id: request.session_id,
        endpoint_tag: request.endpoint_tag,
        challenge_id: request.challenge_id,
        username: String::new(),
        password: String::new(),
        secret: "unique-transient-answer".into(),
        form_values: BTreeMap::new(),
    })
    .await
    .unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(3), sink.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes > 0);
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    assert!(!std::fs::read_to_string(data.join("library.json"))
        .unwrap()
        .contains("unique-transient-answer"));
    e.disconnect().await.unwrap();

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.unwrap();
        let mut data = [0u8; 64];
        loop {
            let n = socket.read(&mut data).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&data[..n]).await.unwrap();
        }
    });
    let mut endpoint = outbound;
    endpoint["tag"] = json!("proxy");
    let full = json!({"log":{"disabled":true},"endpoints":[endpoint],"inbounds":[{"type":"mixed","tag":"fixture-in","listen":"127.0.0.1","listen_port":port}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}});
    let full_id = profile(
        &mut e,
        ProfileKind::SingBoxConfig,
        full,
        "Full JSON independent route",
    );
    e.connect(&full_id).await.unwrap();
    wait_state(&mut e, "auth-pending").await;
    assert_eq!(e.snapshot().phase, "connected");
    let mut held = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    held.write_all(
        format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(held.read_u8().await.unwrap());
        assert!(header.len() < 4096);
    }
    assert!(String::from_utf8(header).unwrap().contains("200"));
    held.write_all(b"before-cancel").await.unwrap();
    let mut echoed = [0; 13];
    held.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"before-cancel");
    let request = identity(&mut e);
    e.cancel_vpn_challenge(request).await.unwrap();
    wait_state(&mut e, "error").await;
    assert_eq!(e.snapshot().phase, "connected");
    held.write_all(b"after-cancel!").await.unwrap();
    held.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"after-cancel!");
    assert_eq!(e.owned_core_process().unwrap(), owned);
    drop(held);
    echo_task.await.unwrap();
    e.shutdown().await;
    println!("PASS actual userspace OpenVPN credentials/secret/Cancel, stale session, no answer persistence, full JSON held CONNECT before and after endpoint cancellation; no OS TUN");
}
