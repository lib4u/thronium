//! Explicit opt-in fixture; genuine local VPN authentication, no OS TUN.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use thronium_engine::{
    store::ProfileKind,
    system_proxy::ConnectionMode,
    vpn_auth::credentials::{
        CredentialEditRequest, CredentialRequest, CredentialView, RestartCredentialsRequest,
    },
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const USER: &str = " credentials-fixture-new-user ";
const PASSWORD: &str = " credentials-fixture-new-password-31 ";
struct Helper(Child);
impl Drop for Helper {
    fn drop(&mut self) {
        self.0.stdin.take();
        let _ = self.0.wait();
    }
}
fn request(engine: &mut Engine) -> CredentialRequest {
    CredentialRequest {
        session_id: engine.snapshot().vpn.session_id.unwrap(),
        endpoint_tag: "proxy".into(),
    }
}
fn edit(view: &CredentialView) -> CredentialEditRequest {
    CredentialEditRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
    }
}
fn restart(view: &CredentialView) -> RestartCredentialsRequest {
    RestartCredentialsRequest {
        session_id: view.session_id.clone(),
        endpoint_tag: view.endpoint_tag.clone(),
        edit_token: view.edit_token.clone(),
        username: USER.into(),
        password: PASSWORD.into(),
    }
}
async fn state(engine: &mut Engine, wanted: &str) {
    let end = Instant::now() + Duration::from_secs(12);
    loop {
        engine.vpn_tick().await;
        let snapshot = engine.snapshot();
        if snapshot
            .vpn
            .endpoints
            .iter()
            .any(|e| e.tag == "proxy" && e.state == wanted)
        {
            return;
        }
        assert!(Instant::now() < end, "VPN state did not reach {wanted}");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
struct Held {
    stream: TcpStream,
    task: tokio::task::JoinHandle<()>,
    count: usize,
}
impl Held {
    async fn new(proxy: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            loop {
                let mut header = Vec::new();
                loop {
                    let Ok(byte) = stream.read_u8().await else {
                        return;
                    };
                    header.push(byte);
                    assert!(header.len() < 4096);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\nowned31").await.is_err() { return; }
            }
        });
        let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
        stream
            .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = vec![];
        timeout(Duration::from_secs(3), async {
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 4096);
            }
        })
        .await
        .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        Self {
            stream,
            task,
            count: 0,
        }
    }
    async fn http(&mut self) {
        self.stream
            .write_all(b"GET /proof HTTP/1.1\r\nHost: owned.fixture.invalid\r\n\r\n")
            .await
            .unwrap();
        let mut head = vec![];
        timeout(Duration::from_secs(3), async {
            while !head.ends_with(b"\r\n\r\n") {
                head.push(self.stream.read_u8().await.unwrap());
                assert!(head.len() < 4096);
            }
        })
        .await
        .unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let mut body = [0u8; 7];
        self.stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"owned31");
        self.count += 1;
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE and THRONIUM_CREDENTIALS_FIXTURE; private local servers"]
async fn local_manual_credentials_are_ephemeral_and_frozen_for_openvpn_and_openconnect() {
    const TEST: &str =
        "local_manual_credentials_are_ephemeral_and_frozen_for_openvpn_and_openconnect";
    if std::env::var_os("THRONIUM_CREDENTIALS_CHILD").is_none() {
        let own = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            own.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(
            std::env::var_os("THRONIUM_TEST_CORE").expect("pinned owned Core"),
            own.path().join("ThroniumCore"),
        )
        .unwrap();
        let output = Command::new(own.path().join("Thronium"))
            .args(["--ignored", "--exact", TEST, "--nocapture"])
            .env("THRONIUM_CREDENTIALS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let python = Command::new("python3")
        .args(["-c", "import sys;print(sys.executable)"])
        .output()
        .unwrap();
    assert!(python.status.success());
    std::fs::copy(
        String::from_utf8(python.stdout).unwrap().trim(),
        root.path().join("Thronium"),
    )
    .unwrap();
    std::fs::copy(&core, root.path().join("ThroniumCore")).unwrap();
    let mut helper = Helper(
        Command::new(root.path().join("Thronium"))
            .arg(std::env::var_os("THRONIUM_CREDENTIALS_FIXTURE").expect("fixture path"))
            .arg(root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(helper.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line.is_empty() {
        let mut diagnostic = String::new();
        helper
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut diagnostic)
            .unwrap();
        panic!(
            "Fixture startup failed: {}",
            diagnostic
                .replace(USER, "[username]")
                .replace(PASSWORD, "[password]")
        );
    }
    let ready: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["systemTun"], false);
    let events = PathBuf::from(ready["events"].as_str().unwrap());
    let mut http_proofs = 0;
    for protocol in ["openvpn", "openconnect"] {
        let dir = tempfile::tempdir().unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        engine
            .connection_settings(ConnectionMode::Local, port)
            .unwrap();
        let config = ready[protocol].clone();
        let id = engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: protocol.into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: config.clone(),
            })
            .unwrap();
        let other = engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Selected later".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"direct"}),
            })
            .unwrap();
        let otp = engine
            .otp_save(
                "",
                "",
                thronium_engine::otp::Draft {
                    name: "Reserved for live challenge only".into(),
                    secret: "JBSWY3DPEHPK3PXP".into(),
                    kind: thronium_engine::otp::Kind::Hotp,
                    counter: "17".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let binding = engine.get_vpn_otp_binding(&id).unwrap();
        engine
            .save_vpn_otp_binding(thronium_engine::vpn_otp_bindings::SaveRequest {
                profile_id: id.clone(),
                edit_token: binding.edit_token,
                otp_id: Some(otp["id"].as_str().unwrap().into()),
                otp_revision: Some(otp["revision"].as_str().unwrap().into()),
                mode: None,
            })
            .unwrap();
        let mut routing = engine.routing();
        routing.profiles[0]
            .rules
            .push(thronium_engine::routing::Rule {
                id: "owned-http".into(),
                name: "Owned loopback".into(),
                enabled: true,
                config: json!({"ip_cidr":["127.0.0.0/8"],"action":"route","outbound":"direct"}),
                simple: None,
            });
        engine.save_routing(routing).unwrap();
        engine.connect(&id).await.unwrap();
        state(&mut engine, "error").await;
        let status = engine.snapshot();
        assert!(status.vpn.endpoints[0].auth_failed);
        assert!(status.vpn.endpoints[0].challenge_id.is_none());
        let owner = engine.owned_core_process().unwrap();
        let before = engine.connection_configuration(&id, true).await.unwrap();
        let mut held = Held::new(port).await;
        held.http().await;
        let identity = request(&mut engine);
        let view = engine.vpn_credentials(identity).await.unwrap();
        assert_eq!(view.username, config["username"].as_str().unwrap());
        engine.cancel_vpn_credentials(edit(&view)).unwrap();
        held.http().await;
        assert_eq!(engine.owned_core_process().unwrap(), owner);
        assert_eq!(
            engine.connection_configuration(&id, true).await.unwrap(),
            before
        );
        assert_eq!(
            engine
                .restart_vpn_credentials(restart(&view))
                .await
                .unwrap_err(),
            "vpn_credentials_stale"
        );
        held.http().await;
        http_proofs += held.count;
        drop(held);
        // Persisted selection and pending routing remain different from the
        // active frozen request across the explicit credential-only restart.
        engine.select(&other).unwrap();
        let mut pending = engine.routing();
        pending.profiles[0].rules.clear();
        engine.save_routing(pending).unwrap();
        let disk = std::fs::read(dir.path().join("library.json")).unwrap();
        let saved_otp = engine.otp_list();
        let identity = request(&mut engine);
        let next = engine.vpn_credentials(identity).await.unwrap();
        engine
            .restart_vpn_credentials(restart(&next))
            .await
            .unwrap();
        state(
            &mut engine,
            if protocol == "openvpn" {
                "connected"
            } else {
                "auth-pending"
            },
        )
        .await;
        let snapshot = engine.snapshot();
        assert_ne!(
            snapshot.vpn.session_id.as_deref(),
            Some(next.session_id.as_str())
        );
        assert_eq!(snapshot.routing["pending"], true);
        assert_eq!(snapshot.selected.as_deref(), Some(other.as_str()));
        assert_eq!(snapshot.running.as_deref(), Some(id.as_str()));
        let mut expected = before.clone();
        let endpoint = expected["parts"][0]["config"]["endpoints"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["tag"] == "proxy")
            .unwrap();
        endpoint["username"] = json!(USER);
        endpoint["password"] = json!(PASSWORD);
        assert_eq!(
            engine.connection_configuration(&id, true).await.unwrap(),
            expected
        );
        assert_eq!(engine.otp_list(), saved_otp);
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            disk
        );
        assert!(!serde_json::to_string(&snapshot).unwrap().contains(PASSWORD));
        assert_eq!(engine.profile(&id).unwrap().config, config);
        let mut traffic = Held::new(port).await;
        traffic.http().await;
        http_proofs += traffic.count;
        drop(traffic);
        engine.disconnect().await.unwrap();
        assert_eq!(
            engine.cancel_vpn_credentials(edit(&next)).unwrap_err(),
            "vpn_credentials_stale"
        );
        let rows: Vec<Value> = std::fs::read_to_string(&events)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        if protocol == "openconnect" {
            assert!(rows.iter().any(|e| e["protocol"] == protocol
                && e["newExact"] == true
                && e["accepted"] == true));
            assert!(!snapshot.vpn.endpoints[0].auth_failed);
        } else {
            assert!(rows
                .iter()
                .any(|e| e["protocol"] == protocol && e["singletonCredentialsAccepted"] == true));
        }
        drop(engine);
        let reopened = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(reopened.profile(&id).unwrap().config, config);
        assert_eq!(reopened.otp_list(), saved_otp);
    }
    println!("credentials31 actual OpenVPN connected; OpenConnect exact accepted/operator form; {http_proofs} owned HTTP responses; unchanged Store and HOTP");
}
