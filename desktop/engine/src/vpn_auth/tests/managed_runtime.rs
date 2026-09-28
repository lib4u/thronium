//! Real supervisor/Rust bridge in private user, network and mount namespaces.
use super::*;
use crate::{store::ProfileKind, system_proxy::ConnectionMode, ProfileDraft};

fn ip(args: &[&str]) -> serde_json::Value {
    let r = std::process::Command::new("ip")
        .args(args)
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    serde_json::from_slice(&r.stdout).unwrap_or(serde_json::Value::Null)
}
fn rules() -> serde_json::Value {
    json!([ip(&["-4", "-j", "rule"]), ip(&["-6", "-j", "rule"])])
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE with managed VPN v1; real private namespace/TUN"]
async fn real_guarded_managed_status_details_cancel_and_old_generation_refusal() {
    const TEST:&str="vpn_auth::tests::managed_runtime::real_guarded_managed_status_details_cancel_and_old_generation_refusal";
    if std::env::var_os("THRONIUM_MANAGED_VPN_TEST_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("new preserved managed core"),
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            dir.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(core, dir.path().join("ThroniumCore")).unwrap();
        let before = std::fs::read("/etc/resolv.conf").unwrap();
        let r=std::process::Command::new("unshare").args(["--user","--map-root-user","--net","--mount","sh","-c","mount --make-rprivate / && mount -t tmpfs -o mode=700 tmpfs /run && ip link set lo up && exec \"$@\"","sh"]).arg(dir.path().join("Thronium")).args(["--ignored","--exact",TEST,"--nocapture"])
            .env("THRONIUM_MANAGED_VPN_TEST_CHILD","1").env("THRONIUM_TEST_ORIGINAL_NETNS",std::fs::read_link("/proc/self/ns/net").unwrap()).env("THRONIUM_TEST_ORIGINAL_MNTNS",std::fs::read_link("/proc/self/ns/mnt").unwrap())
            .env("DBUS_SYSTEM_BUS_ADDRESS","unix:path=/run/no-host-system-bus").env("DBUS_SESSION_BUS_ADDRESS","unix:path=/run/no-host-session-bus").output().unwrap();
        assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), before);
        assert!(
            r.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&r.stderr)
        );
        println!("{}", String::from_utf8_lossy(&r.stdout));
        return;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(std::env::var_os("THRONIUM_TEST_ORIGINAL_NETNS").unwrap())
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt").unwrap(),
        std::path::PathBuf::from(std::env::var_os("THRONIUM_TEST_ORIGINAL_MNTNS").unwrap())
    );
    ip(&["link", "add", "uplink", "type", "dummy"]);
    ip(&["addr", "add", "192.0.2.2/24", "dev", "uplink"]);
    ip(&["link", "set", "uplink", "up"]);
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "192.0.2.1",
        "dev",
        "uplink",
    ]);
    let baseline = rules();
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let r = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(key)
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
    assert!(r.status.success());
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let mut e = Engine::open(&dir.path().join("data"), &core).unwrap();
    e.store.library.preferences.inbound_port = port;
    e.store.library.preferences.connection_mode = ConnectionMode::Tun;
    let id=e.save_profile(ProfileDraft{ vpn_policy: Default::default(),id:None,name:"Managed auth fixture".into(),group_id:"personal".into(),kind:ProfileKind::SingBoxOutbound,config:json!({"type":"openvpn-client","server":"127.0.0.1","server_port":sink.local_addr().unwrap().port(),"network":"udp","system":false,"static_challenge":"Synthetic answer","tls":{"certificate_path":cert,"server_name":"vpn.fixture.invalid"}})}).unwrap();
    e.connect(&id).await.unwrap();
    for _ in 0..100 {
        e.vpn_tick().await;
        if e.snapshot().phase == "auth-pending" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(e.snapshot().phase, "auth-pending");
    assert_eq!(e.vpn.managed_version, 1);
    let generation = e.vpn.generation.unwrap();
    assert!(generation > 0);
    let request = ChallengeRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: e.vpn.status.endpoints[0].challenge_id.clone().unwrap(),
    };
    let details = e.vpn_challenge(request.clone()).await.unwrap();
    assert_eq!(details.kind, "credentials");
    assert_eq!(details.message, "Synthetic answer");
    let mut data = [0u8; 64];
    assert!(sink.try_recv(&mut data).is_err());
    // Probe the actual supervisor refusal directly; generation 0 is never a wildcard.
    let reply = e
        .rpc
        .as_mut()
        .unwrap()
        .call::<_, proto::ManagedVpnResponse>(
            "ManagedVPN",
            proto::ManagedVpnRequest {
                version: Some(1),
                generation: Some(generation + 1),
                operation: Some(proto::managed_vpn_request::Operation::Cancel(
                    proto::SubmitVpnChallengeRequest {
                        endpoint_tag: Some("proxy".into()),
                        challenge_id: Some(request.challenge_id.clone()),
                        ..Default::default()
                    },
                )),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        reply.error_code.as_deref(),
        Some("managed_vpn_stale_generation")
    );
    assert_eq!(
        e.vpn_challenge(request.clone()).await.unwrap().challenge_id,
        request.challenge_id
    );
    e.cancel_vpn_challenge(request.clone()).await.unwrap();
    for _ in 0..100 {
        e.vpn_tick().await;
        if e.snapshot().phase == "error" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(e.snapshot().phase, "error");
    e.disconnect().await.unwrap();
    assert_eq!(
        e.cancel_vpn_challenge(request).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    assert_eq!(rules(), baseline);
    assert!(!ip(&["-j", "link"])
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["ifname"] == crate::tun::INTERFACE));
    e.shutdown().await;
    println!("PASS real namespace managed TUN + generation-bound Query/details/Cancel; wrong generation refused without cancelling current challenge; owned network rules restored; host DNS unchanged");
}
