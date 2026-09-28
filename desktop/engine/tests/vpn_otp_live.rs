//! Opt-in real core/HTTPS auto-code proof, separate from native UI acceptance.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};
use thronium_engine::{
    otp::{Draft, Kind},
    store::ProfileKind,
    vpn_otp_bindings::SaveRequest,
    Engine, ProfileDraft,
};

struct Helper(Child);
impl Drop for Helper {
    fn drop(&mut self) {
        self.0.stdin.take();
        let _ = self.0.wait();
    }
}
fn events(path: &std::path::Path, name: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .filter(|v| v["case"] == format!("/otp/{name}"))
        .collect()
}
fn count(path: &std::path::Path, name: &str) -> usize {
    events(path, name)
        .iter()
        .filter(|v| v["event"] == "validated" && v.get("otpExact").is_some())
        .count()
}
#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE and THRONIUM_TEST_OTP_FIXTURE, owned real HTTPS/core"]
async fn actual_auto_hotp_totp_templates_limits_and_invalid_shape() {
    run(false).await;
}
#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE and private Linux namespaces; real managed auto auth"]
async fn actual_managed_auto_hotp_totp_templates_limits_and_invalid_shape() {
    run(true).await;
}
async fn run(managed: bool) {
    let test = if managed {
        "actual_managed_auto_hotp_totp_templates_limits_and_invalid_shape"
    } else {
        "actual_auto_hotp_totp_templates_limits_and_invalid_shape"
    };
    if std::env::var_os("THRONIUM_OTP_LIVE_CHILD").is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            dir.path().join("Thronium"),
        )
        .unwrap();
        std::fs::copy(
            std::env::var_os("THRONIUM_TEST_CORE").expect("core fixture"),
            dir.path().join("ThroniumCore"),
        )
        .unwrap();
        let mut command = if managed {
            let mut cmd = Command::new("unshare");
            cmd.args(["--user","--map-root-user","--net","--mount","sh","-c","mount --make-rprivate / && mount -t tmpfs -o mode=700 tmpfs /run && ip link set lo up && exec \"$@\"","sh"]).arg(dir.path().join("Thronium"));
            cmd.env(
                "THRONIUM_OTP_ORIGINAL_NETNS",
                std::fs::read_link("/proc/self/ns/net").unwrap(),
            )
            .env(
                "THRONIUM_OTP_ORIGINAL_MNTNS",
                std::fs::read_link("/proc/self/ns/mnt").unwrap(),
            )
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                "unix:path=/run/no-host-system-bus",
            )
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/run/no-host-session-bus",
            );
            cmd
        } else {
            Command::new(dir.path().join("Thronium"))
        };
        let dns = std::fs::read("/etc/resolv.conf").unwrap();
        let out = command
            .args(["--ignored", "--exact", test, "--nocapture"])
            .env("THRONIUM_OTP_LIVE_CHILD", "1")
            .output()
            .unwrap();
        assert_eq!(std::fs::read("/etc/resolv.conf").unwrap(), dns);
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("{}", String::from_utf8_lossy(&out.stdout));
        return;
    }
    if managed {
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(std::env::var_os("THRONIUM_OTP_ORIGINAL_NETNS").unwrap())
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/mnt").unwrap(),
            std::path::PathBuf::from(std::env::var_os("THRONIUM_OTP_ORIGINAL_MNTNS").unwrap())
        );
        for args in [
            vec!["link", "add", "uplink", "type", "dummy"],
            vec!["addr", "add", "192.0.2.2/24", "dev", "uplink"],
            vec!["link", "set", "uplink", "up"],
            vec![
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
                "dev",
                "uplink",
            ],
        ] {
            assert!(Command::new("ip").args(args).status().unwrap().success());
        }
    }
    let baseline = if managed {
        Some(
            Command::new("ip")
                .args(["-j", "rule"])
                .output()
                .unwrap()
                .stdout,
        )
    } else {
        None
    };
    let fixture = std::env::var_os("THRONIUM_TEST_OTP_FIXTURE").expect("owned verifier");
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("events.jsonl");
    let mut helper = Helper(
        Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/vpn_otp_live.py"
            ))
            .arg(fixture)
            .arg(data.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(helper.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let configs: Value = serde_json::from_str(&line).unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    for (name, kind, wanted) in [
        ("hotp", Kind::Hotp, 2),
        ("login", Kind::Hotp, 1),
        ("template", Kind::Hotp, 1),
        ("limited", Kind::Hotp, 4),
        ("totp", Kind::Totp, 2),
        ("invalid", Kind::Hotp, 0),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), &core).unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        e.connection_settings(
            if managed {
                thronium_engine::system_proxy::ConnectionMode::Tun
            } else {
                thronium_engine::system_proxy::ConnectionMode::Local
            },
            port,
        )
        .unwrap();
        let profile = e
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: format!("Synthetic {name}"),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: configs[name].clone(),
            })
            .unwrap();
        let meta = e
            .otp_save(
                "",
                "",
                Draft {
                    name: "RFC synthetic".into(),
                    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                    kind,
                    period: 8,
                    ..Default::default()
                },
            )
            .unwrap();
        let otp_id = meta["id"].as_str().unwrap();
        let view = e.get_vpn_otp_binding(&profile).unwrap();
        assert!(view.supported);
        e.save_vpn_otp_binding(SaveRequest {
            profile_id: profile.clone(),
            edit_token: view.edit_token,
            otp_id: Some(otp_id.into()),
            otp_revision: Some(meta["revision"].as_str().unwrap().into()),
            mode: None,
        })
        .unwrap();
        let before = std::fs::read(dir.path().join("library.json")).unwrap();
        e.check(&e.profile(&profile).unwrap()).await.unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            before,
            "Check never consumes"
        );
        assert_eq!(count(&path, name), 0);
        e.connect(&profile).await.unwrap();
        for _ in 0..160 {
            e.vpn_tick().await;
            let snapshot = e.snapshot();
            let state = snapshot
                .vpn
                .endpoints
                .first()
                .and_then(|x| x.otp.as_ref())
                .map(|x| x.state.as_str());
            if count(&path, name) >= wanted && matches!(state, Some("manual" | "limited")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(count(&path, name), wanted, "{name}");
        let observed = events(&path, name);
        assert!(
            observed
                .iter()
                .filter(|v| v.get("otpExact").is_some())
                .all(|v| v["otpExact"] == true && v["codeRepeated"] == false),
            "{name}"
        );
        let snapshot = e.snapshot();
        assert_eq!(
            snapshot.vpn.endpoints[0].otp.as_ref().unwrap().state,
            if name == "limited" {
                "limited"
            } else {
                "manual"
            }
        );
        let current = e.otp_get(otp_id).unwrap();
        assert_eq!(
            current["counter"],
            if kind == Kind::Hotp {
                wanted.to_string()
            } else {
                "0".into()
            }
        );
        if name == "hotp" {
            let counters: Vec<_> = observed
                .iter()
                .filter_map(|v| v["counter"].as_str())
                .collect();
            assert_eq!(counters, vec!["1", "2"]);
        }
        if name == "totp" {
            let steps: Vec<_> = observed
                .iter()
                .filter_map(|v| v["timeStep"].as_u64())
                .collect();
            assert_eq!(steps.len(), 2);
            assert!(steps[1] > steps[0]);
        }
        let stored: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("library.json")).unwrap())
                .unwrap();
        assert_eq!(
            stored["profiles"][0]["config"], configs[name],
            "source template preserved"
        );
        for _ in 0..12 {
            e.vpn_tick().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            count(&path, name),
            wanted,
            "no replay after terminal/manual"
        );
        if name == "hotp" {
            let owner = e.owned_core_process().unwrap();
            let active_config = e.connection_configuration(&profile, true).await.unwrap();
            let otp_revision = e.otp_get(otp_id).unwrap()["revision"]
                .as_str()
                .unwrap()
                .to_owned();
            for entries in [
                serde_json::json!([{"submission_key":"shadow:answer:1","value":"fixed"},{"submission_key":"shadow:answer:1","value":"{otp}"}]),
                serde_json::json!([{"name":"answer","form_id":"shadow","value":"fixed"},{"name":"answer","value":"{otp}"}]),
                serde_json::json!([{"submission_key":"shadow:answer:1","value":"fixed"},{"name":"answer","value":"{otp}"}]),
            ] {
                let mut config = configs["template"].clone();
                config["form_entries"] = entries;
                let shadow = e
                    .save_profile(ProfileDraft {
                        vpn_policy: Default::default(),
                        id: None,
                        name: "Synthetic shadow".into(),
                        group_id: "personal".into(),
                        kind: ProfileKind::SingBoxOutbound,
                        config,
                    })
                    .unwrap();
                let before = std::fs::read(dir.path().join("library.json")).unwrap();
                let view = e.get_vpn_otp_binding(&shadow).unwrap();
                assert!(!view.supported);
                assert_eq!(view.reason.as_deref(), Some("vpn_otp_form_shadowed"));
                assert_eq!(
                    e.save_vpn_otp_binding(SaveRequest {
                        profile_id: shadow,
                        edit_token: view.edit_token,
                        otp_id: Some(otp_id.into()),
                        otp_revision: Some(otp_revision.clone()),
                        mode: None,
                    })
                    .err()
                    .as_deref(),
                    Some("vpn_otp_form_shadowed")
                );
                assert_eq!(
                    std::fs::read(dir.path().join("library.json")).unwrap(),
                    before
                );
                assert_eq!(e.owned_core_process().unwrap(), owner);
                assert_eq!(
                    e.connection_configuration(&profile, true).await.unwrap(),
                    active_config
                );
                assert_eq!(count(&path, "template"), 0);
            }
            println!("PASS real core retained across three shadowed binding refusals; no extra auth or counter change");
        }
        e.disconnect().await.unwrap();
        e.shutdown().await;
        if let Some(baseline) = &baseline {
            assert_eq!(
                &Command::new("ip")
                    .args(["-j", "rule"])
                    .output()
                    .unwrap()
                    .stdout,
                baseline
            );
        }
        println!("PASS real auto {name}: {wanted} exact code responses; counter/revision/source retention and no replay");
    }
}
