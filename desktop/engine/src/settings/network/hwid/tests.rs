//! Synthetic values only: no calls to production SystemDevice or system files.
use super::*;
use crate::subscriptions::{Downloads, Settings};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{timeout, Duration},
};

#[derive(Default)]
struct Device {
    calls: Vec<String>,
    absent: bool,
}
impl DeviceProvider for Device {
    fn value(&mut self, field: &str) -> Option<String> {
        self.calls.push(field.into());
        if self.absent {
            return None;
        }
        Some(
            match field {
                "hwid" => "fixture-id",
                "os" => "Linux",
                "osversion" => "fixture-kernel",
                "model" => "fixture-model",
                _ => panic!("unexpected field"),
            }
            .into(),
        )
    }
}
#[test]
fn twenty_actual_qt_cases_match_without_reading_real_device_details() {
    let golden: Value = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    let cases = golden["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let mut headers = BTreeMap::new();
        let mut device = Device::default();
        apply(
            &mut headers,
            case["enabled"].as_bool().unwrap(),
            case["custom"].as_str().unwrap(),
            &mut device,
        );
        assert_eq!(json!(headers), case["headers"], "{}", case["name"]);
        if case["name"] == "all-custom" || case["name"] == "disabled" {
            assert!(device.calls.is_empty());
        }
    }
}
#[test]
fn mixed_case_group_headers_override_custom_and_defaults_including_explicit_empty() {
    let original = BTreeMap::from([
        ("X-HwId".into(), "".into()),
        ("X-DEVICE-os".into(), "group-os".into()),
        ("x-Ver-Os".into(), "group-version".into()),
        ("x-device-MODEL".into(), "group-model".into()),
    ]);
    for enabled in [false, true] {
        let mut headers = original.clone();
        let mut device = Device::default();
        apply(
            &mut headers,
            enabled,
            "hwid=global,os=global,osversion=global,model=global",
            &mut device,
        );
        assert_eq!(headers, original);
        assert!(device.calls.is_empty());
    }
}
#[test]
fn only_missing_fields_are_requested_and_no_identifier_is_read_for_other_defaults() {
    let mut headers = BTreeMap::from([("X-HWID".into(), "group-id".into())]);
    let mut device = Device::default();
    apply(
        &mut headers,
        true,
        "os=CustomOS,osversion=1,model=",
        &mut device,
    );
    assert_eq!(device.calls, ["model"]);
    assert_eq!(headers["x-device-model"], "fixture-model");
    assert_eq!(headers["X-HWID"], "group-id");
    let mut device = Device {
        absent: true,
        ..Default::default()
    };
    let mut headers = BTreeMap::new();
    apply(&mut headers, true, "", &mut device);
    assert!(headers.is_empty());
    assert_eq!(device.calls, ["hwid", "os", "osversion", "model"]);
    apply(
        &mut headers,
        false,
        "",
        &mut Device {
            absent: true,
            ..Default::default()
        },
    );
    assert!(headers.is_empty());
}
#[test]
fn linux_machine_id_fallback_distinguishes_missing_from_readable_empty() {
    for (primary, expected, paths) in [
        (
            None,
            Some("dbus-fixture"),
            vec!["/etc/machine-id", "/var/lib/dbus/machine-id"],
        ),
        (Some(" \n"), None, vec!["/etc/machine-id"]),
        (
            Some("primary-fixture\n"),
            Some("primary-fixture"),
            vec!["/etc/machine-id"],
        ),
    ] {
        let mut reads = vec![];
        let actual = linux_value("hwid", &mut |path| {
            reads.push(path.to_owned());
            match path {
                "/etc/machine-id" => primary.map(str::to_owned),
                "/var/lib/dbus/machine-id" => Some("dbus-fixture\n".into()),
                _ => panic!("unexpected read"),
            }
        });
        assert_eq!(actual.as_deref(), expected);
        assert_eq!(reads, paths);
    }
}
#[test]
fn linux_field_provider_reads_only_the_requested_fixture_file() {
    for (field, expected, path) in [
        ("os", "Linux", None),
        (
            "osversion",
            "fixture-kernel",
            Some("/proc/sys/kernel/osrelease"),
        ),
        ("model", "Fixture OS", Some("/etc/os-release")),
    ] {
        let mut reads = vec![];
        let result = linux_value(field, &mut |file| {
            reads.push(file.to_owned());
            assert_eq!(Some(file), path);
            Some(
                if field == "model" {
                    "PRETTY_NAME=\"Fixture OS\"\nNAME=Other\n"
                } else {
                    "fixture-kernel\n"
                }
                .into(),
            )
        });
        assert_eq!(result.as_deref(), Some(expected));
        assert_eq!(reads.len(), usize::from(path.is_some()));
    }
}

fn settings(url: &str) -> Settings {
    serde_json::from_value(
        json!({"url":url,"headers":{},"userAgent":"hwid-fixture-agent","viaProxy":false}),
    )
    .unwrap()
}
async fn serve(responses: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = vec![];
        for response in responses {
            let (mut socket, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = vec![];
            loop {
                let mut block = [0; 1024];
                let n = timeout(Duration::from_secs(5), socket.read(&mut block))
                    .await
                    .unwrap()
                    .unwrap();
                bytes.extend_from_slice(&block[..n]);
                assert!(bytes.len() < 32768);
                if n == 0 || bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            socket.write_all(response.as_bytes()).await.unwrap();
            requests.push(String::from_utf8(bytes).unwrap());
        }
        requests
    });
    (url, task)
}
fn response() -> String {
    let body = "socks://127.0.0.1:19080";
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
fn redirect(location: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
async fn fetch(s: &Settings) {
    Downloads::default()
        .fetch(&uuid::Uuid::new_v4().to_string(), s, None)
        .await
        .unwrap();
}
#[tokio::test]
async fn real_loopback_get_sends_synthetic_fallback_and_explicit_group_override_once() {
    let (url, server) = serve(vec![response()]).await;
    let mut s = settings(&url);
    s.headers.insert("X-HWID".into(), "group-fixture-id".into());
    let mut device = Device::default();
    apply(
        &mut s.headers,
        true,
        "hwid=global-id,os=,osversion=,model=",
        &mut device,
    );
    assert_eq!(device.calls, ["os", "osversion", "model"]);
    fetch(&s).await;
    let request = server.await.unwrap().remove(0).to_ascii_lowercase();
    for expected in [
        "x-hwid: group-fixture-id\r\n",
        "x-device-os: linux\r\n",
        "x-ver-os: fixture-kernel\r\n",
        "x-device-model: fixture-model\r\n",
    ] {
        assert!(request.contains(expected));
    }
    assert_eq!(request.matches("x-hwid:").count(), 1);
    assert!(!request.contains("global-id"));
}
#[tokio::test]
async fn same_origin_redirect_keeps_hwid_and_cross_origin_strips_all_device_headers() {
    let (url, server) = serve(vec![redirect("/next"), response()]).await;
    let mut s = settings(&url);
    apply(&mut s.headers, true, "", &mut Device::default());
    fetch(&s).await;
    for request in server.await.unwrap() {
        assert!(request
            .to_ascii_lowercase()
            .contains("x-hwid: fixture-id\r\n"));
    }
    let (destination, other) = serve(vec![response()]).await;
    let (url, origin) = serve(vec![redirect(&destination)]).await;
    s.url = url;
    fetch(&s).await;
    assert!(origin.await.unwrap()[0]
        .to_ascii_lowercase()
        .contains("x-hwid: fixture-id\r\n"));
    let request = other.await.unwrap().remove(0).to_ascii_lowercase();
    for (_, header) in FIELDS {
        assert!(!request.contains(header));
    }
    assert!(!request.contains("fixture-id"));
}

fn engine_with_custom_device() -> (tempfile::TempDir, crate::Engine) {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        crate::Engine::open(directory.path(), &directory.path().join("missing-core")).unwrap();
    let mut library = engine.store.library.clone();
    library.settings.insert("sub_send_hwid".into(), json!(true));
    library.settings.insert("sub_custom_hwid_params".into(),json!("hwid=global-fixture-id,os=global-fixture-os,osversion=global-fixture-version,model=global-fixture-model"));
    library
        .settings
        .insert("user_agent".into(), json!("global-fixture-agent"));
    engine.store.commit(library).unwrap();
    (directory, engine)
}
#[tokio::test]
async fn manual_and_queue_use_same_priority_without_persisting_automatic_headers() {
    // Four complete explicit global values ensure the production lazy provider
    // performs no system reads. Missing/default cases above use injected fakes.
    for inherit in [false, true] {
        let (_directory, mut engine) = engine_with_custom_device();
        let (url, server) = serve(vec![response(), response()]).await;
        let mut s = settings(&url);
        s.inherit_defaults = Some(inherit);
        s.headers.insert("X-HwId".into(), "group-fixture-id".into());
        let group = engine
            .save_group(crate::subscriptions::GroupDraft {
                auto_clear_unavailable: None,
                proxy_chain: None,
                id: None,
                name: "Local HWID test".into(),
                subscription: Some(s),
            })
            .unwrap();
        let manual_id = uuid::Uuid::new_v4().to_string();
        let manual = engine
            .begin_manual_subscription(&group, &manual_id)
            .unwrap();
        assert_eq!(
            manual.settings.user_agent,
            if inherit {
                "global-fixture-agent"
            } else {
                "hwid-fixture-agent"
            }
        );
        fetch(&manual.settings).await;
        engine.end_manual_subscription(&group, &manual_id);
        engine.enqueue_subscription_update(&group).unwrap();
        let worker = uuid::Uuid::new_v4().to_string();
        let id = engine.claim_subscription_job(&worker).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let queued = engine.subscription_job_request(&id, &worker).unwrap();
        assert_eq!(queued.settings.headers, manual.settings.headers);
        fetch(&queued.settings).await;
        for request in server.await.unwrap() {
            let request = request.to_ascii_lowercase();
            for pair in [
                "x-hwid: group-fixture-id\r\n",
                "x-device-os: global-fixture-os\r\n",
                "x-ver-os: global-fixture-version\r\n",
                "x-device-model: global-fixture-model\r\n",
            ] {
                assert!(request.contains(pair));
            }
            assert!(!request.contains("x-hwid: global-fixture-id"));
        }
        let saved = engine
            .group(&group)
            .unwrap()
            .subscription
            .unwrap()
            .settings
            .headers;
        assert_eq!(saved.len(), 1);
        assert_eq!(saved["X-HwId"], "group-fixture-id");
        let snapshot = json!(engine.snapshot()).to_string();
        for secret in [
            "group-fixture-id",
            "global-fixture-id",
            "global-fixture-os",
            "global-fixture-version",
            "global-fixture-model",
        ] {
            assert!(!snapshot.contains(secret));
        }
        assert!(engine.owned_core_process().is_none());
        engine.cancel_subscription_jobs().unwrap();
        let mut library = engine.store.library.clone();
        library
            .settings
            .insert("sub_send_hwid".into(), json!(false));
        engine.store.commit(library).unwrap();
        let disabled = engine.subscription_request(&group).unwrap();
        assert_eq!(disabled.settings.headers, saved);
    }
}
#[test]
fn changing_global_hwid_invalidates_a_download_without_committing_profiles() {
    let (_directory, mut engine) = engine_with_custom_device();
    let group = engine
        .save_group(crate::subscriptions::GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: None,
            name: "Local HWID stamp".into(),
            subscription: Some(settings("http://127.0.0.1:19080/sub")),
        })
        .unwrap();
    let request = engine.subscription_request(&group).unwrap();
    assert_eq!(request.settings.headers["x-hwid"], "global-fixture-id");
    let mut library = engine.store.library.clone();
    library
        .settings
        .insert("sub_send_hwid".into(), json!(false));
    engine.store.commit(library).unwrap();
    let before = json!(engine.store.library);
    let download = crate::subscriptions::Download {
        metadata: Default::default(),
        body: "socks://127.0.0.1:19081".into(),
        usage: None,
    };
    assert_eq!(
        engine
            .subscription_downloaded(request, download)
            .unwrap_err(),
        "subscription_changed"
    );
    assert_eq!(json!(engine.store.library), before);
    assert!(engine.owned_core_process().is_none());
}

#[test]
fn windows_fields_follow_the_qt_registry_sources_and_pair_the_board_names() {
    let values = |model: &'static str, board: &'static str| {
        move |path: &str, name: &str| -> Option<String> {
            Some(
                match (path, name) {
                    (r"SOFTWARE\Microsoft\Cryptography", "MachineGuid") => "fixture-guid\0",
                    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") => {
                        "26100"
                    }
                    (
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        "CurrentMajorVersionNumber",
                    ) => "10",
                    (
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        "CurrentMinorVersionNumber",
                    ) => "0",
                    (r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName") => model,
                    (r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct") => board,
                    _ => return None,
                }
                .trim_end_matches('\0')
                .to_owned(),
            )
        }
    };
    let mut host = || Some("FIXTURE-PC".to_owned());
    for (field, expected) in [
        ("hwid", "fixture-guid"),
        ("os", "Windows"),
        ("osversion", "10.0.26100"),
        ("model", "Fixture Model/Fixture Board"),
    ] {
        let mut read = values("Fixture Model", "Fixture Board");
        assert_eq!(
            windows_value(field, &mut read, &mut host).as_deref(),
            Some(expected),
            "{field}"
        );
    }
    // One name for both sources is reported once, as in Qt.
    let mut same = values("Fixture Model", "Fixture Model");
    assert_eq!(
        windows_value("model", &mut same, &mut host).as_deref(),
        Some("Fixture Model")
    );
    // A machine without a GUID falls back to the host name and product type.
    let mut empty = |path: &str, name: &str| {
        (path != r"SOFTWARE\Microsoft\Cryptography").then(|| values("A", "A")(path, name))?
    };
    assert_eq!(
        windows_value("hwid", &mut empty, &mut host).as_deref(),
        Some("FIXTURE-PC-windows")
    );
    assert_eq!(
        windows_value("hwid", &mut empty, &mut || None).as_deref(),
        None
    );
    // Pre-10 builds keep the string version pair.
    let mut legacy = |path: &str, name: &str| match name {
        "CurrentMajorVersionNumber" | "CurrentMinorVersionNumber" => None,
        "CurrentVersion" => Some("6.3".to_owned()),
        _ => values("A", "A")(path, name),
    };
    assert_eq!(
        windows_value("osversion", &mut legacy, &mut host).as_deref(),
        Some("6.3.26100")
    );
    assert_eq!(windows_value("unknown", &mut legacy, &mut host), None);
}
