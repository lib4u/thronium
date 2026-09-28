use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, kind: ProfileKind, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Probe fixture".into(),
        group_id: "personal".into(),
        kind,
        config,
    })
    .unwrap()
}
fn options(ids: &[&str]) -> Options {
    Options {
        ids: ids.iter().map(|s| (*s).into()).collect(),
        url: "https://example.test/204".into(),
        timeout_ms: 500,
        concurrency: None,
    }
}
fn begin(e: &mut Engine, ids: &[&str]) -> Run {
    e.store.library.preferences.ping.method = Method::Http;
    e.start_url_tests(options(ids)).unwrap()
}

#[tokio::test]
async fn method_migration_and_settings_roundtrip() {
    let legacy: PingSettings =
        serde_json::from_value(json!({"url":"https://example.test/", "timeoutMs":3000})).unwrap();
    assert_eq!(legacy.method, Method::Auto);
    assert!(serde_json::from_value::<PingSettings>(
        json!({"method":"udp", "url":legacy.url, "timeoutMs":3000})
    )
    .is_err());
    let (dir, mut e) = setup();
    let previous = crate::settings::section(&e.store.library, "testing");
    let mut desired = previous.clone();
    desired["ping_method"] = json!("icmp");
    e.save_settings("testing", previous, desired).await.unwrap();
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(e.store.library.preferences.ping.method, Method::Icmp);
}

#[test]
fn each_method_has_its_own_cache_and_a_run_freezes_its_method() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    e.store.library.preferences.ping.method = Method::Http;
    let http = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&http.id).unwrap();
    e.finish_url_test(&http.id, &id, Ok(77));
    let p = e.profile(&id).unwrap();
    e.store.library.preferences.ping.method = Method::Tcp;
    assert!(e.measurement(&p).is_none());
    let tcp = e.start_ping(vec![id.clone()]).unwrap();
    e.store.library.preferences.ping.method = Method::Icmp;
    let probe = e.next_url_test(&tcp.id).unwrap();
    let Request::Endpoint(req) = probe.request else {
        panic!("endpoint expected")
    };
    assert_eq!(req.method.as_deref(), Some("tcp"));
    assert_eq!(e.measurement(&p).unwrap().method, Method::Tcp);
    e.finish_url_test(&tcp.id, &id, Ok(12));
    assert!(e.measurement(&p).is_none());
    e.store.library.preferences.ping.method = Method::Http;
    assert_eq!(e.measurement(&p).unwrap().latency_ms, Some(77));
    e.store.library.preferences.ping.method = Method::Tcp;
    assert_eq!(e.measurement(&p).unwrap().latency_ms, Some(12));
    let mut edited = p.clone();
    edited.config["server_port"] = json!(2080);
    assert!(e.measurement(&edited).is_none());
}

#[test]
fn endpoint_errors_are_sanitized_and_permissions_are_not_server_failures() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    e.store.library.preferences.ping.method = Method::Icmp;
    for (error, status) in [
        ("probe_icmp_unavailable", Status::Unsupported),
        ("probe_direct_unavailable", Status::Unsupported),
        ("probe_icmp_no_reply", Status::Error),
        ("secret arbitrary raw error", Status::Error),
    ] {
        let run = e.start_ping(vec![id.clone()]).unwrap();
        e.next_url_test(&run.id).unwrap();
        e.finish_url_test(&run.id, &id, Err(error.into()));
        let b = e.snapshot().url_tests.unwrap();
        assert_eq!(b.entries[0].status, status);
        assert!(!serde_json::to_string(&b).unwrap().contains("secret"));
    }
}

#[test]
fn cancelled_tcp_cannot_overwrite_a_new_icmp_run() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    e.store.library.preferences.ping.method = Method::Tcp;
    let tcp = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&tcp.id).unwrap();
    e.cancel_url_tests();
    e.store.library.preferences.ping.method = Method::Icmp;
    let icmp = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&icmp.id).unwrap();
    e.finish_url_test(&tcp.id, &id, Ok(1));
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Testing
    );
    e.finish_url_test(&icmp.id, &id, Ok(7));
    e.clear_url_tests().unwrap();
    for method in [Method::Http, Method::Tcp, Method::Icmp] {
        e.store.library.preferences.ping.method = method;
        assert!(e.measurement(&e.profile(&id).unwrap()).is_none());
    }
}

#[test]
fn ping_preferences_migrate_and_persist_without_changing_library_content() {
    let (dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    e.select(&id).unwrap();
    let path = dir.path().join("library.json");
    let mut legacy = serde_json::to_value(&e.store.library).unwrap();
    legacy["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("ping");
    drop(e);
    let bytes = serde_json::to_vec(&legacy).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(e.store.library.preferences.ping, PingSettings::default());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    e.save_ping_settings(PingSettings {
        url: " https://example.test/new-check ".into(),
        timeout_ms: 1700,
        method: Method::Http,
    })
    .unwrap();
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    e.start_ping(vec![id.clone()]).unwrap();
    let batch = e.snapshot().url_tests.unwrap();
    assert_eq!(batch.url, "https://example.test/new-check");
    assert_eq!(batch.timeout_ms, 1700);
    assert_eq!(batch.entries[0].profile_id, id);
    let mut stored = serde_json::to_value(&e.store.library).unwrap();
    stored["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("ping");
    assert_eq!(stored, legacy);
}

#[test]
fn invalid_saved_ping_settings_leave_disk_and_running_batch_untouched() {
    let (dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = e.start_ping(vec![id]).unwrap();
    let original = std::fs::read(dir.path().join("library.json")).unwrap();
    for url in [
        "file:///tmp/check",
        "https://user:secret@example.test/",
        "https://example.test/#fragment",
        "",
    ] {
        assert_eq!(
            e.save_ping_settings(PingSettings {
                url: url.into(),
                ..PingSettings::default()
            })
            .unwrap_err(),
            "probe_invalid_url"
        );
    }
    for timeout_ms in [0, 99, 10001, u32::MAX] {
        assert_eq!(
            e.save_ping_settings(PingSettings {
                timeout_ms,
                ..PingSettings::default()
            })
            .unwrap_err(),
            "probe_invalid_timeout"
        );
    }
    // The generic preferences path and backup/library validation use the same rules.
    let mut preferences = e.store.library.preferences.clone();
    preferences.ping.url = "ftp://example.test/".into();
    assert_eq!(e.preferences(preferences).unwrap_err(), "probe_invalid_url");
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        original
    );
    assert_eq!(e.store.library.preferences.ping, PingSettings::default());
    assert_eq!(e.snapshot().url_tests.unwrap().id, run.id);
    assert!(!*run.cancelled.borrow());
}

#[test]
fn changing_ping_defaults_applies_only_to_next_run() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.save_ping_settings(PingSettings {
        url: "http://example.test/changed".into(),
        timeout_ms: 750,
        method: Method::Http,
    })
    .unwrap();
    let batch = e.snapshot().url_tests.unwrap();
    assert_eq!(batch.url, PingSettings::default().url);
    assert_eq!(batch.timeout_ms, 3000);
    assert_eq!(batch.entries[0].status, Status::Testing);
    assert!(!*run.cancelled.borrow());
    assert_eq!(
        e.start_ping(vec![id.clone()]).err().as_deref(),
        Some("probe_busy")
    );
    e.finish_url_test(&run.id, &id, Ok(12));
    e.start_ping(vec![id]).unwrap();
    let batch = e.snapshot().url_tests.unwrap();
    assert_eq!(batch.url, "http://example.test/changed");
    assert_eq!(batch.timeout_ms, 750);
}

#[test]
fn invalid_batch_is_atomic_and_credentials_are_rejected() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    for url in [
        "file:///etc/passwd",
        "https://user:secret@example.test/",
        "https://example.test/#secret",
        "invalid",
    ] {
        let mut o = options(&[&id]);
        o.url = url.into();
        assert_eq!(
            e.start_url_tests(o).err().as_deref(),
            Some("probe_invalid_url")
        );
    }
    for timeout in [0, 99, 10001] {
        let mut o = options(&[&id]);
        o.timeout_ms = timeout;
        assert!(e.start_url_tests(o).is_err());
    }
    assert!(e.start_url_tests(options(&[])).is_err());
    assert!(e.start_url_tests(options(&[&id, "missing"])).is_err());
    assert!(e.snapshot().url_tests.is_none());
}

#[test]
fn queue_is_fifo_deduplicated_and_accepts_only_its_current_result() {
    let (_dir, mut e) = setup();
    let a = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let b = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = begin(&mut e, &[&a, &a, &b]);
    assert_eq!(e.next_url_test(&run.id).unwrap().id, a);
    assert!(e.next_url_test(&run.id).is_none());
    assert!(e.start_url_tests(options(&[&b])).is_err());
    e.finish_url_test("wrong-batch", &a, Ok(10));
    e.finish_url_test(&run.id, &b, Ok(10));
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Testing
    );
    e.finish_url_test(&run.id, &a, Ok(0));
    assert_eq!(e.next_url_test(&run.id).unwrap().id, b);
    e.finish_url_test(&run.id, &b, Err("secret credential in raw error".into()));
    let snap = e.snapshot();
    let data = serde_json::to_string(&snap).unwrap();
    assert!(!data.contains("secret credential"));
    let batch = snap.url_tests.unwrap();
    assert_eq!(batch.entries.len(), 2);
    assert_eq!(batch.entries[0].latency_ms, Some(0));
    assert_eq!(batch.entries[1].error.as_deref(), Some("probe_failed"));
}

#[test]
fn cancellation_rejects_late_results_after_a_new_batch() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = begin(&mut e, &[&id]);
    e.next_url_test(&run.id).unwrap();
    e.cancel_url_tests();
    assert!(*run.cancelled.borrow());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Cancelled
    );
    let next = begin(&mut e, &[&id]);
    e.next_url_test(&next.id).unwrap();
    e.finish_url_test(&run.id, &id, Ok(1));
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Testing
    );
    e.finish_url_test(&next.id, &id, Ok(7));
    assert_eq!(e.snapshot().profiles[0]["measurement"]["latencyMs"], 7);
}

#[test]
fn measurements_survive_name_and_favorite_changes_but_not_configuration_changes() {
    let (dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = begin(&mut e, &[&id]);
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test(&run.id, &id, Ok(15));
    let mut p = e.profile(&id).unwrap();
    p.name = "Renamed".into();
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(id.clone()),
        name: p.name,
        group_id: p.group_id,
        kind: p.kind,
        config: p.config,
    })
    .unwrap();
    assert_eq!(e.snapshot().profiles[0]["measurement"]["latencyMs"], 15);
    e.store.library.profiles[0].config["domain_strategy"] = json!("ipv4_only");
    let snap = e.snapshot();
    assert!(snap.profiles[0]["measurement"].is_null());
    assert_eq!(snap.url_tests.unwrap().entries[0].status, Status::Stale);
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(e.snapshot().url_tests.is_none());
    assert!(e.snapshot().profiles[0]["measurement"].is_null());
}

#[test]
fn edited_queued_and_inflight_profiles_never_receive_an_old_measurement() {
    let (_dir, mut e) = setup();
    let a = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let b = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = begin(&mut e, &[&a, &b]);
    e.next_url_test(&run.id).unwrap();
    for p in &mut e.store.library.profiles {
        p.config["domain_strategy"] = json!("ipv4_only");
    }
    e.finish_url_test(&run.id, &a, Ok(5));
    assert!(e.next_url_test(&run.id).is_none());
    assert!(e
        .snapshot()
        .url_tests
        .unwrap()
        .entries
        .iter()
        .all(|e| e.status == Status::Stale && e.latency_ms.is_none()));
}

#[test]
fn test_config_has_no_user_listeners_and_preserves_xray_transport() {
    let (_dir, mut e) = setup();
    let stream = json!({"network":"xhttp", "security":"reality", "realitySettings":{"serverName":"example.test", "publicKey":"private-fixture-value"}, "xhttpSettings":{"path":"/test"}});
    let id = add(
        &mut e,
        ProfileKind::XrayOutbound,
        json!({"protocol":"vless", "settings":{}, "streamSettings":stream}),
    );
    let run = begin(&mut e, &[&id]);
    let probe = e.next_url_test(&run.id).unwrap();
    let Request::Http(request) = probe.request else {
        panic!("expected HTTP");
    };
    let config: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(config["inbounds"], json!([]));
    assert_eq!(config["services"], json!([]));
    let xray: Value = serde_json::from_str(request.xray_config.as_ref().unwrap()).unwrap();
    assert_eq!(xray["outbounds"][0]["streamSettings"], stream);
    assert_eq!(xray["inbounds"].as_array().unwrap().len(), 1);
    assert!(!serde_json::to_string(&e.snapshot())
        .unwrap()
        .contains("private-fixture-value"));
}

#[test]
fn unsupported_profiles_are_explicit_and_other_cached_results_remain() {
    let (_dir, mut e) = setup();
    let a = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let run = begin(&mut e, &[&a]);
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test(&run.id, &a, Ok(4));
    let b = add(
        &mut e,
        ProfileKind::SingBoxConfig,
        json!({"inbounds":[{"type":"tun"}]}),
    );
    let c = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"wireguard"}),
    );
    let run = begin(&mut e, &[&b, &c]);
    assert!(e.next_url_test(&run.id).is_none());
    let snap = e.snapshot();
    assert!(snap
        .url_tests
        .unwrap()
        .entries
        .iter()
        .all(|e| e.status == Status::Unsupported));
    assert_eq!(snap.profiles[0]["measurement"]["latencyMs"], 4);
    e.clear_url_tests().unwrap();
    assert!(e.snapshot().profiles[0]["measurement"].is_null());
}

#[tokio::test]
async fn cancelled_or_missing_core_does_not_touch_the_primary_engine() {
    let (_dir, mut e) = setup();
    let id = add(
        &mut e,
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    );
    let mut run = begin(&mut e, &[&id]);
    let probe = e.next_url_test(&run.id).unwrap();
    assert_eq!(
        probe.execute(&mut run.cancelled).await.unwrap_err(),
        "probe_core_failed"
    );
    e.cancel_url_tests();
    let mut next = begin(&mut e, &[&id]);
    let probe = e.next_url_test(&next.id).unwrap();
    e.cancel_url_tests();
    assert_eq!(
        probe.execute(&mut next.cancelled).await.unwrap_err(),
        "probe_cancelled"
    );
    assert!(e.rpc.is_none());
    assert!(e.snapshot().error.is_none());
}
