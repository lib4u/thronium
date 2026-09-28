use super::*;
use crate::{
    probes::{HttpFailure, Method, Options, Outcome, Status},
    Engine, ProfileDraft,
};
const URL: &str = "https://example.test/204?token=synthetic-private-query";
fn setup() -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let d:ProfileDraft=serde_json::from_value(json!({"name":"Measured","groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":1080,"password":"latency-private-secret"}})).unwrap();
    let id = e.save_profile(d).unwrap();
    (dir, e, id)
}
fn begin(e: &mut Engine, id: &str) -> String {
    let run = e
        .start_url_tests(Options {
            ids: vec![id.into()],
            url: URL.into(),
            timeout_ms: 1000,
            concurrency: None,
        })
        .unwrap();
    assert!(e.next_url_test(&run.id).is_some());
    run.id
}
fn measure(e: &mut Engine, id: &str, value: Result<Outcome, String>) {
    let batch = begin(e, id);
    e.finish_url_test_detailed(&batch, id, value);
}
fn fresh(e: &Engine, id: &str) -> Option<Option<i32>> {
    e.store
        .library
        .latency_measurements
        .fresh(&e.store.library, id, URL, 60)
        .map(|e| e.latency_ms)
}

#[test]
fn completed_http_cache_reopens_without_url_keys_or_portable_library_changes() {
    let (dir, mut e, id) = setup();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let revision = e.store.generation();
    measure(&mut e, &id, Ok(Outcome::Latency(0)));
    assert_eq!(fresh(&e, &id), Some(Some(0)));
    assert!(e.store.generation() > revision);
    let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
    assert!(
        !text.contains("example.test")
            && !text.contains("synthetic-private-query")
            && !text.contains("latency-private-secret")
    );
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        before
    );
    assert!(serde_json::to_value(&e.store.library)
        .unwrap()
        .get("latencyMeasurements")
        .is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join(FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(fresh(&e, &id), Some(Some(0)));
}
#[test]
fn ttl_boundary_zero_validity_clock_rollback_and_different_url_are_unknown() {
    let (_dir, mut e, id) = setup();
    measure(&mut e, &id, Ok(Outcome::Latency(25)));
    let l = &e.store.library;
    let cache = &l.latency_measurements;
    let at = cache.entries[&id].tested_at;
    assert!(cache.fresh_at(l, &id, URL, 1, at + 60).is_some());
    assert!(cache.fresh_at(l, &id, URL, 1, at + 61).is_none());
    assert!(cache.fresh_at(l, &id, URL, 0, at).is_none());
    assert!(cache.fresh_at(l, &id, URL, 1, at - 1).is_none());
    assert!(cache
        .fresh_at(l, &id, "https://example.test/other", 1, at)
        .is_none());
}
#[test]
fn only_classified_http_failure_replaces_success_not_core_errors_or_cancel() {
    let (dir, mut e, id) = setup();
    measure(&mut e, &id, Ok(Outcome::Latency(25)));
    let original = std::fs::read(dir.path().join(FILE)).unwrap();
    for code in [
        "probe_core_failed",
        "probe_configuration_failed",
        "probe_cancelled",
        "probe_timeout",
        "probe_failed",
        "probe_unsupported",
    ] {
        measure(&mut e, &id, Err(code.into()));
        assert_eq!(
            std::fs::read(dir.path().join(FILE)).unwrap(),
            original,
            "{code}"
        );
    }
    measure(&mut e, &id, Ok(Outcome::HttpFailed(HttpFailure::Timeout)));
    assert_eq!(fresh(&e, &id), Some(None));
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Error
    );
}
#[test]
fn late_result_rejects_changed_profile_or_core_presets_and_rename_remains_valid() {
    let (_dir, mut e, id) = setup();
    measure(&mut e, &id, Ok(Outcome::Latency(25)));
    let batch = begin(&mut e, &id);
    let mut next = e.store.library.clone();
    next.profiles[0].name = "Renamed".into();
    e.store.commit(next).unwrap();
    e.finish_url_test_detailed(&batch, &id, Ok(Outcome::Latency(20)));
    assert_eq!(fresh(&e, &id), Some(Some(20)));
    let batch = begin(&mut e, &id);
    let mut next = e.store.library.clone();
    next.profiles[0].config["server_port"] = json!(1081);
    e.store.commit(next).unwrap();
    e.finish_url_test_detailed(&batch, &id, Ok(Outcome::Latency(5)));
    assert_eq!(fresh(&e, &id), None);
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Stale
    );
    measure(&mut e, &id, Ok(Outcome::Latency(15)));
    let batch = begin(&mut e, &id);
    e.store
        .library
        .settings
        .insert("fragment_default_on".into(), json!(true));
    e.finish_url_test_detailed(&batch, &id, Ok(Outcome::Latency(1)));
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Stale
    );
    assert_eq!(fresh(&e, &id), None);
}
#[test]
fn auto_fallback_waits_for_completion_and_never_ranks_tcp_as_http() {
    let (dir, mut e, id) = setup();
    e.store.library.preferences.ping.method = Method::Auto;
    e.store.library.preferences.ping.url = URL.into();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(&run.id, &id, Ok(Outcome::HttpFailed(HttpFailure::Request)));
    assert!(!dir.path().join(FILE).exists());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Queued
    );
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(&run.id, &id, Ok(Outcome::Latency(1)));
    assert_eq!(fresh(&e, &id), Some(None));
    let before = std::fs::read(dir.path().join(FILE)).unwrap();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(&run.id, &id, Ok(Outcome::HttpFailed(HttpFailure::Tls)));
    e.cancel_url_tests();
    assert_eq!(std::fs::read(dir.path().join(FILE)).unwrap(), before);
    for method in [Method::Tcp, Method::Icmp] {
        e.store.library.preferences.ping.method = method;
        let run = e.start_ping(vec![id.clone()]).unwrap();
        e.next_url_test(&run.id).unwrap();
        e.finish_url_test_detailed(&run.id, &id, Ok(Outcome::Latency(2)));
        assert_eq!(std::fs::read(dir.path().join(FILE)).unwrap(), before);
    }
}
#[test]
fn persistence_failure_retains_previous_cache_but_notices_the_new_probe_result() {
    let (dir, mut e, id) = setup();
    measure(&mut e, &id, Ok(Outcome::Latency(30)));
    let revision = e.store.generation();
    std::fs::remove_file(dir.path().join(FILE)).unwrap();
    std::fs::create_dir(dir.path().join(FILE)).unwrap();
    measure(&mut e, &id, Ok(Outcome::Latency(2)));
    assert_eq!(fresh(&e, &id), Some(Some(30)));
    assert_eq!(e.store.generation(), revision);
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].latency_ms,
        Some(2)
    );
    assert_eq!(
        e.clear_url_tests().unwrap_err(),
        "latency_cache_write_failed"
    );
}
#[test]
fn clearing_results_removes_persisted_http_history_and_keeps_countries() {
    let (dir, mut e, id) = setup();
    let test = e.ip_test(&id).unwrap();
    e.remember_ip_country(&test, &json!({"ip":"203.0.113.46","countryCode":"JP"}))
        .unwrap();
    let countries = std::fs::read(dir.path().join("exit-countries-v1.json")).unwrap();
    measure(&mut e, &id, Ok(Outcome::Latency(20)));
    e.clear_url_tests().unwrap();
    assert_eq!(fresh(&e, &id), None);
    assert_eq!(
        std::fs::read(dir.path().join("exit-countries-v1.json")).unwrap(),
        countries
    );
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(fresh(&e, &id), None);
}
#[test]
fn malformed_or_future_cache_does_not_block_library_open() {
    let (dir, mut e, id) = setup();
    measure(&mut e, &id, Ok(Outcome::Latency(25)));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
    drop(e);
    for bad in [
        json!({"version":99,"entries":{}}),
        json!({"version":1,"entries":{"unknown":{"url":"private"}}}),
    ] {
        std::fs::write(dir.path().join(FILE), bad.to_string()).unwrap();
        let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
        assert!(e.profile(&id).is_ok());
        assert_eq!(fresh(&e, &id), None);
    }
    let mut bad = value;
    bad["entries"][&id]["testedAt"] = json!(now() + 3600);
    std::fs::write(dir.path().join(FILE), bad.to_string()).unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(fresh(&e, &id), None);
}
