use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, name: &str, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config,
    })
    .unwrap()
}
fn socks(port: u16) -> Value {
    json!({"type":"socks","server":"127.0.0.1","server_port":port})
}
fn entries(e: &mut Engine) -> Vec<Measurement> {
    e.snapshot().url_tests.unwrap().entries
}

#[test]
fn ip_batch_prepares_isolated_tests_and_marks_unsupported_entries_without_a_core() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", socks(1080));
    let wg = add(&mut e, "WG without keys", json!({"type":"wireguard"}));
    let run = e.start_ip_tests(vec![a.clone(), wg.clone()]).unwrap();
    let probe = e
        .next_url_test(&run.id)
        .expect("the supported profile is prepared");
    assert_eq!(probe.id, a);
    assert!(probe.owns_execution() && !probe.is_disposable_vpn());
    let testing = entries(&mut e).remove(0);
    assert_eq!((testing.kind, testing.status), (Kind::Ip, Status::Testing));
    assert_eq!(testing.transport.as_deref(), Some("isolated-core"));
    e.finish_url_test_detailed(&run.id, &a, Err("probe_timeout".into()));
    // The unsupported entry advances without any network work once a slot is free.
    assert!(e.next_url_test(&run.id).is_none());
    let batch = e.snapshot().url_tests.unwrap();
    assert_eq!(batch.kind, Kind::Ip);
    let statuses: Vec<_> = batch
        .entries
        .iter()
        .map(|e| (e.status, e.error.clone()))
        .collect();
    assert_eq!(
        statuses,
        [
            (Status::Error, Some("probe_timeout".into())),
            (Status::Unsupported, Some("probe_unsupported".into()))
        ]
    );
    assert!(e.rpc.is_none());
}

#[test]
fn ip_batch_result_publishes_ip_country_and_persists_the_country_cache() {
    let (dir, mut e) = setup();
    let a = add(&mut e, "A", socks(1080));
    let run = e.start_ip_tests(vec![a.clone()]).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(
        &run.id,
        &a,
        Ok(Outcome::Ip {
            ip: "203.0.113.9".into(),
            country: Some("JP".into()),
        }),
    );
    let entry = entries(&mut e).remove(0);
    assert_eq!(entry.status, Status::Ok);
    assert_eq!(entry.ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(entry.country_code.as_deref(), Some("JP"));
    assert!(entry.at.is_some() && entry.latency_ms.is_none());
    let published = serde_json::to_value(&entry).unwrap();
    assert_eq!(published["kind"], "ip");
    assert_eq!(published["transport"], "isolated-core");
    assert_eq!(
        e.store
            .library
            .country_measurements
            .current(&e.store.library, &a)
            .map(|c| c.country_code.clone()),
        Some("JP".into())
    );
    let cache = std::fs::read_to_string(dir.path().join("exit-countries-v1.json")).unwrap();
    assert!(cache.contains("JP") && !cache.contains("203.0.113.9"));
    // Latency rows are untouched by an IP batch.
    assert!(e.measurement(&e.profile(&a).unwrap()).is_none());
}

#[test]
fn ip_batch_result_after_an_edit_or_setting_change_is_stale_and_never_cached() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", socks(1080));
    for change in ["config", "ping-timeout"] {
        let run = e.start_ip_tests(vec![a.clone()]).unwrap();
        e.next_url_test(&run.id).unwrap();
        match change {
            "config" => e.store.library.profiles[0].config["server_port"] = json!(1081),
            _ => e.store.library.preferences.ping.timeout_ms += 100,
        }
        e.finish_url_test_detailed(
            &run.id,
            &a,
            Ok(Outcome::Ip {
                ip: "203.0.113.9".into(),
                country: Some("US".into()),
            }),
        );
        let entry = entries(&mut e).remove(0);
        assert_eq!(
            (entry.status, entry.error.as_deref()),
            (Status::Stale, Some("probe_stale")),
            "{change}"
        );
        assert!(entry.ip.is_none());
        assert!(e
            .store
            .library
            .country_measurements
            .current(&e.store.library, &a)
            .is_none());
    }
}

#[test]
fn speed_batch_measures_one_profile_at_a_time_and_records_bytes() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", socks(1080));
    let b = add(&mut e, "B", socks(1081));
    e.store.library.preferences.ping.method = Method::Auto;
    let run = e.start_speed_tests(vec![a.clone(), b.clone()]).unwrap();
    assert_eq!(run.concurrency, 1);
    let first = e.next_url_test(&run.id).unwrap();
    assert_eq!(first.id, a);
    assert!(
        e.next_url_test(&run.id).is_none(),
        "a speed sample saturates the link"
    );
    e.finish_url_test_detailed(
        &run.id,
        &a,
        Ok(Outcome::Speed(SpeedResult {
            download: "43.95Mbps".into(),
            upload: String::new(),
            latency_ms: Some(38),
            download_bytes: 8_388_608,
            upload_bytes: 0,
        })),
    );
    assert_eq!(e.next_url_test(&run.id).unwrap().id, b);
    e.finish_url_test_detailed(&run.id, &b, Err("probe_timeout".into()));
    let batch = e.snapshot().url_tests.unwrap();
    assert_eq!(batch.kind, Kind::Speed);
    assert_eq!(batch.method, Method::Http, "no Auto fallback for speed");
    let [first, second] = batch.entries.as_slice() else {
        panic!("two entries")
    };
    assert_eq!(first.status, Status::Ok);
    assert_eq!(first.download.as_deref(), Some("43.95Mbps"));
    assert_eq!(first.download_bytes, Some(8_388_608));
    assert_eq!(first.latency_ms, Some(38));
    assert_eq!(
        (second.status, second.error.as_deref()),
        (Status::Error, Some("probe_timeout"))
    );
    assert_eq!(
        second.attempts.len(),
        1,
        "speed never falls back to TCP/ICMP"
    );
}

#[test]
fn ip_and_latency_batches_do_not_share_rows_or_the_busy_queue() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", socks(1080));
    let run = e.start_ip_tests(vec![a.clone()]).unwrap();
    e.next_url_test(&run.id).unwrap();
    assert_eq!(
        e.start_ping(vec![a.clone()]).err().as_deref(),
        Some("probe_busy")
    );
    e.cancel_url_tests();
    let entry = entries(&mut e).remove(0);
    assert_eq!(entry.status, Status::Cancelled);
    let ping = e.start_ping(vec![a.clone()]).unwrap();
    e.next_url_test(&ping.id).unwrap();
    e.finish_url_test(&ping.id, &a, Ok(7));
    assert_eq!(
        e.measurement(&e.profile(&a).unwrap())
            .map(|m| (m.kind, m.latency_ms)),
        Some((Kind::Latency, Some(7)))
    );
    assert_eq!(e.snapshot().url_tests.unwrap().kind, Kind::Latency);
}
