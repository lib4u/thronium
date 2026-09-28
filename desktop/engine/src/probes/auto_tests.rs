use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(e.store.library.preferences.ping.method, Method::Auto);
    let id = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Auto fixture".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
        })
        .unwrap();
    (dir, e, id)
}

fn next(e: &mut Engine, run: &Run, method: Method) {
    let probe = e.next_url_test(&run.id).expect("next fallback attempt");
    match probe.request {
        Request::Http(_) => assert_eq!(method, Method::Http),
        Request::Endpoint(req) => assert_eq!(
            req.method.as_deref(),
            Some(if method == Method::Tcp { "tcp" } else { "icmp" })
        ),
        Request::Profile(_) => panic!("latency batches never prepare isolated IP/speed tests"),
    }
    assert!(
        e.next_url_test(&run.id).is_none(),
        "the same profile must not be probed concurrently"
    );
}

#[test]
fn auto_stops_at_first_success_and_preserves_attempt_details() {
    for success in [Method::Http, Method::Tcp, Method::Icmp] {
        let (_dir, mut e, id) = setup();
        let run = e.start_ping(vec![id.clone()]).unwrap();
        let mut methods = vec![];
        for method in [Method::Http, Method::Tcp, Method::Icmp] {
            methods.push(method);
            next(&mut e, &run, method);
            e.finish_url_test(
                &run.id,
                &id,
                if method == success {
                    Ok(7)
                } else {
                    Err("probe_timeout".into())
                },
            );
            if method == success {
                break;
            }
            let entry = &e.snapshot().url_tests.unwrap().entries[0];
            assert_eq!(entry.status, Status::Queued);
            assert!(entry.latency_ms.is_none());
        }
        assert!(e.next_url_test(&run.id).is_none());
        let entry = &e.snapshot().url_tests.unwrap().entries[0];
        assert_eq!(
            (
                entry.method,
                entry.effective_method,
                entry.status,
                entry.latency_ms
            ),
            (Method::Auto, success, Status::Ok, Some(7))
        );
        assert_eq!(
            entry.attempts.iter().map(|a| a.method).collect::<Vec<_>>(),
            methods
        );
        assert!(entry.attempts[..entry.attempts.len() - 1]
            .iter()
            .all(|a| a.error.as_deref() == Some("probe_timeout")));
    }
}

#[test]
fn auto_tries_http_through_a_wireguard_endpoint_and_skips_only_tcp() {
    let (_dir, mut e, id) = setup();
    e.store.library.profiles[0].config = json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.0.0.2/32"],
        "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}],"amnezia_wg":{"jc":2}});
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Http);
    e.finish_url_test(&run.id, &id, Err("probe_timeout".into()));
    next(&mut e, &run, Method::Icmp);
    e.finish_url_test(&run.id, &id, Ok(0));
    let entry = &e.snapshot().url_tests.unwrap().entries[0];
    assert_eq!(
        entry
            .attempts
            .iter()
            .map(|a| a.error.as_deref())
            .collect::<Vec<_>>(),
        [Some("probe_timeout"), Some("probe_tcp_inapplicable"), None]
    );
    assert_eq!(entry.effective_method, Method::Icmp);
    assert_eq!(entry.latency_ms, Some(0));
}
#[test]
fn auto_skips_http_for_an_endpoint_context_a_disposable_core_cannot_own() {
    let (_dir, mut e, id) = setup();
    e.store.library.profiles[0].config = json!({"type":"wireguard","system":true,"private_key":"cHJpdmF0ZQ==","address":["10.0.0.2/32"],
        "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]});
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Icmp);
    e.finish_url_test(&run.id, &id, Ok(0));
    let entry = &e.snapshot().url_tests.unwrap().entries[0];
    assert_eq!(
        entry.attempts[0].error.as_deref(),
        Some("probe_endpoint_context_unsupported")
    );
    assert_eq!(entry.effective_method, Method::Icmp);
}

#[test]
fn exhausted_auto_reports_failure_without_latency_or_raw_errors() {
    let (_dir, mut e, id) = setup();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    for (method, error) in [
        (Method::Http, "secret raw failure"),
        (Method::Tcp, "probe_connection_refused"),
        (Method::Icmp, "probe_icmp_no_reply"),
    ] {
        next(&mut e, &run, method);
        e.finish_url_test(&run.id, &id, Err(error.into()));
    }
    assert!(e.next_url_test(&run.id).is_none());
    let batch = e.snapshot().url_tests.unwrap();
    let entry = &batch.entries[0];
    assert_eq!(entry.status, Status::Error);
    assert_eq!(entry.error.as_deref(), Some("probe_auto_failed"));
    assert_eq!(entry.attempts.len(), 3);
    assert_eq!(entry.attempts[0].error.as_deref(), Some("probe_failed"));
    assert!(entry.latency_ms.is_none());
    assert!(!serde_json::to_string(&batch).unwrap().contains("secret"));
}

#[test]
fn unavailable_auto_is_unsupported_unless_an_attempt_actually_failed() {
    let (_dir, mut e, id) = setup();
    e.store.library.profiles[0].kind = ProfileKind::SingBoxConfig;
    // A background-selecting outbound is not a client the check can measure.
    e.store.library.profiles[0].config = json!({"outbounds":[{"type":"urltest","tag":"auto"}]});
    let run = e.start_ping(vec![id.clone()]).unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    let entry = &e.snapshot().url_tests.unwrap().entries[0];
    assert_eq!(entry.status, Status::Unsupported);
    assert_eq!(entry.error.as_deref(), Some("probe_auto_unsupported"));
    assert_eq!(entry.attempts.len(), 3);
    e.store.library.profiles[0].kind = ProfileKind::SingBoxOutbound;
    e.store.library.profiles[0].config = json!({"type":"direct"});
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Http);
    e.finish_url_test(&run.id, &id, Err("probe_timeout".into()));
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Error
    );
}

#[test]
fn cancel_and_stale_configuration_never_trigger_fallback() {
    for between in [false, true] {
        for stale in [false, true] {
            let (_dir, mut e, id) = setup();
            let run = e.start_ping(vec![id.clone()]).unwrap();
            next(&mut e, &run, Method::Http);
            if between {
                e.finish_url_test(&run.id, &id, Err("probe_timeout".into()));
            }
            if stale {
                e.store.library.profiles[0].config["server_port"] = json!(2080);
            } else {
                e.cancel_url_tests();
            }
            if !between {
                e.finish_url_test(&run.id, &id, Err("probe_timeout".into()));
            }
            assert!(e.next_url_test(&run.id).is_none());
            let entry = &e.snapshot().url_tests.unwrap().entries[0];
            assert_eq!(
                entry.status,
                if stale {
                    Status::Stale
                } else {
                    Status::Cancelled
                }
            );
            assert_eq!(entry.attempts.len(), usize::from(between));
        }
    }
    let (_dir, mut e, id) = setup();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Http);
    e.finish_url_test(&run.id, &id, Err("probe_cancelled".into()));
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(
        e.snapshot().url_tests.unwrap().entries[0].status,
        Status::Cancelled
    );
}

#[test]
fn settings_changes_and_old_batches_do_not_change_auto_sequence_or_caches() {
    let (_dir, mut e, id) = setup();
    let old = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &old, Method::Http);
    e.cancel_url_tests();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Http);
    e.finish_url_test(&old.id, &id, Ok(1));
    e.store.library.preferences.ping.method = Method::Http;
    e.finish_url_test(&run.id, &id, Err("probe_timeout".into()));
    next(&mut e, &run, Method::Tcp);
    e.finish_url_test(&run.id, &id, Ok(9));
    let p = e.profile(&id).unwrap();
    assert!(e.measurement(&p).is_none());
    e.store.library.preferences.ping.method = Method::Auto;
    assert_eq!(e.measurement(&p).unwrap().effective_method, Method::Tcp);
    e.store.library.preferences.ping.method = Method::Tcp;
    assert!(e.measurement(&p).is_none());
}

#[test]
fn explicit_manual_preferences_survive_auto_default_migration() {
    for method in [Method::Auto, Method::Http, Method::Tcp, Method::Icmp] {
        let (dir, mut e, _id) = setup();
        e.save_ping_settings(PingSettings {
            method,
            ..Default::default()
        })
        .unwrap();
        drop(e);
        let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
        assert_eq!(e.store.library.preferences.ping.method, method);
    }
}

#[test]
fn full_sing_client_auto_uses_http_and_stops_on_success() {
    let (_dir, mut e, id) = setup();
    e.store.library.profiles[0].kind = ProfileKind::SingBoxConfig;
    e.store.library.profiles[0].config = json!({"outbounds":[{"type":"direct"}]});
    let run = e.start_ping(vec![id.clone()]).unwrap();
    next(&mut e, &run, Method::Http);
    e.finish_url_test(&run.id, &id, Ok(17));
    assert!(e.next_url_test(&run.id).is_none());
    let batch = e.snapshot().url_tests.unwrap();
    let entry = &batch.entries[0];
    assert_eq!(entry.status, Status::Ok);
    assert_eq!(entry.effective_method, Method::Http);
    assert_eq!(entry.attempts.len(), 1);
    assert_eq!(entry.latency_ms, Some(17));
}
