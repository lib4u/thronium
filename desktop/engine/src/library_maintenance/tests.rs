use crate::probes::{Method, Options};
use crate::{Engine, ProfileDraft};
use serde_json::json;
use std::path::Path;

fn engine() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, engine)
}

fn add(engine: &mut Engine, name: &str, config: serde_json::Value) -> String {
    engine
        .save_profile(ProfileDraft {
            id: None,
            name: name.into(),
            group_id: crate::store::PERSONAL_GROUP.into(),
            kind: crate::store::ProfileKind::SingBoxOutbound,
            vpn_policy: Default::default(),
            config,
        })
        .unwrap()
}

#[test]
fn only_named_servers_are_resolved_and_written_back_where_they_were_read() {
    let (_dir, mut engine) = engine();
    let named = add(
        &mut engine,
        "Named",
        json!({"type":"socks","server":"server.invalid","server_port":1080}),
    );
    let numeric = add(
        &mut engine,
        "Numeric",
        json!({"type":"socks","server":"192.0.2.10","server_port":1080}),
    );
    let peer = add(
        &mut engine,
        "Peer",
        json!({"type":"wireguard","peers":[{"endpoint":"peer.invalid:51820","public_key":"k"}]}),
    );
    let ids = vec![named.clone(), numeric.clone(), peer.clone()];
    let hosts = engine.resolvable_hosts(&ids);
    assert_eq!(
        hosts,
        vec![
            (named.clone(), "server.invalid".into()),
            (peer.clone(), "peer.invalid".into())
        ]
    );
    let changed = engine
        .apply_resolved_hosts(&[
            (named.clone(), "192.0.2.20".into()),
            (peer.clone(), "2001:db8::1".into()),
            // A profile that is not there and an answer that is not an address.
            ("missing".into(), "192.0.2.30".into()),
            (numeric.clone(), "still.a.name".into()),
        ])
        .unwrap();
    assert_eq!(changed, 2);
    let config = |id: &str| engine.profile(id).unwrap().config;
    assert_eq!(config(&named)["server"], json!("192.0.2.20"));
    assert_eq!(config(&numeric)["server"], json!("192.0.2.10"));
    assert_eq!(
        config(&peer)["peers"][0]["endpoint"],
        json!("[2001:db8::1]:51820")
    );
    // Nothing left to resolve, so a second run is a no-op.
    assert_eq!(engine.resolvable_hosts(&ids), vec![]);
    assert_eq!(
        engine
            .apply_resolved_hosts(&[(named, "192.0.2.20".into())])
            .unwrap(),
        0
    );
}

#[test]
fn resetting_traffic_forgets_one_profile_and_keeps_the_others() {
    let (dir, mut engine) = engine();
    let first = add(
        &mut engine,
        "First",
        json!({"type":"socks","server":"192.0.2.10","server_port":1080}),
    );
    let second = add(
        &mut engine,
        "Second",
        json!({"type":"socks","server":"192.0.2.11","server_port":1080}),
    );
    let mut history = crate::settings::history::History::default();
    for (profile, bytes) in [(&first, 100), (&second, 200)] {
        history.record(
            dir.path(),
            profile,
            "personal",
            vec![crate::traffic::Delta {
                process: "curl".into(),
                upload: bytes,
                download: bytes * 2,
                direct: false,
            }],
            30,
        );
    }
    assert_eq!(history.profile_totals(&first), Some((100, 200)));
    history
        .reset_profiles(dir.path(), std::slice::from_ref(&first))
        .unwrap();
    assert_eq!(history.profile_totals(&first), None);
    assert_eq!(history.profile_totals(&second), Some((200, 400)));
}

#[test]
fn a_finished_manual_test_clears_only_the_unavailable_servers_of_an_opted_in_group() {
    let (_dir, mut engine) = engine();
    let socks = |port: u16| json!({"type":"socks","server":"192.0.2.10","server_port":port});
    let failed = add(&mut engine, "Failed", socks(1080));
    let working = add(&mut engine, "Working", socks(1081));
    let other = add(&mut engine, "Other group", socks(1082));
    engine.add_group("Kept").unwrap();
    let second = engine
        .store
        .library
        .groups
        .iter()
        .find(|g| g.name == "Kept")
        .unwrap()
        .id
        .clone();
    engine.move_profiles(vec![other.clone()], &second).unwrap();
    for group in &mut engine.store.library.groups {
        group.auto_clear_unavailable = group.id == crate::store::PERSONAL_GROUP;
    }
    engine.store.library.preferences.ping.method = Method::Http;
    let run = engine
        .start_url_tests(Options {
            ids: vec![failed.clone(), working.clone(), other.clone()],
            url: "https://example.test/204".into(),
            timeout_ms: 500,
            concurrency: None,
        })
        .unwrap();
    // Report each probe the queue hands out, as a worker does.
    let results = std::collections::BTreeMap::from([
        (failed.clone(), Err("probe_failed".to_string())),
        (other.clone(), Err("probe_failed".to_string())),
        (working.clone(), Ok(42)),
    ]);
    let mut done = 0;
    while let Some(probe) = engine.next_url_test(&run.id) {
        let result = results[&probe.id].clone();
        engine.finish_url_test(&run.id, &probe.id, result);
        done += 1;
        if done < results.len() {
            assert!(
                engine.profile(&failed).is_ok(),
                "an unfinished test removes nothing"
            );
        }
    }
    assert_eq!(done, results.len());
    assert!(engine.profile(&failed).is_err());
    assert!(engine.profile(&working).is_ok());
    assert!(
        engine.profile(&other).is_ok(),
        "other group keeps its server"
    );
}
