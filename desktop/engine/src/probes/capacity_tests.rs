use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, name: &str, port: u16) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":port}),
    })
    .unwrap()
}

#[test]
fn a_single_diagnostic_and_a_batch_never_run_together() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", 1080);
    let b = add(&mut e, "B", 1081);
    e.reserve_probe("single-1").unwrap();
    assert_eq!(e.reserve_probe("single-2").unwrap_err(), "probe_busy");
    for start in [
        Engine::start_ip_tests as fn(&mut Engine, Vec<String>) -> Result<Run, String>,
        Engine::start_speed_tests,
        Engine::start_ping,
    ] {
        assert_eq!(
            start(&mut e, vec![a.clone()]).err().as_deref(),
            Some("probe_busy")
        );
    }
    e.release_probe("single-1");
    e.release_probe("never-reserved");
    let run = e.start_ip_tests(vec![a.clone(), b.clone()]).unwrap();
    let probe = e.next_url_test(&run.id).expect("first entry starts");
    assert_eq!(e.reserve_probe("single-3").unwrap_err(), "probe_busy");
    e.finish_url_test(&run.id, &probe.id, Err("probe_failed".into()));
    // A queued entry still holds the batch: the queue stays busy until it drains.
    assert_eq!(e.reserve_probe("single-3").unwrap_err(), "probe_busy");
    e.cancel_url_tests();
    e.reserve_probe("single-3").unwrap();
    e.release_probe("single-3");
    e.reserve_probe("single-4").unwrap();
}
