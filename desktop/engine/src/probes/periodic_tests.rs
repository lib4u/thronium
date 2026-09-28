use super::periodic::{ENABLED, INTERVAL_MINUTES, KIND};
use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, name: &str, port: u16, favorite: bool) -> String {
    let id = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: name.into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":port}),
        })
        .unwrap();
    if favorite {
        e.favorite(&id).unwrap();
    }
    id
}
async fn configure(e: &mut Engine, enabled: bool, minutes: i64, kind: &str) {
    let previous = crate::settings::section(&e.store.library, "testing");
    let mut next = previous.clone();
    next[ENABLED] = json!(enabled);
    next[INTERVAL_MINUTES] = json!(minutes);
    next[KIND] = json!(kind);
    e.save_settings("testing", previous, next).await.unwrap();
}

#[tokio::test]
async fn nothing_runs_until_enabled_and_the_first_check_waits_one_interval() {
    let (_dir, mut e) = setup();
    let favorite = add(&mut e, "Favourite", 1080, true);
    add(&mut e, "Plain", 1081, false);
    assert!(
        e.periodic_probe_tick(1_000).is_none(),
        "disabled by default"
    );
    assert!(e.periodic_probe_tick(1_000_000).is_none());
    configure(&mut e, true, 2, "latency").await;
    assert!(e.periodic_probe_tick(10_000).is_none(), "arming tick");
    assert!(e.periodic_probe_tick(10_119).is_none(), "one second early");
    let run = e
        .periodic_probe_tick(10_120)
        .expect("due after two minutes");
    let batch = e.probes.batch.as_ref().unwrap();
    assert_eq!(batch.id, run.id);
    assert_eq!(batch.source, Source::Periodic);
    assert_eq!(batch.kind, Kind::Latency);
    assert_eq!(
        batch
            .entries
            .iter()
            .map(|m| m.profile_id.as_str())
            .collect::<Vec<_>>(),
        [favorite.as_str()],
        "only favourites are measured"
    );
    assert!(
        e.periodic_probe_tick(10_121).is_none(),
        "the running batch owns the slot"
    );
}

#[tokio::test]
async fn periodic_runs_defer_to_manual_measurements_and_stop_when_switched_off() {
    let (_dir, mut e) = setup();
    let favorite = add(&mut e, "Favourite", 1080, true);
    configure(&mut e, true, 1, "ip").await;
    assert!(e.periodic_probe_tick(0).is_none());
    e.reserve_probe("dialog").unwrap();
    assert!(
        e.periodic_probe_tick(60).is_none(),
        "a single measurement holds the queue"
    );
    e.release_probe("dialog");
    let run = e.periodic_probe_tick(75).unwrap();
    let batch = e.probes.batch.as_ref().unwrap();
    assert_eq!((batch.kind, batch.source), (Kind::Ip, Source::Periodic));
    assert_eq!(
        e.start_ip_tests(vec![favorite.clone()]).err().as_deref(),
        Some("probe_busy")
    );
    configure(&mut e, false, 1, "ip").await;
    assert!(e.periodic_probe_tick(76).is_none());
    let batch = e.probes.batch.as_ref().unwrap();
    assert_eq!(batch.id, run.id);
    assert!(
        batch.entries.iter().all(|m| m.status == Status::Cancelled),
        "switching the option off cancels its own batch"
    );
    assert!(*run.cancelled.borrow());
    // A manual batch is never cancelled by the schedule.
    let manual = e.start_ip_tests(vec![favorite]).unwrap();
    assert!(e.periodic_probe_tick(77).is_none());
    assert!(!*manual.cancelled.borrow());
    assert_eq!(e.probes.batch.as_ref().unwrap().source, Source::Manual);
}

#[tokio::test]
async fn a_finished_periodic_row_is_journaled_with_its_own_source_and_the_next_run_waits_a_full_interval(
) {
    let (_dir, mut e) = setup();
    let favorite = add(&mut e, "Favourite", 1080, true);
    configure(&mut e, true, 1, "latency").await;
    assert!(e.periodic_probe_tick(0).is_none());
    let run = e.periodic_probe_tick(60).unwrap();
    let probe = e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(&run.id, &probe.id, Ok(Outcome::Latency(42)));
    let view = e.measurement_journal();
    assert_eq!(view["entries"][0]["source"], "periodic");
    assert_eq!(view["entries"][0]["profileId"], favorite);
    assert_eq!(view["entries"][0]["latencyMs"], 42);
    assert!(
        e.periodic_probe_tick(100).is_none(),
        "the interval counts from the last start"
    );
    assert!(e.periodic_probe_tick(120).is_some());
    // Removing the last favourite arms the schedule again without a batch.
    let mut without = e.store.library.clone();
    without.profiles.iter_mut().for_each(|p| p.favorite = false);
    e.store.commit(without).unwrap();
    assert!(e.periodic_probe_tick(240).is_none());
    assert!(e.periodic_probe_tick(241).is_none());
}

#[tokio::test]
async fn periodic_speed_uses_one_slot_only_favourites_and_the_shared_result_journal() {
    let (_dir, mut e) = setup();
    let favorite = add(&mut e, "Favourite speed", 1080, true);
    add(&mut e, "Not scheduled", 1081, false);
    configure(&mut e, true, 1, "speed").await;
    assert!(e.periodic_probe_tick(100).is_none());
    let run = e.periodic_probe_tick(160).unwrap();
    assert_eq!(
        run.concurrency, 1,
        "speed tests must not compete with each other"
    );
    let batch = e.probes.batch.as_ref().unwrap();
    assert_eq!((batch.kind, batch.source), (Kind::Speed, Source::Periodic));
    assert_eq!(batch.entries.len(), 1);
    assert_eq!(batch.entries[0].profile_id, favorite);
    let probe = e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(
        &run.id,
        &probe.id,
        Ok(Outcome::Speed(SpeedResult {
            download: "42 Mbps".into(),
            upload: "12 Mbps".into(),
            latency_ms: Some(13),
            download_bytes: 1000,
            upload_bytes: 200,
        })),
    );
    let journal = e.measurement_journal();
    assert_eq!(journal["entries"][0]["kind"], "speed");
    assert_eq!(journal["entries"][0]["source"], "periodic");
    assert_eq!(journal["entries"][0]["download"], "42 Mbps");
    assert_eq!(journal["entries"][0]["upload"], "12 Mbps");
    assert!(e.periodic_probe_tick(219).is_none());
    assert!(e.periodic_probe_tick(220).is_some());
}

#[tokio::test]
async fn schedule_edits_cancel_only_the_old_periodic_batch_and_wait_a_new_interval() {
    let (_dir, mut e) = setup();
    let favorite = add(&mut e, "Favourite", 1080, true);
    configure(&mut e, true, 1, "speed").await;
    e.periodic_probe_tick(100);
    let speed = e.periodic_probe_tick(160).unwrap();
    configure(&mut e, true, 2, "ip").await;
    assert!(
        *speed.cancelled.borrow(),
        "settings commit cancels before the next timer tick"
    );
    assert!(e.periodic_probe_tick(161).is_none());
    assert!(e
        .probes
        .batch
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .all(|e| e.status == Status::Cancelled));
    assert!(e.periodic_probe_tick(280).is_none());
    let ip = e.periodic_probe_tick(281).unwrap();
    configure(&mut e, true, 3, "ip").await;
    assert!(e.periodic_probe_tick(282).is_none());
    assert!(*ip.cancelled.borrow());
    let manual = e.start_speed_tests(vec![favorite]).unwrap();
    configure(&mut e, true, 1, "latency").await;
    assert!(e.periodic_probe_tick(283).is_none());
    assert!(!*manual.cancelled.borrow());
    assert_eq!(e.probes.batch.as_ref().unwrap().source, Source::Manual);
    configure(&mut e, false, 1, "latency").await;
    assert!(e.periodic_probe_tick(500).is_none());
    assert!(!*manual.cancelled.borrow());
}

#[tokio::test]
async fn unrelated_settings_keep_the_deadline_and_clock_rollback_rearms_it() {
    let (_dir, mut e) = setup();
    add(&mut e, "Favourite", 1080, true);
    configure(&mut e, true, 1, "latency").await;
    e.periodic_probe_tick(100);
    let previous = crate::settings::section(&e.store.library, "testing");
    let mut next = previous.clone();
    next["test_concurrent"] = json!(3);
    e.save_settings("testing", previous, next).await.unwrap();
    assert!(e.periodic_probe_tick(150).is_none());
    assert!(e.periodic_probe_tick(160).is_some());
    e.cancel_url_tests();
    assert!(e.periodic_probe_tick(20).is_none());
    assert!(e.periodic_probe_tick(79).is_none());
    assert!(e.periodic_probe_tick(80).is_some());
}

#[tokio::test]
async fn failed_settings_write_keeps_the_running_periodic_batch_and_its_schedule() {
    let (_dir, mut e) = setup();
    add(&mut e, "Favourite", 1080, true);
    configure(&mut e, true, 1, "speed").await;
    e.periodic_probe_tick(0);
    let run = e.periodic_probe_tick(60).unwrap();
    let previous = crate::settings::section(&e.store.library, "testing");
    let mut next = previous.clone();
    next[ENABLED] = json!(false);
    e.store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert!(e.save_settings("testing", previous, next).await.is_err());
    assert!(!*run.cancelled.borrow());
    assert_eq!(
        crate::settings::value(&e.store.library, ENABLED),
        json!(true)
    );
    assert!(e.periodic_probe_tick(61).is_none());
    assert_eq!(e.probes.batch.as_ref().unwrap().id, run.id);
}

/// A background check of favorites gives way to a connection the user asked
/// for: measuring a pool before connecting cancels it instead of failing with
/// `probe_busy`. A manual batch is not cancelled.
#[tokio::test]
async fn connecting_through_a_measured_pool_cancels_a_running_periodic_check() {
    let (_dir, mut e) = setup();
    add(&mut e, "First", 1080, true);
    add(&mut e, "Second", 1081, true);
    configure(&mut e, true, 2, "latency").await;
    assert!(e.periodic_probe_tick(10_000).is_none());
    let periodic = e.periodic_probe_tick(10_120).unwrap();
    e.next_url_test(&periodic.id).unwrap();
    let plan = e
        .connection_measurements(crate::auto_selector::AUTO_SELECT_ID)
        .unwrap()
        .expect("the quick pool measures before it connects");
    let pool = &plan.pools[0];
    let sweep = e.start_preflight_tests(pool, &pool.ids).unwrap();
    let batch = e.probes.batch.as_ref().unwrap();
    assert_eq!(
        (batch.id.as_str(), batch.source),
        (sweep.id.as_str(), Source::AutoSelect)
    );
    e.cancel_url_tests();
    let ids = e
        .store
        .library
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();
    let manual = e.start_ip_tests(ids).unwrap();
    e.next_url_test(&manual.id).unwrap();
    assert_eq!(
        e.start_preflight_tests(pool, &pool.ids).err().as_deref(),
        Some("probe_busy")
    );
}

/// A cancelled pool sweep leaves no row measurement behind either.
#[test]
fn a_cancelled_quick_sweep_never_becomes_a_row_measurement() {
    let (_dir, mut e) = setup();
    let ids = [
        add(&mut e, "First", 1080, false),
        add(&mut e, "Second", 1081, false),
    ];
    e.store.library.preferences.ping.method = Method::Http;
    let plan = e
        .connection_measurements(crate::auto_selector::AUTO_SELECT_ID)
        .unwrap()
        .unwrap();
    let pool = &plan.pools[0];
    let run = e.start_preflight_tests(pool, &pool.ids).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.cancel_url_test_batch(&run.id);
    for id in &ids {
        assert!(e.measurement(&e.profile(id).unwrap()).is_none(), "{id}");
    }
    assert!(e.probes.cache.is_empty());
}

/// More favorites than one batch holds are checked in turn instead of never.
#[tokio::test]
async fn favorites_beyond_one_batch_are_checked_in_turn() {
    let (_dir, mut e) = setup();
    let template = e.store.library.profiles.len();
    add(&mut e, "Template", 1080, true);
    let base = e.store.library.profiles[template].clone();
    for i in 0..1500 {
        e.store.library.profiles.push(crate::store::Profile {
            id: format!("favorite-{i:04}"),
            name: format!("Favorite {i}"),
            ..base.clone()
        });
    }
    configure(&mut e, true, 1, "latency").await;
    assert!(e.periodic_probe_tick(10_000).is_none());
    let first = e.periodic_probe_tick(10_060).unwrap();
    let ids = |e: &Engine| -> Vec<String> {
        e.probes
            .batch
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|m| m.profile_id.clone())
            .collect()
    };
    let batch = ids(&e);
    assert_eq!(batch.len(), MAX_BATCH);
    e.cancel_url_test_batch(&first.id);
    e.periodic_probe_tick(10_120).unwrap();
    let next = ids(&e);
    assert_eq!(next.len(), MAX_BATCH);
    assert_eq!(
        next[0], "favorite-0999",
        "the next slice continues the list"
    );
    let checked: std::collections::HashSet<_> = batch.iter().chain(&next).collect();
    assert_eq!(checked.len(), 1501, "every favorite was measured");
}
