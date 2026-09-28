use super::*;
use crate::store::ProfileKind;
use std::path::Path;

#[test]
fn individual_import_resumes_after_restart_and_explicit_cancel_stays_cancelled() {
    let (dir, mut e) = setup();
    let group = add(&mut e, "Import", 0);
    let other = add(&mut e, "Other", 0);
    assert_eq!(e.enqueue_subscription_update(&group).unwrap(), 1);
    assert_eq!(e.enqueue_subscription_update(&group).unwrap(), 0);
    assert_eq!(e.subscription_jobs.jobs.len(), 1);
    assert!(e
        .group(&other)
        .unwrap()
        .subscription
        .unwrap()
        .last_update
        .is_none());
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let worker = owner();
    let id = claim(&mut e, &worker);
    assert_eq!(e.subscription_jobs.jobs[0].group_id, group);
    e.release_subscription_worker(&worker).unwrap();
    let next = claim(&mut e, &owner());
    assert_ne!(next, id);
    e.cancel_subscription_jobs().unwrap();
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(e.claim_subscription_job(&owner()).unwrap().is_null());
}

#[test]
fn unwritable_store_reports_failure_and_does_not_spin_the_schedule() {
    let (dir, mut e) = setup();
    let g = add(&mut e, "Storage", 60);
    let file = dir.path().join("library.json");
    let backup = dir.path().join("library.saved");
    std::fs::rename(&file, &backup).unwrap();
    std::fs::create_dir(&file).unwrap();
    let before = state(&e);
    let worker = owner();
    assert!(e.claim_subscription_job(&worker).unwrap().is_null());
    assert_eq!(
        e.subscription_jobs.jobs[0].error.as_deref(),
        Some("subscription_storage_error")
    );
    assert_eq!(state(&e), before);
    e.queue_due_subscriptions();
    assert_eq!(e.subscription_jobs.jobs.len(), 1);
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&backup, &file).unwrap();
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    assert_eq!(e.subscription_jobs.jobs.last().unwrap().group_id, g);
    assert!(e.subscription_job_request(&id, &worker).is_ok());
}

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, engine)
}
fn add(e: &mut Engine, name: &str, interval: u32) -> String {
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: None,
        name: name.into(),
        subscription: Some(Settings {
            name_rules: Default::default(),
            inherit_defaults: Some(false),
            allow_insecure: false,
            timeout_seconds: 30,
            url: "https://example.test/source-secret".into(),
            headers: BTreeMap::from([("Authorization".into(), "header-secret".into())]),
            user_agent: user_agent(),
            via_proxy: false,
            use_provider_routing: false,
            interval_minutes: interval,
        }),
    })
    .unwrap()
}
fn owner() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn claim(e: &mut Engine, owner: &str) -> String {
    e.claim_subscription_job(owner).unwrap()["id"]
        .as_str()
        .unwrap()
        .into()
}
fn draft(group: &str) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Fixture".into(),
        group_id: group.into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    }
}
fn downloaded(e: &mut Engine, id: &str, owner: &str) {
    let request = e.subscription_job_request(id, owner).unwrap();
    e.subscription_job_downloaded(
        id,
        owner,
        request,
        Download {
            metadata: Default::default(),
            body: "fixture".into(),
            usage: None,
        },
    )
    .unwrap();
}
fn state(e: &Engine) -> Value {
    serde_json::to_value(&e.store.library).unwrap()
}

#[test]
fn schedules_default_off_and_use_persisted_success_or_retry_times() {
    let (dir, mut e) = setup();
    let g = add(&mut e, "Auto", 60);
    let local = add(&mut e, "Manual", 0);
    let at = now();
    assert_eq!(
        next_due(e.group(&g).unwrap().subscription.as_ref().unwrap()),
        Some(0)
    );
    assert_eq!(
        next_due(e.group(&local).unwrap().subscription.as_ref().unwrap()),
        None
    );
    e.queue_due_subscriptions_at(at);
    e.queue_due_subscriptions_at(at);
    assert_eq!(e.subscription_jobs.jobs.len(), 1);
    let worker = owner();
    let id = claim(&mut e, &worker);
    assert_eq!(e.subscription_jobs.jobs[0].status, Status::Downloading);
    e.fail_subscription_job(&id, &worker, "subscription_network_error")
        .unwrap();
    let attempted = e
        .group(&g)
        .unwrap()
        .subscription
        .unwrap()
        .last_update
        .unwrap()
        .at;
    assert_eq!(
        next_due(e.group(&g).unwrap().subscription.as_ref().unwrap()),
        Some(attempted + 300)
    );
    e.queue_due_subscriptions_at(attempted + 299);
    assert_eq!(e.subscription_jobs.jobs.len(), 1);
    e.queue_due_subscriptions_at(attempted + 300);
    assert_eq!(e.subscription_jobs.jobs.len(), 2);
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        next_due(reopened.group(&g).unwrap().subscription.as_ref().unwrap()),
        Some(attempted + 300)
    );
    let old: Settings = serde_json::from_value(json!({"url":"https://example.test"})).unwrap();
    assert_eq!(old.interval_minutes, 0);
    let bad: Settings =
        serde_json::from_value(json!({"url":"https://example.test","intervalMinutes":43201}))
            .unwrap();
    assert_eq!(
        bad.validate().err().as_deref(),
        Some("invalid_subscription_interval")
    );
}

#[test]
fn queue_is_fifo_deduplicated_and_has_one_worker() {
    let (_dir, mut e) = setup();
    let first = add(&mut e, "One", 0);
    let second = add(&mut e, "Two", 0);
    assert_eq!(e.enqueue_subscription_updates().unwrap(), 2);
    assert_eq!(e.enqueue_subscription_updates().unwrap(), 0);
    let a = owner();
    let b = owner();
    let id = claim(&mut e, &a);
    assert_eq!(e.subscription_jobs.jobs[0].group_id, first);
    assert!(e.claim_subscription_job(&b).unwrap().is_null());
    assert!(e.subscription_job_request(&id, &b).is_err());
    e.fail_subscription_job(&id, &a, "subscription_network_error")
        .unwrap();
    let next = claim(&mut e, &b);
    assert_ne!(next, id);
    assert_eq!(e.subscription_jobs.jobs[1].group_id, second);
    e.clear_subscription_jobs();
    assert_eq!(e.subscription_jobs.jobs.len(), 1);
    assert_eq!(e.subscription_jobs.jobs[0].id, next);
}

#[test]
fn manual_downloads_and_previews_take_precedence_without_becoming_stale() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Manual", 0);
    let worker = owner();
    let request_id = owner();
    let request = e.begin_manual_subscription(&g, &request_id).unwrap();
    e.enqueue_subscription_updates().unwrap();
    assert!(e.claim_subscription_job(&worker).unwrap().is_null());
    e.end_manual_subscription(&g, &request_id);
    let result = e
        .subscription_downloaded(
            request,
            Download {
                metadata: Default::default(),
                body: "fixture".into(),
                usage: None,
            },
        )
        .unwrap();
    let token = result["ticket"].as_str().unwrap();
    e.preview_subscription(token, vec![draft(&g)]).unwrap();
    assert!(e.claim_subscription_job(&worker).unwrap().is_null());
    e.cancel_subscription_jobs().unwrap();
    e.apply_subscription(token).unwrap();
    assert_eq!(e.store.library.profiles.len(), 1);
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    assert_eq!(
        e.begin_manual_subscription(&g, &owner()).err().as_deref(),
        Some("subscription_group_busy")
    );
    assert!(e.subscription_job_request(&id, &worker).is_ok());
}

#[tokio::test]
async fn automatic_apply_requires_real_core_validation_and_errors_preserve_profiles() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Check", 0);
    let worker = owner();
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    assert_eq!(
        e.prepare_subscription_job(&id, &worker, vec![draft(&g)], Omitted::default())
            .unwrap(),
        1
    );
    let before = state(&e);
    assert_eq!(
        e.apply_subscription_job(&id, &worker).err().as_deref(),
        Some("subscription_validation_required")
    );
    assert_eq!(
        e.check_subscription_job(&id, &worker)
            .await
            .err()
            .as_deref(),
        // No Core here: the stage that failed names itself, not a Core rejection.
        Some("core_missing")
    );
    assert_eq!(state(&e), before);
    assert!(e.store.library.profiles.is_empty());
    e.fail_subscription_job(&id, &worker, "core_missing")
        .unwrap();
    assert_eq!(
        e.subscription_jobs.jobs[0].error.as_deref(),
        Some("core_missing")
    );
    assert!(e.store.library.profiles.is_empty());
    assert!(e.subscription_tickets.is_empty());
}

#[test]
fn unchanged_updates_need_no_recheck_and_preserve_selection_and_local_entries() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Existing", 60);
    let request = e.subscription_request(&g).unwrap();
    let result = e
        .subscription_downloaded(
            request,
            Download {
                metadata: Default::default(),
                body: "fixture".into(),
                usage: None,
            },
        )
        .unwrap();
    let token = result["ticket"].as_str().unwrap();
    e.preview_subscription(token, vec![draft(&g)]).unwrap();
    e.apply_subscription(token).unwrap();
    let id = e.store.library.profiles[0].id.clone();
    e.favorite(&id).unwrap();
    let mut local = draft(&g);
    local.name = "Local".into();
    let local_id = e.save_profile(local).unwrap();
    e.select(&local_id).unwrap();
    let worker = owner();
    e.enqueue_subscription_updates().unwrap();
    let job = claim(&mut e, &worker);
    downloaded(&mut e, &job, &worker);
    assert_eq!(
        e.prepare_subscription_job(&job, &worker, vec![draft(&g)], Omitted::default())
            .unwrap(),
        0
    );
    e.apply_subscription_job(&job, &worker).unwrap();
    assert_eq!(e.subscription_jobs.jobs[0].status, Status::Unchanged);
    assert_eq!(e.store.library.profiles.len(), 2);
    assert!(e.profile(&id).unwrap().favorite);
    assert_eq!(e.store.library.selected, Some(local_id));
    let s = e.group(&g).unwrap().subscription.unwrap();
    assert_eq!(next_due(&s), Some(s.last_update.unwrap().at + 3600));
}

#[test]
fn cancellation_and_worker_reload_reject_every_late_stage() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Cancel", 60);
    let worker = owner();
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    let request = e.subscription_job_request(&id, &worker).unwrap();
    assert_eq!(e.cancel_subscription_jobs().unwrap(), vec![id.clone()]);
    assert!(e
        .subscription_job_downloaded(
            &id,
            &worker,
            request,
            Download {
                metadata: Default::default(),
                body: "late".into(),
                usage: None
            }
        )
        .is_err());
    assert!(e.store.library.profiles.is_empty());
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    e.prepare_subscription_job(&id, &worker, vec![draft(&g)], Omitted::default())
        .unwrap();
    assert_eq!(
        e.release_subscription_worker(&worker).unwrap(),
        vec![id.clone()]
    );
    assert!(e.apply_subscription_job(&id, &worker).is_err());
    assert!(e.subscription_tickets.is_empty());
    assert!(e.store.library.profiles.is_empty());
    assert_eq!(
        e.subscription_jobs.jobs.last().unwrap().error.as_deref(),
        Some("subscription_worker_interrupted")
    );
}

#[test]
fn changed_sources_and_expired_workers_cannot_commit_or_leak_secrets() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Source", 60);
    e.enqueue_subscription_updates().unwrap();
    let mut group = e.group(&g).unwrap();
    group
        .subscription
        .as_mut()
        .unwrap()
        .settings
        .headers
        .insert("X-Token".into(), "new-secret".into());
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: group.name,
        subscription: group.subscription.map(|s| s.settings),
    })
    .unwrap();
    assert!(e.claim_subscription_job(&owner()).unwrap().is_null());
    assert_eq!(e.subscription_jobs.jobs[0].status, Status::Cancelled);
    // An enabled schedule may immediately queue a new job for the edited source.
    e.enqueue_subscription_updates().unwrap();
    let worker = owner();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    let i = e.job_index(&id, &worker).unwrap();
    e.subscription_jobs.jobs[i].touched = Instant::now() - LEASE - Duration::from_secs(1);
    e.queue_due_subscriptions();
    assert!(e.subscription_tickets.is_empty());
    assert!(e.apply_subscription_job(&id, &worker).is_err());
    let snapshot = serde_json::to_string(&e.snapshot()).unwrap();
    assert!(!snapshot.contains("secret"));
}

#[test]
fn warning_jobs_wait_for_review_and_raw_errors_are_never_persisted() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Warnings", 60);
    let worker = owner();
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    e.fail_subscription_job(&id, &worker, "subscription_untransferred_parameters")
        .unwrap();
    assert_eq!(e.subscription_jobs.jobs[0].status, Status::NeedsReview);
    let s = e.group(&g).unwrap().subscription.unwrap();
    assert_eq!(next_due(&s), Some(s.last_update.unwrap().at + 3600));
    assert!(e.subscription_tickets.is_empty());
    assert!(e.store.library.profiles.is_empty());
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    e.fail_subscription_job(&id, &worker, "decode source-secret header-secret")
        .unwrap();
    let snapshot = serde_json::to_string(&e.snapshot()).unwrap();
    assert!(snapshot.contains("subscription_update_failed"));
    assert!(!snapshot.contains("secret"));
}

#[test]
fn omitted_rows_are_counted_on_the_job_and_keep_the_applied_update_visible() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Partial", 0);
    let worker = owner();
    e.enqueue_subscription_updates().unwrap();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    let omitted = Omitted {
        skipped: 2,
        warned: 1,
    };
    e.prepare_subscription_job(&id, &worker, vec![draft(&g)], omitted)
        .unwrap();
    let job = e
        .subscription_jobs
        .jobs
        .iter()
        .find(|j| j.id == id)
        .unwrap();
    assert_eq!((job.counts.skipped, job.counts.warned), (2, 1));
    // What could not be imported asks for review instead of discarding the rest.
    let reviewed = LastUpdate::of(&[], omitted);
    assert_eq!(reviewed.status, Status::NeedsReview);
    assert_eq!(reviewed.counts.skipped, 2);
    assert_eq!(reviewed.counts.warned, 1);
    assert!(reviewed.error.is_none());
    assert_eq!(
        LastUpdate::of(&[], Omitted::default()).status,
        Status::Unchanged
    );
}

/// Validating a large subscription can outlast both the ten-minute review of
/// its download and the job lease. Progress and the host's renewal keep them
/// alive; an idle worker still expires.
#[test]
fn a_long_validation_keeps_its_download_and_lease_alive() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Source", 60);
    e.enqueue_subscription_updates().unwrap();
    let worker = owner();
    let id = claim(&mut e, &worker);
    downloaded(&mut e, &id, &worker);
    assert_eq!(
        e.prepare_subscription_job(&id, &worker, vec![draft(&g)], Default::default())
            .unwrap(),
        1
    );
    let i = e.job_index(&id, &worker).unwrap();
    let token = e.subscription_jobs.jobs[i].ticket.clone().unwrap();
    let old = Instant::now() - Duration::from_secs(590);
    e.subscription_tickets.get_mut(&token).unwrap().used = old;
    e.subscription_jobs.jobs[i].touched = Instant::now() - LEASE + Duration::from_secs(5);
    let request = e.subscription_job_check_request(&id, &worker).unwrap();
    assert!(
        e.subscription_tickets[&token].used > old,
        "progress renews the review"
    );
    // The check itself runs past the lease; the host renews it meanwhile.
    e.subscription_jobs.jobs[i].touched = Instant::now() - LEASE + Duration::from_secs(5);
    e.renew_subscription_job(&id, &worker).unwrap();
    e.queue_due_subscriptions();
    assert!(e.subscription_jobs.jobs[i].status.active());
    e.subscription_job_checked(&id, &worker, request.checked)
        .unwrap();
    e.subscription_jobs.jobs[i].touched = Instant::now() - LEASE - Duration::from_secs(1);
    e.queue_due_subscriptions();
    assert_eq!(
        e.renew_subscription_job(&id, &worker).err().as_deref(),
        Some("subscription_job_cancelled"),
        "a worker that stopped renewing loses the job"
    );
}
