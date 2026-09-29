//! Checking an automatic update as one batch: all servers are saved after one
//! Core check, a rejected server is narrowed down and skipped, and failing
//! provider routing is turned off instead of blocking the update.
use super::super::validation::{run, Checker};
use super::*;
use crate::proto::LoadConfigReq;
use crate::subscriptions::provider_routing::ProviderRouting;

/// A scripted Core: rejects every request whose configuration contains one
/// of `rejects`, and counts the checks it was asked for.
#[derive(Default)]
struct Core {
    rejects: Vec<&'static str>,
    calls: usize,
}
impl Checker for Core {
    async fn check(&mut self, request: &LoadConfigReq) -> Result<Result<(), String>, String> {
        self.calls += 1;
        let config = request.core_config.as_deref().unwrap_or_default();
        Ok(if self.rejects.iter().any(|r| config.contains(r)) {
            Err("subscription_configuration_rejected".into())
        } else {
            Ok(())
        })
    }
}

fn server(group: &str, i: usize, extra: Value) -> ProfileDraft {
    let mut draft = draft(group);
    draft.name = format!("Server {i}");
    draft.config = json!({"type":"socks","server":format!("192.0.2.{i}"),"server_port":1080});
    if let (Some(config), Some(extra)) = (draft.config.as_object_mut(), extra.as_object()) {
        config.extend(extra.clone());
    }
    draft
}
fn servers(group: &str, n: usize) -> Vec<ProfileDraft> {
    (1..=n).map(|i| server(group, i, json!({}))).collect()
}
/// Claims the queued job, downloads it with `metadata` and prepares `drafts`.
fn prepared(
    e: &mut Engine,
    worker: &str,
    metadata: Metadata,
    drafts: Vec<ProfileDraft>,
) -> (String, usize) {
    e.enqueue_subscription_updates().unwrap();
    let id = claim(e, worker);
    let request = e.subscription_job_request(&id, worker).unwrap();
    let body = "fixture".into();
    let download = Download {
        metadata,
        body,
        usage: None,
    };
    e.subscription_job_downloaded(&id, worker, request, download)
        .unwrap();
    let checks = e
        .prepare_subscription_job(&id, worker, drafts, Omitted::default())
        .unwrap();
    (id, checks)
}
/// Runs the check with `core`, reporting stages to the job as the host does.
async fn checked(e: &mut Engine, id: &str, worker: &str, core: &mut Core) -> Vec<Status> {
    let request = e.subscription_job_check_request(id, worker).unwrap();
    let mut stages = vec![];
    let verdict = run(&request, core, |stage| {
        e.subscription_job_stage(id, worker, stage).unwrap();
        stages.push(stage);
        std::future::ready(())
    })
    .await
    .unwrap();
    e.subscription_job_checked(id, worker, verdict).unwrap();
    stages
}
fn job<'a>(e: &'a Engine, id: &str) -> &'a Job {
    e.subscription_jobs
        .jobs
        .iter()
        .find(|j| j.id == id)
        .unwrap()
}

#[tokio::test]
async fn one_core_check_saves_every_server_and_the_geodata_stage_is_reported() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Batch", 0);
    let worker = owner();
    let (id, checks) = prepared(&mut e, &worker, Default::default(), servers(&g, 58));
    assert_eq!(checks, 58);
    // Routing lists are prepared before anything is checked.
    assert_eq!(job(&e, &id).status, Status::Geodata);
    let mut core = Core::default();
    let stages = checked(&mut e, &id, &worker, &mut core).await;
    assert_eq!(stages, [Status::Geodata, Status::Checking]);
    assert_eq!(core.calls, 1, "58 servers are one pool, one Core check");
    assert_eq!((job(&e, &id).checked, job(&e, &id).total), (58, 58));
    e.apply_subscription_job(&id, &worker).unwrap();
    assert_eq!(e.store.library.profiles.len(), 58);
    let done = job(&e, &id);
    assert_eq!(done.status, Status::Updated);
    assert_eq!((done.counts.added, done.counts.skipped), (58, 0));
    assert!(done.error.is_none());
}

#[tokio::test]
async fn a_rejected_server_is_skipped_and_counted_while_the_rest_are_saved() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Partial", 0);
    let worker = owner();
    let mut drafts = servers(&g, 12);
    drafts[6] = server(&g, 66, json!({}));
    let (id, _) = prepared(&mut e, &worker, Default::default(), drafts);
    let mut core = Core {
        rejects: vec!["192.0.2.66"],
        ..Default::default()
    };
    checked(&mut e, &id, &worker, &mut core).await;
    assert!(core.calls < 12, "halving finds one server: {}", core.calls);
    e.apply_subscription_job(&id, &worker).unwrap();
    let saved = &e.store.library.profiles;
    assert_eq!(saved.len(), 11);
    assert!(saved.iter().all(|p| p.config["server"] != "192.0.2.66"));
    let done = job(&e, &id);
    assert_eq!(done.status, Status::NeedsReview);
    assert_eq!(
        done.error.as_deref(),
        Some("subscription_profiles_rejected")
    );
    assert_eq!((done.counts.added, done.counts.skipped), (11, 1));
    let last = e
        .group(&g)
        .unwrap()
        .subscription
        .unwrap()
        .last_update
        .unwrap();
    assert_eq!(last.status, Status::NeedsReview);
    assert_eq!(last.counts.skipped, 1);

    // An updated server the Core rejects keeps its saved version.
    let before = saved.iter().find(|p| p.name == "Server 1").unwrap().clone();
    let mut drafts = servers(&g, 12);
    drafts[6] = server(&g, 66, json!({}));
    drafts[0] = server(&g, 1, json!({"username":"rejected-user"}));
    drafts[1] = server(&g, 2, json!({"username":"accepted-user"}));
    let (id, checks) = prepared(&mut e, &worker, Default::default(), drafts);
    assert_eq!(checks, 3, "two updated servers and the one skipped before");
    let mut core = Core {
        rejects: vec!["rejected-user", "192.0.2.66"],
        ..Default::default()
    };
    checked(&mut e, &id, &worker, &mut core).await;
    e.apply_subscription_job(&id, &worker).unwrap();
    assert_eq!(e.profile(&before.id).unwrap().config, before.config);
    let updated = e
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.name == "Server 2");
    assert_eq!(updated.unwrap().config["username"], "accepted-user");
    let done = job(&e, &id);
    assert_eq!((done.counts.updated, done.counts.skipped), (1, 2));
    assert_eq!(done.status, Status::NeedsReview);

    // When every changed server fails, nothing is saved and the job fails.
    let mut drafts = servers(&g, 12);
    drafts[6] = server(&g, 66, json!({}));
    let (id, _) = prepared(&mut e, &worker, Default::default(), drafts);
    let request = e.subscription_job_check_request(&id, &worker).unwrap();
    let mut core = Core {
        rejects: vec!["192.0.2."],
        ..Default::default()
    };
    let error = run(&request, &mut core, |_| std::future::ready(())).await;
    assert_eq!(
        error.err().as_deref(),
        Some("subscription_configuration_rejected")
    );
}

#[tokio::test]
async fn failing_provider_routing_is_turned_off_and_the_servers_are_still_saved() {
    let (_dir, mut e) = setup();
    let g = add(&mut e, "Routing", 0);
    let group = e.store.library.groups.iter_mut().find(|x| x.id == g);
    let subscription = group.unwrap().subscription.as_mut().unwrap();
    subscription.settings.use_provider_routing = true;
    let worker = owner();
    // A policy this build refuses to compile, as a provider could send.
    let metadata = Metadata {
        routing: Some(ProviderRouting {
            action: "add".into(),
            config: json!({"RouteOrder":"proxy-proxy-proxy"}),
            error: None,
        }),
        ..Default::default()
    };
    let (id, _) = prepared(&mut e, &worker, metadata, servers(&g, 5));
    let mut core = Core::default();
    checked(&mut e, &id, &worker, &mut core).await;
    e.apply_subscription_job(&id, &worker).unwrap();
    assert_eq!(e.store.library.profiles.len(), 5);
    let done = job(&e, &id);
    assert_eq!(done.status, Status::NeedsReview);
    assert_eq!(
        done.error.as_deref(),
        Some("subscription_provider_routing_failed")
    );
    assert_eq!((done.counts.added, done.counts.skipped), (5, 0));
    let subscription = e.group(&g).unwrap().subscription.unwrap();
    assert!(!subscription.settings.use_provider_routing);
    assert!(
        subscription.metadata.routing.is_some(),
        "the policy stays reviewable"
    );
}
