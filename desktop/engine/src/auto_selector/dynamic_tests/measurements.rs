use super::*;

fn measurable() -> ProfileDraft {
    let mut d = ranked_draft("saved-http-latency", true, 60);
    d.config["member_source"]["pool_cap"] = json!(2);
    d.config["member_source"]["build_limit"] = json!(1);
    d
}
fn context(plan: &Value) -> &str {
    plan["context"].as_str().unwrap()
}

#[test]
fn measurement_plan_skips_fresh_success_and_failure_before_both_caps() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    http_measured(&mut e, "a", Some(20));
    http_measured(&mut e, "b", None);
    let d = measurable();
    let before = json!(e.store.library);
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    assert_eq!(plan["candidateCount"], 3);
    assert_eq!(plan["freshCount"], 2);
    assert_eq!(plan["ids"], json!(["c"]));
    assert_eq!(plan["url"], "https://example.test/ranking");
    assert_eq!(plan["timeoutMs"], 3000);
    assert_eq!(json!(e.store.library), before);
    http_measured(&mut e, "c", None);
    let done = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    assert_eq!(context(&plan), context(&done));
    assert_eq!(done["ids"], json!([]));
    assert_eq!(
        e.rank_measured_selector(d, context(&plan)).unwrap()["members"],
        json!(["a"])
    );
}

#[test]
fn partial_measurements_do_not_publish_ranking_and_cache_updates_do_not_invalidate_plan() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    let d = measurable();
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    http_measured(&mut e, "c", Some(1));
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&plan))
            .unwrap_err(),
        "selector_measurements_incomplete"
    );
    http_measured(&mut e, "b", Some(2));
    http_measured(&mut e, "a", Some(3));
    let before = json!(e.store.library);
    assert_eq!(
        context(&plan),
        context(&e.plan_selector_measurements(limit_copy(&d)).unwrap())
    );
    let result = e.rank_measured_selector(d, context(&plan)).unwrap();
    assert_eq!(result["members"], json!(["c", "b"]));
    assert_eq!(json!(e.store.library), before);
}

#[test]
fn candidate_mutation_membership_order_and_draft_changes_invalidate_context() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    let d = measurable();
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    e.store.library.profiles[0].config["server_port"] = json!(9999);
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&plan))
            .unwrap_err(),
        "selector_measurements_stale"
    );
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    e.store.library.profiles.reverse();
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&plan))
            .unwrap_err(),
        "selector_measurements_stale"
    );
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    e.store.library.profiles.push(leaf("c", "C"));
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&plan))
            .unwrap_err(),
        "selector_measurements_stale"
    );
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    let mut changed = limit_copy(&d);
    changed.config["member_source"]["name_regex"] = json!("^A$");
    assert_eq!(
        e.rank_measured_selector(changed, context(&plan))
            .unwrap_err(),
        "selector_measurements_stale"
    );
}

#[test]
fn owner_network_mode_and_timeout_changes_are_distinct_from_appearance_and_http_cache() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let id = e.save_profile(measurable()).unwrap();
    let mut d = measurable();
    d.id = Some(id.clone());
    let first = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    e.store.library.preferences.language = "ru".into();
    e.store.library.preferences.theme = "light".into();
    http_measured(&mut e, "a", Some(1));
    assert_eq!(
        context(&first),
        context(&e.plan_selector_measurements(limit_copy(&d)).unwrap())
    );
    e.store.library.preferences.ping.timeout_ms = 2000;
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&first))
            .unwrap_err(),
        "selector_measurements_stale"
    );
    let next = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    e.store.library.preferences.tun.mtu += 1;
    assert_eq!(
        e.rank_measured_selector(limit_copy(&d), context(&next))
            .unwrap_err(),
        "selector_measurements_stale"
    );
    let next = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    let mut edited = as_draft(&e.profile(&id).unwrap());
    edited.config["member_source"]["build_limit"] = json!(2);
    e.save_profile(edited).unwrap();
    assert_eq!(
        e.rank_measured_selector(d, context(&next)).unwrap_err(),
        "selector_measurements_stale"
    );
}

#[test]
fn incompatible_policy_disabled_lifetime_and_invalid_urls_refuse_before_queueing() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let d = measurable();
    let mut zero = limit_copy(&d);
    zero.config["member_source"]["result_validity_mins"] = json!(0);
    assert_eq!(
        e.plan_selector_measurements(zero).unwrap_err(),
        "selector_measurement_lifetime_required"
    );
    for url in [
        json!(1),
        json!("file:///tmp/no-network"),
        json!("https://user:pass@example.test/x"),
        json!("https://example.test/x#fragment"),
    ] {
        let mut bad = limit_copy(&d);
        bad.config["url"] = url;
        assert_eq!(
            e.plan_selector_measurements(bad).unwrap_err(),
            "probe_invalid_url"
        );
    }
    let mut front = leaf("front", "Front");
    front.group_id = "personal".into();
    e.store.library.profiles.push(front);
    e.store
        .library
        .groups
        .iter_mut()
        .find(|g| g.id == "source")
        .unwrap()
        .proxy_chain
        .front = Some("front".into());
    assert_eq!(
        e.plan_selector_measurements(d).unwrap_err(),
        "selector_measurement_context"
    );
    assert!(e.url_tests_snapshot().is_none());
}

#[test]
fn plans_include_over_a_batch_and_all_3000_candidates_before_pool_cap() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..3000)
        .map(|i| leaf(&format!("m{i:04}"), &format!("M{i:04}")))
        .collect();
    let mut d = measurable();
    d.config["member_source"]["pool_cap"] = json!(1);
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    assert_eq!(plan["ids"].as_array().unwrap().len(), 3000);
    assert_eq!(plan["candidateCount"], 3000);
    e.store.library.profiles.push(leaf("overflow", "Overflow"));
    assert_eq!(
        e.plan_selector_measurements(limit_copy(&d)).unwrap_err(),
        "selector_too_many_candidates"
    );
    d.config["member_source"]["name_regex"] = json!("^M000[01]$");
    assert_eq!(
        e.plan_selector_measurements(d).unwrap()["candidateCount"],
        2
    );
}

#[test]
fn country_and_name_filters_precede_measurement_planning_and_all_fresh_failure_is_complete() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    measured(&mut e, "a", Some("DE"));
    measured(&mut e, "b", Some("DE"));
    measured(&mut e, "c", Some("JP"));
    let mut d = measurable();
    d.config["member_source"]["country_filter"] = json!("DE");
    d.config["member_source"]["exclude_regex"] = json!("^B$");
    let plan = e.plan_selector_measurements(limit_copy(&d)).unwrap();
    assert_eq!(plan["ids"], json!(["a"]));
    http_measured(&mut e, "a", None);
    assert_eq!(
        e.rank_measured_selector(d, context(&plan)).unwrap()["members"],
        json!(["a"])
    );
}

#[test]
fn cancelled_old_batch_id_cannot_cancel_a_new_probe_run() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let options = || crate::probes::Options {
        ids: vec!["a".into()],
        url: "https://example.test/ranking".into(),
        timeout_ms: 1000,
        concurrency: None,
    };
    let old = e.start_url_tests(options()).unwrap();
    assert!(!e.cancel_url_test_batch("missing"));
    assert!(!*old.cancelled.borrow());
    assert!(e.cancel_url_test_batch(&old.id));
    assert!(*old.cancelled.borrow());
    let next = e.start_url_tests(options()).unwrap();
    assert!(!e.cancel_url_test_batch(&old.id));
    assert!(!*next.cancelled.borrow());
    let batch = e.url_tests_snapshot().unwrap();
    assert_eq!(batch.id, next.id);
    assert!(batch
        .entries
        .iter()
        .all(|p| p.status == crate::probes::Status::Queued));
    assert!(e.cancel_url_test_batch(&next.id));
    assert!(*next.cancelled.borrow());
}
