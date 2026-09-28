use super::*;

fn ordered(ids: &[&str]) -> ProfileDraft {
    let mut d = ranked_draft("saved-http-latency", false, 60);
    d.config["member_source"]["saved_ranking"] = json!({"members":ids,"ranked_at":1});
    d
}

#[test]
fn saved_order_retains_prior_members_and_appends_newcomers_by_http() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("a", "A"),
        leaf("b", "B"),
        leaf("c", "C"),
        leaf("d", "D"),
    ];
    for (id, ms) in [("a", 10), ("b", 20), ("c", 1), ("d", 2)] {
        http_measured(&mut e, id, Some(ms));
    }
    let d = ordered(&["b", "a"]);
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["b", "a", "c", "d"]);
    http_measured(&mut e, "a", Some(1));
    http_measured(&mut e, "c", Some(50));
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["b", "a", "d", "c"]);
    let p = e.preview_selector(d).unwrap();
    assert_eq!(p["savedRankingCount"], 2);
    assert_eq!(p["savedOrderKept"], 2);
    assert_eq!(p["newCandidatesCount"], 2);
    assert_eq!(p["savedRankedAt"], 1);
}

#[test]
fn rank_is_a_pure_draft_operation_on_whole_candidate_pool_before_startup_limit() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    for (id, ms) in [("a", 30), ("b", 20), ("c", 10)] {
        http_measured(&mut e, id, Some(ms));
    }
    let mut d = ordered(&["a", "b", "c"]);
    d.config["member_source"]["pool_cap"] = json!(2);
    d.config["member_source"]["build_limit"] = json!(1);
    let id = e.save_profile(limit_copy(&d)).unwrap();
    d.id = Some(id.clone());
    let before = json!(e.store.library);
    let frozen = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    let result = e.rank_selector(limit_copy(&d)).unwrap();
    assert_eq!(result["members"], json!(["c", "b"]));
    assert!(result["ranked_at"].as_u64().unwrap() > 1);
    assert_eq!(json!(e.store.library), before);
    assert_eq!(pool(&e, &id), ["a"]);
    d.config["member_source"]["saved_ranking"] = result;
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["c"]);
    assert_eq!(json!(e.store.library), before);
    e.save_profile(d).unwrap();
    assert_eq!(pool(&e, &id), ["c"]);
    assert_eq!(frozen.config["members"], json!(["a"]));
}

#[test]
fn removed_and_filtered_ranked_ids_are_advisory_not_deletion_references() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    let mut d = ordered(&["missing", "b", "a"]);
    let id = e.save_profile(limit_copy(&d)).unwrap();
    e.delete_profiles(vec!["b".into()]).unwrap();
    assert_eq!(pool(&e, &id), ["a", "c"]);
    d.config["member_source"]["exclude_regex"] = json!("^A$");
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["c"]);
    d.config["member_source"]["name_regex"] = json!("^Z$");
    let before = json!(e.store.library);
    assert_eq!(e.rank_selector(d).unwrap()["members"], json!([]));
    assert_eq!(json!(e.store.library), before);
}

#[test]
fn malformed_saved_orders_are_rejected_without_overwriting_library() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let id = e.save_profile(ordered(&["a"])).unwrap();
    let before = json!(e.store.library);
    for bad in [
        json!(null),
        json!([]),
        json!({}),
        json!({"members":["a","a"],"ranked_at":1}),
        json!({"members":[""],"ranked_at":1}),
        json!({"members":[1],"ranked_at":1}),
        json!({"members":["a"],"ranked_at":-1}),
        json!({"members":["a"],"ranked_at":"1"}),
        json!({"members":["a"],"ranked_at":253402300800u64}),
        json!({"members":["a"],"ranked_at":1,"unknown":true}),
        json!({"members":["x".repeat(513)],"ranked_at":1}),
        json!({"members":(0..3001).map(|i|i.to_string()).collect::<Vec<_>>(),"ranked_at":1}),
    ] {
        let mut d = ordered(&[]);
        d.id = Some(id.clone());
        d.config["member_source"]["saved_ranking"] = bad;
        assert_eq!(
            e.preview_selector(limit_copy(&d)).unwrap_err(),
            "selector_invalid_saved_order"
        );
        assert_eq!(
            e.rank_selector(limit_copy(&d)).unwrap_err(),
            "selector_invalid_saved_order"
        );
        assert_eq!(
            e.save_profile(d).unwrap_err(),
            "selector_invalid_saved_order"
        );
        assert_eq!(json!(e.store.library), before);
    }
}

#[test]
fn old_modes_ignore_saved_order_and_ranking_requires_explicit_mode() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    http_measured(&mut e, "a", Some(20));
    http_measured(&mut e, "b", Some(10));
    let mut d = ordered(&["a", "b"]);
    d.config["member_source"]["order"] = json!("library");
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["a", "b"]);
    assert_eq!(
        e.rank_selector(limit_copy(&d)).unwrap_err(),
        "selector_saved_order_required"
    );
    d.config["member_source"]["order"] = json!("http-latency");
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["b", "a"]);
    d.config["member_source"]["order"] = json!("saved-http-latency");
    d.config["member_source"]
        .as_object_mut()
        .unwrap()
        .remove("saved_ranking");
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert!(p["savedRankedAt"].is_null());
    assert_eq!(p["savedOrderKept"], 0);
    assert_eq!(preview_ids(&e, d), ["b", "a"]);
}

#[test]
fn saved_order_ranking_is_bounded_but_not_by_the_startup_limit() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..3000)
        .map(|i| leaf(&format!("m{i:04}"), &format!("M{i:04}")))
        .collect();
    let mut d = ordered(&[]);
    d.config["member_source"]["build_limit"] = json!(1);
    d.config["member_source"]["pool_cap"] = json!(3000);
    let ranking = e.rank_selector(limit_copy(&d)).unwrap();
    assert_eq!(ranking["members"].as_array().unwrap().len(), 3000);
    d.config["member_source"]["saved_ranking"] = ranking;
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["total"], 1);
    assert_eq!(p["savedOrderKept"], 3000);
    e.store.library.profiles.push(leaf("overflow", "Overflow"));
    assert_eq!(
        e.rank_selector(d).unwrap_err(),
        "selector_too_many_candidates"
    );
}

#[test]
fn saved_order_reopens_and_full_backup_retains_it_while_portable_export_materializes() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    let mut d = ordered(&["b", "a", "c"]);
    d.config["member_source"]["build_limit"] = json!(1);
    let id = e.save_profile(d).unwrap();
    let bundle: Value = serde_json::from_str(
        &e.export_profiles(vec![id.clone()], exports::Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    let profiles = bundle["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    assert!(profiles.iter().any(|p| p["name"] == "B"));
    assert!(!bundle.to_string().contains("saved_ranking"));
    let backup = e.export_backup().unwrap();
    let (_other_dir, mut other) = setup();
    let preview = other.preview_backup(&backup).unwrap();
    other.restore_backup(&preview.token).unwrap();
    assert_eq!(
        other.profile(&id).unwrap().config,
        e.profile(&id).unwrap().config
    );
    assert_eq!(pool(&other, &id), ["b"]);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(pool(&e, &id), ["b"]);
}

#[test]
fn saved_order_still_applies_http_failure_filters_and_final_warm_tags() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    for id in ["a", "b", "c"] {
        http_measured(&mut e, id, None);
    }
    let mut d = ordered(&["c", "b", "a"]);
    d.config["member_source"]["exclude_unavailable"] = json!(true);
    d.config["member_source"]["warm_start"] = json!(true);
    d.config["member_source"]["pool_cap"] = json!(2);
    d.config["member_source"]["build_limit"] = json!(1);
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["keptUnavailable"], 1);
    assert_eq!(p["warmCandidatesCount"], 1);
    let id = e.save_profile(limit_copy(&d)).unwrap();
    let core = pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy");
    assert_eq!(core["outbounds"], json!([member_tag("proxy", "c")]));
    assert_eq!(core["warm"][0]["tag"], member_tag("proxy", "c"));
    http_measured(&mut e, "a", Some(1));
    assert_eq!(preview_ids(&e, d), ["a"]);
}
