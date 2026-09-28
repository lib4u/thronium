use super::*;

fn capped(cap: Value, limit: usize) -> ProfileDraft {
    let mut d = limited_draft(json!(limit));
    d.config["member_source"]["pool_cap"] = cap;
    d
}

#[test]
fn candidate_cap_is_optional_and_invalid_values_are_rejected_atomically() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    let id = e.save_profile(capped(json!(1), 2)).unwrap();
    let before = json!(e.store.library);
    for value in [
        json!(0),
        json!(3001),
        json!(-1),
        json!(null),
        json!(1.5),
        json!("2"),
        json!(true),
        json!([]),
    ] {
        let mut d = capped(value, 2);
        d.id = Some(id.clone());
        assert_eq!(
            e.save_profile(limit_copy(&d)).unwrap_err(),
            "selector_invalid_pool_cap"
        );
        assert_eq!(
            e.preview_selector(d).unwrap_err(),
            "selector_invalid_pool_cap"
        );
        assert_eq!(json!(e.store.library), before);
    }
    let mut d = capped(json!(2), 2);
    d.config["member_source"]
        .as_object_mut()
        .unwrap()
        .remove("build_limit");
    assert_eq!(
        e.save_profile(limit_copy(&d)).unwrap_err(),
        "selector_pool_cap_requires_limit"
    );
    assert_eq!(
        e.preview_selector(d).unwrap_err(),
        "selector_pool_cap_requires_limit"
    );
    assert_eq!(json!(e.store.library), before);
    let old = e.preview_selector(limited_draft(json!(1))).unwrap();
    assert_eq!(old["matchingBeforeLimit"], 2);
    assert!(old.get("matchingBeforePoolCap").is_none());
    assert!(old.get("candidatePoolSize").is_none());
}

#[test]
fn candidate_cap_preserves_scan_safety_and_applies_before_startup_limit() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..3000)
        .map(|i| leaf(&format!("m{i:04}"), &format!("M{i:04}")))
        .collect();
    for (cap, limit, pool, total) in [
        (3000, 500, 3000, 500),
        (1000, 300, 1000, 300),
        (1, 500, 1, 1),
        (3000, 1, 3000, 1),
    ] {
        let p = e.preview_selector(capped(json!(cap), limit)).unwrap();
        assert_eq!(p["matchingBeforePoolCap"], 3000);
        assert_eq!(p["candidatePoolSize"], pool);
        assert_eq!(p["omittedByPoolCap"], 3000 - pool);
        assert_eq!(p["matchingBeforeLimit"], pool);
        assert_eq!(p["omittedByLimit"], pool - total);
        assert_eq!(p["total"], total);
    }
    e.store.library.profiles.push(leaf("overflow", "Overflow"));
    assert_eq!(
        e.preview_selector(capped(json!(1), 1)).unwrap_err(),
        "selector_too_many_candidates"
    );
    let mut d = capped(json!(1), 1);
    d.config["member_source"]["name_regex"] = json!("^M000[01]$");
    assert_eq!(e.preview_selector(d).unwrap()["matchingBeforePoolCap"], 2);
}

#[test]
fn candidate_cap_follows_filters_http_order_and_failure_exclusion() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("a", "A"),
        leaf("b", "B"),
        leaf("c", "C"),
        leaf("d", "D"),
    ];
    http_measured(&mut e, "a", Some(50));
    http_measured(&mut e, "b", Some(10));
    http_measured(&mut e, "c", None);
    let mut d = ranked_draft("http-latency", true, 60);
    d.config["member_source"]["pool_cap"] = json!(2);
    d.config["member_source"]["build_limit"] = json!(3);
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["b", "a"]);
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["matchingBeforePoolCap"], 3);
    assert_eq!(p["candidatePoolSize"], 2);
    assert_eq!(p["omittedByLimit"], 0);
    measured(&mut e, "a", Some("DE"));
    measured(&mut e, "b", Some("JP"));
    d.config["member_source"]["country_filter"] = json!("DE");
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["a"]);
    d.config["member_source"]["exclude_regex"] = json!("^A$");
    let empty = e.preview_selector(d).unwrap();
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["omittedByPoolCap"], 0);
}

#[test]
fn all_failed_candidate_cap_limits_real_generated_warm_tags() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    for id in ["a", "b", "c"] {
        http_measured(&mut e, id, None);
    }
    let mut d = ranked_draft("http-latency", true, 60);
    d.config["member_source"]["pool_cap"] = json!(1);
    d.config["member_source"]["build_limit"] = json!(3);
    d.config["member_source"]["warm_start"] = json!(true);
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["keptUnavailable"], 1);
    assert_eq!(p["warmCandidatesCount"], 1);
    assert_eq!(p["matchingBeforePoolCap"], 3);
    assert_eq!(p["omittedByPoolCap"], 2);
    let id = e.save_profile(d).unwrap();
    let core = pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy");
    assert_eq!(core["outbounds"], json!([member_tag("proxy", "a")]));
    assert_eq!(core["warm"].as_array().unwrap().len(), 1);
    assert_eq!(core["warm"][0]["tag"], member_tag("proxy", "a"));
    assert_eq!(core["warm"][0]["rtt"], 0);
}

#[test]
fn candidate_cap_survives_reopen_and_exports_only_final_members() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    let id = e.save_profile(capped(json!(1), 3)).unwrap();
    let exported = e
        .export_profiles(vec![id.clone()], exports::Format::Profiles)
        .unwrap();
    assert!(!exported.contains("pool_cap") && !exported.contains("member_source"));
    let bundle: Value = serde_json::from_str(&exported).unwrap();
    let profiles = bundle["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let leaf = profiles.iter().find(|p| p["name"] == "A").unwrap();
    let selector = profiles
        .iter()
        .find(|p| p["kind"] == "auto-selector")
        .unwrap();
    assert_eq!(selector["config"]["members"], json!([leaf["reference"]]));
    let frozen = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    let mut d = capped(json!(2), 3);
    d.id = Some(id.clone());
    e.save_profile(d).unwrap();
    assert_eq!(frozen.config["members"], json!(["a"]));
    assert_eq!(pool(&e, &id), ["a", "b"]);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        e.profile(&id).unwrap().config["member_source"]["pool_cap"],
        2
    );
    assert_eq!(pool(&e, &id), ["a", "b"]);
}

#[test]
fn auxiliary_pool_candidate_cap_uses_only_final_tags_and_does_not_mutate_library() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    http_measured(&mut e, "a", Some(30));
    http_measured(&mut e, "b", Some(10));
    let mut d = capped(json!(1), 3);
    d.config["url"] = json!("https://example.test/ranking");
    d.config["member_source"]["order"] = json!("http-latency");
    d.config["member_source"]["warm_start"] = json!(true);
    let id = e.save_profile(d).unwrap();
    let route = e
        .store
        .library
        .routing
        .profiles
        .iter_mut()
        .find(|p| p.id == e.store.library.routing.active)
        .unwrap();
    route.rules=vec![serde_json::from_value(json!({"id":"capped-route","name":"Capped","enabled":true,"config":{"domain":["example.test"],"outbound":format!("profile:{id}")}})).unwrap()];
    let before = json!(e.store.library);
    let tag = format!("thronium-route-{id}");
    let core = pool_outbound(&e.build(&e.profile("a").unwrap()).unwrap(), &tag);
    assert_eq!(core["outbounds"], json!([member_tag(&tag, "b")]));
    assert_eq!(core["warm"][0]["tag"], member_tag(&tag, "b"));
    assert_eq!(json!(e.store.library), before);
}
