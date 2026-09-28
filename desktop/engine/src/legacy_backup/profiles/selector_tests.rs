use super::*;
use crate::legacy_backup::{autoselector::Choice, SourceSetting};

fn source(id: i64, gid: i64, kind: &str, outbound: Value) -> SourceProfile {
    SourceProfile {
        id,
        group_id: gid,
        kind: kind.into(),
        name: Some(format!("Database name {id}")),
        columns: BTreeMap::from([(
            "outbound_json".into(),
            SourceValue::Text(outbound.to_string()),
        )]),
        outbound,
    }
}
fn group(id: i64, ids: &[i64]) -> SourceGroup {
    SourceGroup {
        id,
        name: format!("Group {id}"),
        columns: BTreeMap::from([(
            "profiles_json".into(),
            SourceValue::Text(json!(ids).to_string()),
        )]),
    }
}
fn fixture() -> SourceDatabase {
    let socks = |id, gid| {
        source(
            id,
            gid,
            "socks",
            json!({"type":"socks","tag":format!("Socks {id}"),"server":"127.0.0.1","server_port":19000+id}),
        )
    };
    SourceDatabase {
        groups: vec![group(1, &[11, 12, 13, 14]), group(2, &[90])],
        profiles: vec![
            socks(11, 1),
            source(
                12,
                1,
                "xrayvless",
                json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":19012,"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}}),
            ),
            socks(13, 1),
            socks(14, 1),
            source(
                90,
                2,
                "autoselector",
                json!({"type":"autoselector","name":"Actual selector 🦊","gid":1,"last_built":[12,11],"pool":[14,13],"pinned_id":11,"name_filter":"(?<=stale)ignored","test_url":"http://127.0.0.1:19000/private-probe"}),
            ),
        ],
        ..Default::default()
    }
}
fn convert_last(db: &SourceDatabase, settings: bool) -> ProfilePlan {
    convert_selected_with_selectors(db, settings, Choice::LastBuilt)
        .unwrap_or_else(|issues| panic!("{}", json!(issues)))
}
/// Codes of a selector conversion that failed: the section is blocked or the
/// selector is left out of the plan.
fn errors(db: &SourceDatabase) -> Vec<String> {
    match convert_selected_with_selectors(db, false, Choice::LastBuilt) {
        Err(issues) => issues.into_iter().map(|i| i.code).collect(),
        Ok(plan) => {
            let codes: Vec<String> = plan.report.into_iter().map(|i| i.code).collect();
            assert!(
                codes.iter().any(|c| c == "legacy_profile_skipped"),
                "accepted unsupported snapshot"
            );
            codes
        }
    }
}
fn library(plan: &ProfilePlan) -> Library {
    let mut library = Library {
        profiles: plan.profiles.clone(),
        groups: plan.groups.clone(),
        ..Default::default()
    };
    library.preferences.vless_overrides = plan.vless_overrides.clone();
    library
}

#[test]
fn source_warp_marks_import_dependency_without_becoming_a_candidate() {
    let mut db = fixture();
    db.settings.push(SourceSetting {
        key: "enable_warp".into(),
        value: "true".into(),
        columns: BTreeMap::new(),
    });
    let plan = convert_last(&db, true);
    assert!(plan.requires_warp);
    assert_eq!(plan.profiles.len(), 5);
    let selector = plan
        .profiles
        .iter()
        .find(|p| p.kind == ProfileKind::AutoSelector)
        .unwrap();
    assert_eq!(
        selector.config["members"],
        json!([plan.profile_ids[&12], plan.profile_ids[&11]])
    );
    assert!(!selector.config.to_string().contains("warp"));
    assert!(!convert_last(&db, false).requires_warp);
}

#[test]
fn explicit_snapshot_retains_actual_name_member_order_pin_core_and_safe_reports() {
    let db = fixture();
    let original: Vec<_> = db
        .profiles
        .iter()
        .map(|p| (p.outbound.clone(), p.columns.clone()))
        .collect();
    assert!(convert_selected(&db, false)
        .err()
        .unwrap()
        .iter()
        .any(|i| i.code == "legacy_selector_snapshot_choice_required"));
    let plan = convert_last(&db, false);
    let selector = plan
        .profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&90])
        .unwrap();
    assert_eq!(selector.kind, ProfileKind::AutoSelector);
    assert_eq!(selector.name, "Actual selector 🦊");
    assert_eq!(selector.group_id, plan.group_ids[&2]);
    assert_eq!(
        selector.config["members"],
        json!([plan.profile_ids[&12], plan.profile_ids[&11]])
    );
    assert_eq!(selector.config["pinned_profile"], plan.profile_ids[&11]);
    assert_eq!(
        selector.config["url"],
        "http://127.0.0.1:19000/private-probe"
    );
    assert_eq!(plan.vless_overrides[&plan.profile_ids[&12]], Core::Xray);
    for key in [
        "member_source",
        "gid",
        "pool",
        "last_built",
        "warm",
        "history",
        "name_filter",
        "outbounds",
    ] {
        assert!(selector.config.get(key).is_none(), "{key}");
    }
    crate::store::validate_library(&library(&plan)).unwrap();
    let report = json!(plan.report).to_string();
    assert!(report.contains("legacy_selector_fixed_snapshot"));
    assert!(!report.contains("private-probe"));
    assert!(!report.contains("stale"));
    assert!(
        original
            == db
                .profiles
                .iter()
                .map(|p| (p.outbound.clone(), p.columns.clone()))
                .collect::<Vec<_>>()
    );
}

#[test]
fn activated_snapshot_wraps_each_candidate_in_containing_group_only() {
    let mut db = fixture();
    db.groups[0]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(14));
    db.groups[1]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(13));
    db.groups[1]
        .columns
        .insert("landing_proxy_id".into(), SourceValue::Integer(14));
    let plan = convert_last(&db, false);
    let mut library = library(&plan);
    let mut selector = library
        .profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&90])
        .unwrap()
        .clone();
    let roots = std::collections::HashSet::from([selector.id.clone()]);
    crate::group_chains::prepare(&mut library, &mut selector, &roots).unwrap();
    for source_id in [12, 11] {
        assert_eq!(
            selector.config[crate::group_chains::MEMBER_HOPS][&plan.profile_ids[&source_id]],
            json!([
                format!("thronium-group-raw-{}", plan.profile_ids[&13]),
                format!("thronium-group-raw-{}", plan.profile_ids[&source_id]),
                format!("thronium-group-raw-{}", plan.profile_ids[&14])
            ])
        );
    }
    // Persisted output contains no runtime-only map, including after compilation.
    assert!(plan
        .profiles
        .last()
        .unwrap()
        .config
        .get(crate::group_chains::MEMBER_HOPS)
        .is_none());
}

#[test]
fn invalid_converted_members_or_containing_wrappers_reject_the_whole_profile_plan() {
    let mut db = fixture();
    db.profiles[0].outbound["future_secret_option"] = json!("private-value");
    assert!(errors(&db).contains(&"legacy_profile_field_unsupported".into()));
    let mut db = fixture();
    db.profiles[4].outbound["last_built"] = json!([11, 999]);
    assert!(errors(&db).contains(&"legacy_selector_reference_missing".into()));
    let mut db = fixture();
    db.groups[1]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(90));
    assert!(errors(&db).contains(&"legacy_group_chain_unsupported".into()));
    let mut db = fixture();
    db.profiles.push(source(
        91,
        1,
        "chain",
        json!({"type":"chain","list":vec![13;16]}),
    ));
    db.groups[1]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(91));
    assert!(errors(&db).contains(&"legacy_group_chain_unsupported".into()));
}

#[test]
fn snapshot_fallback_urls_obey_selected_settings_without_reading_excluded_rows() {
    let mut db = fixture();
    db.profiles[4]
        .outbound
        .as_object_mut()
        .unwrap()
        .remove("test_url");
    db.settings = vec![SourceSetting {
        key: "test_url".into(),
        value: "https://probe.invalid/source-secret".into(),
        columns: BTreeMap::new(),
    }];
    let plan = convert_last(&db, true);
    assert_eq!(
        plan.profiles.last().unwrap().config["url"],
        "https://probe.invalid/source-secret"
    );
    db.settings[0].value = "invalid-private-url".into();
    db.settings.push(SourceSetting {
        key: "enable_warp".into(),
        value: "invalid-private-bool".into(),
        columns: BTreeMap::new(),
    });
    assert_eq!(
        convert_last(&db, false).profiles.last().unwrap().config["url"],
        "http://cp.cloudflare.com/"
    );
    // Invalid selected settings leave the selector out instead of guessing a URL.
    let plan = convert_selected_with_selectors(&db, true, Choice::LastBuilt).unwrap();
    assert!(plan
        .profiles
        .iter()
        .all(|p| p.kind != ProfileKind::AutoSelector));
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_skipped"));
}

#[test]
fn auxiliary_route_maps_snapshot_reference_and_keeps_profile_dependency_requirement() {
    use crate::legacy_backup::{Parts, SourceArchive, SourceRoute};
    let mut db = fixture();
    db.routes.push(SourceRoute {
        id: 1,
        name: "Selector route".into(),
        columns: BTreeMap::from([
            ("is_raw".into(), SourceValue::Integer(1)),
            (
                "raw_route".into(),
                SourceValue::Text(
                    json!({"rules":[{"domain":["fixture.invalid"],"outbound":90}]}).to_string(),
                ),
            ),
        ]),
    });
    let plan = convert_last(&db, false);
    let mut source = SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            profiles: true,
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(db),
    };
    let routes = crate::legacy_backup::routes::convert(&source, Some(&plan))
        .unwrap_or_else(|i| panic!("{}", json!(i)));
    assert_eq!(
        routes.presets[0].rules[0].config["outbound"],
        format!("profile:{}", plan.profile_ids[&90])
    );
    source.parts.profiles = false;
    assert!(crate::legacy_backup::routes::convert(&source, Some(&plan))
        .err()
        .unwrap()
        .iter()
        .any(|i| i.code == "legacy_route_reference_missing"));
}

fn archive(db: SourceDatabase) -> crate::legacy_backup::SourceArchive {
    crate::legacy_backup::SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: crate::legacy_backup::Parts {
            profiles: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(db),
    }
}

#[test]
fn actual_prepare_exposes_safe_snapshot_choice_then_restores_one_plan_without_source_settings() {
    use crate::backups::legacy::{prepare, AutoSelectors, Scopes};
    let mut db = fixture();
    db.settings.push(SourceSetting {
        key: "enable_warp".into(),
        value: "malformed-excluded-setting".into(),
        columns: BTreeMap::new(),
    });
    let source = archive(db);
    let folder = tempfile::tempdir().unwrap();
    let mut engine =
        crate::Engine::open(folder.path(), &folder.path().join("nonexistent-core")).unwrap();
    let original = json!(engine.store.library);
    let first = engine.preview_legacy_import(prepare(&source)).unwrap();
    let review = first.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], false);
    assert_eq!(review["autoSelectorCount"], 1);
    assert_eq!(
        review["selectorSnapshots"],
        json!([{"sourceId":90,"name":"Actual selector 🦊","members":2,"pinned":true}])
    );
    assert_eq!(
        engine.restore_backup(&first.token).unwrap_err(),
        "legacy_import_blocked"
    );
    let accepted = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: true,
                routes: false,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(accepted.legacy.as_ref().unwrap()["canApply"], true);
    let safe = serde_json::to_string(&accepted).unwrap();
    for secret in [
        "private-probe",
        "malformed-excluded-setting",
        "127.0.0.1",
        "(?<=stale)",
    ] {
        assert!(!safe.contains(secret));
    }
    engine.restore_backup(&accepted.token).unwrap();
    let selector = engine
        .store
        .library
        .profiles
        .iter()
        .find(|p| p.kind == ProfileKind::AutoSelector)
        .unwrap();
    assert_eq!(selector.config["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        selector.config["url"],
        "http://127.0.0.1:19000/private-probe"
    );
    assert_eq!(engine.store.library.routing.active, "default");
    assert_eq!(
        json!(engine.store.library)["settings"],
        original["settings"]
    );
    assert!(engine.owned_core_process().is_none());
    let undo = engine.preview_previous_backup().unwrap();
    engine.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(engine.store.library), original);
}

#[test]
fn actual_prepare_excluded_profile_part_has_no_snapshot_names_or_choice_bypass() {
    use crate::backups::legacy::{prepare, AutoSelectors, Scopes};
    let mut source = archive(fixture());
    source.parts.profiles = false;
    source.database.as_mut().unwrap().profiles[4].outbound["test_url"] =
        json!("malformed-hidden-secret");
    let folder = tempfile::tempdir().unwrap();
    let mut engine =
        crate::Engine::open(folder.path(), &folder.path().join("nonexistent-core")).unwrap();
    let first = engine.preview_legacy_import(prepare(&source)).unwrap();
    let review = first.legacy.as_ref().unwrap();
    assert_eq!(review["autoSelectorCount"], 0);
    assert_eq!(review["selectorSnapshots"], json!([]));
    let attempted = engine
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles: true,
                routes: false,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(attempted.legacy.as_ref().unwrap()["canApply"], false);
    let safe = serde_json::to_string(&attempted).unwrap();
    assert!(!safe.contains("Actual selector"));
    assert!(!safe.contains("malformed-hidden-secret"));
    assert_eq!(
        engine.restore_backup(&attempted.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert!(!folder.path().join("backup-before-restore.json").exists());
}
