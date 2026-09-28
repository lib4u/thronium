use super::*;
use crate::store::ProfileKind;
use crate::{
    auto_selector::{ConnectionMeasurements, AUTO_SELECT_ID},
    probes,
    store::Group,
};
use serde_json::Value;

fn setup(count: usize) -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let mut library = engine.store.library.clone();
    library.profiles = (0..count)
        .map(|i| Profile {
            id: format!("server-{i:03}"),
            name: format!("Server {i}"),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            favorite: false,
            vpn_policy: None,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":1080+i}),
        })
        .collect();
    engine.store.commit(library).unwrap();
    (dir, engine)
}
fn plan(engine: &Engine) -> ConnectionMeasurements {
    engine
        .connection_measurements(AUTO_SELECT_ID)
        .unwrap()
        .unwrap()
}
fn sweep(engine: &mut Engine, plan: &mut ConnectionMeasurements, success: bool) -> bool {
    let pool = &plan.pools[0];
    let run = engine.start_preflight_tests(pool, &pool.ids).unwrap();
    for (i, id) in pool.ids.iter().enumerate() {
        engine.next_url_test(&run.id).unwrap();
        engine.finish_url_test(
            &run.id,
            id,
            if success {
                Ok(10 + i as i32)
            } else {
                Err("probe_timeout".into())
            },
        );
    }
    engine
        .complete_connection_measurements(plan, Some(&run.id))
        .unwrap()
}
fn ranked(engine: &Engine, plan: &ConnectionMeasurements) -> Result<Vec<String>, String> {
    let library = engine.ranked_connection_library(plan)?;
    Ok(serde_json::from_value(
        library
            .profiles
            .iter()
            .find(|p| p.id == AUTO_SELECT_ID)
            .unwrap()
            .config["members"]
            .clone(),
    )
    .unwrap())
}

fn source_group(engine: &mut Engine, count: usize) {
    let mut next = engine.store.library.clone();
    next.groups.push(Group {
        id: "source".into(),
        name: "Source".into(),
        subscription: None,
        collapsed: false,
        auto_clear_unavailable: false,
        proxy_chain: Default::default(),
    });
    for profile in next.profiles.iter_mut().take(count) {
        profile.group_id = "source".into();
    }
    engine.store.commit(next).unwrap();
}

#[test]
fn source_filter_counts_two_candidates_before_failover_truncation() {
    let (_dir, mut e) = setup(4);
    source_group(&mut e, 2);
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.source_group_id = Some("source".into());
    prefs.auto_select.failover = false;
    e.preferences(prefs).unwrap();
    assert_eq!(e.auto_select_source(), Some("source"));
    assert_eq!(plan(&e).pools[0].ids, ["server-000", "server-001"]);
    let snapshot = e.snapshot();
    assert_eq!(snapshot.auto_select_member_count, 2);
    assert!(snapshot.auto_select_available);
    let mut next = e.store.library.clone();
    next.profiles[1].group_id = "personal".into();
    e.store.commit(next).unwrap();
    let snapshot = e.snapshot();
    assert_eq!(snapshot.auto_select_member_count, 1);
    assert!(!snapshot.auto_select_available);
}

#[test]
fn failover_off_measures_every_candidate_and_runs_only_the_fastest() {
    let (_dir, mut e) = setup(4);
    source_group(&mut e, 3);
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.source_group_id = Some("source".into());
    prefs.auto_select.failover = false;
    e.preferences(prefs).unwrap();
    let mut p = plan(&e);
    assert_eq!(p.pools[0].ids.len(), 3);
    let run = e
        .start_preflight_tests(&p.pools[0], &p.pools[0].ids)
        .unwrap();
    for id in &p.pools[0].ids {
        e.next_url_test(&run.id).unwrap();
        e.finish_url_test(&run.id, id, Ok(if id == "server-002" { 5 } else { 90 }));
    }
    assert!(!e
        .complete_connection_measurements(&mut p, Some(&run.id))
        .unwrap());
    assert_eq!(ranked(&e, &p).unwrap(), ["server-002"]);
    let library = e.ranked_connection_library(&p).unwrap();
    crate::store::validate_library(&library).unwrap();
    assert_eq!(
        e.auto_select_profile().unwrap().config["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    e.remember_quick_connection("server-002".into(), false);
    let mut reuse = plan(&e);
    assert!(reuse.reuses_selection());
    assert_eq!(reuse.pools[0].ids, ["server-002"]);
    assert_eq!(
        ranked(&e, &reuse).unwrap_err(),
        "selector_measurements_incomplete"
    );
    assert!(!sweep(&mut e, &mut reuse, true));
    assert_eq!(ranked(&e, &reuse).unwrap(), ["server-002"]);
    let mut failed = plan(&e);
    assert!(sweep(&mut e, &mut failed, false));
    assert_eq!(failed.pools[0].ids.len(), 3);
    assert!(!sweep(&mut e, &mut failed, true));
    assert_eq!(ranked(&e, &failed).unwrap(), ["server-000"]);
}

#[test]
fn changing_source_or_failover_invalidates_memory_and_marks_running_pool() {
    for source in [false, true] {
        let (_dir, mut e) = setup(4);
        source_group(&mut e, 3);
        e.running = Some(AUTO_SELECT_ID.into());
        e.remember_quick_connection("server-000".into(), false);
        let before = context(&e.store.library);
        assert!(!e.quick_needs_reconnect());
        let mut prefs = e.store.library.preferences.clone();
        if source {
            prefs.auto_select.source_group_id = Some("source".into());
        } else {
            prefs.auto_select.failover = false;
        }
        e.preferences(prefs).unwrap();
        assert_ne!(context(&e.store.library), before);
        assert!(e.quick_needs_reconnect());
        assert!(!plan(&e).reuses_selection());
        assert_eq!(plan(&e).pools[0].ids.len(), if source { 3 } else { 4 });
    }
}

#[test]
fn scoped_options_are_atomic_reject_unknown_sources_and_guard_stale_dialogs() {
    let (_dir, mut e) = setup(3);
    source_group(&mut e, 2);
    let original = e.store.library.preferences.auto_select.config.clone();
    let previous_options = AutoSelectOptions {
        failover: true,
        source_group_id: None,
    };
    let updated = json!({"reuse_ttl":"1h"});
    let revision = e.store.generation();
    assert_eq!(
        e.save_auto_select_settings(
            &original,
            updated.clone(),
            AutoSelectSettingsUpdate {
                failover: Some(false),
                source_group_id: Some(Some("missing".into())),
                previous_options: Some(previous_options.clone()),
            }
        )
        .unwrap_err(),
        "auto_select_source_missing"
    );
    assert_eq!(e.store.generation(), revision);
    assert_eq!(e.store.library.preferences.auto_select.config, original);
    assert!(e.store.library.preferences.auto_select.failover);
    e.save_auto_select_settings(
        &original,
        updated,
        AutoSelectSettingsUpdate {
            failover: Some(false),
            source_group_id: Some(Some("source".into())),
            previous_options: Some(previous_options.clone()),
        },
    )
    .unwrap();
    assert_eq!(e.store.generation(), revision + 1);
    let config = e.store.library.preferences.auto_select.config.clone();
    // Even an unchanged config cannot bypass concurrency checks on the new fields.
    assert_eq!(
        e.save_auto_select_settings(
            &config,
            config.clone(),
            AutoSelectSettingsUpdate {
                failover: Some(true),
                previous_options: Some(previous_options),
                ..Default::default()
            }
        )
        .unwrap_err(),
        "auto_select_settings_changed"
    );
    // Legacy config-only commands preserve both new options.
    e.save_auto_select_settings(&config, config.clone(), Default::default())
        .unwrap();
    assert!(!e.store.library.preferences.auto_select.failover);
    assert_eq!(e.auto_select_source(), Some("source"));
    e.save_auto_select_settings(
        &config,
        config.clone(),
        AutoSelectSettingsUpdate {
            source_group_id: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(e.auto_select_source(), None);
}

#[test]
fn deleting_source_resets_to_all_groups_and_logs_without_manual_pool_guard() {
    let (_dir, mut e) = setup(4);
    source_group(&mut e, 2);
    let mut prefs = e.store.library.preferences.clone();
    prefs.auto_select.source_group_id = Some("source".into());
    e.preferences(prefs).unwrap();
    e.delete_group("source", false).unwrap();
    assert_eq!(
        e.store.library.preferences.auto_select.source_group_id,
        None
    );
    assert_eq!(e.snapshot().auto_select_member_count, 4);
    assert!(e
        .logs
        .view(crate::logs::Filter::default())
        .unwrap()
        .entries
        .iter()
        .any(|entry| entry.text.contains("source group was deleted")));
}

#[test]
fn missing_source_falls_back_and_reopen_persists_repair_without_version_bump() {
    let (dir, mut e) = setup(3);
    let version = e.store.library.version;
    e.store.library.preferences.auto_select.source_group_id = Some("missing".into());
    assert_eq!(e.auto_select_source(), None);
    assert_eq!(e.snapshot().auto_select_member_count, 3);
    let mut wire = serde_json::to_value(&e.store.library).unwrap();
    wire["preferences"]["autoSelect"]
        .as_object_mut()
        .unwrap()
        .remove("failover");
    drop(e);
    std::fs::write(
        dir.path().join("library.json"),
        serde_json::to_vec(&wire).unwrap(),
    )
    .unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(e.store.library.preferences.auto_select.failover);
    assert_eq!(
        e.store.library.preferences.auto_select.source_group_id,
        None
    );
    assert_eq!(e.store.library.version, version);
    let saved: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("library.json")).unwrap()).unwrap();
    assert!(saved["preferences"]["autoSelect"]["sourceGroupId"].is_null());
    assert_eq!(saved["version"], version);
    assert!(e
        .logs
        .view(crate::logs::Filter::default())
        .unwrap()
        .entries
        .iter()
        .any(|entry| entry.text.contains("source group was missing")));
}

#[test]
fn backup_with_missing_source_restores_with_all_groups() {
    let (_dir, mut e) = setup(3);
    let mut wire = serde_json::to_value(&e.store.library).unwrap();
    wire["preferences"]["autoSelect"]["sourceGroupId"] = json!("missing");
    let text =
        json!({"format":"thronium-backup","version":1,"createdAt":1,"library":wire}).to_string();
    let preview = e.preview_backup(&text).unwrap();
    e.restore_backup(&preview.token).unwrap();
    assert_eq!(
        e.store.library.preferences.auto_select.source_group_id,
        None
    );
    assert_eq!(e.snapshot().auto_select_member_count, 3);
}

#[test]
fn quick_reuse_always_rechecks_one_member_and_does_not_extend_ttl() {
    let (dir, mut e) = setup(3);
    let chosen = "server-002".to_string();
    e.remember_quick_connection(chosen.clone(), false);
    let at = e.quick_select.remembered.as_ref().unwrap().verified_at_ms;
    let mut p = plan(&e);
    assert_eq!(p.pools[0].ids, std::slice::from_ref(&chosen));
    assert_eq!(
        ranked(&e, &p).unwrap_err(),
        "selector_measurements_incomplete"
    );
    assert!(!sweep(&mut e, &mut p, true));
    assert_eq!(ranked(&e, &p).unwrap()[0], chosen);
    e.remember_quick_connection(chosen.clone(), true);
    assert_eq!(
        e.quick_select.remembered.as_ref().unwrap().verified_at_ms,
        at
    );
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(plan(&e).pools[0].ids, [chosen]);
    let saved = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
    assert!(!saved.contains("127.0.0.1"));
}

#[test]
fn failed_reuse_falls_back_once_and_all_failed_never_produces_a_connection() {
    let (_dir, mut e) = setup(3);
    e.remember_quick_connection("server-002".into(), false);
    let mut p = plan(&e);
    assert!(sweep(&mut e, &mut p, false));
    assert_eq!(p.pools[0].ids.len(), 3);
    assert!(!sweep(&mut e, &mut p, false));
    assert_eq!(ranked(&e, &p).unwrap_err(), "auto_select_no_reachable");
    assert!(e.quick_select.remembered.is_none());
    assert!(e.rpc.is_none());
    assert!(e.store.library.selected.is_none());
}

#[test]
fn successful_full_fallback_ranks_only_its_own_results() {
    let (_dir, mut e) = setup(3);
    e.remember_quick_connection("server-002".into(), false);
    let mut p = plan(&e);
    assert!(sweep(&mut e, &mut p, false));
    assert!(!sweep(&mut e, &mut p, true));
    assert_eq!(ranked(&e, &p).unwrap()[0], "server-000");
    assert!(
        e.quick_select.remembered.is_none(),
        "only a successful Start may remember a new member"
    );
}

#[test]
fn ttl_expired_disabled_future_and_context_changes_force_full_sweep() {
    let (_dir, mut e) = setup(3);
    e.remember_quick_connection("server-001".into(), false);
    let original = e.store.library.clone();
    let remembered = e.quick_select.remembered.clone();
    for change in 0..9 {
        e.store.library = original.clone();
        e.quick_select.remembered = remembered.clone();
        match change {
            0 => e.quick_select.remembered.as_mut().unwrap().verified_at_ms = now() - 1_800_000,
            1 => e.quick_select.remembered.as_mut().unwrap().verified_at_ms = now() + 10_000,
            2 => e.store.library.preferences.auto_select.config["reuse_ttl"] = json!("0s"),
            3 => e.store.library.profiles[0].config["server_port"] = json!(9999),
            4 => e.store.library.preferences.inbound_port += 1,
            5 => e.store.library.routing.revision += 1,
            6 => e.store.library.groups[0].proxy_chain.front = Some("server-000".into()),
            7 => {
                e.store.library.preferences.auto_select.config["url"] = json!("https://other.test/")
            }
            _ => e.clear_quick_memory(),
        }
        assert_eq!(plan(&e).pools[0].ids.len(), 3, "change {change}");
    }
    e.store.library = original;
    e.quick_select.remembered = remembered;
    e.store.library.preferences.theme = "dark".into();
    e.store.library.profiles[0].favorite = true;
    assert_eq!(plan(&e).pools[0].ids.len(), 1);
}

/// A sealed plan keeps the results it measured, so a later batch replacing the
/// queue's only slot does not interrupt it; stale, cleared or unsealed plans
/// still cannot connect.
#[test]
fn stale_cleared_or_unsealed_batches_cannot_connect_but_a_replaced_one_can() {
    let (_dir, mut e) = setup(3);
    let mut p = plan(&e);
    assert!(!sweep(&mut e, &mut p, true));
    let original = e.store.library.clone();
    e.store.library.profiles[0].config["server_port"] = json!(9999);
    assert_eq!(ranked(&e, &p).unwrap_err(), "selector_measurements_stale");
    e.store.library = original;
    let unsealed = plan(&e);
    assert_eq!(
        ranked(&e, &unsealed).unwrap_err(),
        "selector_measurements_incomplete"
    );
    e.start_preflight_tests(&p.pools[0], &p.pools[0].ids)
        .unwrap();
    assert!(ranked(&e, &p).is_ok());
    e.cancel_url_tests();
    e.clear_url_tests().unwrap();
    assert_eq!(ranked(&e, &p).unwrap_err(), "selector_measurements_stale");
}

#[test]
fn quick_pool_excludes_direct_exits_including_explicit_chains() {
    let (_dir, mut e) = setup(3);
    let template = e.store.library.profiles[0].clone();
    e.store.library.profiles.push(Profile {
        id: "direct".into(),
        config: json!({"type":"direct"}),
        ..template.clone()
    });
    e.store.library.profiles.push(Profile {
        id: "direct-chain".into(),
        kind: ProfileKind::Chain,
        config: json!({"type":"chain","hops":["server-000","direct"]}),
        ..template
    });
    assert_eq!(plan(&e).pools[0].ids.len(), 3);
}

#[test]
fn group_routes_match_probes_and_are_active_dependencies() {
    let (_dir, mut e) = setup(3);
    e.store.library.groups.push(Group {
        id: "routed".into(),
        name: "Routed".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: group_chains::GroupChain {
            front: Some("server-000".into()),
            landing: None,
        },
    });
    e.store.library.profiles[2].group_id = "routed".into();
    let member = e.profile("server-002").unwrap();
    let probe =
        probes::prepared_request(&e.store.library, &member, "https://example.test/", 1000).unwrap();
    let probe: Value = serde_json::from_str(probe.config.as_deref().unwrap()).unwrap();
    let request = e.build(&e.auto_select_profile().unwrap()).unwrap();
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let exit = |core: &Value, tag: &str| {
        core["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == tag)
            .unwrap()
            .clone()
    };
    let live = exit(
        &core,
        &crate::auto_selector::member_tag("proxy", &member.id),
    );
    assert!(exit(&probe, "proxy").get("detour").is_some());
    assert!(live.get("detour").is_some());
    assert_eq!(
        exit(&core, live["detour"].as_str().unwrap())["server_port"],
        1080
    );
    assert_eq!(live["server_port"], 1082);
    let mut library = e.store.library.clone();
    library.profiles.push(e.auto_select_profile().unwrap());
    let roots = std::collections::HashSet::from([AUTO_SELECT_ID.to_string()]);
    let policies = group_chains::policy_roots(&library, &roots);
    assert!(policies.contains("server-002"));
    assert!(group_chains::dependencies(&library, &roots).contains("server-000"));
}

#[test]
fn bounded_pool_does_not_add_unswept_501st_member_when_results_reorder_it() {
    let (_dir, mut e) = setup(501);
    e.store.library.preferences.ping.method = probes::Method::Http;
    let run = e
        .start_url_tests(probes::Options {
            ids: vec!["server-500".into()],
            url: "https://example.test/".into(),
            timeout_ms: 1000,
            concurrency: Some(1),
        })
        .unwrap();
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test(&run.id, "server-500", Ok(1));
    let mut p = plan(&e);
    let mut expected = p.pools[0].ids.clone();
    assert_eq!(expected.len(), 500);
    assert!(expected.contains(&"server-500".into()));
    assert!(!sweep(&mut e, &mut p, true));
    let mut actual = ranked(&e, &p).unwrap();
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected);
}

#[test]
fn quick_config_validation_is_atomic_and_durations_are_exact() {
    let (dir, mut e) = setup(3);
    let before = json!(e.store.library.preferences);
    for bad in [
        json!({"url":"not a URL"}),
        json!({"timeout":"broken5s"}),
        json!({"timeout":"30s"}),
        json!({"timeout":"1s ignored"}),
        json!({"concurrency":-1}),
        json!({"reuse_ttl":"25h"}),
        json!({"members":["direct"]}),
        json!({"balance":"yes"}),
    ] {
        let mut prefs = e.store.library.preferences.clone();
        prefs.auto_select.config = bad;
        assert!(e.preferences(prefs).is_err());
        assert_eq!(json!(e.store.library.preferences), before);
    }
    assert_eq!(config::duration_ms("1m30s"), Some(90_000));
    assert_eq!(config::duration_ms("0.5s"), Some(500));
    assert_eq!(config::duration_ms("1s!"), None);
    assert_eq!(
        config::normalize(&json!({"tolerance":0,"dial_retries":0})).unwrap()["dial_retries"],
        2
    );
    drop(e);
    assert_eq!(
        json!(
            Engine::open(dir.path(), Path::new("missing-core"))
                .unwrap()
                .store
                .library
                .preferences
        ),
        before
    );
}

#[test]
fn scoped_settings_save_preserves_other_preferences_and_refuses_stale_writers() {
    let (_dir, mut e) = setup(3);
    let previous = e.store.library.preferences.auto_select.config.clone();
    e.store.library.preferences.language = "en".into();
    e.store.library.preferences.library_sort_descending = true;
    let mut config = previous.clone();
    config["reuse_ttl"] = json!("10m");
    e.save_auto_select_settings(&previous, config.clone(), Default::default())
        .unwrap();
    assert!(e.store.library.preferences.library_sort_descending);
    assert_eq!(e.store.library.preferences.language, "en");
    assert_eq!(
        e.store.library.preferences.auto_select.config["reuse_ttl"],
        "10m"
    );
    assert_eq!(
        e.save_auto_select_settings(&previous, previous.clone(), Default::default())
            .unwrap_err(),
        "auto_select_settings_changed"
    );
    assert_eq!(e.store.library.preferences.auto_select.config, config);
}

#[test]
fn core_switch_changes_the_remembered_server_without_renewing_ttl_or_hiding_pending_settings() {
    let (_dir, mut e) = setup(3);
    e.running = Some(AUTO_SELECT_ID.into());
    e.remember_quick_connection("server-000".into(), false);
    e.quick_select.remembered.as_mut().unwrap().verified_at_ms -= 120_000;
    let at = e.quick_select.remembered.as_ref().unwrap().verified_at_ms;
    let reply = proto::QueryAutoSelectorsResponse {
        groups: vec![proto::AutoSelectorStatus {
            tag: Some("settings-warp-base".into()),
            selected: Some(crate::auto_selector::member_tag("proxy", "server-001")),
            selected_udp: Some(crate::auto_selector::member_tag("proxy", "server-002")),
            ..Default::default()
        }],
    };
    e.observe_quick_selection(&reply);
    let remembered = e.quick_select.remembered.as_ref().unwrap();
    assert_eq!(remembered.member, "server-002");
    assert_eq!(remembered.verified_at_ms, at);
    assert!(!e.quick_needs_reconnect());
    e.store.library.preferences.auto_select.config["timeout"] = json!("2s");
    assert!(e.quick_needs_reconnect());
    e.observe_quick_selection(&reply);
    assert_eq!(
        e.quick_select.remembered.as_ref().unwrap().context,
        e.quick_select.applied_context.as_deref().unwrap()
    );
    assert!(e
        .quick_select
        .candidate(
            &context(&e.store.library),
            1_800_000,
            &["server-002".into()]
        )
        .is_none());
}

#[test]
fn damaged_or_future_cache_files_are_ignored_and_io_errors_do_not_break_memory() {
    let (dir, mut e) = setup(3);
    for text in [
        "not json".to_string(),
        "x".repeat(2049),
        json!({"member":"server-000","context":"a".repeat(64),"verified_at_ms":now()+10_000})
            .to_string(),
    ] {
        std::fs::write(dir.path().join(FILE), text).unwrap();
        assert!(State::load(dir.path()).remembered.is_none());
    }
    std::fs::remove_file(dir.path().join(FILE)).unwrap();
    std::fs::create_dir(dir.path().join(FILE)).unwrap();
    e.remember_quick_connection("server-000".into(), false);
    assert_eq!(
        plan(&e).pools[0].ids.len(),
        1,
        "an unwritable optional cache does not prevent an in-session recheck"
    );
}

#[test]
fn disabling_reuse_erases_memory_and_fractional_ttl_is_not_rounded_to_seconds() {
    let (dir, mut e) = setup(3);
    e.remember_quick_connection("server-000".into(), false);
    e.quick_select.remembered.as_mut().unwrap().verified_at_ms = now() - 200;
    assert!(e
        .quick_select
        .candidate(&context(&e.store.library), 100, &["server-000".into()])
        .is_none());
    let previous = e.store.library.preferences.auto_select.config.clone();
    let mut disabled = previous.clone();
    disabled["reuse_ttl"] = json!("0s");
    e.save_auto_select_settings(&previous, disabled, Default::default())
        .unwrap();
    assert!(e.quick_select.remembered.is_none());
    assert!(!dir.path().join(FILE).exists());
    e.remember_quick_connection("server-000".into(), false);
    assert!(e.quick_select.remembered.is_none());
    assert!(!dir.path().join(FILE).exists());
}

#[test]
fn legacy_sparse_defaults_do_not_invalidate_memory_or_conflict_on_unrelated_saves() {
    let (_dir, mut e) = setup(3);
    let previous = json!({"interval":"120s"});
    e.store.library.preferences.auto_select.config = previous.clone();
    e.remember_quick_connection("server-000".into(), false);
    let p = plan(&e);
    let mut prefs = e.store.library.preferences.clone();
    prefs.theme = if prefs.theme == "light" {
        "dark"
    } else {
        "light"
    }
    .into();
    e.preferences(prefs).unwrap();
    assert!(e.connection_measurements_current(&p));
    assert_eq!(plan(&e).pools[0].ids.len(), 1);
    let mut updated = previous.clone();
    updated["reuse_ttl"] = json!("10m");
    e.save_auto_select_settings(&previous, updated, Default::default())
        .unwrap();
    assert_eq!(
        e.store.library.preferences.auto_select.config["reuse_ttl"],
        "10m"
    );
    assert_eq!(plan(&e).pools[0].ids.len(), 3);
    assert!(!config::equivalent(
        &json!({"url":"bad"}),
        &json!({"url":"also bad"})
    ));
}

#[test]
fn explicit_warp_default_remembers_udp_carrier_from_the_retained_request() {
    let (_dir, mut e) = setup(3);
    e.running = Some(AUTO_SELECT_ID.into());
    e.remember_quick_connection("server-000".into(), false);
    let at = e.quick_select.remembered.as_ref().unwrap().verified_at_ms;
    e.active_connection = Some(crate::connection::ActiveConnection {
        id: AUTO_SELECT_ID.into(), profiles: Default::default(), groups: Default::default(),
        request: proto::LoadConfigReq { core_config: Some(json!({"route":{"final":"settings-warp-exit"},"endpoints":[{"tag":"settings-warp-exit","type":"wireguard","detour":"proxy"}]}).to_string()), ..Default::default() },
        routing_revision: 0, system_port: None, tun: false, external_instance: None,
        vpn_primary: false, vpn_otp: Default::default(), vpn_otp_start: Default::default(),
    });
    e.observe_quick_selection(&proto::QueryAutoSelectorsResponse {
        groups: vec![proto::AutoSelectorStatus {
            tag: Some("proxy".into()),
            selected: Some(crate::auto_selector::member_tag("proxy", "server-001")),
            selected_udp: Some(crate::auto_selector::member_tag("proxy", "server-002")),
            ..Default::default()
        }],
    });
    assert_eq!(
        e.quick_select.remembered.as_ref().unwrap().member,
        "server-002"
    );
    assert_eq!(
        e.quick_select.remembered.as_ref().unwrap().verified_at_ms,
        at
    );
}

/// Disconnect first reads the pool's current member with a short timeout. That
/// read closes IPC when the core is slow; the core then stops on EOF, and the
/// explicit Disconnect must report the finished stop instead of an error.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_pool_read_before_disconnect_still_ends_in_a_clean_stop() {
    let (_dir, mut e) = setup(2);
    let stops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = stops.clone();
    e.rpc = Some(crate::transport::Rpc::scripted_local_test_rpc(
        move |method, _| {
            if method == "QueryAutoSelectors" {
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            if method == "Stop" {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            prost::Message::encode_to_vec(&crate::proto::ErrorResp::default())
        },
    ));
    e.running = Some(super::super::AUTO_SELECT_ID.into());
    e.quick_select.remembered = Some(Remembered {
        member: "member".into(),
        context: "context".into(),
        verified_at_ms: now(),
    });
    e.disconnect()
        .await
        .expect("a stop over the closed stream is still a stop");
    assert!(e.running.is_none());
    assert!(
        e.rpc.is_none(),
        "a closed RPC is not kept for the next connect"
    );
    assert_eq!(e.error, None);
    assert_eq!(stops.load(std::sync::atomic::Ordering::SeqCst), 0);
}
