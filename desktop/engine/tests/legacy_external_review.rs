//! Public reader→profile plan→scopes→apply coverage. All fixtures are synthetic Qt archives.
//! No core/proxy is started. Runtime TCP coverage belongs to the separate native suite.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use thronium_engine::{
    backups::{
        legacy::{prepare, AutoSelectors, Scopes},
        Preview,
    },
    config,
    legacy_backup::{
        self,
        autoselector::Choice,
        profiles::{self, ProfilePlan},
        SourceArchive, SourceProfile, SourceValue,
    },
    store::{Profile, ProfileKind},
    Engine,
};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/legacy_backup/external_core/fixtures/archives")
}
fn source(name: &str) -> SourceArchive {
    legacy_backup::read(&directory().join(format!("{name}.thrbackup"))).unwrap()
}
fn converted(source: &SourceArchive) -> ProfilePlan {
    profiles::convert_selected_with_selectors(
        source.database.as_ref().unwrap(),
        source.parts.settings,
        Choice::LastBuilt,
    )
    .unwrap_or_else(|issues| panic!("{}", json!(issues)))
}
/// What the conversion reports, whether it skips a profile (F3b) or blocks the
/// whole section.
fn codes(source: &SourceArchive) -> Vec<String> {
    match profiles::convert_selected_with_selectors(
        source.database.as_ref().unwrap(),
        source.parts.settings,
        Choice::LastBuilt,
    ) {
        Ok(plan) => plan.report.into_iter().map(|issue| issue.code).collect(),
        Err(issues) => issues.into_iter().map(|issue| issue.code).collect(),
    }
}
fn app(path: &Path) -> Engine {
    let mut app = Engine::open(path, &path.join("deliberately-absent-core")).unwrap();
    let mut library = app.store.library.clone();
    library.profiles.push(Profile {
        vpn_policy: None,
        id: "existing".into(),
        name: "Existing profile".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: true,
    });
    library.selected = Some("existing".into());
    library.preferences.inbound_port = 17439;
    library.preferences.connection_mode = thronium_engine::system_proxy::ConnectionMode::Tun;
    library
        .settings
        .insert("enable_dns_routing".into(), json!(true));
    app.store.commit(library).unwrap();
    app
}
fn review(preview: &Preview) -> &Value {
    preview.legacy.as_ref().unwrap()
}
fn has_code(preview: &Preview, code: &str) -> bool {
    review(preview)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == code)
}
fn safe(preview: &Preview) {
    let serialized = json!(preview).to_string();
    for value in [
        "/missing/",
        "--config",
        "quoted spaces",
        "extra_core_args",
        "extra_core_conf",
        "old-install/history-only",
        "SQLite format",
        "outbound_json",
        "metadata-secret-fixture",
        "synthetic-private-marker",
    ] {
        assert!(!serialized.contains(value), "private source content leaked");
    }
}
fn profile(plan: &ProfilePlan, id: i64) -> &Profile {
    plan.profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&id])
        .unwrap()
}
fn last_built() -> Scopes {
    Scopes {
        auto_selectors: AutoSelectors::LastBuilt,
        vpn_bindings: Default::default(),
        ..Default::default()
    }
}

#[test]
fn actual_qt_standalone_preserves_authoritative_name_order_exact_strings_and_launch_request() {
    let source = source("standalone-parts-31");
    let plan = converted(&source);
    assert_eq!(plan.profiles.len(), 3);
    assert_eq!(plan.groups.len(), 1);
    assert_eq!(
        plan.profiles
            .iter()
            .map(|p| p.id.clone())
            .collect::<Vec<_>>(),
        [42, 41, 43].map(|id| plan.profile_ids[&id].clone())
    );
    let original = source
        .database
        .as_ref()
        .unwrap()
        .profiles
        .iter()
        .find(|p| p.id == 41)
        .unwrap();
    let external = profile(&plan, 41);
    assert_eq!(external.kind, ProfileKind::ExternalCore);
    assert_eq!(external.name, original.outbound["name"].as_str().unwrap());
    assert_ne!(external.name, original.name.as_deref().unwrap());
    assert_eq!(external.config, original.outbound);
    assert_eq!(
        profile(&plan, 42).config,
        json!({"type":"extracore","name":"","socks_address":"127.0.0.1","socks_port":19081,
        "extra_core_path":"/missing/synthetic-helper2","extra_core_args":"","extra_core_conf":"","no_logs":false})
    );
    assert_eq!(profile(&plan, 42).name, "Fallback database42");
    assert!(plan.vless_overrides.is_empty());
    assert_eq!(plan.selected, Some(external.id.clone()));
    let request = config::build(external, 2080, Some(2081)).unwrap();
    assert_eq!(request.need_extra_process, Some(true));
    assert_eq!(
        request.extra_process_path.as_deref(),
        external.config["extra_core_path"].as_str()
    );
    assert_eq!(
        request.extra_process_args.as_deref(),
        external.config["extra_core_args"].as_str()
    );
    assert_eq!(
        request.extra_process_conf.as_deref(),
        external.config["extra_core_conf"].as_str()
    );
    assert_eq!(request.extra_no_out, Some(true));
    let options = request.extra_process_options.unwrap();
    assert_eq!(options.version, Some(1));
    assert_eq!(options.socks_port, Some(19080));
    assert_eq!(options.startup_timeout_ms, Some(10000));
    let adapter: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    // The adapter carries UDP too, as Qt's SOCKS outbound does.
    assert!(adapter["outbounds"][0].get("network").is_none());
    assert_eq!(adapter["outbounds"][0]["type"], "socks");
    assert_eq!(
        plan.report
            .iter()
            .filter(|i| i.code == "legacy_external_output_enabled")
            .map(|i| i.source_id)
            .collect::<Vec<_>>(),
        vec![Some(42)]
    );
    for note in plan
        .report
        .iter()
        .filter(|note| note.code.starts_with("legacy_external_"))
    {
        let profile = profile(&plan, note.source_id.unwrap());
        assert_eq!(
            note.name,
            Some(
                profile
                    .name
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(256)
                    .collect()
            )
        );
    }
}

#[test]
fn all_thirteen_archives_are_actual_reader_inputs_and_source_settings_do_not_replace_launch_fields()
{
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory().join("manifest.json")).unwrap()).unwrap();
    let archives = manifest["archives"].as_object().unwrap();
    assert_eq!(archives.len(), 13);
    for (name, entry) in archives {
        let source = legacy_backup::read(&directory().join(name)).unwrap();
        assert_eq!(
            source.parts.profiles,
            entry["partsMask"].as_u64().unwrap() & 1 != 0
        );
    }
    let included = converted(&source("standalone-parts-05"));
    let excluded = converted(&source("standalone-parts-01"));
    for id in [41, 42] {
        assert_eq!(profile(&included, id).config, profile(&excluded, id).config);
    }
    assert!(excluded.selected.is_none());
    assert_eq!(included.selected, Some(included.profile_ids[&41].clone()));
}

/// An external core that cannot run where Qt placed it is left out with its
/// reason (F3b) and never turns into a plain SOCKS profile; the rest imports.
#[test]
fn actual_qt_graph_blockers_skip_the_external_core_and_never_become_socks() {
    for (name, wanted, skipped, remaining) in [
        (
            "containing-front",
            "legacy_group_chain_unsupported",
            &[41, 42][..],
            0,
        ),
        (
            "selector-member",
            "legacy_selector_member_unsupported",
            &[44][..],
            2,
        ),
        ("missing-port", "legacy_external_port_invalid", &[41][..], 1),
        (
            "relative-path",
            "legacy_external_path_invalid",
            &[41][..],
            1,
        ),
    ] {
        let source = source(&format!("{name}-parts-31"));
        assert!(codes(&source).iter().any(|code| code == wanted), "{name}");
        let plan = converted(&source);
        for id in skipped {
            assert!(!plan.profile_ids.contains_key(id), "{name}: {id}");
        }
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        let first = app.preview_legacy_import(prepare(&source)).unwrap();
        let preview = app
            .legacy_backup_scopes(&first.token, last_built())
            .unwrap();
        safe(&preview);
        assert!(has_code(&preview, wanted), "{name}");
        assert!(has_code(&preview, "legacy_profile_skipped"), "{name}");
        assert_eq!(review(&preview)["canApply"], true, "{name}");
        assert_eq!(review(&preview)["externalCoreCount"], remaining, "{name}");
        app.restore_backup(&preview.token).unwrap();
        let external = |kind: ProfileKind| {
            app.store
                .library
                .profiles
                .iter()
                .filter(|p| p.kind == kind && p.id != "existing")
                .count()
        };
        assert_eq!(external(ProfileKind::ExternalCore), remaining, "{name}");
        // The one ordinary SOCKS profile of every archive, nothing converted.
        assert_eq!(external(ProfileKind::SingBoxOutbound), 1, "{name}");
        assert!(app.owned_core_process().is_none());
    }
}

/// A group of another archive whose own proxy chain would hold the external
/// core is a database-level conflict: the section stays blocked as a whole.
#[test]
fn external_core_in_a_group_proxy_chain_blocks_the_section_atomically() {
    let source = source("other-empty-group-front-parts-31");
    assert!(codes(&source)
        .iter()
        .any(|code| code == "legacy_group_chain_unsupported"));
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let before = json!(app.store.library);
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    let preview = app
        .legacy_backup_scopes(&first.token, last_built())
        .unwrap();
    safe(&preview);
    assert_eq!(review(&preview)["canApply"], false);
    assert_eq!(
        app.restore_backup(&preview.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    assert!(app.owned_core_process().is_none());
}

/// A chain may start at an external core, also through a nested
/// chain; after any other hop it is left out, and a group landing on one
/// blocks as before.
#[test]
fn nested_chain_and_landing_graphs_keep_existing_runtime_restrictions() {
    let first_hop = converted(&source("chain-parts-31"));
    let chain = first_hop
        .profiles
        .iter()
        .find(|p| p.kind == ProfileKind::Chain)
        .expect("chain starting at the external core");
    assert_eq!(
        thronium_engine::references::members(chain).unwrap(),
        vec![
            first_hop.profile_ids[&41].as_str(),
            first_hop.profile_ids[&43].as_str()
        ]
    );
    let mut nested = source("chain-parts-31");
    let db = nested.database.as_mut().unwrap();
    db.profiles.push(SourceProfile {
        id: 45,
        kind: "chain".into(),
        name: Some("Nested source".into()),
        group_id: 0,
        outbound: json!({"type":"chain","name":"Nested source","list":[44]}),
        columns: BTreeMap::new(),
    });
    db.groups[0].columns.insert(
        "profiles_json".into(),
        SourceValue::Text("[42,41,43,44,45]".into()),
    );
    let plan = converted(&nested);
    assert!(plan.profile_ids.contains_key(&45));
    let mut behind = source("chain-parts-31");
    behind.database.as_mut().unwrap().profiles[3].outbound["list"] = json!([43, 41]);
    let codes_behind = codes(&behind);
    assert!(codes_behind
        .iter()
        .any(|c| c == "legacy_chain_hop_unsupported"));
    assert!(codes_behind.iter().any(|c| c == "legacy_profile_skipped"));
    let mut landing = source("other-empty-group-front-parts-31");
    let group = &mut landing.database.as_mut().unwrap().groups[1];
    group
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(-1));
    group
        .columns
        .insert("landing_proxy_id".into(), SourceValue::Integer(41));
    assert!(codes(&landing)
        .iter()
        .any(|c| c == "legacy_group_chain_unsupported"));
}

#[test]
fn external_only_in_source_pool_or_tracked_group_is_not_a_snapshot_member() {
    let source = source("selector-pool-only-parts-31");
    let plan = converted(&source);
    let selector = profile(&plan, 44);
    assert_eq!(selector.config["members"], json!([plan.profile_ids[&43]]));
    assert_eq!(selector.config["pinned_profile"], plan.profile_ids[&43]);
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert_eq!(review(&first)["canApply"], false);
    assert!(has_code(&first, "legacy_selector_snapshot_choice_required"));
    let picked = app
        .legacy_backup_scopes(&first.token, last_built())
        .unwrap();
    assert_eq!(review(&picked)["canApply"], true);
    assert_eq!(review(&picked)["externalCoreCount"], 2);
    app.restore_backup(&picked.token).unwrap();
    assert_eq!(
        app.store
            .library
            .profiles
            .iter()
            .filter(|p| p.kind == ProfileKind::ExternalCore)
            .count(),
        2
    );
    assert!(app.owned_core_process().is_none());
}

#[test]
fn route_target_blocker_only_blocks_selected_routes_and_cannot_partially_apply() {
    let source = source("route-target-parts-31");
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let before = json!(app.store.library);
    let first = app.preview_legacy_import(prepare(&source)).unwrap();
    assert_eq!(review(&first)["canApply"], true);
    assert_eq!(review(&first)["externalCoreCount"], 2);
    assert!(has_code(&first, "legacy_routing_deferred"));
    let both = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    safe(&both);
    assert_eq!(review(&both)["canApply"], false);
    assert!(has_code(&both, "legacy_route_target_unsupported"));
    assert_eq!(
        app.restore_backup(&both.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(app.store.library), before);
    let profiles = app
        .legacy_backup_scopes(&both.token, Scopes::default())
        .unwrap();
    app.restore_backup(&profiles.token).unwrap();
    assert_eq!(json!(app.store.library.routing), before["routing"]);
    assert_eq!(app.store.library.profiles.len(), 4);
}

#[test]
fn excluded_source_profiles_and_user_profile_optout_allow_independent_routes() {
    for name in [
        "missing-port-parts-30",
        "missing-port-parts-31",
        "relative-path-parts-31",
    ] {
        let mut source = source(name);
        // The preserved research archive has a custom DNS tag but no route
        // resolver. Supply an explicit matching resolver in this SourceDTO-only
        // scope test; keep original Qt bytes/manifest unchanged.
        source.database.as_mut().unwrap().routes[0].columns.insert(
            "raw_route".into(),
            SourceValue::Text(
                json!({"rules":[],"final":"direct","default_domain_resolver":"fixture-dns"})
                    .to_string(),
            ),
        );
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        let before = json!(app.store.library);
        let first = app.preview_legacy_import(prepare(&source)).unwrap();
        let only = app
            .legacy_backup_scopes(
                &first.token,
                Scopes {
                    profiles: false,
                    routes: true,
                    ..Default::default()
                },
            )
            .unwrap();
        safe(&only);
        assert_eq!(review(&only)["canApply"], true, "{name}: {}", review(&only));
        assert_eq!(review(&only)["externalCoreCount"], 0);
        app.restore_backup(&only.token).unwrap();
        for key in ["profiles", "groups", "settings", "preferences", "selected"] {
            assert_eq!(json!(app.store.library)[key], before[key]);
        }
        assert_eq!(
            app.store.library.routing.profiles.len(),
            before["routing"]["profiles"].as_array().unwrap().len() + 1
        );
        assert!(app.owned_core_process().is_none());
    }
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let empty = app
        .preview_legacy_import(prepare(&source("standalone-parts-00")))
        .unwrap();
    assert_eq!(review(&empty)["canApply"], false);
    let forged = app
        .legacy_backup_scopes(&empty.token, Scopes::default())
        .unwrap();
    assert_eq!(review(&forged)["canApply"], false);
    assert_eq!(review(&forged)["externalCoreCount"], 0);
    assert_eq!(
        app.restore_backup(&forged.token).unwrap_err(),
        "legacy_import_blocked"
    );
}

#[test]
fn private_plan_refresh_preserves_uuid_exact_library_undo_and_source_bytes() {
    let path = directory().join("standalone-parts-31.thrbackup");
    let bytes = std::fs::read(&path).unwrap();
    let source = legacy_backup::read(&path).unwrap();
    let prepared = prepare(&source);
    let sqlite = source.files.get("database").unwrap().clone();
    let reference_dir = tempfile::tempdir().unwrap();
    let mut reference = app(reference_dir.path());
    let first = reference.preview_legacy_import(prepared.clone()).unwrap();
    reference.restore_backup(&first.token).unwrap();
    let expected = json!(&reference.store.library.profiles[1..]);
    let expected_groups = json!(&reference.store.library.groups[1..]);
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let preview = app.preview_legacy_import(prepared).unwrap();
    safe(&preview);
    assert!(has_code(&preview, "legacy_external_launch_review"));
    assert!(has_code(&preview, "legacy_external_runtime_subset"));
    let mut newer = app.store.library.clone();
    newer.settings.insert("font_size".into(), json!(19));
    app.store.commit(newer).unwrap();
    let before = json!(app.store.library);
    assert_eq!(
        app.restore_backup(&preview.token).unwrap_err(),
        "backup_preview_stale"
    );
    let fresh = app.refresh_backup_preview(&preview.token).unwrap();
    safe(&fresh);
    assert_ne!(fresh.token, preview.token);
    app.restore_backup(&fresh.token).unwrap();
    assert_eq!(json!(&app.store.library.profiles[1..]), expected);
    assert_eq!(json!(&app.store.library.groups[1..]), expected_groups);
    let after = json!(app.store.library);
    for key in ["settings", "preferences", "selected", "routing", "otp"] {
        assert_eq!(after[key], before[key]);
    }
    let exported: Value = serde_json::from_str(&app.export_backup().unwrap()).unwrap();
    assert_eq!(exported["library"]["profiles"], after["profiles"]);
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert_eq!(source.files.get("database").unwrap(), &sqlite);
    assert!(app.owned_core_process().is_none());
}

#[test]
fn prepare_cancel_apply_and_undo_do_not_execute_core_or_external_or_parse_shell_arguments() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("must-not-run");
    let marker = dir.path().join("unexpected-execution");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf unexpected > '{}'\nexit 77\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut source = source("standalone-parts-31");
    for profile in &mut source.database.as_mut().unwrap().profiles {
        if profile.kind == "extracore" {
            profile.outbound["extra_core_path"] = json!(executable.to_str().unwrap());
            profile.outbound["socks_port"] = json!(held.local_addr().unwrap().port());
            profile.outbound["extra_core_args"] =
                json!("--broken 'unterminated synthetic-private-marker");
            profile.outbound["extra_core_conf"] =
                json!("synthetic-private-marker without placeholder");
        }
    }
    let mut app = Engine::open(&dir.path().join("library"), &executable).unwrap();
    let before = json!(app.store.library);
    let prepared = prepare(&source);
    let cancel = app.preview_legacy_import(prepared.clone()).unwrap();
    safe(&cancel);
    app.discard_backup_preview(&cancel.token);
    assert_eq!(
        app.restore_backup(&cancel.token).unwrap_err(),
        "backup_preview_expired"
    );
    let first = app.preview_legacy_import(prepared).unwrap();
    safe(&first);
    assert_eq!(review(&first)["canApply"], true);
    app.restore_backup(&first.token).unwrap();
    assert_eq!(
        app.store
            .library
            .profiles
            .iter()
            .filter(|p| p.kind == ProfileKind::ExternalCore)
            .count(),
        2
    );
    let undo = app.preview_previous_backup().unwrap();
    app.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(app.store.library), before);
    assert!(!marker.exists());
    assert!(app.owned_core_process().is_none());
}

#[test]
fn malformed_external_field_values_remain_private_in_blocked_preview() {
    let mut source = source("standalone-parts-31");
    source.database.as_mut().unwrap().profiles[0].outbound["command"] =
        json!("synthetic-private-marker");
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let preview = app.preview_legacy_import(prepare(&source)).unwrap();
    safe(&preview);
    // The malformed profile is left out with its reason (F3b); its value
    // never reaches the review or the library.
    assert!(has_code(&preview, "legacy_profile_field_unsupported"));
    assert!(has_code(&preview, "legacy_profile_skipped"));
    let preview = app
        .legacy_backup_scopes(&preview.token, last_built())
        .unwrap();
    safe(&preview);
    app.restore_backup(&preview.token).unwrap();
    assert!(!json!(app.store.library)
        .to_string()
        .contains("synthetic-private-marker"));
}

#[test]
fn independently_generated_native_qt_fixtures_match_consumer_gate_and_source_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/legacy-external-core");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let read = |name: &str| legacy_backup::read(&root.join(format!("{name}.thrbackup"))).unwrap();
    for name in ["valid", "excluded-settings", "selector-pool"] {
        let source = read(name);
        let plan = converted(&source);
        let expected = &manifest["cases"][format!("{name}.thrbackup")];
        assert_eq!(
            plan.profiles.len(),
            expected["profiles"].as_u64().unwrap() as usize
        );
        assert_eq!(
            plan.profiles
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            expected["order"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| plan.profile_ids[&id.as_i64().unwrap()].as_str())
                .collect::<Vec<_>>()
        );
        for id in [11, 12, 14] {
            assert_eq!(
                profile(&plan, id).name,
                expected["names"][id.to_string()].as_str().unwrap()
            );
            if id != 12 {
                assert_eq!(
                    profile(&plan, id).config,
                    expected["configs"][id.to_string()]
                );
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        let first = app.preview_legacy_import(prepare(&source)).unwrap();
        let selected = app
            .legacy_backup_scopes(&first.token, last_built())
            .unwrap();
        assert_eq!(
            review(&selected)["canApply"],
            true,
            "{name}: {}",
            review(&selected)
        );
        assert_eq!(review(&selected)["externalCoreCount"], 3);
        assert!(!json!(selected)
            .to_string()
            .contains("legacy-external-synthetic-private-value"));
    }
    for (name, wanted) in [
        ("relative-path", "legacy_external_path_invalid"),
        ("unknown-field", "legacy_profile_field_unsupported"),
        ("chain", "legacy_chain_hop_unsupported"),
        ("containing-wrapper", "legacy_group_chain_unsupported"),
        ("empty-group-wrapper", "legacy_group_chain_unsupported"),
        ("selector-member", "legacy_selector_member_unsupported"),
    ] {
        assert!(
            codes(&read(name)).iter().any(|code| code == wanted),
            "{name}"
        );
    }
    let excluded = read("excluded-profiles");
    assert!(!excluded.parts.profiles);
    let dir = tempfile::tempdir().unwrap();
    let mut app = app(dir.path());
    let preview = app.preview_legacy_import(prepare(&excluded)).unwrap();
    assert_eq!(review(&preview)["externalCoreCount"], 0);
    assert_eq!(review(&preview)["canApply"], false);
}
