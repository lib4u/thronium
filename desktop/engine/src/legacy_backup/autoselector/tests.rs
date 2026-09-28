use super::*;
use crate::{
    legacy_backup::{SourceGroup, SourceRow, SourceValue},
    store::{Library, Profile, ProfileKind},
};

fn profile(id: i64, group_id: i64, kind: &str, outbound: Value) -> SourceProfile {
    SourceProfile {
        id,
        group_id,
        kind: kind.into(),
        name: Some(format!("Stale DB name {id}")),
        outbound,
        columns: SourceRow::new(),
    }
}
fn group(id: i64, ids: &[i64]) -> SourceGroup {
    SourceGroup {
        id,
        name: format!("Source group {id}"),
        columns: SourceRow::from([(
            "profiles_json".into(),
            SourceValue::Text(json!(ids).to_string()),
        )]),
    }
}
fn database() -> SourceDatabase {
    let socks = |id| {
        profile(
            id,
            7,
            "socks",
            json!({"type":"socks","tag":format!("Source socks {id}"),"server":"127.0.0.1","server_port":19001}),
        )
    };
    SourceDatabase {
        groups: vec![group(7, &[11, 12, 13, 14]), group(9, &[])],
        profiles: vec![
            socks(11),
            profile(
                12,
                7,
                "custom",
                json!({"type":"custom","name":"Source Xray","subtype":"xrayoutbound","config":json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":19002}}).to_string()}),
            ),
            socks(13),
            socks(14),
        ],
        ..Default::default()
    }
}
fn selector() -> SourceProfile {
    profile(
        90,
        9,
        "autoselector",
        json!({"type":"autoselector","name":"Saved selector 🦊","gid":7,"last_built":[12,11]}),
    )
}
fn convert_fixture(source: &SourceProfile, db: &SourceDatabase) -> SnapshotSpec {
    convert(
        source,
        db,
        &db.profiles_by_id(),
        SourceSettings::Excluded,
        Choice::LastBuilt,
    )
    .unwrap_or_else(|code| panic!("synthetic snapshot failed: {code}"))
}
fn error(source: &SourceProfile, db: &SourceDatabase) -> &'static str {
    convert(
        source,
        db,
        &db.profiles_by_id(),
        SourceSettings::Excluded,
        Choice::LastBuilt,
    )
    .err()
    .expect("accepted malformed snapshot")
}
fn setting(key: &str, value: &str) -> SourceSetting {
    SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: SourceRow::new(),
    }
}
fn converted_library(source: &SourceProfile, db: &SourceDatabase) -> (Library, Profile) {
    let mut complete = SourceDatabase {
        profiles: db
            .profiles
            .iter()
            .map(|p| SourceProfile {
                id: p.id,
                group_id: p.group_id,
                kind: p.kind.clone(),
                name: p.name.clone(),
                outbound: p.outbound.clone(),
                columns: p.columns.clone(),
            })
            .collect(),
        groups: db
            .groups
            .iter()
            .map(|g| SourceGroup {
                id: g.id,
                name: g.name.clone(),
                columns: g.columns.clone(),
            })
            .collect(),
        ..Default::default()
    };
    complete.profiles.push(profile(
        source.id,
        source.group_id,
        "autoselector",
        source.outbound.clone(),
    ));
    let group = complete
        .groups
        .iter_mut()
        .find(|g| g.id == source.group_id)
        .unwrap();
    let mut list: Vec<i64> = serde_json::from_str(match &group.columns["profiles_json"] {
        SourceValue::Text(text) => text,
        _ => panic!("invalid synthetic group"),
    })
    .unwrap();
    list.push(source.id);
    group.columns.insert(
        "profiles_json".into(),
        SourceValue::Text(json!(list).to_string()),
    );
    // Actual activated converter path; the helper's pure tests remain separate.
    let plan = super::super::profiles::convert_selected_with_selectors(
        &complete,
        false,
        Choice::LastBuilt,
    )
    .unwrap_or_else(|issues| panic!("fixture members rejected: {}", json!(issues)));
    let selector = plan
        .profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&source.id])
        .unwrap()
        .clone();
    assert_eq!(selector.kind, ProfileKind::AutoSelector);
    let mut library = Library {
        profiles: plan.profiles,
        groups: plan.groups,
        ..Default::default()
    };
    library.preferences.vless_overrides = plan.vless_overrides;
    crate::references::validate_all(&library).unwrap();
    (library, selector)
}

#[test]
fn caller_must_explicitly_choose_snapshot_and_live_converter_stays_blocked() {
    let mut db = database();
    let source = selector();
    assert_eq!(
        convert(
            &source,
            &db,
            &db.profiles_by_id(),
            SourceSettings::Excluded,
            Choice::RequireChoice
        )
        .err(),
        Some("legacy_selector_snapshot_choice_required")
    );
    db.groups[1]
        .columns
        .insert("profiles_json".into(), SourceValue::Text("[90]".into()));
    db.profiles.push(source);
    let errors = super::super::profiles::convert_selected(&db, false)
        .err()
        .expect("selector accepted without explicit choice");
    assert!(errors
        .iter()
        .any(|issue| issue.code == "legacy_selector_snapshot_choice_required"));
}

#[test]
fn exact_constructor_defaults_are_materialized_without_source_mutation() {
    let source = selector();
    let original = source.outbound.clone();
    let columns = source.columns.clone();
    let spec = convert_fixture(&source, &database());
    assert_eq!(
        spec.runtime_options,
        json!({"url":DEFAULT_URL,"interval":"300s","bench_interval":"600s","watch_interval":"15s","active_size":8,"sampling":10,"tolerance":300,"expected":3,"dial_retries":2,"interrupt_exist_connections":true})
    );
    assert_eq!(spec.name, "Saved selector 🦊");
    assert_eq!(
        (
            spec.source_id,
            spec.containing_group_id,
            spec.tracked_group_id
        ),
        (90, 9, Some(7))
    );
    assert_eq!(spec.member_ids, [12, 11]);
    assert_eq!(spec.pin_id, None);
    assert_eq!(source.outbound, original);
    assert!(source.columns == columns);
}

#[test]
fn last_built_order_pin_and_uuid_remap_ignore_filters_pool_and_small_build_limit() {
    let mut source = selector();
    source.outbound.as_object_mut().unwrap().extend(json!({"pool":[11,13,12],"pinned_id":11,"name_filter":"(?<=never-match)this","country_filter":"ZZ","exclude_unavailable":true,"build_limit":1,"last_built_at":100,"history":[{"id":14,"first":1,"last":2,"builds":3,"fails":1,"name":"Old member"}]}).as_object().unwrap().clone());
    let spec = convert_fixture(&source, &database());
    assert_eq!(spec.member_ids, [12, 11]);
    assert_eq!(spec.pin_id, Some(11));
    let ids = BTreeMap::from([(11, "z-member".into()), (12, "a-member".into())]);
    let config = spec.to_config(&ids).unwrap();
    assert_eq!(config["members"], json!(["a-member", "z-member"]));
    assert_eq!(config["pinned_profile"], "z-member");
    for key in [
        "pool",
        "gid",
        "last_built",
        "name_filter",
        "country_filter",
        "warm",
        "outbounds",
        "pinned",
        "history",
        crate::group_chains::MEMBER_HOPS,
    ] {
        assert!(
            config.get(key).is_none(),
            "leaked generated/client field {key}"
        );
    }
    assert!(spec
        .to_config(&BTreeMap::from([(11, "one".into())]))
        .is_err());
    assert!(spec
        .to_config(&BTreeMap::from([(11, "same".into()), (12, "same".into())]))
        .is_err());
}

#[test]
fn qt_normalize_order_clamps_only_source_options_and_core_uint16_is_enforced() {
    let mut source = selector();
    source.outbound.as_object_mut().unwrap().extend(json!({"pool_cap":1,"build_limit":5000,"interval_sec":-1,"bench_interval_sec":2,"watch_interval_sec":500,"active_size":-2,"expected":99,"sampling":100,"tolerance_ms":-9,"max_rtt_ms":-1,"dial_retries":99,"balance":true,"balance_mode":"future-mode","balance_interval_sec":1,"interrupt_on_switch":false,"result_validity_mins":-2}).as_object().unwrap().clone());
    let spec = convert_fixture(&source, &database());
    assert_eq!(
        spec.runtime_options,
        json!({"url":DEFAULT_URL,"interval":"10s","bench_interval":"10s","watch_interval":"10s","active_size":1,"expected":1,"sampling":60,"tolerance":0,"dial_retries":5,"interrupt_exist_connections":false,"balance":true,"balance_mode":"rotate","balance_interval":"5s"})
    );
    source.outbound["balance_mode"] = json!("connection");
    source.outbound["max_rtt_ms"] = json!(2500);
    source.outbound["tolerance_ms"] = json!(65535);
    source.outbound["dial_retries"] = json!(-4);
    source.outbound["sampling"] = json!(-4);
    let spec = convert_fixture(&source, &database());
    assert_eq!(spec.runtime_options["balance_mode"], "connection");
    assert_eq!(spec.runtime_options["max_rtt"], "2500ms");
    assert_eq!(spec.runtime_options["dial_retries"], 0);
    assert_eq!(spec.runtime_options["sampling"], 2);
    source.outbound["tolerance_ms"] = json!(65536);
    assert_eq!(
        error(&source, &database()),
        "legacy_selector_value_unsupported"
    );
}

#[test]
fn selected_settings_supply_only_fallbacks_and_excluded_rows_are_never_read() {
    let source = selector();
    let mut db = database();
    let mut rows = vec![
        setting("test_url", "https://probe.invalid/private-token"),
        setting(
            "direct_test_url",
            "http://connectivity.invalid/private-path",
        ),
        setting("enable_warp", "false"),
        // An unknown row named after the C++ member must not override test_url.
        setting("test_latency_url", "private-invalid-member"),
    ];
    let spec = convert(
        &source,
        &db,
        &db.profiles_by_id(),
        SourceSettings::Included(&rows),
        Choice::LastBuilt,
    )
    .unwrap();
    assert_eq!(
        spec.runtime_options["url"],
        "https://probe.invalid/private-token"
    );
    assert_eq!(
        spec.runtime_options["connectivity_url"],
        "http://connectivity.invalid/private-path"
    );
    let report = json!(spec.report).to_string();
    assert!(!report.contains("private-token"));
    assert!(!report.contains("private-path"));
    rows.push(setting("test_url", "malformed-secret"));
    rows[2].value = "unknown-secret-bool".into();
    assert!(convert(
        &source,
        &db,
        &db.profiles_by_id(),
        SourceSettings::Included(&rows),
        Choice::LastBuilt
    )
    .is_err());
    db.settings = vec![
        setting("test_url", "malformed-excluded-secret"),
        setting("test_url", "duplicate-excluded-secret"),
        setting("enable_warp", "malformed-excluded-bool"),
    ];
    let excluded = convert(
        &source,
        &db,
        &db.profiles_by_id(),
        SourceSettings::Excluded,
        Choice::LastBuilt,
    )
    .unwrap();
    assert_eq!(excluded.runtime_options["url"], DEFAULT_URL);
    let mut explicit = source;
    explicit.outbound["test_url"] = json!("http://127.0.0.1:19000/probe");
    explicit.outbound["connectivity_url"] = json!("http://127.0.0.1:19000/connectivity");
    rows[2].value = "false".into();
    let explicit = convert(
        &explicit,
        &db,
        &db.profiles_by_id(),
        SourceSettings::Included(&rows),
        Choice::LastBuilt,
    )
    .unwrap();
    assert_eq!(
        explicit.runtime_options["url"],
        "http://127.0.0.1:19000/probe"
    );
}

#[test]
fn source_warp_is_a_separate_dependency_and_invalid_probe_urls_stay_errors() {
    let source = selector();
    let db = database();
    for value in ["true", "1"] {
        let converted = convert(
            &source,
            &db,
            &db.profiles_by_id(),
            SourceSettings::Included(&[setting("enable_warp", value)]),
            Choice::LastBuilt,
        )
        .unwrap();
        assert!(converted.requires_warp);
        assert!(converted.runtime_options.get("enable_warp").is_none());
    }
    for key in ["test_url", "connectivity_url"] {
        for value in [
            "file:///private/secret",
            "ftp://private.invalid/path",
            "http://user:secret@127.0.0.1/",
            "http://127.0.0.1/#secret",
            "http://127.0.0.1/\r\nsecret",
            "http:// 127.0.0.1/",
        ] {
            let mut source = selector();
            source.outbound[key] = json!(value);
            assert!(error(&source, &db).starts_with("legacy_selector_"));
            assert!(!error(&source, &db).contains("secret"));
        }
    }
}

#[test]
fn missing_empty_oversized_duplicate_self_and_pin_references_do_not_fall_back() {
    let db = database();
    for (list, code) in [
        (json!([]), "legacy_selector_snapshot_empty"),
        (json!([11, 11]), "legacy_selector_reference_invalid"),
        (json!([11, 999]), "legacy_selector_reference_missing"),
        (json!(vec![11; 501]), "legacy_selector_snapshot_limit"),
        (json!([-1]), "legacy_selector_reference_invalid"),
    ] {
        let mut source = selector();
        source.outbound["pool"] = json!([11, 12]);
        source.outbound["last_built"] = list;
        assert_eq!(error(&source, &db), code);
    }
    let mut source = selector();
    source
        .outbound
        .as_object_mut()
        .unwrap()
        .remove("last_built");
    source.outbound["pool"] = json!([11]);
    assert_eq!(error(&source, &db), "legacy_selector_snapshot_empty");
    let mut source = selector();
    source.outbound["pinned_id"] = json!(13);
    assert_eq!(error(&source, &db), "legacy_selector_pin_outside_snapshot");
    let mut db = database();
    let mut source = selector();
    source.outbound["last_built"] = json!([90]);
    db.profiles.push(selector());
    assert_eq!(error(&source, &db), "legacy_selector_member_unsupported");
}

#[test]
fn endpoint_fullconfig_chain_and_nested_members_stay_blocked() {
    for kind in [
        "wireguard",
        "warp",
        "tailscale",
        "openvpn",
        "openconnect",
        "extracore",
        "chain",
        "autoselector",
        "future",
    ] {
        let mut db = database();
        db.profiles[0].kind = kind.into();
        assert_eq!(
            error(&selector(), &db),
            "legacy_selector_member_unsupported"
        );
    }
    for subtype in ["fullconfig", "xrayfullconfig"] {
        let mut db = database();
        db.profiles[1].outbound["subtype"] = json!(subtype);
        assert_eq!(
            error(&selector(), &db),
            "legacy_selector_member_unsupported"
        );
    }
    for kind in [
        "wireguard",
        "tailscale",
        "openvpn-client",
        "openconnect",
        "auto-selector",
    ] {
        let mut db = database();
        db.profiles[1].outbound["subtype"] = json!("outbound");
        db.profiles[1].outbound["config"] = json!(json!({"type":kind}).to_string());
        assert_eq!(
            error(&selector(), &db),
            "legacy_selector_member_unsupported"
        );
    }
}

#[test]
fn all_persisted_fields_have_strict_types_limits_and_unknowns_are_rejected() {
    let db = database();
    for key in [
        "gid",
        "pool_cap",
        "build_limit",
        "result_validity_mins",
        "interval_sec",
        "bench_interval_sec",
        "watch_interval_sec",
        "active_size",
        "sampling",
        "tolerance_ms",
        "max_rtt_ms",
        "expected",
        "dial_retries",
        "balance_interval_sec",
        "pinned_id",
    ] {
        for value in [
            json!(null),
            json!("private-invalid"),
            json!(1.5),
            json!(2147483648i64),
        ] {
            let mut source = selector();
            source.outbound[key] = value;
            assert_eq!(error(&source, &db), "legacy_selector_structure", "{key}");
        }
    }
    for key in ["exclude_unavailable", "balance", "interrupt_on_switch"] {
        let mut source = selector();
        source.outbound[key] = json!(1);
        assert_eq!(error(&source, &db), "legacy_selector_structure");
    }
    for key in [
        "name",
        "name_filter",
        "country_filter",
        "test_url",
        "connectivity_url",
        "balance_mode",
    ] {
        let mut source = selector();
        source.outbound[key] = json!(false);
        assert_eq!(error(&source, &db), "legacy_selector_structure");
    }
    for key in ["last_built_at", "pool_ranked_at"] {
        let mut source = selector();
        source.outbound[key] = json!(-1);
        assert_eq!(error(&source, &db), "legacy_selector_structure");
    }
    let mut source = selector();
    source.outbound["history"] = json!(vec![json!({"id":11}); 2001]);
    assert_eq!(error(&source, &db), "legacy_selector_history_limit");
    for key in [
        "outbounds",
        "pinned",
        "warm",
        "members",
        "member_source",
        "unknown_secret",
    ] {
        let mut source = selector();
        source.outbound[key] = json!("private-secret");
        assert_eq!(error(&source, &db), "legacy_selector_field_unsupported");
    }
}

#[test]
fn tracked_group_missing_or_changed_membership_does_not_replace_containing_group() {
    let mut source = selector();
    source.outbound["gid"] = json!(777);
    let spec = convert_fixture(&source, &database());
    assert_eq!(spec.containing_group_id, 9);
    assert_eq!(spec.tracked_group_id, Some(777));
    assert!(spec
        .report
        .iter()
        .any(|i| i.code == "legacy_selector_source_group_missing"));
    let mut db = database();
    db.profiles[0].group_id = 9;
    assert_eq!(convert_fixture(&selector(), &db).member_ids, [12, 11]);
    db.groups.retain(|g| g.id != 9);
    assert_eq!(error(&source, &db), "legacy_selector_group_missing");
}

#[test]
fn containing_group_wraps_each_member_once_in_physical_front_member_landing_order() {
    let mut db = database();
    // Tracked group policy differs; only the containing selector's group applies.
    db.groups[0]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(14));
    db.groups[1]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(13));
    db.groups[1]
        .columns
        .insert("landing_proxy_id".into(), SourceValue::Integer(14));
    let (mut library, mut selector) = converted_library(&selector(), &db);
    let front = library
        .profiles
        .iter()
        .find(|p| p.name == "Source socks 13")
        .unwrap()
        .id
        .clone();
    let landing = library
        .profiles
        .iter()
        .find(|p| p.name == "Source socks 14")
        .unwrap()
        .id
        .clone();
    let members = selector.config["members"].as_array().unwrap().clone();
    let roots = std::collections::HashSet::from([selector.id.clone()]);
    crate::group_chains::prepare(&mut library, &mut selector, &roots).unwrap();
    for member in members {
        let member = member.as_str().unwrap();
        assert_eq!(
            selector.config[crate::group_chains::MEMBER_HOPS][member],
            json!([
                format!("thronium-group-raw-{front}"),
                format!("thronium-group-raw-{member}"),
                format!("thronium-group-raw-{landing}")
            ])
        );
    }
    let request = crate::auto_selector::build(&selector, &library.profiles, 2080).unwrap();
    assert_eq!(request.need_xray, Some(true));
}

#[test]
fn independent_actual_qt_header_and_generator_oracle_matches_all_eighteen_cases() {
    use sha2::Digest;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/legacy-autoselector-oracle");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["qtVersion"], "6.11.2");
    for (name, expected) in manifest["fixtures"].as_object().unwrap() {
        let actual = sha2::Sha256::digest(std::fs::read(directory.join(name)).unwrap());
        assert_eq!(
            format!("{actual:x}"),
            expected.as_str().unwrap(),
            "oracle fixture {name} changed without regeneration"
        );
    }
    let cases: Value =
        serde_json::from_slice(&std::fs::read(directory.join("cases.json")).unwrap()).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 18);
    assert_eq!(manifest["cases"], 18);
    let ids = BTreeMap::from([(11, "source-11".into()), (12, "source-12".into())]);
    for case in cases.as_array().unwrap() {
        let source = profile(90, 9, "autoselector", case["source"].clone());
        let mut db = database();
        db.settings = case["settings"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                // Oracle JSON describes SettingsRepo members, not SQLite keys.
                let stored_key = if key == "test_latency_url" {
                    "test_url"
                } else {
                    key
                };
                setting(stored_key, value.as_str().unwrap())
            })
            .collect();
        let settings = if case["includeSettings"].as_bool().unwrap() {
            SourceSettings::Included(&db.settings)
        } else {
            SourceSettings::Excluded
        };
        let spec = convert(
            &source,
            &db,
            &db.profiles_by_id(),
            settings,
            Choice::LastBuilt,
        )
        .unwrap_or_else(|code| panic!("Qt oracle case {} rejected: {code}", case["name"]));
        let mut expected = case["qtCore"].clone();
        for field in ["type", "tag", "outbounds", "pinned"] {
            expected.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            spec.runtime_options, expected,
            "runtime differs from actual Qt case {}",
            case["name"]
        );
        assert_eq!(json!(spec.member_ids), case["qtNormalized"]["last_built"]);
        assert_eq!(spec.name, case["qtNormalized"]["name"]);
        let config = spec.to_config(&ids).unwrap();
        assert_eq!(config["members"], case["qtCore"]["outbounds"]);
        assert_eq!(config.get("pinned_profile"), case["qtCore"].get("pinned"));
    }
}

#[test]
fn actual_qt_native_archives_validate_selector_choices_route_dependencies_and_blockers() {
    use crate::backups::legacy::{AutoSelectors, Scopes};
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/legacy-selector");
    let archive = crate::legacy_backup::read(&directory.join("valid.thrbackup")).unwrap();
    assert_eq!(archive.database.as_ref().unwrap().profiles.len(), 15);
    let temporary = tempfile::tempdir().unwrap();
    let mut engine =
        crate::Engine::open(temporary.path(), std::path::Path::new("missing-core")).unwrap();
    let initial = engine
        .preview_legacy_import(crate::backups::legacy::prepare(&archive))
        .unwrap();
    assert_eq!(
        initial.legacy.as_ref().unwrap()["routeCount"],
        1,
        "actual Qt route fixture must validate before testing scope guards"
    );
    assert_eq!(initial.legacy.as_ref().unwrap()["canApply"], false);
    let route_only = engine
        .legacy_backup_scopes(
            &initial.token,
            Scopes {
                profiles: false,
                routes: true,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                otp: false,
                icons: false,
                settings: Default::default(),
            },
        )
        .unwrap();
    let review = route_only.legacy.as_ref().unwrap();
    assert_eq!(review["canApply"], false);
    assert!(review["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_routes_require_profiles"));
    let accepted = engine
        .legacy_backup_scopes(
            &route_only.token,
            Scopes {
                profiles: true,
                routes: true,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                otp: false,
                icons: false,
                settings: Default::default(),
            },
        )
        .unwrap();
    assert_eq!(
        accepted.legacy.as_ref().unwrap()["canApply"],
        true,
        "{}",
        accepted.legacy.as_ref().unwrap()
    );
    let archive = crate::legacy_backup::read(&directory.join("blocked.thrbackup")).unwrap();
    let blocked = engine
        .preview_legacy_import(crate::backups::legacy::prepare(&archive))
        .unwrap();
    let blocked = engine
        .legacy_backup_scopes(
            &blocked.token,
            Scopes {
                profiles: true,
                routes: false,
                auto_selectors: AutoSelectors::LastBuilt,
                vpn_bindings: Default::default(),
                otp: false,
                icons: false,
                settings: Default::default(),
            },
        )
        .unwrap();
    // The unsupported selectors are left out and named; the rest can import.
    assert!(blocked.legacy.as_ref().unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_profile_skipped"));
    for code in [
        "legacy_selector_reference_missing",
        "legacy_selector_pin_outside_snapshot",
        "legacy_selector_snapshot_empty",
        "legacy_selector_member_unsupported",
        "legacy_selector_field_unsupported",
    ] {
        assert!(
            blocked.legacy.as_ref().unwrap()["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["code"] == code),
            "missing fixture blocker {code}"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires explicit disposable pinned core; Check only, never Start"]
async fn real_core_checks_singbox_xray_mixed_and_group_wrapped_snapshots_without_probe_traffic() {
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE required");
    if std::env::var_os("THRONIUM_LEGACY_SELECTOR_FIXTURE").is_none() {
        let bundle = tempfile::tempdir().unwrap();
        let executable = bundle.path().join("Thronium");
        let bundled_core = bundle.path().join("ThroniumCore");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(&core, &bundled_core).unwrap();
        let output=std::process::Command::new(executable).args(["--exact","legacy_backup::autoselector::tests::real_core_checks_singbox_xray_mixed_and_group_wrapped_snapshots_without_probe_traffic","--ignored","--nocapture"])
            .env("THRONIUM_LEGACY_SELECTOR_FIXTURE","1").env("THRONIUM_TEST_CORE",bundled_core).output().unwrap();
        assert!(
            output.status.success(),
            "owned selector fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let mut engine = crate::Engine::open(directory.path(), std::path::Path::new(&core)).unwrap();
    for (members, wrapped) in [
        (json!([11]), false),
        (json!([12]), false),
        (json!([12, 11]), false),
        (json!([12, 11]), true),
    ] {
        let mut source = selector();
        let mut db = database();
        source.outbound["last_built"] = members.clone();
        source.outbound["pinned_id"] = members[0].clone();
        source.outbound["test_url"] = json!(format!("http://127.0.0.1:{port}/probe"));
        source.outbound["connectivity_url"] = json!(format!("http://127.0.0.1:{port}/online"));
        source.outbound["balance"] = json!(true);
        source.outbound["balance_mode"] = json!("connection");
        source.outbound["max_rtt_ms"] = json!(3000);
        for member in &mut db.profiles {
            if member.kind == "socks" {
                member.outbound["server_port"] = json!(port);
            } else {
                member.outbound["config"] = json!(
                    json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":port}})
                        .to_string()
                );
            }
        }
        if wrapped {
            db.groups[1]
                .columns
                .insert("front_proxy_id".into(), SourceValue::Integer(13));
            db.groups[1]
                .columns
                .insert("landing_proxy_id".into(), SourceValue::Integer(14));
        }
        let (library, selector) = converted_library(&source, &db);
        engine.store.commit(library).unwrap();
        if let Err(code) = engine.check(&selector).await {
            engine.shutdown().await;
            panic!("synthetic selector Check failed (wrapped={wrapped}): {code}");
        }
        assert!(engine.running.is_none());
        assert!(engine.active_connection.is_none());
    }
    engine.shutdown().await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), probe.accept())
            .await
            .is_err(),
        "Check attempted an outbound/probe connection"
    );
}
