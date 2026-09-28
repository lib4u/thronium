use super::tests::{codes, row, source};
use super::*;

fn rows() -> Vec<SourceSetting> {
    vec![
        row("net_use_proxy", "false"),
        row("net_insecure", "false"),
        row("user_agent2", "private-agent75/1.0"),
        row("sub_auto_update", "60"),
        row("sub_clear", "false"),
        row("sub_show_change_popup", "true"),
        row("sub_send_hwid", "true"),
        row(
            "sub_custom_hwid_params",
            "hwid=private-hwid75, model=private-model75",
        ),
        row("allow_stopping_active_profile", "false"),
    ]
}
fn replace(field: &str, text: &str) -> SourceArchive {
    source(
        rows()
            .into_iter()
            .map(|r| if r.key == field { row(field, text) } else { r })
            .collect(),
    )
}
#[test]
fn legacy_network_exact_alias_maps_to_catalog_without_exposing_agent_or_hwid() {
    let archive = source(rows());
    for group in [Group::Network, Group::Subscriptions] {
        let plan = convert(&archive, &group).unwrap_or_else(|_| panic!("valid group"));
        assert_eq!(plan.imported_fields, fields(&group));
        let public = json!({"fields":plan.imported_fields,"issues":plan.report});
        for marker in [
            "private-agent75",
            "private-hwid75",
            "private-model75",
            "user_agent2",
        ] {
            assert!(!public.to_string().contains(marker));
        }
        if group == Group::Network {
            assert_eq!(plan.values["user_agent"], "private-agent75/1.0");
            assert!(!plan.values.contains_key("user_agent2"));
        } else {
            assert_eq!(plan.values["sub_clear"], true);
            assert_eq!(plan.values["sub_auto_update"], 60);
            assert_eq!(
                plan.values["sub_custom_hwid_params"],
                "hwid=private-hwid75, model=private-model75"
            );
        }
    }
    let old = convert(
        &source(vec![row("user_agent", "not-the-SQLite-alias")]),
        &Group::Network,
    )
    .unwrap_or_else(|_| panic!("ignored old key"));
    assert!(old.values.is_empty());
    assert_eq!(old.deferred_count, 1);
}
#[test]
fn legacy_network_empty_and_missing_agent_are_distinct_and_header_injection_is_rejected() {
    let missing = convert(&source(vec![]), &Group::Network).unwrap_or_else(|_| panic!("missing"));
    assert!(missing.values.is_empty());
    let empty =
        convert(&replace("user_agent2", ""), &Group::Network).unwrap_or_else(|_| panic!("empty"));
    assert_eq!(
        empty.values["user_agent"],
        crate::settings::fields()
            .iter()
            .find(|f| f.id == "user_agent")
            .unwrap()
            .default
    );
    assert!(empty
        .report
        .iter()
        .any(|i| i.code == "legacy_network_default_user_agent"));
    for text in [
        "agent\r\nx-hwid: private75".to_owned(),
        "agent\0".into(),
        "agent\t".into(),
        "x".repeat(1025),
    ] {
        let s = replace("user_agent2", &text);
        assert_eq!(
            codes(convert(&s, &Group::Network)),
            ["legacy_network_value_unsupported"]
        );
        assert!(convert(&s, &Group::Subscriptions).is_ok());
    }
    assert!(convert(&replace("user_agent2", &"x".repeat(1024)), &Group::Network).is_ok());
}
#[test]
fn legacy_network_qt_runtime_interval_threshold_and_clear_semantics_are_preserved() {
    for source_value in [i32::MIN, -30, -1, 0, 1, 29, 30, 43200] {
        let plan = convert(
            &replace("sub_auto_update", &source_value.to_string()),
            &Group::Subscriptions,
        )
        .unwrap_or_else(|_| panic!("interval"));
        assert_eq!(
            plan.values["sub_auto_update"],
            if source_value < 30 { 0 } else { source_value }
        );
        assert_eq!(
            plan.report
                .iter()
                .any(|i| i.code == "legacy_subscription_interval_disabled"),
            source_value != 0 && source_value < 30
        );
    }
    assert_eq!(
        codes(convert(
            &replace("sub_auto_update", "43201"),
            &Group::Subscriptions
        )),
        ["legacy_settings_limit"]
    );
    assert_eq!(
        codes(convert(
            &replace("sub_auto_update", "2147483648"),
            &Group::Subscriptions
        )),
        ["legacy_network_value_unsupported"]
    );
    let recreate = convert(&replace("sub_clear", "true"), &Group::Subscriptions)
        .unwrap_or_else(|_| panic!("recreate"));
    assert_eq!(recreate.values["sub_update_mode"], "recreate");
    assert_eq!(recreate.values["sub_clear"], true);
    assert!(recreate
        .report
        .iter()
        .any(|i| i.code == "legacy_subscription_recreate"));
    let plan = convert(&replace("sub_clear", "0"), &Group::Subscriptions)
        .unwrap_or_else(|_| panic!("reconcile"));
    assert_eq!(plan.values["sub_clear"], true);
    assert_eq!(plan.values["sub_update_mode"], "reconcile");
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_subscription_reconcile"));
    assert!(crate::qt_source::frozen("mainwindow-setup-minutes.cpp")
        .contains("return v >= 30 ? v : 0;"));
    let updater = crate::qt_source::frozen("group-updater-refresh.cpp");
    assert!(
        updater.contains("if (settings->sub_clear)")
            && updater.contains("deleteProfiles(members())")
            && updater.contains("deleteProfiles(plan.stale)")
    );
}
#[test]
fn legacy_network_selected_flags_have_notices_and_structural_refusals_are_private() {
    for (field, group, code) in [
        (
            "net_use_proxy",
            Group::Network,
            "legacy_network_proxy_enabled",
        ),
        (
            "net_insecure",
            Group::Network,
            "legacy_network_insecure_enabled",
        ),
        (
            "sub_send_hwid",
            Group::Subscriptions,
            "legacy_subscription_hwid_enabled",
        ),
        (
            "allow_stopping_active_profile",
            Group::Subscriptions,
            "legacy_subscription_stopping_enabled",
        ),
    ] {
        let p = convert(&replace(field, "1"), &group).unwrap_or_else(|_| panic!("flag"));
        assert!(p.report.iter().any(|i| i.code == code));
        assert_eq!(
            codes(convert(&replace(field, "yes"), &group)),
            ["legacy_settings_value_invalid"]
        );
    }
    let mut s = source(rows());
    s.database
        .as_mut()
        .unwrap()
        .settings
        .push(row("user_agent2", "private-duplicate75"));
    let errors = convert(&s, &Group::Network).err().unwrap();
    assert_eq!(errors[0].code, "legacy_settings_duplicate");
    assert_eq!(errors[0].name.as_deref(), Some("user_agent"));
    assert!(!json!(errors).to_string().contains("private"));
    let mut s = source(rows());
    s.database.as_mut().unwrap().settings[2]
        .columns
        .insert("private-column75".into(), SourceValue::Null);
    assert_eq!(
        codes(convert(&s, &Group::Network)),
        ["legacy_settings_structure"]
    );
    assert!(convert(&s, &Group::Subscriptions).is_ok());
    assert_eq!(
        codes(convert(
            &replace("sub_custom_hwid_params", &"x".repeat(8193)),
            &Group::Subscriptions
        )),
        ["legacy_network_value_unsupported"]
    );
    s.parts.settings = false;
    assert_eq!(
        codes(convert(&s, &Group::Network)),
        ["legacy_settings_part_missing"]
    );
}

#[test]
fn legacy_network_real_qt_archives_match_independent_sqlite_aliases_and_runtime_modes() {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/settings/network-fixtures");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["qtRuntime"], "6.11.2");
    for (filename, hash) in manifest["sha256"].as_object().unwrap() {
        let bytes = std::fs::read(dir.join(filename)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            hash.as_str().unwrap()
        );
        let archive = crate::legacy_backup::parse(&bytes).unwrap();
        let mode = filename.trim_end_matches(".thrbackup");
        for (name, group) in [
            ("network", Group::Network),
            ("subscriptions", Group::Subscriptions),
        ] {
            let result = convert(&archive, &group);
            let expected = &manifest["expectations"][mode][name];
            if let Some(error) = expected.as_str() {
                assert!(codes(result).iter().all(|c| c == error), "{mode}/{name}");
            } else {
                let plan = result.unwrap_or_else(|_| panic!("{mode}/{name}"));
                // The golden files name the default agent of the version they
                // were made with; the agent follows the current version.
                let expected: Value = serde_json::from_str(&expected.to_string().replace(
                    manifest["defaultUserAgent"].as_str().unwrap(),
                    crate::subscriptions::DEFAULT_USER_AGENT,
                ))
                .unwrap();
                assert_eq!(json!(plan.values), expected);
            }
        }
        assert_eq!(std::fs::read(dir.join(filename)).unwrap(), bytes);
    }
}
