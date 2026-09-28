use super::{
    tests::{codes, row, source},
    *,
};

fn manifest() -> Value {
    serde_json::from_str(include_str!("basic-fixtures/manifest.json")).unwrap()
}

#[test]
fn basic_settings_real_qt_archives_preserve_types_and_sparse_values() {
    for (mode, expected) in manifest()["modes"].as_object().unwrap() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "src/legacy_backup/settings/basic-fixtures/{mode}.thrbackup"
            )),
        )
        .unwrap();
        let archive = crate::legacy_backup::parse(&bytes).unwrap();
        let testing = convert(&archive, &Group::Testing).unwrap_or_else(|_| panic!("{mode}"));
        assert_eq!(
            testing.values["direct_test_url"],
            expected["direct_test_url"]
        );
        let result = convert(&archive, &Group::Logging);
        if mode.starts_with("bad-") {
            assert_eq!(
                codes(result),
                [match mode.as_str() {
                    "bad-sort" => "legacy_settings_sort_unsupported",
                    "bad-regex" => "legacy_settings_regex_unsupported",
                    _ => "legacy_settings_value_invalid",
                }]
            );
            continue;
        }
        let plan = result.unwrap_or_else(|_| panic!("{mode}"));
        assert_eq!(plan.values.len(), if mode == "sparse" { 0 } else { 17 });
        for (key, value) in &plan.values {
            let expected = match key.as_str() {
                "connection_sort" => json!(if mode == "defaults" {
                    "created"
                } else {
                    "process"
                }),
                "traffic_stats_retention_days" if mode == "retention-minimum" => json!(1),
                _ => expected[key].clone(),
            };
            assert_eq!(*value, expected, "{mode}/{key}");
        }
    }
}

#[test]
fn qt_appearance_is_not_imported_and_source_values_never_escape_review() {
    let s = source(vec![
        row("font", "private-marker82"),
        row("font_size", "20"),
        row("theme", "private-marker82"),
        row("log_include_regex", "[\"(?=private-marker82)\"]"),
    ]);
    let appearance = convert(&s, &Group::Appearance).unwrap_or_else(|_| panic!("appearance"));
    assert!(appearance.values.is_empty());
    assert_eq!(appearance.deferred_count, 4);
    let errors = convert(&s, &Group::Logging).err().unwrap();
    assert!(!json!(errors).to_string().contains("private-marker82"));
    assert_eq!(errors[0].name.as_deref(), Some("log_include_regex"));
}

#[test]
fn basic_settings_use_catalog_bounds_and_explicit_semantic_notices() {
    for (key, text) in [
        ("max_log_line", "20001"),
        ("log_level", "verbose"),
        ("log_file_level", "panic"),
        ("log_exclude_keyword", "[null]"),
        ("traffic_stats_retention_days", "3651"),
        ("enable_stats", "yes"),
    ] {
        assert_eq!(
            codes(convert(&source(vec![row(key, text)]), &Group::Logging)),
            ["legacy_settings_value_invalid"]
        );
    }
    for (text, expected) in [("1", "download"), ("2", "upload"), ("3", "process")] {
        assert_eq!(
            convert(&source(vec![row("connection_sort", text)]), &Group::Logging)
                .unwrap_or_else(|_| panic!("sort"))
                .values["connection_sort"],
            expected
        );
    }
    let p = convert(
        &source(vec![
            row("connection_sort", "0"),
            row("traffic_stats_retention_days", "0"),
        ]),
        &Group::Logging,
    )
    .unwrap_or_else(|_| panic!("notices"));
    assert_eq!(
        p.report.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
        [
            "legacy_settings_sort_default",
            "legacy_settings_retention_minimum"
        ]
    );
}

#[test]
fn log_filters_match_the_actual_qt_predicate_oracle() {
    let root = tempfile::tempdir().unwrap();
    for case in manifest()["filterOracle"].as_array().unwrap() {
        let mut library = crate::store::Library::default();
        library
            .settings
            .extend(case["settings"].as_object().unwrap().clone());
        crate::settings::validate(&library).unwrap();
        let logs = crate::logs::Logs::default();
        logs.configure(&library, root.path());
        for (line, expected) in case["lines"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["matches"].as_array().unwrap())
        {
            logs.clear();
            logs.push("app", Some("info"), line.as_str().unwrap(), false);
            assert_eq!(
                logs.view(crate::logs::Filter::default()).unwrap().matching != 0,
                expected.as_bool().unwrap(),
                "{} / {line}",
                case["name"]
            );
        }
    }
}
