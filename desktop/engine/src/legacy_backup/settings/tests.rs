use super::super::{Parts, SourceDatabase};
use super::*;

pub(super) fn row(key: &str, text: &str) -> SourceSetting {
    SourceSetting {
        key: key.into(),
        value: text.into(),
        columns: [
            ("key".into(), SourceValue::Text(key.into())),
            ("value".into(), SourceValue::Text(text.into())),
        ]
        .into(),
    }
}
pub(super) fn source(rows: Vec<SourceSetting>) -> SourceArchive {
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: Value::Null,
        created_at: None,
        parts: Parts {
            settings: true,
            ..Parts::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            settings: rows,
            ..SourceDatabase::default()
        }),
    }
}
pub(super) fn codes(result: Result<SettingsPlan, Vec<Issue>>) -> Vec<String> {
    result.err().unwrap().into_iter().map(|i| i.code).collect()
}

#[test]
fn settings_flag_is_authoritative_and_other_groups_are_not_inspected() {
    let mut s = source(vec![
        row("language", "not a number"),
        row("log_auto_scroll", "1"),
    ]);
    assert_eq!(
        convert(&s, &Group::Logging)
            .unwrap_or_else(|_| panic!("logging"))
            .values["log_auto_scroll"],
        true
    );
    assert_eq!(
        codes(convert(&s, &Group::Appearance)),
        ["legacy_settings_value_invalid"]
    );
    s.parts.settings = false;
    s.database = None;
    assert_eq!(
        codes(convert(&s, &Group::Appearance)),
        ["legacy_settings_part_missing"]
    );
    s.parts.settings = true;
    assert_eq!(
        codes(convert(&s, &Group::Appearance)),
        ["legacy_database_missing"]
    );
}
#[test]
fn exact_ten_values_and_missing_keys_do_not_copy_defaults() {
    let s = source(vec![
        row("language", "4"),
        row("show_config_security", "true"),
        row("skip_delete_confirmation", "0"),
        row("log_auto_scroll", "false"),
        row("test_url", "http://localhost/probe?synthetic=private"),
        row("url_test_timeout_ms", "10000"),
        row("test_concurrent", "10"),
        row("speed_test_mode", "3"),
        row("speed_test_timeout_ms", "120000"),
        row("simple_dl_url", "http://localhost/file"),
    ]);
    let mut all = BTreeMap::new();
    for group in [Group::Appearance, Group::Testing, Group::Logging] {
        let p = convert(&s, &group).unwrap_or_else(|_| panic!("valid"));
        let expected: Vec<_> = fields(&group)
            .iter()
            .copied()
            .filter(|field| {
                s.database
                    .as_ref()
                    .unwrap()
                    .settings
                    .iter()
                    .any(|row| row.key == *field)
            })
            .collect();
        assert_eq!(p.values.len(), expected.len());
        assert_eq!(p.deferred_count, 10 - expected.len());
        assert_eq!(p.imported_fields, expected);
        all.extend(p.values);
    }
    assert_eq!(all["language"], "ru");
    assert_eq!(all["speed_test_mode"], "simple");
    assert_eq!(all["speed_test_timeout_ms"], 120000);
    assert_eq!(all["test_url"], "http://localhost/probe?synthetic=private");
    let empty = convert(&source(vec![]), &Group::Testing).unwrap_or_else(|_| panic!("empty"));
    assert!(empty.values.is_empty() && empty.imported_fields.is_empty());
}
#[test]
fn unknown_keys_values_and_columns_never_escape_public_report() {
    let private = "synthetic-private-secret";
    let mut other = row(private, private);
    other
        .columns
        .insert(private.into(), SourceValue::Blob(vec![1; 100]));
    let s = source(vec![row("log_auto_scroll", "true"), other]);
    let p = convert(&s, &Group::Logging).unwrap_or_else(|_| panic!("unknown ignored"));
    assert_eq!(p.deferred_count, 1);
    assert_eq!(p.values.len(), 1);
    let public = json!({"fields":p.imported_fields,"report":p.report,"deferred":p.deferred_count});
    assert!(!public.to_string().contains(private));
    let mut known = row("test_url", private);
    known.columns.insert(private.into(), SourceValue::Null);
    let errors = convert(&source(vec![known]), &Group::Testing)
        .err()
        .unwrap();
    assert_eq!(errors[0].name.as_deref(), Some("test_url"));
    assert!(!json!(errors).to_string().contains(private));
}
#[test]
fn invalid_rows_and_duplicates_block_only_their_group_atomically() {
    for field in ["key", "value"] {
        for invalid in [
            SourceValue::Null,
            SourceValue::Integer(1),
            SourceValue::Real(1.),
            SourceValue::Blob(vec![1]),
        ] {
            let mut bad = row("language", "1");
            bad.columns.insert(field.into(), invalid);
            let s = source(vec![
                row("show_config_security", "true"),
                bad,
                row("log_auto_scroll", "false"),
            ]);
            assert_eq!(
                codes(convert(&s, &Group::Appearance)),
                ["legacy_settings_structure"]
            );
            assert!(convert(&s, &Group::Logging).is_ok());
        }
    }
    let s = source(vec![
        row("language", "1"),
        row("language", "4"),
        row("log_auto_scroll", "true"),
    ]);
    assert_eq!(
        codes(convert(&s, &Group::Appearance)),
        ["legacy_settings_duplicate"]
    );
    assert!(convert(&s, &Group::Logging).is_ok());
}
#[test]
fn booleans_integer_ranges_enums_and_urls_are_strict_without_silent_fallback() {
    for (source_value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
        let p = convert(
            &source(vec![row("log_auto_scroll", source_value)]),
            &Group::Logging,
        )
        .unwrap_or_else(|_| panic!("bool"));
        assert_eq!(p.values["log_auto_scroll"], expected);
    }
    for text in [
        "",
        "TRUE",
        "False",
        "2",
        " true",
        "null",
        "synthetic-private",
    ] {
        assert_eq!(
            codes(convert(
                &source(vec![row("log_auto_scroll", text)]),
                &Group::Logging
            )),
            ["legacy_settings_value_invalid"]
        );
    }
    for (key, min, max) in [
        ("url_test_timeout_ms", 100, 10000),
        ("test_concurrent", 1, 10),
        ("speed_test_timeout_ms", 1000, 120000),
    ] {
        for value in [min, max] {
            assert!(convert(&source(vec![row(key, &value.to_string())]), &Group::Testing).is_ok());
        }
        for value in [min - 1, max + 1] {
            assert_eq!(
                codes(convert(
                    &source(vec![row(key, &value.to_string())]),
                    &Group::Testing
                )),
                ["legacy_settings_value_invalid"]
            );
        }
        for text in ["1.0", "1e3", "NaN", "9223372036854775808", "100\n"] {
            assert_eq!(
                codes(convert(&source(vec![row(key, text)]), &Group::Testing)),
                ["legacy_settings_value_invalid"]
            );
        }
    }
    for (n, target) in [(1, "en"), (4, "ru")] {
        let p = convert(
            &source(vec![row("language", &n.to_string())]),
            &Group::Appearance,
        )
        .unwrap_or_else(|_| panic!("language"));
        assert_eq!(p.values["language"], target);
    }
    for n in [0, 2, 3, 5, -1] {
        assert_eq!(
            codes(convert(
                &source(vec![row("language", &n.to_string())]),
                &Group::Appearance
            )),
            ["legacy_settings_language_unsupported"]
        );
    }
    for (n, target) in [(0, "full"), (1, "download"), (2, "upload"), (3, "simple")] {
        let p = convert(
            &source(vec![row("speed_test_mode", &n.to_string())]),
            &Group::Testing,
        )
        .unwrap_or_else(|_| panic!("mode"));
        assert_eq!(p.values["speed_test_mode"], target);
    }
    for n in [4, 5, -1] {
        assert_eq!(
            codes(convert(
                &source(vec![row("speed_test_mode", &n.to_string())]),
                &Group::Testing
            )),
            ["legacy_settings_speed_mode_unsupported"]
        );
    }
    for text in [
        "",
        "ftp://example.test",
        "https://user:private@example.test",
        "https://user@example.test",
        "https://",
        "https://example.test/line\nbreak",
        "http://example.test/a b",
    ] {
        assert_eq!(
            codes(convert(
                &source(vec![row("test_url", text)]),
                &Group::Testing
            )),
            ["legacy_settings_value_invalid"]
        );
    }
    assert_eq!(
        codes(convert(
            &source(vec![row(
                "test_url",
                &format!("https://example.test/{}", "x".repeat(8192))
            )]),
            &Group::Testing
        )),
        ["legacy_settings_value_invalid"]
    );
}

#[test]
fn real_qt_container_fixtures_keep_independent_groups_and_exact_source_values() {
    let manifest: Value = serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    assert_eq!(manifest["qtRuntime"], "6.11.2");
    assert_eq!(manifest["sha256"].as_object().unwrap().len(), 11);
    for name in [
        "valid-en",
        "valid-ru",
        "defaults",
        "blocked-appearance",
        "blocked-testing",
        "missing-fields",
        "empty",
        "unknown-values",
        "unknown-column",
        "excluded-settings",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "src/legacy_backup/settings/fixtures/{name}.thrbackup"
        ));
        let before = std::fs::read(&path).unwrap();
        let archive = super::super::parse(&before).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(archive.parts.settings, name != "excluded-settings");
        if name == "excluded-settings" {
            assert_eq!(
                archive
                    .database
                    .as_ref()
                    .unwrap()
                    .settings
                    .iter()
                    .find(|r| r.key == "language")
                    .unwrap()
                    .value,
                "2"
            );
        }
        for group in [Group::Appearance, Group::Testing, Group::Logging] {
            let result = convert(&archive, &group);
            if name == "excluded-settings" {
                assert_eq!(codes(result), ["legacy_settings_part_missing"]);
                continue;
            }
            if name == "unknown-column" {
                assert!(codes(result)
                    .iter()
                    .all(|c| c == "legacy_settings_structure"));
                continue;
            }
            if (name == "defaults" || name == "blocked-appearance") && group == Group::Appearance {
                assert_eq!(codes(result), ["legacy_settings_language_unsupported"]);
                continue;
            }
            if name == "blocked-testing" && group == Group::Testing {
                assert_eq!(codes(result), ["legacy_settings_speed_mode_unsupported"]);
                continue;
            }
            let plan = result.unwrap_or_else(|_| panic!("{name}"));
            if name == "empty" {
                assert!(plan.values.is_empty());
            } else if name == "missing-fields" {
                assert!(plan.imported_fields.iter().all(|f| [
                    "log_auto_scroll",
                    "test_concurrent"
                ]
                .contains(&f.as_str())));
            } else {
                let original_group = match group {
                    Group::Appearance => "appearance",
                    Group::Testing => "testing",
                    Group::Logging => "logging",
                    _ => unreachable!(),
                };
                assert_eq!(
                    plan.values.len(),
                    manifest["groups"][original_group].as_array().unwrap().len()
                );
                if group == Group::Appearance {
                    assert_eq!(
                        plan.values["language"],
                        if name == "valid-ru" { "ru" } else { "en" }
                    );
                }
                if group == Group::Testing {
                    assert_eq!(
                        plan.values["test_url"],
                        manifest[if name == "defaults" {
                            "sourceDefaults"
                        } else {
                            "validSourceRows"
                        }]["test_url"]
                    );
                }
            }
            let public = json!({"fields":plan.imported_fields,"report":plan.report,"deferred":plan.deferred_count});
            assert!(!public.to_string().contains("synthetic-private"));
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    // Structural SQL type errors are rejected by the reader before conversion.
    assert!(super::super::parse(include_bytes!("fixtures/bad-sqlite-type.thrbackup")).is_err());
}

#[test]
fn candidate_maps_preference_fields_correctly_and_preserves_unrelated_current_values() {
    let source = super::super::parse(include_bytes!("fixtures/valid-en.thrbackup")).unwrap();
    let mut current = crate::store::Library::default();
    current.preferences.theme = "dark".into();
    current.settings.insert("font_size".into(), json!(18));
    current
        .settings
        .insert("log_include_keyword".into(), json!(["current-only"]));
    let before = json!(current);
    let mut candidate = current.clone();
    let mut preferences = json!(candidate.preferences);
    for group in [Group::Appearance, Group::Testing, Group::Logging] {
        let plan = convert(&source, &group).unwrap_or_else(|_| panic!("valid"));
        for (id, value) in plan.values {
            let field = crate::settings::fields()
                .iter()
                .find(|f| f.id == id)
                .unwrap();
            if let Some(path) = &field.preference {
                *preferences.pointer_mut(path).unwrap() = value;
            } else {
                candidate.settings.insert(id, value);
            }
        }
    }
    candidate.preferences = serde_json::from_value(preferences).unwrap();
    crate::settings::validate(&candidate).unwrap();
    crate::store::validate_library(&candidate).unwrap();
    assert_eq!(crate::settings::value(&candidate, "language"), "en");
    assert_eq!(candidate.preferences.ping.timeout_ms, 4500);
    assert_eq!(
        candidate.preferences.ping.url,
        "http://127.0.0.1:38173/probe?fixture=synthetic-private"
    );
    assert_eq!(candidate.preferences.theme, "dark");
    assert_eq!(candidate.settings["font_size"], 18);
    assert_eq!(
        candidate.settings["log_include_keyword"],
        json!(["current-only"])
    );
    assert!(
        !candidate.settings.contains_key("language")
            && !candidate.settings.contains_key("test_url")
    );
    assert_eq!(json!(current), before);
}

#[test]
fn row_limit_precedes_data_inspection_and_duplicates_are_bounded() {
    let s = source(
        (0..super::super::MAX_ROWS_PER_TABLE)
            .map(|n| row(&format!("unknown-{n}"), "invalid-private"))
            .collect(),
    );
    let plan = convert(&s, &Group::Logging).unwrap_or_else(|_| panic!("limit inclusive"));
    assert_eq!(plan.deferred_count, super::super::MAX_ROWS_PER_TABLE);
    assert!(plan.values.is_empty());
    let mut s = s;
    s.database
        .as_mut()
        .unwrap()
        .settings
        .push(row("log_auto_scroll", "true"));
    assert_eq!(
        codes(convert(&s, &Group::Logging)),
        ["legacy_settings_limit"]
    );
    s.parts.settings = false;
    assert_eq!(
        codes(convert(&s, &Group::Logging)),
        ["legacy_settings_part_missing"]
    );
    let s = source(
        (0..super::super::MAX_ROWS_PER_TABLE)
            .map(|_| row("log_auto_scroll", "true"))
            .collect(),
    );
    assert_eq!(
        codes(convert(&s, &Group::Logging)),
        ["legacy_settings_duplicate"]
    );
}
