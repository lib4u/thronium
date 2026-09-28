use super::{
    tests::{codes, row, source},
    *,
};

#[test]
fn geodata_explicit_sources_and_five_saved_urls_are_preserved_without_defaults() {
    let ip = "https://assets.test/private73/geoip.dat";
    let site = "https://assets.test/private73/geosite.dat";
    let history = json!([
        site,
        ip,
        site,
        "https://other.test/a",
        "https://other.test/b"
    ]);
    let s = source(vec![
        row("xray_geoip_url", ip),
        row("xray_geosite_url", site),
        row("xray_geoip_url_history", "[]"),
        row("xray_geosite_url_history", &history.to_string()),
        row("language", "not a number"),
        row("private-unmapped-key", "private-unmapped-value"),
    ]);
    let p = convert(&s, &Group::Geodata).unwrap_or_else(|_| panic!("valid geodata"));
    assert_eq!(p.values["xray_geoip_url"], ip);
    assert_eq!(p.values["xray_geosite_url_history"], history);
    assert_eq!(p.values["xray_geoip_url_history"], json!([]));
    assert_eq!(p.imported_fields, fields(&Group::Geodata));
    assert_eq!(p.deferred_count, 2);
    let public = json!({"fields":p.imported_fields,"issues":p.report});
    assert!(!public.to_string().contains("private"));
    assert!(convert(&s, &Group::Appearance).is_err());
    let p = convert(
        &source(vec![row("xray_geosite_url_history", "[]")]),
        &Group::Geodata,
    )
    .unwrap_or_else(|_| panic!("clear only history"));
    assert_eq!(
        p.values,
        BTreeMap::from([("xray_geosite_url_history".into(), json!([]))])
    );
    assert!(convert(&source(vec![]), &Group::Geodata)
        .unwrap_or_else(|_| panic!("empty source"))
        .values
        .is_empty());
}

#[test]
fn geodata_explicit_empty_current_url_has_qt_fallback_and_public_notice() {
    let p = convert(
        &source(vec![row("xray_geoip_url", ""), row("xray_geosite_url", "")]),
        &Group::Geodata,
    )
    .unwrap_or_else(|_| panic!("explicit Qt fallback"));
    assert_eq!(
        p.values["xray_geoip_url"],
        "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geoip.dat"
    );
    assert_eq!(
        p.values["xray_geosite_url"],
        "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geosite.dat"
    );
    assert_eq!(
        p.report.iter().map(|i| i.code.as_str()).collect::<Vec<_>>(),
        ["legacy_geodata_default_source"; 2]
    );
    assert!(p.report.iter().all(|i| i
        .name
        .as_deref()
        .is_some_and(|n| fields(&Group::Geodata).contains(&n))));
}

#[test]
fn geodata_unsupported_sources_block_only_selected_category_without_leaking_values() {
    for text in [
        "http://private.test/a",
        "file:///private73",
        "https://u:p@private.test/a",
        "https://private.test/a#secret",
        " https://private.test/a",
        "https://private.test/a\n",
        "https://private.test/a b",
    ] {
        let s = source(vec![
            row("xray_geosite_url", text),
            row("log_auto_scroll", "true"),
        ]);
        let errors = convert(&s, &Group::Geodata).err().unwrap();
        assert_eq!(errors[0].code, "legacy_geodata_url_unsupported");
        assert!(!json!(errors).to_string().contains("private"));
        assert_eq!(
            convert(&s, &Group::Logging)
                .unwrap_or_else(|_| panic!("independent logging"))
                .values["log_auto_scroll"],
            true
        );
    }
    assert!(convert(
        &source(vec![row(
            "xray_geoip_url",
            &format!("https://private.test/{}", "x".repeat(8192))
        )]),
        &Group::Geodata
    )
    .is_err());
}

#[test]
fn geodata_history_rejects_malformed_types_limits_and_unsafe_members() {
    for value in [
        json!(null),
        json!({}),
        json!("[]"),
        json!([42]),
        json!([null]),
        json!([""]),
        json!(["http://private.test/a"]),
        json!(["https://u:p@private.test/a"]),
        json!(vec!["https://private.test/a"; 6]),
    ] {
        assert!(
            convert(
                &source(vec![row("xray_geosite_url_history", &value.to_string())]),
                &Group::Geodata
            )
            .is_err(),
            "{value}"
        );
    }
    for raw in [
        "[",
        "[\"https://private.test/a\",]",
        "",
        &" ".repeat(5 * 8192 * 6 + 65),
    ] {
        assert!(convert(
            &source(vec![row("xray_geoip_url_history", raw)]),
            &Group::Geodata
        )
        .is_err());
    }
    let safe = json!(["https://private.test/a", "https://private.test/a"]);
    assert_eq!(
        geodata::value("xray_geoip_url_history", &safe.to_string()).unwrap(),
        safe
    );
}

#[test]
fn geodata_duplicate_or_malformed_sqlite_fields_never_partially_convert() {
    let s = source(vec![
        row("xray_geoip_url", "https://private.test/a"),
        row("xray_geoip_url", "https://private.test/b"),
    ]);
    assert_eq!(
        codes(convert(&s, &Group::Geodata)),
        ["legacy_settings_duplicate"]
    );
    for key in fields(&Group::Geodata) {
        let mut r = row(
            key,
            if geodata::is_history(key) {
                "[]"
            } else {
                "https://private.test/a"
            },
        );
        r.columns.insert("private-column".into(), SourceValue::Null);
        let errors = convert(&source(vec![r]), &Group::Geodata).err().unwrap();
        assert_eq!(errors[0].code, "legacy_settings_structure");
        assert!(!json!(errors).to_string().contains("private"));
    }
    let mut s = source(vec![row("xray_geoip_url_history", "[]")]);
    s.parts.settings = false;
    assert_eq!(
        codes(convert(&s, &Group::Geodata)),
        ["legacy_settings_part_missing"]
    );
}

#[test]
fn geodata_real_qt_archives_match_the_independent_settings_schema_and_masks() {
    use sha2::{Digest, Sha256};
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/settings/geodata-fixtures");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["qtRuntime"], "6.11.2");
    for (filename, expected_hash) in manifest["sha256"].as_object().unwrap() {
        let raw = std::fs::read(folder.join(filename)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            expected_hash.as_str().unwrap()
        );
        if filename == "bad-sqlite-type.thrbackup" {
            assert!(
                matches!(crate::legacy_backup::parse(&raw), Err(error) if error == "legacy_backup_invalid_data")
            );
            continue;
        }
        let archive =
            crate::legacy_backup::parse(&raw).unwrap_or_else(|error| panic!("{filename}: {error}"));
        let result = convert(&archive, &Group::Geodata);
        match filename.as_str() {
            "valid.thrbackup" => {
                let plan = result.unwrap_or_else(|_| panic!("valid Qt settings"));
                assert_eq!(plan.values.len(), 4);
                assert_eq!(plan.values["xray_geosite_url_history"], manifest["history"]);
                assert_eq!(
                    plan.values["xray_geoip_url"],
                    manifest["sourceRows"]["xray_geoip_url"]
                );
                assert_eq!(plan.deferred_count, 1);
            }
            "clear-site-history.thrbackup" => assert_eq!(
                result.unwrap_or_else(|_| panic!("explicit clear")).values,
                BTreeMap::from([("xray_geosite_url_history".into(), json!([]))])
            ),
            "explicit-empty-sources.thrbackup" => {
                let plan = result.unwrap_or_else(|_| panic!("Qt fallback"));
                for key in ["xray_geoip_url", "xray_geosite_url"] {
                    assert_eq!(plan.values[key], manifest["sourceDefaults"][key]);
                }
                assert_eq!(
                    plan.report
                        .iter()
                        .filter(|issue| issue.code == "legacy_geodata_default_source")
                        .count(),
                    2
                );
            }
            "excluded-settings.thrbackup" => {
                assert_eq!(codes(result), ["legacy_settings_part_missing"])
            }
            "too-many.thrbackup" => assert_eq!(codes(result), ["legacy_settings_limit"]),
            "http-url.thrbackup" | "credential-url.thrbackup" => {
                assert_eq!(codes(result), ["legacy_geodata_url_unsupported"])
            }
            "unknown-column.thrbackup" => assert!(codes(result)
                .iter()
                .all(|code| code == "legacy_settings_structure")),
            "bad-json.thrbackup" | "bad-history-type.thrbackup" => {
                assert_eq!(codes(result), ["legacy_settings_value_invalid"])
            }
            _ => panic!("unexpected fixture"),
        }
        assert_eq!(std::fs::read(folder.join(filename)).unwrap(), raw);
    }
}
