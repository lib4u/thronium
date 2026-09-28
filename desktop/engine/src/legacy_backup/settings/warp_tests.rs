use super::tests::{codes, row, source};
use super::*;

pub(super) fn rows() -> Vec<SourceSetting> {
    vec![
        row("enable_warp", "true"),
        row(
            "warp_private_key",
            "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
        ),
        row(
            "warp_public_key",
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
        ),
        row(
            "warp_ifc_addrs",
            r#"["172.16.0.2/32","2606:4700:110:8c5a::2/128"]"#,
        ),
        row("warp_ep", "engage.cloudflareclient.com:2408"),
        row("warp_reserved", r#"["0","128","255"]"#),
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
fn legacy_warp_exact_bundle_peer_key_and_enable_notice_without_private_review_values() {
    let plan = convert(&source(rows()), &Group::Warp).unwrap_or_else(|_| panic!("valid"));
    assert_eq!(plan.imported_fields, warp::FIELDS);
    assert_eq!(plan.values["enable_warp"], true);
    assert_eq!(plan.values["warp_reserved"], json!(["0", "128", "255"]));
    assert_eq!(
        plan.values["warp_ifc_addrs"],
        json!(["172.16.0.2/32", "2606:4700:110:8c5a::2/128"])
    );
    assert_eq!(plan.values["warp_private_key"], rows()[1].value);
    assert_eq!(plan.values["warp_public_key"], rows()[2].value);
    let public = json!({"fields":plan.imported_fields,"report":plan.report});
    assert!(public.to_string().contains("legacy_warp_enabled"));
    for r in rows().into_iter().skip(1) {
        assert!(!public.to_string().contains(&r.value));
    }
    for endpoint in [
        "engage.cloudflareclient.com",
        "127.0.0.1:20408",
        "example.test.:02408",
    ] {
        let p = convert(&replace("warp_ep", endpoint), &Group::Warp)
            .unwrap_or_else(|_| panic!("endpoint"));
        assert_eq!(p.values["warp_ep"], endpoint);
    }
}
#[test]
fn legacy_warp_missing_fields_cannot_mix_identities_but_off_is_independent() {
    assert!(convert(&source(vec![]), &Group::Warp)
        .unwrap_or_else(|_| panic!("missing"))
        .values
        .is_empty());
    for field in warp::FIELDS {
        let s = source(rows().into_iter().filter(|r| r.key != *field).collect());
        assert_eq!(
            codes(convert(&s, &Group::Warp)),
            ["legacy_warp_bundle_incomplete"]
        );
    }
    assert_eq!(
        codes(convert(
            &source(vec![row("enable_warp", "true")]),
            &Group::Warp
        )),
        ["legacy_warp_bundle_incomplete"]
    );
    let off = convert(&source(vec![row("enable_warp", "0")]), &Group::Warp)
        .unwrap_or_else(|_| panic!("off"));
    assert_eq!(
        off.values,
        BTreeMap::from([("enable_warp".into(), json!(false))])
    );
    assert!(off.report.is_empty());
    let empty = warp::FIELDS
        .iter()
        .map(|&k| {
            row(
                k,
                match k {
                    "enable_warp" => "false",
                    "warp_ifc_addrs" | "warp_reserved" => "[]",
                    _ => "",
                },
            )
        })
        .collect();
    let cleared =
        convert(&source(empty), &Group::Warp).unwrap_or_else(|_| panic!("disabled empty identity"));
    assert_eq!(cleared.values.len(), 6);
    assert!(cleared.report.is_empty());
    for field in [
        "warp_private_key",
        "warp_public_key",
        "warp_ep",
        "warp_ifc_addrs",
    ] {
        assert_eq!(
            codes(convert(
                &replace(field, if field == "warp_ifc_addrs" { "[]" } else { "" }),
                &Group::Warp
            )),
            ["legacy_warp_bundle_incomplete"]
        );
    }
}
#[test]
fn legacy_warp_rejects_unsupported_shapes_without_inspecting_other_categories() {
    for (field, invalid) in [
        ("warp_private_key", "private-canary74"),
        ("warp_public_key", "private-canary74"),
        ("warp_ep", "[::1]:2408"),
        ("warp_ep", "host:0"),
        ("warp_ep", "host:65536"),
        ("warp_ep", "host:2408/path"),
        ("warp_ep", "user:secret@host:2408"),
        ("warp_ep", " host:2408"),
        ("warp_ep", "host:2408#private-canary74"),
        ("warp_ep", "host:2408?x=1"),
        ("warp_ep", "https://host:2408"),
        ("warp_ifc_addrs", r#"["host/32"]"#),
        ("warp_ifc_addrs", r#"["10.0.0.2/33"]"#),
        ("warp_ifc_addrs", r#"["::1/129"]"#),
        ("warp_ifc_addrs", r#"["10.0.0.2"]"#),
        ("warp_ifc_addrs", "[42]"),
        ("warp_ifc_addrs", "{}"),
        ("warp_reserved", "[0,128,255]"),
        ("warp_reserved", r#"["0","256","1"]"#),
        ("warp_reserved", r#"["0","1"]"#),
        ("warp_reserved", "null"),
        ("warp_reserved", r#"["+1","1","2"]"#),
        ("warp_reserved", "["),
    ] {
        let mut s = replace(field, invalid);
        s.database
            .as_mut()
            .unwrap()
            .settings
            .push(row("log_auto_scroll", "true"));
        let errors = convert(&s, &Group::Warp)
            .err()
            .unwrap_or_else(|| panic!("{field} accepted"));
        assert_eq!(errors[0].code, "legacy_warp_value_unsupported");
        assert!(!json!(errors).to_string().contains("private-canary74"));
        assert_eq!(
            convert(&s, &Group::Logging)
                .unwrap_or_else(|_| panic!("logging"))
                .values["log_auto_scroll"],
            true
        );
    }
    assert_eq!(
        codes(convert(
            &replace("warp_reserved", &" ".repeat(8193)),
            &Group::Warp
        )),
        ["legacy_settings_limit"]
    );
    let mut s = source(rows());
    s.database
        .as_mut()
        .unwrap()
        .settings
        .push(row("enable_warp", "false"));
    assert_eq!(
        codes(convert(&s, &Group::Warp)),
        ["legacy_settings_duplicate"]
    );
    let mut s = source(rows());
    s.database.as_mut().unwrap().settings[1]
        .columns
        .insert("private-column74".into(), SourceValue::Null);
    assert_eq!(
        codes(convert(&s, &Group::Warp)),
        ["legacy_settings_structure"]
    );
    s.parts.settings = false;
    assert_eq!(
        codes(convert(&s, &Group::Warp)),
        ["legacy_settings_part_missing"]
    );
}
#[test]
fn legacy_warp_real_qt_archives_preserve_six_fields_and_reject_incomplete_or_invalid_sources() {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/settings/warp-fixtures");
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
        let result = convert(&archive, &Group::Warp);
        match filename.as_str() {
            "valid.thrbackup" | "disabled.thrbackup" | "empty.thrbackup" => {
                let plan = result.unwrap_or_else(|_| panic!("{filename}"));
                assert_eq!(plan.values.len(), 6);
                for key in ["warp_private_key", "warp_public_key", "warp_ep"] {
                    assert_eq!(
                        plan.values[key],
                        manifest["modes"][filename.trim_end_matches(".thrbackup")][key]
                    );
                }
            }
            "off-only.thrbackup" => {
                assert_eq!(result.unwrap_or_else(|_| panic!("off")).values.len(), 1)
            }
            "incomplete.thrbackup" => assert_eq!(codes(result), ["legacy_warp_bundle_incomplete"]),
            "bad-key.thrbackup" | "bad-reserved.thrbackup" | "ipv6-endpoint.thrbackup" => {
                assert_eq!(codes(result), ["legacy_warp_value_unsupported"])
            }
            "excluded-settings.thrbackup" => {
                assert_eq!(codes(result), ["legacy_settings_part_missing"])
            }
            "unknown-column.thrbackup" => assert!(codes(result)
                .iter()
                .all(|v| v == "legacy_settings_structure")),
            _ => panic!("unknown fixture"),
        }
        assert_eq!(std::fs::read(dir.join(filename)).unwrap(), bytes);
    }
}
