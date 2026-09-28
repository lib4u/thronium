use super::*;
use serde_json::{json, Value};

#[test]
fn real_qt_migration_goldens_and_explicit_strict_boundaries() {
    let golden: Value =
        serde_json::from_str(include_str!("../fixtures/migration/golden.json")).unwrap();
    assert_eq!(golden["qtRuntime"], "6.11.2");
    let cases = golden["cases"].as_array().unwrap();
    assert!(cases.len() >= 117);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        if let Some(entries) = case.get("entries") {
            let drafts: Vec<Draft> = serde_json::from_value(entries.clone()).unwrap();
            let exported = export_migration(&drafts);
            if case["strictExportReject"] == true {
                assert!(exported.is_err(), "{id}");
                continue;
            }
            let link = exported.unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(
                decode_uri(&link).unwrap(),
                decode_uri(case["expected"]["link"].as_str().unwrap()).unwrap(),
                "{id}"
            );
            assert!(import_migration(&[&link]).unwrap() == drafts, "{id}");
        } else if case.get("assemblyLinks").is_some() {
            let links: Vec<_> = case["assemblyLinks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let parsed = import_migration(&links);
            if case["strictAssemblyReject"] == true {
                assert!(parsed.is_err(), "{id}");
            } else {
                let names: Vec<_> = parsed.unwrap().iter().map(|e| e.name.clone()).collect();
                assert_eq!(json!(names), case["assemblyOrder"], "{id}");
            }
        } else {
            let parsed = import_migration(&[case["link"].as_str().unwrap()]);
            if case.get("strictReject").is_some() || case.get("assembly").is_some() {
                assert!(parsed.is_err(), "{id}");
            } else {
                assert_eq!(
                    json!(parsed.unwrap_or_else(|e| panic!("{id}: {e}"))),
                    case["expected"]["parsed"],
                    "{id}"
                );
            }
        }
    }
}

fn sample() -> Draft {
    Draft {
        name: "Synthetic account".into(),
        issuer: "Test".into(),
        secret: "MY".into(),
        ..Draft::default()
    }
}
fn wire_item(name: &str) -> Vec<u8> {
    // Literal protobuf tags from the schema, independent of the exporter.
    let mut result = vec![10, 1, b'f', 18, name.len() as u8];
    result.extend_from_slice(name.as_bytes());
    result.extend_from_slice(&[32, 1, 40, 1, 48, 2]);
    result
}
fn packet(items: &[Vec<u8>], size: u64, index: u64, id: Option<i32>) -> String {
    let mut data = Vec::new();
    for item in items {
        blob(&mut data, 1, item);
    }
    number(&mut data, 2, 1);
    number(&mut data, 3, size);
    number(&mut data, 4, index);
    if let Some(id) = id {
        number(&mut data, 5, id as i64 as u64);
    }
    format!("otpauth-migration://offline?data={}", STANDARD.encode(data))
}
fn names(drafts: &[Draft]) -> Vec<&str> {
    drafts.iter().map(|d| d.name.as_str()).collect()
}
fn fixture(id: &str) -> Value {
    let golden: Value =
        serde_json::from_str(include_str!("../fixtures/migration/golden.json")).unwrap();
    golden["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone()
}

#[test]
fn complete_groups_reorder_parts_and_keep_first_group_appearance() {
    let a0 = packet(&[wire_item("a0"), wire_item("a0-second")], 2, 0, Some(-17));
    let a1 = packet(&[wire_item("a1")], 2, 1, Some(-17));
    let b = packet(&[wire_item("b")], 1, 0, None);
    let c0 = packet(&[wire_item("c0")], 2, 0, Some(0));
    let c1 = packet(&[wire_item("c1")], 2, 1, Some(0));
    let result = import_migration(&[&a1, &b, &c1, &a0, &c0]).unwrap();
    assert_eq!(names(&result), ["a0", "a0-second", "a1", "b", "c0", "c1"]);
    for links in [
        &[a0.as_str(), b.as_str()][..],
        &[a1.as_str(), c0.as_str()][..],
    ] {
        assert_eq!(
            import_migration(links).err(),
            Some("otp_migration_batch_incomplete")
        );
    }
}

#[test]
fn duplicate_policy_distinguishes_absent_and_explicit_batch_id() {
    let one = packet(&[wire_item("first")], 1, 0, None);
    let two = packet(&[wire_item("second")], 1, 0, None);
    assert_eq!(
        names(&import_migration(&[&one, &two, &one]).unwrap()),
        ["first", "second", "first"]
    );
    for id in [i32::MIN, -17, 0, i32::MAX] {
        let first = packet(&[wire_item("first")], 1, 0, Some(id));
        let conflicting = packet(&[wire_item("second")], 1, 0, Some(id));
        assert_eq!(names(&import_migration(&[&first]).unwrap()), ["first"]);
        for other in [&first, &conflicting] {
            assert_eq!(
                import_migration(&[&first, other]).err(),
                Some("otp_migration_batch_duplicate")
            );
        }
        let other_size = packet(&[wire_item("second")], 2, 1, Some(id));
        assert_eq!(
            import_migration(&[&first, &other_size]).err(),
            Some("otp_migration_batch_invalid")
        );
    }
    let fixture = fixture("assembly-conflicting-duplicate-index");
    let links: Vec<_> = fixture["assemblyLinks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_ne!(links[0], links[1]);
    assert_eq!(
        import_migration(&links).err(),
        Some("otp_migration_batch_duplicate")
    );
}

#[test]
fn bounds_apply_to_fragments_total_entries_and_source_bytes_without_truncation() {
    let small = packet(&[wire_item("")], 1, 0, None);
    assert_eq!(import_migration(&[]).err(), Some("otp_import_empty"));
    assert_eq!(
        import_migration(&vec![small.as_str(); MAX_FRAGMENTS])
            .unwrap()
            .len(),
        MAX_FRAGMENTS
    );
    assert_eq!(
        import_migration(&vec![small.as_str(); MAX_FRAGMENTS + 1]).err(),
        Some("otp_migration_batch_invalid")
    );
    let half = packet(&vec![wire_item(""); MAX_ENTRIES / 2], 1, 0, None);
    assert_eq!(
        import_migration(&[&half, &half]).unwrap().len(),
        MAX_ENTRIES
    );
    assert_eq!(
        import_migration(&[&half, &half, &small]).err(),
        Some("otp_entry_limit")
    );
    let oversized = packet(&vec![wire_item(""); MAX_ENTRIES + 1], 1, 0, None);
    assert_eq!(
        import_migration(&[&oversized]).err(),
        Some("otp_entry_limit")
    );
    let oversized_source = " ".repeat(MAX_TEXT + 1);
    assert_eq!(
        import_migration(&[&oversized_source]).err(),
        Some("otp_text_too_large")
    );
    // Even ignored surrounding whitespace counts before decoding/allocation.
    let padded = format!("{small}{}", " ".repeat(MAX_TEXT / 2));
    assert!(import_migration(&[&padded]).is_ok());
    assert_eq!(
        import_migration(&[&padded, &padded]).err(),
        Some("otp_text_too_large")
    );
    let exact = vec![sample(); MAX_ENTRIES];
    let link = export_migration(&exact).unwrap();
    assert!(import_migration(&[&link]).unwrap() == exact);
    assert_eq!(
        export_migration(&vec![sample(); MAX_ENTRIES + 1]).err(),
        Some("otp_entry_limit")
    );
    let large = Draft {
        secret: encode_secret(&[42; super::super::MAX_KEY_BYTES]),
        ..sample()
    };
    assert_eq!(
        export_migration(&vec![large; 1000]).err(),
        Some("otp_text_too_large")
    );
}

#[test]
fn all_export_fields_are_representable_or_whole_export_fails_and_json_preserves_them() {
    let mut unsupported = Vec::new();
    for digits in [4, 5, 7, 9, 10] {
        unsupported.push(Draft { digits, ..sample() });
    }
    for kind in [Kind::Totp, Kind::Hotp] {
        unsupported.push(Draft {
            kind,
            period: 60,
            ..sample()
        });
    }
    unsupported.push(Draft {
        counter: "7".into(),
        ..sample()
    });
    for draft in unsupported {
        let batch = vec![sample(), draft];
        assert_eq!(
            export_migration(&batch).err(),
            Some("otp_migration_export_unsupported")
        );
        let fallback = super::super::formats::export_json(&batch).unwrap();
        assert!(super::super::formats::import(&fallback).unwrap() == batch);
    }
    assert_eq!(
        export_migration(&[
            sample(),
            Draft {
                name: String::new(),
                ..sample()
            }
        ])
        .err(),
        Some("otp_migration_label_unsupported")
    );
    assert_eq!(
        export_migration(&[
            sample(),
            Draft {
                secret: "invalid!".into(),
                ..sample()
            }
        ])
        .err(),
        Some("otp_secret_invalid")
    );
    for (name, issuer) in [
        ("", ""),
        (" : /%+日本🦊 ", " prefix:issuer "),
        ("literal:label", ""),
    ] {
        let draft = Draft {
            name: name.into(),
            issuer: issuer.into(),
            kind: Kind::Hotp,
            counter: i64::MAX.to_string(),
            ..sample()
        };
        let link = export_migration(std::slice::from_ref(&draft)).unwrap();
        assert!(import_migration(&[&link]).unwrap() == [draft]);
    }
}

#[test]
fn optional_defaults_are_literal_and_totp_counter_is_not_silently_dropped_on_import() {
    let mut item = vec![10, 1, b'f', 26, 6];
    item.extend_from_slice(b"Issuer");
    item.extend_from_slice(&[32, 1, 40, 1, 48, 2, 56, 7]);
    let link = packet(&[item], 1, 0, None);
    let result = import_migration(&[&link]).unwrap();
    assert_eq!(result[0].name, "");
    assert_eq!(result[0].issuer, "Issuer");
    assert_eq!(result[0].counter, "7");
    assert_eq!(result[0].period, 30);
    let saved = super::super::formats::export_json(&result).unwrap();
    assert!(super::super::formats::import(&saved).unwrap() == result);
    assert_eq!(
        export_migration(&result).err(),
        Some("otp_migration_export_unsupported")
    );
}

#[test]
fn malformed_fixtures_return_static_specific_errors_without_source_data() {
    for (id, expected) in [
        ("duplicate-entry-1", "otp_migration_duplicate_field"),
        ("duplicate-header-5", "otp_migration_duplicate_field"),
        ("unknown-inner-field", "otp_migration_field_unsupported"),
        ("unknown-outer-field", "otp_migration_field_unsupported"),
        ("unknown-algorithm-4", "otp_migration_enum_unsupported"),
        ("unknown-type-None", "otp_migration_enum_unsupported"),
        ("missing-version", "otp_migration_version"),
        ("future-version", "otp_migration_version"),
        ("zero-size", "otp_migration_batch_invalid"),
        ("batch-id-overflow", "otp_migration_batch_invalid"),
        ("secret-absent", "otp_secret_empty"),
        ("one-valid-one-empty", "otp_secret_empty"),
        ("oversized-secret", "otp_secret_too_large"),
        ("oversized-label", "otp_label_invalid"),
        ("invalid-utf8-name", "otp_label_invalid"),
        ("counter-overflow", "otp_counter_invalid"),
        ("varint-overflow", "otp_migration_invalid"),
        ("varint-elevenbytes", "otp_migration_invalid"),
        ("group-wire", "otp_migration_invalid"),
        ("invalid-base64-bad-character", "otp_migration_invalid"),
        ("invalid-base64-bad-padding", "otp_migration_invalid"),
    ] {
        let value = fixture(id);
        assert_eq!(
            import_migration(&[value["link"].as_str().unwrap()]).err(),
            Some(expected),
            "{id}"
        );
    }
}

#[test]
fn literal_base64_plus_slash_padding_and_percent_escape_round_trip() {
    let plain = fixture("base64-plus-slash-padding");
    let link = plain["link"].as_str().unwrap();
    let base64 = link.split_once("data=").unwrap().1;
    for c in ['+', '/', '='] {
        assert!(base64.contains(c));
    }
    let drafts = import_migration(&[link]).unwrap();
    for id in ["base64-percent-encoded", "base64-unpadded"] {
        let variant = fixture(id);
        assert!(import_migration(&[variant["link"].as_str().unwrap()]).unwrap() == drafts);
    }
    for malformed in [
        link.replace("data=", "data=%FF"),
        link.replace("data=", "data=%ZZ"),
        link.replace("offline?", "user@offline?"),
        link.replace("offline?", "offline:443?"),
    ] {
        assert_eq!(
            import_migration(&[&malformed]).err(),
            Some("otp_migration_invalid")
        );
    }
}

#[test]
fn formats_dispatch_complete_migration_lines_and_reject_mixed_formats_atomically() {
    let draft = sample();
    let migration = export_migration(std::slice::from_ref(&draft)).unwrap();
    let upper = migration.replacen(
        "otpauth-migration://offline",
        "OTPAUTH-MIGRATION://OFFLINE",
        1,
    );
    let text = format!("  {migration} \n\n\t{upper}\r\n");
    assert!(super::super::formats::import(&text).unwrap() == [draft.clone(), draft.clone()]);
    let uri = super::super::formats::export_uri(&draft).unwrap();
    for ordinary in [uri.as_str(), "MY", "{\"otp\":[]}"] {
        for text in [
            format!("{migration}\n{ordinary}"),
            format!("{ordinary}\n{migration}"),
        ] {
            let error = super::super::formats::import(&text).err().unwrap();
            // A leading JSON document retains strict JSON parsing rather than line dispatch.
            assert!(matches!(
                error,
                "otp_migration_mixed_input" | "otp_json_invalid"
            ));
        }
    }
    let incomplete = fixture("batch-two-fragment-0");
    assert_eq!(
        super::super::formats::import(&format!(
            "{migration}\n{}",
            incomplete["link"].as_str().unwrap()
        ))
        .err(),
        Some("otp_migration_batch_incomplete")
    );
}
