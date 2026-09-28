use super::*;
use crate::legacy_backup::{Parts, SourceDatabase, SourceRow, SourceSetting};
use serde_json::{json, Value};

fn row(id: i64) -> SourceOtp {
    SourceOtp {
        id,
        columns: BTreeMap::from([
            ("id".into(), SourceValue::Integer(id)),
            ("name".into(), SourceValue::Text(format!("OTP {id}"))),
            ("issuer".into(), SourceValue::Text("Fixture issuer".into())),
            ("secret".into(), SourceValue::Text("MZ".into())),
            ("algorithm".into(), SourceValue::Integer(0)),
            ("type".into(), SourceValue::Integer(0)),
            ("digits".into(), SourceValue::Integer(6)),
            ("period".into(), SourceValue::Integer(30)),
            ("counter".into(), SourceValue::Integer(0)),
            ("sort_order".into(), SourceValue::Integer(0)),
        ]),
    }
}
fn sample() -> SourceArchive {
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            otp: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            otp: vec![row(1)],
            ..Default::default()
        }),
    }
}
fn plan(source: &SourceArchive) -> OtpPlan {
    convert(source).unwrap_or_else(|issues| panic!("{}", json!(issues)))
}
fn codes(source: &SourceArchive) -> Vec<String> {
    convert(source)
        .err()
        .expect("accepted invalid OTP section")
        .into_iter()
        .map(|i| i.code)
        .collect()
}
fn fixture(name: &str) -> SourceArchive {
    crate::legacy_backup::read(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/legacy_backup/otp/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn parts_flag_is_checked_before_database_rows_and_other_parts_are_unneeded() {
    let mut source = sample();
    source.parts.otp = false;
    source.database = None;
    assert_eq!(codes(&source), ["legacy_otp_parts_required"]);
    source.parts.otp = true;
    assert_eq!(codes(&source), ["legacy_database_missing"]);
    let mut source = fixture("excluded-otp.thrbackup");
    assert!(!source.parts.otp);
    assert!(source.database.as_ref().unwrap().otp.len() > 6);
    assert_eq!(codes(&source), ["legacy_otp_parts_required"]);
    source.parts.otp = true;
    assert!(codes(&source).len() > 1);
    let mut source = sample();
    source
        .database
        .as_mut()
        .unwrap()
        .settings
        .push(SourceSetting {
            key: "future-invalid-setting".into(),
            value: "private-malformed-settings".into(),
            columns: SourceRow::new(),
        });
    assert_eq!(plan(&source).entries.len(), 1);
}

#[test]
fn actual_qt_archive_preserves_order_every_parameter_codes_and_exact_large_counters() {
    use sha2::Digest;
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/legacy_backup/otp/fixtures");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["qtRuntime"], "6.11.2");
    for (file, expected) in manifest["sha256"].as_object().unwrap() {
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(std::fs::read(directory.join(file)).unwrap())
            ),
            expected.as_str().unwrap()
        );
    }
    let source = fixture("valid.thrbackup");
    assert!(source.parts.otp);
    assert!(!source.parts.settings);
    assert!(!source.parts.profiles);
    let original: Vec<_> = source
        .database
        .as_ref()
        .unwrap()
        .otp
        .iter()
        .map(|r| (r.id, r.columns.clone()))
        .collect();
    let plan = plan(&source);
    assert_eq!(plan.entries.len(), 6);
    let order = manifest["order"].as_array().unwrap();
    for (index, entry) in plan.entries.iter().enumerate() {
        entry.validate().unwrap();
        let id = order[index].as_i64().unwrap();
        assert_eq!(entry.id, plan.otp_ids[&id]);
        assert!(uuid::Uuid::parse_str(&entry.id).is_ok());
        assert_ne!(entry.id, entry.revision);
        let row = manifest["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap();
        assert_eq!(entry.value.name, row["name"]);
        assert_eq!(entry.value.issuer, row["issuer"]);
        assert_eq!(
            entry.value.secret,
            crate::otp::normalize_secret(row["secret"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            entry.value.algorithm.as_str(),
            ["SHA1", "SHA256", "SHA512"][row["algorithm"].as_u64().unwrap() as usize]
        );
        assert_eq!(
            entry.value.kind.as_str(),
            ["totp", "hotp"][row["type"].as_u64().unwrap() as usize]
        );
        assert_eq!(json!(entry.value.digits), row["digits"]);
        assert_eq!(json!(entry.value.period), row["period"]);
        assert_eq!(
            entry.value.counter,
            row["counter"].as_i64().unwrap().to_string()
        );
        assert_eq!(
            entry.value.code_at(59).unwrap().code,
            manifest["codeAt59"][index]
        );
    }
    let cloned = plan.clone();
    assert!(cloned.entries == plan.entries);
    assert_eq!(cloned.otp_ids, plan.otp_ids);
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_otp_timestamps_deferred"));
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_otp_bindings_deferred"));
    assert!(
        original
            == source
                .database
                .as_ref()
                .unwrap()
                .otp
                .iter()
                .map(|r| (r.id, r.columns.clone()))
                .collect::<Vec<_>>()
    );
}

#[test]
fn actual_qt_blocked_and_unknown_columns_never_return_partial_entries_or_secret_values() {
    let source = fixture("blocked.thrbackup");
    let issues = convert(&source).err().unwrap();
    assert_eq!(issues.len(), 7);
    let expected = [
        "legacy_otp_algorithm_invalid",
        "legacy_otp_type_invalid",
        "legacy_otp_secret_invalid",
        "legacy_otp_digits_invalid",
        "legacy_otp_period_invalid",
        "legacy_otp_counter_invalid",
        "legacy_otp_structure",
    ];
    for code in expected {
        assert!(issues.iter().any(|i| i.code == code), "{code}");
    }
    let safe = json!(issues).to_string();
    for secret in [
        "invalid-private-fixture",
        "private-blob",
        "Fixture issuer",
        "MZ",
        "gezdgnbv",
    ] {
        assert!(!safe.contains(secret));
    }
    let source = fixture("unknown-column.thrbackup");
    let errors = codes(&source);
    assert_eq!(errors.len(), 6);
    assert!(errors.iter().all(|c| c == "legacy_otp_field_unsupported"));
}

#[test]
fn old_sort_column_uses_only_documented_qt_migration_default() {
    let source = fixture("old-no-sort.thrbackup");
    let plan = plan(&source);
    assert_eq!(
        plan.entries
            .iter()
            .map(|e| plan.otp_ids.iter().find(|(_, id)| *id == &e.id).unwrap().0)
            .copied()
            .collect::<Vec<_>>(),
        [10, 20, 30, 40, 50, 60]
    );
    assert_eq!(
        plan.report
            .iter()
            .filter(|i| i.code == "legacy_otp_order_default")
            .count(),
        6
    );
    let mut source = sample();
    source.database.as_mut().unwrap().otp[0]
        .columns
        .remove("algorithm");
    assert_eq!(codes(&source), ["legacy_otp_structure"]);
}

#[test]
fn malformed_types_duplicate_ids_and_nullable_fields_reject_atomically() {
    for key in [
        "name",
        "issuer",
        "secret",
        "algorithm",
        "type",
        "digits",
        "period",
        "counter",
        "sort_order",
        "created_at",
        "updated_at",
    ] {
        let mut source = sample();
        source.database.as_mut().unwrap().otp[0]
            .columns
            .insert(key.into(), SourceValue::Null);
        assert_eq!(codes(&source), ["legacy_otp_structure"], "{key}");
    }
    for key in [
        "algorithm",
        "type",
        "digits",
        "period",
        "counter",
        "sort_order",
    ] {
        let mut source = sample();
        source.database.as_mut().unwrap().otp[0]
            .columns
            .insert(key.into(), SourceValue::Text("1".into()));
        assert_eq!(codes(&source), ["legacy_otp_structure"]);
    }
    let mut source = sample();
    source.database.as_mut().unwrap().otp.push(row(1));
    assert_eq!(codes(&source), ["legacy_otp_id_invalid"]);
    let mut source = sample();
    source.database.as_mut().unwrap().otp[0].id = -1;
    assert_eq!(codes(&source), ["legacy_otp_id_invalid"]);
    let mut source = sample();
    source.database.as_mut().unwrap().otp[0]
        .columns
        .insert("id".into(), SourceValue::Integer(2));
    assert_eq!(codes(&source), ["legacy_otp_id_invalid"]);
}

#[test]
fn limits_labels_and_empty_sections_are_bounded_without_truncating_entries() {
    let mut source = sample();
    source.database.as_mut().unwrap().otp.clear();
    assert_eq!(codes(&source), ["legacy_otp_empty"]);
    source.database.as_mut().unwrap().otp = (0..=MAX_ENTRIES as i64).map(row).collect();
    assert_eq!(codes(&source), ["legacy_otp_limit"]);
    let mut source = sample();
    source.database.as_mut().unwrap().otp[0]
        .columns
        .insert("secret".into(), SourceValue::Text("A".repeat(1640)));
    assert_eq!(codes(&source), ["legacy_otp_limit"]);
    let mut source = sample();
    let row = &mut source.database.as_mut().unwrap().otp[0];
    row.columns.insert(
        "name".into(),
        SourceValue::Text("\n".to_owned() + &"я".repeat(600)),
    );
    row.columns
        .insert("algorithm".into(), SourceValue::Integer(99));
    let errors = convert(&source).err().unwrap();
    assert_eq!(errors[0].name.as_ref().unwrap().chars().count(), 256);
    assert!(!errors[0].name.as_ref().unwrap().contains('\n'));
}

#[test]
fn full_five_thousand_entry_scope_is_supported_but_oversized_collection_is_atomic() {
    let mut source = sample();
    source.database.as_mut().unwrap().otp = (0..MAX_ENTRIES as i64).map(row).collect();
    let converted = plan(&source);
    assert_eq!(converted.entries.len(), MAX_ENTRIES);
    assert_eq!(converted.otp_ids.len(), MAX_ENTRIES);
    // Every row/key/name is individually supported. Only their combined stored
    // size exceeds the destination's8MiB collection limit.
    let key = crate::otp::encode_secret(&vec![1; crate::otp::MAX_KEY_BYTES]);
    for row in &mut source.database.as_mut().unwrap().otp {
        row.columns
            .insert("secret".into(), SourceValue::Text(key.clone()));
        row.columns
            .insert("name".into(), SourceValue::Text("n".repeat(512)));
        row.columns
            .insert("issuer".into(), SourceValue::Text("i".repeat(512)));
    }
    assert_eq!(codes(&source), ["legacy_otp_limit"]);
}
