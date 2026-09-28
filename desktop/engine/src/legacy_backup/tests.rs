use super::*;
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/legacy_backup/fixtures")
            .join(name),
    )
    .unwrap()
}
fn put_blob(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    bytes.extend_from_slice(&value.map_or(u32::MAX, |v| v.len() as u32).to_le_bytes());
    if let Some(value) = value {
        bytes.extend_from_slice(value);
    }
}
fn put_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    let encoded = value.map(|v| {
        v.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    });
    put_blob(bytes, encoded.as_deref());
}
// Negative tests mutate controlled bytes; compatibility uses the real Qt goldens.
fn container(version: u32, metadata: &str, files: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    let mut bytes = b"THRN".to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    put_string(&mut bytes, Some(metadata));
    bytes.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for (key, value) in files {
        put_string(&mut bytes, Some(key));
        put_blob(&mut bytes, *value);
    }
    bytes
}
fn sqlite(build: impl FnOnce(&Connection)) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.sqlite");
    let connection = Connection::open(&path).unwrap();
    build(&connection);
    connection.close().unwrap();
    std::fs::read(path).unwrap()
}
fn db_sql(sql: &str) -> Vec<u8> {
    sqlite(|c| c.execute_batch(sql).unwrap())
}
fn read_db(bytes: &[u8]) -> Result<SourceDatabase, String> {
    database::read(bytes, Parts::default())
}
fn profile_db(id: i64, raw: &str) -> Vec<u8> {
    sqlite(|c| {
        c.execute_batch("CREATE TABLE profiles(id INTEGER,type TEXT,name TEXT,gid INTEGER,outbound_json TEXT); CREATE TABLE groups(id INTEGER,name TEXT);").unwrap();
        c.execute(
            "INSERT INTO profiles VALUES(?1,'socks',NULL,0,?2)",
            rusqlite::params![id, raw],
        )
        .unwrap();
    })
}

#[test]
fn arbitrary_inputs_never_produce_an_inventory() {
    for bytes in [b"".as_slice(), b"THRN", b"not a backup"] {
        assert!(parse(bytes).is_err());
    }
}

#[test]
fn real_qt_goldens_cover_all_part_combinations_without_selecting_hidden_rows() {
    for mask in 0..32 {
        let archive = parse(&fixture(&format!("parts-{mask:02}.thrbackup")))
            .unwrap_or_else(|error| panic!("mask {mask}: {error}"));
        assert_eq!(
            archive.parts,
            Parts {
                profiles: mask & 1 != 0,
                routes: mask & 2 != 0,
                settings: mask & 4 != 0,
                otp: mask & 8 != 0,
                icons: mask & 16 != 0
            }
        );
        assert_eq!(archive.files["future/null"], None);
        assert_eq!(archive.files["future/empty"], Some(vec![]));
        assert_eq!(
            archive.created_at.as_deref(),
            Some("Fri Sep 11 12:00:00 2026 🦊")
        );
        if mask & 15 != 0 {
            let database = archive.database.as_ref().unwrap();
            assert_eq!(database.profiles.len(), 3);
            assert_eq!(database.otp.len(), 1);
        } else {
            assert!(archive.database.is_none());
        }
        assert_eq!(
            archive.inventory().icons,
            if mask & 16 != 0 { 2 } else { 0 }
        );
    }
}

#[test]
fn golden_manifest_checks_independent_fixture_bytes() {
    let manifest: serde_json::Value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
    assert_eq!(manifest["qtRuntime"], "6.11.2");
    let files = manifest["sha256"].as_object().unwrap();
    assert_eq!(files.len(), 39);
    for (name, expected) in files {
        assert_eq!(
            format!("{:x}", Sha256::digest(fixture(name))),
            expected.as_str().unwrap()
        );
    }
}

#[test]
fn version_one_and_missing_parts_keep_legacy_otp_semantics() {
    for name in ["v1.thrbackup", "v2-no-parts.thrbackup"] {
        let archive = parse(&fixture(name)).unwrap();
        assert_eq!(
            archive.parts,
            Parts {
                profiles: true,
                routes: true,
                settings: true,
                otp: false,
                icons: true
            }
        );
        assert_eq!(archive.database.as_ref().unwrap().otp.len(), 1);
    }
    let archive = container::parse(&container(
        1,
        r#"{"parts":{"profiles":false,"otp":true}}"#,
        &[("database", Some(b"not parsed here"))],
    ))
    .unwrap();
    assert!(archive.parts.profiles);
    assert!(!archive.parts.otp);
}

#[test]
fn golden_unicode_unknown_columns_objects_and_client_json_are_preserved() {
    let archive = parse(&fixture("parts-31.thrbackup")).unwrap();
    assert_eq!(
        archive.metadata["future_metadata"]["keep"],
        "metadata-secret-fixture"
    );
    assert!(archive
        .files
        .contains_key("icons/../../never-extract-fixture"));
    assert!(archive.files.contains_key("icons/日本 🦊.png"));
    let database = archive.database.as_ref().unwrap();
    let profile = database.profiles.iter().find(|p| p.id == 41).unwrap();
    assert_eq!(profile.name.as_deref(), Some("Япония 🦊"));
    assert_eq!(profile.outbound["password"], "legacy-private-secret");
    assert!(
        matches!(&profile.columns["future_profile"],SourceValue::Blob(v) if v==b"\0retained\xff")
    );
    assert!(!profile.columns.contains_key("latency_at")); // older optional column stays absent
    let full = database.profiles.iter().find(|p| p.id == 43).unwrap();
    let config: serde_json::Value =
        serde_json::from_str(full.outbound["config"].as_str().unwrap()).unwrap();
    assert_eq!(config["dns"]["servers"][0], "1.1.1.1");
    assert_eq!(config["routing"]["rules"][0]["domain"][0], "example.test");
    assert!(
        matches!(&database.groups.iter().find(|g|g.id==7).unwrap().columns["profiles_json"],SourceValue::Text(v) if v=="[43,41,42]")
    );
    let table = &database.other_tables["future table\";DROP TABLE profiles;--"];
    assert!(matches!(&table[0]["odd\"column"],SourceValue::Text(v) if v=="unknown-secret-fixture"));
    assert!(matches!(table[0]["value"],SourceValue::Real(v) if v==1.25));
    assert!(matches!(table[0]["missing"], SourceValue::Null));
    assert!(database
        .schema
        .iter()
        .any(|s| s.kind == "view" && s.sql.as_ref().unwrap().contains("load_extension")));
    assert!(database
        .schema
        .iter()
        .any(|s| s.kind == "trigger" && s.name == "future_trigger"));
    assert!(!database
        .settings
        .iter()
        .any(|s| s.key == "trigger-executed"));
}

#[test]
fn public_inventory_contains_only_fixed_keys_counts_and_flags() {
    let archive = parse(&fixture("parts-31.thrbackup")).unwrap();
    let inventory = serde_json::to_value(archive.inventory()).unwrap();
    assert_eq!(inventory["profiles"], 3);
    assert_eq!(inventory["groups"], 2);
    assert_eq!(inventory["otp"], 1);
    assert_eq!(inventory["otherTables"], 1);
    let encoded = inventory.to_string();
    for secret in [
        "secret",
        "example.test",
        "Япония",
        "JBSWY3DPEHPK3PXP",
        "日本",
        "future_view",
        "load_extension",
    ] {
        assert!(!encoded.contains(secret));
    }
    assert!(inventory
        .as_object()
        .unwrap()
        .values()
        .all(|v| v.is_number() || v.is_null() || v.is_object()));
    assert!(inventory["parts"]
        .as_object()
        .unwrap()
        .values()
        .all(|v| v.is_boolean()));
}

#[test]
fn qt_null_empty_and_invalid_utf16_fail_without_collapsing_meanings() {
    for (name, error) in [
        ("null-metadata.thrbackup", "legacy_backup_invalid_metadata"),
        ("empty-metadata.thrbackup", "legacy_backup_invalid_metadata"),
        ("null-database.thrbackup", "legacy_backup_invalid_database"),
        ("empty-database.thrbackup", "legacy_backup_invalid_database"),
        ("invalid-utf16.thrbackup", "legacy_backup_invalid_utf16"),
    ] {
        assert_eq!(parse(&fixture(name)).err().unwrap(), error, "{name}");
    }
    let mut odd = container(2, "{}", &[]);
    odd[8..12].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(parse(&odd).err().unwrap(), "legacy_backup_invalid_utf16");
}

#[test]
fn version_metadata_shape_duplicate_json_and_recursion_are_rejected() {
    for version in [0, 3, u32::MAX] {
        assert_eq!(
            parse(&container(version, "{}", &[])).err().unwrap(),
            "legacy_backup_version_unsupported"
        );
    }
    for metadata in [
        "[]",
        "null",
        r#"{"backup_version":"2"}"#,
        r#"{"backup_version":-1}"#,
        r#"{"created_at":7}"#,
        r#"{"parts":true}"#,
        r#"{"parts":{"otp":1}}"#,
        r#"{"a":1,"a":2}"#,
        r#"{"future":{"a":1,"a":2}}"#,
        r#"{} {}"#,
    ] {
        assert_eq!(
            parse(&container(2, metadata, &[])).err().unwrap(),
            "legacy_backup_invalid_metadata",
            "{metadata}"
        );
    }
    assert_eq!(
        parse(&container(2, r#"{"backup_version":3}"#, &[]))
            .err()
            .unwrap(),
        "legacy_backup_version_unsupported"
    );
    let nested = format!("{}null{}", "[".repeat(200), "]".repeat(200));
    assert!(json::parse(&nested).is_err());
    let many = format!("[{}]", vec!["0"; 100_001].join(","));
    assert!(json::parse(&many).is_err());
    let value=json::parse(r#"{"max":18446744073709551615,"negative":-9223372036854775808,"float":1.25,"array":[null,true,"🦊"]}"#).unwrap();
    assert_eq!(value["max"].as_u64(), Some(u64::MAX));
    assert_eq!(value["negative"].as_i64(), Some(i64::MIN));
    assert_eq!(value["float"], 1.25);
}

#[test]
fn map_order_is_not_significant_but_duplicate_empty_null_and_nul_keys_are_invalid() {
    let ordered = container::parse(&container(2, "{}", &[("z", None), ("a", Some(b""))])).unwrap();
    assert_eq!(ordered.files.len(), 2);
    for files in [
        vec![("a", None), ("a", Some(b"a".as_slice()))],
        vec![("", None)],
        vec![("a\0b", None)],
    ] {
        assert_eq!(
            parse(&container(2, "{}", &files)).err().unwrap(),
            "legacy_backup_invalid_container"
        );
    }
    let mut null_key = container(2, "{}", &[]);
    null_key[16..20].copy_from_slice(&1u32.to_le_bytes());
    put_string(&mut null_key, None);
    put_blob(&mut null_key, None);
    assert_eq!(
        parse(&null_key).err().unwrap(),
        "legacy_backup_invalid_container"
    );
}

#[test]
fn absent_database_and_icon_payloads_cannot_be_selected_by_metadata() {
    let archive=parse(&container(2,r#"{"parts":{"profiles":true,"routes":true,"settings":true,"otp":true,"icons":true,"future":99}}"#,&[])).unwrap();
    assert_eq!(archive.parts, Parts::default());
    assert_eq!(archive.metadata["parts"]["future"], 99);
}

#[test]
fn every_truncation_of_valid_small_qt_fixture_and_trailing_bytes_are_invalid() {
    let bytes = fixture("parts-00.thrbackup");
    for end in 0..bytes.len() {
        assert!(parse(&bytes[..end]).is_err(), "end {end}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        parse(&trailing).err().unwrap(),
        "legacy_backup_invalid_container"
    );
}

#[test]
fn byte_map_metadata_and_key_limits_are_checked_before_allocating_payloads() {
    assert_eq!(
        parse(&vec![0; MAX_BYTES + 1]).err().unwrap(),
        "legacy_backup_limit"
    );
    for length in [(MAX_METADATA_BYTES + 1) as u32, 0xffff_fffe] {
        let mut bytes = container(2, "{}", &[]);
        bytes[8..12].copy_from_slice(&length.to_le_bytes());
        assert_eq!(parse(&bytes).err().unwrap(), "legacy_backup_limit");
    }
    let mut bytes = container(2, "{}", &[]);
    bytes[16..20].copy_from_slice(&((MAX_PARTS + 1) as u32).to_le_bytes());
    assert_eq!(parse(&bytes).err().unwrap(), "legacy_backup_limit");
    assert_eq!(
        parse(&container(
            2,
            "{}",
            &[(&"a".repeat(MAX_KEY_BYTES / 2 + 1), None)]
        ))
        .err()
        .unwrap(),
        "legacy_backup_limit"
    );
    let mut bytes = container(2, "{}", &[("x", None)]);
    let end = bytes.len();
    bytes[end - 4..].copy_from_slice(&((MAX_BYTES + 1) as u32).to_le_bytes());
    assert_eq!(parse(&bytes).err().unwrap(), "legacy_backup_limit");
}

#[test]
fn maximum_map_key_and_metadata_lengths_are_accepted() {
    let keys: Vec<_> = (0..MAX_PARTS).map(|i| format!("key-{i}")).collect();
    let files: Vec<_> = keys.iter().map(|k| (k.as_str(), None)).collect();
    assert_eq!(
        parse(&container(2, "{}", &files)).unwrap().files.len(),
        MAX_PARTS
    );
    assert!(parse(&container(
        2,
        "{}",
        &[(&"a".repeat(MAX_KEY_BYTES / 2), None)]
    ))
    .is_ok());
    let metadata = format!(
        "{{\"padding\":\"{}\"}}",
        "a".repeat(MAX_METADATA_BYTES / 2 - 14)
    );
    assert_eq!(metadata.encode_utf16().count() * 2, MAX_METADATA_BYTES);
    assert!(parse(&container(2, &metadata, &[])).is_ok());
}

#[test]
fn selected_tables_require_mandatory_columns_but_optional_columns_stay_absent() {
    let empty = db_sql("CREATE TABLE future(value TEXT)");
    assert_eq!(
        database::read(
            &empty,
            Parts {
                profiles: true,
                ..Parts::default()
            }
        )
        .err()
        .unwrap(),
        "legacy_backup_invalid_schema"
    );
    for table in [
        "CREATE TABLE profiles(id INTEGER,type TEXT,name TEXT,gid INTEGER)",
        "CREATE TABLE groups(id INTEGER)",
        "CREATE TABLE settings(key TEXT)",
    ] {
        assert_eq!(
            read_db(&db_sql(table)).err().unwrap(),
            "legacy_backup_invalid_schema"
        );
    }
    let bytes = profile_db(1, r#"{"type":"socks"}"#);
    let db = database::read(
        &bytes,
        Parts {
            profiles: true,
            ..Parts::default()
        },
    )
    .unwrap();
    assert!(db.profiles[0].name.is_none());
    assert!(!db.profiles[0].columns.contains_key("traffic_dl"));
}

#[test]
fn readonly_extraction_preserves_empty_unknown_tables_and_sql_defaults_without_evaluation() {
    let db = read_db(&db_sql(
        "CREATE TABLE unknown(value TEXT DEFAULT('literal-secret'), count INTEGER DEFAULT(1+2));",
    ))
    .unwrap();
    assert!(db.other_tables["unknown"].is_empty());
    let table = db.schema.iter().find(|s| s.name == "unknown").unwrap();
    assert_eq!(
        table.columns[0].default_sql.as_deref(),
        Some("'literal-secret'")
    );
    assert_eq!(table.columns[1].default_sql.as_deref(), Some("1+2"));
}

#[test]
fn invalid_database_header_truncation_and_corrupt_pages_are_rejected() {
    for bytes in [b"not sqlite".to_vec(), b"SQLite format 3\0".to_vec()] {
        assert_eq!(
            read_db(&bytes).err().unwrap(),
            "legacy_backup_invalid_database"
        );
    }
    let valid = db_sql("CREATE TABLE unknown(value TEXT); INSERT INTO unknown VALUES('fixture');");
    assert_eq!(
        read_db(&valid[..100]).err().unwrap(),
        "legacy_backup_invalid_database"
    );
    let mut corrupt = valid;
    corrupt[100] = 0xff;
    assert_eq!(
        read_db(&corrupt).err().unwrap(),
        "legacy_backup_invalid_database"
    );
}

#[test]
fn negative_large_duplicate_ids_and_wrong_sql_types_are_rejected_safely() {
    for id in [-1, i32::MAX as i64 + 1] {
        assert_eq!(
            read_db(&profile_db(id, "{}")).err().unwrap(),
            "legacy_backup_invalid_data"
        );
    }
    for sql in [
        "CREATE TABLE groups(id INTEGER,name TEXT); INSERT INTO groups VALUES(1,'one'),(1,'two');",
        "CREATE TABLE route_rules(route_profile_id INTEGER,rule_order INTEGER,type INTEGER); INSERT INTO route_rules VALUES(1,0,0),(1,0,1);",
        "CREATE TABLE groups_order(group_id INTEGER,display_order INTEGER); INSERT INTO groups_order VALUES(1,0),(1,1);",
    ] { assert_eq!(read_db(&db_sql(sql)).err().unwrap(),"legacy_backup_duplicate_id"); }
    for sql in [
        "CREATE TABLE groups(id INTEGER,name TEXT); INSERT INTO groups VALUES('not integer','one');",
        "CREATE TABLE groups(id INTEGER,name BLOB); INSERT INTO groups VALUES(1,x'0102');",
        "CREATE TABLE settings(key TEXT,value TEXT); INSERT INTO settings VALUES('same','one'),('same','two');",
        "CREATE TABLE settings(key TEXT,value TEXT); INSERT INTO settings VALUES('key',NULL);",
    ] { assert_eq!(read_db(&db_sql(sql)).err().unwrap(),"legacy_backup_invalid_data"); }
}

#[test]
fn malformed_nonobject_and_duplicate_profile_json_never_loses_source_fields() {
    for raw in [
        "oops",
        "[]",
        "null",
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"a":1,"a":2}}"#,
    ] {
        assert_eq!(
            read_db(&profile_db(1, raw)).err().unwrap(),
            "legacy_backup_invalid_profile_json"
        );
    }
    let db = read_db(&profile_db(
        1,
        "{ \"type\" : \"socks\", \"future\": [1,true,null] }",
    ))
    .unwrap();
    assert!(
        matches!(&db.profiles[0].columns["outbound_json"],SourceValue::Text(v) if v=="{ \"type\" : \"socks\", \"future\": [1,true,null] }")
    );
    assert_eq!(db.profiles[0].outbound["future"], json!([1, true, null]));
}

#[test]
fn source_sql_cannot_masquerade_as_known_tables_or_evaluate_generated_columns() {
    for sql in [
        "CREATE VIEW profiles AS SELECT 1 AS id;",
        "CREATE TABLE other(id INTEGER); CREATE INDEX profiles ON other(id);",
    ] {
        assert_eq!(
            read_db(&db_sql(sql)).err().unwrap(),
            "legacy_backup_invalid_schema"
        );
    }
    let generated=db_sql("CREATE TABLE unknown(a INTEGER,b INTEGER GENERATED ALWAYS AS(a+1) VIRTUAL); INSERT INTO unknown(a) VALUES(1);");
    assert_eq!(
        read_db(&generated).err().unwrap(),
        "legacy_backup_schema_unsupported"
    );
    let virtual_db = db_sql("CREATE VIRTUAL TABLE unknown USING fts5(content);");
    assert_eq!(
        read_db(&virtual_db).err().unwrap(),
        "legacy_backup_schema_unsupported"
    );
}

#[test]
fn database_row_table_column_and_field_limits_fail_without_partial_inventory() {
    let rows=db_sql("CREATE TABLE unknown(value INTEGER); WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<5001) INSERT INTO unknown SELECT x FROM n;");
    assert_eq!(
        read_db(&rows).err().unwrap(),
        "legacy_backup_database_limit"
    );
    let tables = (0..MAX_TABLES + 1)
        .map(|i| format!("CREATE TABLE table_{i}(value INTEGER);"))
        .collect::<String>();
    assert_eq!(
        read_db(&db_sql(&tables)).err().unwrap(),
        "legacy_backup_database_limit"
    );
    let columns = (0..MAX_COLUMNS + 1)
        .map(|i| format!("field_{i} TEXT"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(read_db(&db_sql(&format!("CREATE TABLE wide({columns})"))).is_err());
    let huge = sqlite(|c| {
        c.execute_batch("CREATE TABLE unknown(value BLOB)").unwrap();
        c.execute(
            "INSERT INTO unknown VALUES(zeroblob(?1))",
            [(MAX_FIELD_BYTES + 1) as i64],
        )
        .unwrap();
    });
    assert_eq!(
        read_db(&huge).err().unwrap(),
        "legacy_backup_database_limit"
    );
}

#[test]
fn maximum_table_and_per_table_row_limits_are_accepted() {
    let tables = (0..MAX_TABLES)
        .map(|i| format!("CREATE TABLE table_{i}(value INTEGER);"))
        .collect::<String>();
    assert_eq!(
        read_db(&db_sql(&tables)).unwrap().other_tables.len(),
        MAX_TABLES
    );
    let rows=db_sql("CREATE TABLE unknown(value INTEGER); WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO unknown SELECT x FROM n;");
    assert_eq!(
        read_db(&rows).unwrap().other_tables["unknown"].len(),
        MAX_ROWS_PER_TABLE
    );
}

#[test]
fn invalid_utf8_nonfinite_reals_and_total_rows_are_rejected() {
    let invalid = db_sql(
        "CREATE TABLE unknown(value TEXT); INSERT INTO unknown VALUES(CAST(x'ff' AS TEXT));",
    );
    assert_eq!(
        read_db(&invalid).err().unwrap(),
        "legacy_backup_invalid_data"
    );
    let infinite = sqlite(|c| {
        c.execute_batch("CREATE TABLE unknown(value REAL)").unwrap();
        c.execute("INSERT INTO unknown VALUES(?1)", [f64::INFINITY])
            .unwrap();
    });
    assert_eq!(
        read_db(&infinite).err().unwrap(),
        "legacy_backup_invalid_data"
    );
    let rows=(0..5).map(|i|format!("CREATE TABLE table_{i}(value INTEGER); WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4001) INSERT INTO table_{i} SELECT x FROM n;")).collect::<String>();
    assert_eq!(
        read_db(&db_sql(&rows)).err().unwrap(),
        "legacy_backup_database_limit"
    );
}

#[test]
fn filesystem_read_never_modifies_backup_or_uses_icon_labels_as_paths() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.thrbackup");
    let bytes = fixture("parts-31.thrbackup");
    std::fs::write(&path, &bytes).unwrap();
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    let archive = read(&path).unwrap();
    assert_eq!(archive.inventory().profiles, 3);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        before
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    assert_eq!(
        read(directory.path()).err().unwrap(),
        "legacy_backup_read_failed"
    );
    assert_eq!(
        read(&directory.path().join("missing")).err().unwrap(),
        "legacy_backup_read_failed"
    );
}

#[test]
fn aggregate_cell_budget_counts_wide_null_tables_before_memory_amplification() {
    let columns = (0..128)
        .map(|i| format!("\"field_{i}_{}\" TEXT", "a".repeat(190)))
        .collect::<Vec<_>>()
        .join(",");
    let source = sqlite(|c| {
        c.execute_batch(&format!("CREATE TABLE wide({columns}); WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO wide(rowid) SELECT x FROM n;")).unwrap();
    });
    assert!(source.len() < 1024 * 1024);
    assert_eq!(
        read_db(&source).err().unwrap(),
        "legacy_backup_database_limit"
    );
}

#[test]
fn combined_profile_json_item_budget_limits_expanded_values() {
    let raw = format!("{{\"nodes\":[{}]}}", vec!["0"; 99_997].join(","));
    let source = sqlite(|c| {
        c.execute_batch(
            "CREATE TABLE profiles(id INTEGER,type TEXT,name TEXT,gid INTEGER,outbound_json TEXT)",
        )
        .unwrap();
        for id in 1..=11 {
            c.execute(
                "INSERT INTO profiles VALUES(?1,'custom','bounded',0,?2)",
                rusqlite::params![id, raw],
            )
            .unwrap();
        }
    });
    assert_eq!(
        read_db(&source).err().unwrap(),
        "legacy_backup_database_limit"
    );
}

#[test]
fn filesystem_size_is_bounded_even_when_sparse() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.thrbackup");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len((MAX_BYTES + 1) as u64).unwrap();
    assert_eq!(read(&path).err().unwrap(), "legacy_backup_limit");
}

#[test]
#[cfg(unix)]
fn special_files_are_rejected_before_open_can_block() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input-fifo");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert_eq!(read(&path).err().unwrap(), "legacy_backup_read_failed");
}

#[test]
fn schema_object_limit_includes_inert_indexes_and_triggers() {
    let source = sqlite(|c| {
        c.execute_batch("CREATE TABLE unknown(value INTEGER)")
            .unwrap();
        for index in 0..256 {
            c.execute_batch(&format!("CREATE INDEX idx_{index} ON unknown(value)"))
                .unwrap();
        }
    });
    assert_eq!(
        read_db(&source).err().unwrap(),
        "legacy_backup_database_limit"
    );
}
