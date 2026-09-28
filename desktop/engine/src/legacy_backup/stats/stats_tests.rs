use super::*;

fn database(rows: &[(&str, &str)]) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("throne_stats.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE config_traffic_minute (bucket_start INTEGER NOT NULL, profile_id INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_start, profile_id));
             CREATE TABLE config_traffic_hour (bucket_start INTEGER NOT NULL, profile_id INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_start, profile_id));
             CREATE TABLE app_traffic_minute (bucket_start INTEGER NOT NULL, process_name TEXT NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_start, process_name));
             CREATE TABLE app_traffic_hour (bucket_start INTEGER NOT NULL, process_name TEXT NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_start, process_name));
             CREATE TABLE config_meta (profile_id INTEGER PRIMARY KEY, name TEXT, group_name TEXT, type TEXT, server_address TEXT, first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE app_meta (process_name TEXT PRIMARY KEY, last_path TEXT, first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
    for (table, values) in rows {
        connection
            .execute_batch(&format!("INSERT INTO {table} VALUES {values}"))
            .unwrap();
    }
    connection.close().unwrap();
    std::fs::read(&path).unwrap()
}

const HOUR: i64 = 1_700_000_000 / 3600 * 3600;

#[test]
fn both_tiers_fold_into_their_hour_and_the_two_tables_stay_apart() {
    let bytes = database(&[
        (
            "config_traffic_minute",
            &format!("({}, 7, 10, 20), ({}, 7, 1, 2)", HOUR + 60, HOUR + 120),
        ),
        (
            "config_traffic_hour",
            &format!("({HOUR}, 7, 100, 200), ({HOUR}, -101, 5, 6)"),
        ),
        (
            "app_traffic_minute",
            &format!("({}, 'curl', 3, 4)", HOUR + 180),
        ),
        (
            "app_traffic_hour",
            &format!("({HOUR}, 'curl', 30, 40), ({HOUR}, 'wget', 1, 1)"),
        ),
        (
            "config_meta",
            "(7, 'Old exit', 'Old team', 'vless', '192.0.2.10', 1, 2)",
        ),
    ]);
    let stats = read(&bytes).unwrap();
    assert!(!stats.truncated && !stats.is_empty());
    let (entries, names) = entries(&stats, &BTreeMap::new());
    let profiles: Vec<_> = entries
        .iter()
        .filter(|e| e.scope == Scope::Profiles)
        .collect();
    let applications: Vec<_> = entries
        .iter()
        .filter(|e| e.scope == Scope::Applications)
        .collect();
    // The two minute rows and the hour row of server 7 are one bucket.
    let seven = profiles.iter().find(|e| e.profile == "throne-7").unwrap();
    assert_eq!(
        (seven.hour, seven.upload, seven.download),
        (HOUR as u64, 111, 222)
    );
    assert!(profiles
        .iter()
        .any(|e| e.profile == DIRECT_PROFILE && e.upload == 5));
    assert!(profiles.iter().all(|e| e.process.is_empty()));
    assert_eq!(applications.len(), 2);
    let curl = applications.iter().find(|e| e.process == "curl").unwrap();
    assert_eq!((curl.upload, curl.download), (33, 44));
    assert!(applications.iter().all(|e| e.profile.is_empty()));
    // The name the copy remembered travels with the imported identifier, and
    // Direct is named by Thronium itself rather than by the old row.
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].0, "throne-7");
    assert_eq!(
        (names[0].1.profile.as_str(), names[0].1.group.as_str()),
        ("Old exit", "Old team")
    );
}

#[test]
fn traffic_imported_beside_its_servers_stays_attached_to_them() {
    let bytes = database(&[(
        "config_traffic_hour",
        &format!("({HOUR}, 7, 10, 20), ({HOUR}, -101, 1, 2)"),
    )]);
    let stats = read(&bytes).unwrap();
    let mapping = BTreeMap::from([(7i64, "0b3a0d5c-uuid-of-the-new-profile".to_string())]);
    let (entries, _) = entries(&stats, &mapping);
    assert!(entries
        .iter()
        .any(|e| e.profile == "0b3a0d5c-uuid-of-the-new-profile" && e.upload == 10));
    // Direct is never one of the user's own servers, so no mapping claims it.
    assert!(entries.iter().any(|e| e.profile == DIRECT_PROFILE));
}

#[test]
fn impossible_moments_control_characters_and_negative_counters_are_left_out() {
    let bytes = database(&[
        (
            "config_traffic_hour",
            &format!("(1, 7, 10, 20), (4102444800, 7, 10, 20), ({HOUR}, 7, -5, -6)"),
        ),
        (
            "app_traffic_hour",
            &format!("({HOUR}, 'quiet' || char(10) || 'app', 7, 8)"),
        ),
    ]);
    let stats = read(&bytes).unwrap();
    let (entries, _) = entries(&stats, &BTreeMap::new());
    // The two impossible buckets are gone and the negative counters read as nothing.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].process, "quietapp");
    assert_eq!((entries[0].upload, entries[0].download), (7, 8));
}

#[test]
fn a_file_that_is_not_a_database_or_has_no_traffic_is_refused_or_empty() {
    assert!(
        matches!(read(b"not a database at all"), Err(code) if code == "legacy_backup_invalid_database")
    );
    // A database without Qt's traffic tables reads as nothing to import.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("other.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TABLE profiles (id INTEGER PRIMARY KEY)")
        .unwrap();
    connection.close().unwrap();
    let stats = read(&std::fs::read(&path).unwrap()).unwrap();
    assert!(stats.is_empty() && !stats.truncated);
    assert!(entries(&stats, &BTreeMap::new()).0.is_empty());
}
