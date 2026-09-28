use super::*;

#[test]
fn private_connection_is_readonly_and_denies_non_inventory_sql() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("CREATE TABLE kept(value TEXT); INSERT INTO kept VALUES('secret fixture'); CREATE VIEW hidden AS SELECT value FROM kept;").unwrap();
    writer.close().unwrap();
    let before = std::fs::read(&path).unwrap();
    let connection = open(&path).unwrap();
    assert!(connection.is_readonly("main").unwrap());
    assert!(connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .unwrap());
    assert!(!connection
        .db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
        .unwrap());
    assert!(!connection
        .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW)
        .unwrap());
    assert!(!connection
        .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
        .unwrap());
    assert_eq!(connection.limit(Limit::SQLITE_LIMIT_ATTACHED).unwrap(), 0);
    for sql in [
        "DELETE FROM kept",
        "CREATE TABLE new(value TEXT)",
        "ATTACH ':memory:' AS extra",
        "PRAGMA writable_schema=ON",
        "PRAGMA query_only=OFF",
        "VACUUM",
        "SELECT load_extension('/must-not-load')",
        "SELECT value FROM hidden",
    ] {
        assert!(connection.execute_batch(sql).is_err(), "{sql}");
    }
    let value: String = connection
        .query_row("SELECT value FROM kept", [], |r| r.get(0))
        .unwrap();
    assert_eq!(value, "secret fixture");
    drop(connection);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn progress_budget_interrupts_expensive_read_queries_with_safe_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch("CREATE TABLE kept(value INTEGER)")
        .unwrap();
    writer.execute_batch("WITH RECURSIVE count(x) AS(SELECT 0 UNION ALL SELECT x+1 FROM count WHERE x<100) INSERT INTO kept SELECT x FROM count").unwrap();
    writer.close().unwrap();
    let connection = open(&path).unwrap();
    let mut statement = connection
        .prepare("SELECT a.value FROM kept a, kept b, kept c, kept d")
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    let result = loop {
        match rows.next() {
            Ok(Some(_)) => (),
            Ok(None) => panic!("unbounded query unexpectedly completed"),
            Err(failure) => break error(failure),
        }
    };
    assert_eq!(result, "legacy_backup_database_limit");
}
