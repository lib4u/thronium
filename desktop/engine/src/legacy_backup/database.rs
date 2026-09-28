use super::*;
use rusqlite::{
    config::DbConfig,
    hooks::{AuthAction, Authorization},
    limits::Limit,
    types::ValueRef,
    Connection, OpenFlags,
};
use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    time::{Duration, Instant},
};

fn error(error: rusqlite::Error) -> String {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::OperationInterrupted
            | rusqlite::ErrorCode::TooBig
            | rusqlite::ErrorCode::OutOfMemory,
        ) => "legacy_backup_database_limit",
        _ => "legacy_backup_invalid_database",
    }
    .into()
}
fn identifier(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > MAX_KEY_BYTES || name.contains('\0') {
        return Err("legacy_backup_invalid_schema".into());
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

fn open(path: &Path) -> Result<Connection, String> {
    // The URI is generated exclusively from our private tempfile path. Immutable
    // mode prevents journal/WAL sidecars as well as writes to the source snapshot.
    let mut uri = reqwest::Url::from_file_path(path).map_err(|_| "legacy_backup_read_failed")?;
    uri.query_pairs_mut()
        .append_pair("mode", "ro")
        .append_pair("immutable", "1");
    let connection = Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(error)?;
    for (config, value) in [
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_DQS_DDL, false),
        (DbConfig::SQLITE_DBCONFIG_DQS_DML, false),
    ] {
        connection.set_db_config(config, value).map_err(error)?;
    }
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, MAX_FIELD_BYTES as i32),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 65536),
        (Limit::SQLITE_LIMIT_COLUMN, MAX_COLUMNS as i32),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4),
        (Limit::SQLITE_LIMIT_VDBE_OP, 50000),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 8),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        connection.set_limit(limit, value).map_err(error)?;
    }
    connection.busy_timeout(Duration::ZERO).map_err(error)?;
    let started = Instant::now();
    let mut operations = 0u64;
    connection
        .progress_handler(
            1000,
            Some(move || {
                operations += 1000;
                operations > 2_000_000 || started.elapsed() > Duration::from_secs(5)
            }),
        )
        .map_err(error)?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA mmap_size=0; PRAGMA cell_size_check=ON; PRAGMA cache_size=-2048; PRAGMA temp_store=MEMORY;").map_err(error)?;
    connection
        .authorizer(Some(|context: rusqlite::hooks::AuthContext<'_>| {
            if context.accessor.is_some() || context.database_name.is_some_and(|db| db != "main") {
                return Authorization::Deny;
            }
            match context.action {
                AuthAction::Select | AuthAction::Read { .. } => Authorization::Allow,
                AuthAction::Pragma { pragma_name, .. }
                    if ["table_xinfo", "quick_check"].contains(&pragma_name) =>
                {
                    Authorization::Allow
                }
                _ => Authorization::Deny,
            }
        }))
        .map_err(error)?;
    Ok(connection)
}

/// A private read-only snapshot of the given bytes. The directory is returned
/// with the connection so both are dropped together on every return path.
pub(super) fn connect(bytes: &[u8]) -> Result<(tempfile::TempDir, Connection), String> {
    if bytes.len() > MAX_BYTES {
        return Err("legacy_backup_limit".into());
    }
    if !bytes.starts_with(b"SQLite format 3\0") {
        return Err("legacy_backup_invalid_database".into());
    }
    let directory = tempfile::tempdir().map_err(|_| "legacy_backup_read_failed")?;
    let path = directory.path().join("snapshot.sqlite");
    let mut file = tempfile::NamedTempFile::new_in(directory.path())
        .map_err(|_| "legacy_backup_read_failed")?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|_| "legacy_backup_read_failed")?;
    file.persist(&path)
        .map_err(|_| "legacy_backup_read_failed")?;
    let connection = open(&path)?;
    Ok((directory, connection))
}

pub(super) fn read(bytes: &[u8], parts: Parts) -> Result<SourceDatabase, String> {
    let (_directory, connection) = connect(bytes)?;
    extract(&connection, parts)
}

fn extract(connection: &Connection, parts: Parts) -> Result<SourceDatabase, String> {
    let mut schema = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 257")
        .map_err(error)?;
    let mut rows = schema.query([]).map_err(error)?;
    let mut result = SourceDatabase::default();
    while let Some(row) = rows.next().map_err(error)? {
        if result.schema.len() >= 256 {
            return Err("legacy_backup_database_limit".into());
        }
        let kind: String = row.get(0).map_err(error)?;
        let name: String = row.get(1).map_err(error)?;
        let table_name: String = row.get(2).map_err(error)?;
        let sql: Option<String> = row.get(3).map_err(error)?;
        identifier(&name)?;
        identifier(&table_name)?;
        if !["table", "view", "index", "trigger"].contains(&kind.as_str()) {
            return Err("legacy_backup_invalid_schema".into());
        }
        result.schema.push(SourceSchema {
            kind,
            name,
            table_name,
            sql,
            columns: Vec::new(),
        });
    }
    let known = [
        (
            "profiles",
            &["id", "type", "name", "gid", "outbound_json"][..],
        ),
        ("groups", &["id", "name"][..]),
        ("groups_order", &["group_id", "display_order"][..]),
        ("route_profiles", &["id", "name"][..]),
        (
            "route_rules",
            &["route_profile_id", "rule_order", "type"][..],
        ),
        ("settings", &["key", "value"][..]),
        ("otp_profiles", &["id", "name", "secret"][..]),
    ];
    for name in if parts.profiles {
        &["profiles", "groups"][..]
    } else {
        &[]
    } {
        if !result
            .schema
            .iter()
            .any(|s| s.name == *name && s.kind == "table")
        {
            return Err("legacy_backup_invalid_schema".into());
        }
    }
    for (enabled, names) in [
        (parts.routes, &["route_profiles", "route_rules"][..]),
        (parts.settings, &["settings"][..]),
        (parts.otp, &["otp_profiles"][..]),
    ] {
        if enabled
            && names.iter().any(|name| {
                !result
                    .schema
                    .iter()
                    .any(|s| s.name == *name && s.kind == "table")
            })
        {
            return Err("legacy_backup_invalid_schema".into());
        }
    }
    if result.schema.iter().filter(|s| s.kind == "table").count() > MAX_TABLES {
        return Err("legacy_backup_database_limit".into());
    }
    let mut total_rows = 0;
    let mut total_bytes = 0;
    for index in 0..result.schema.len() {
        let object = &mut result.schema[index];
        if known.iter().any(|(name, _)| *name == object.name) && object.kind != "table" {
            return Err("legacy_backup_invalid_schema".into());
        }
        if object.kind != "table" {
            continue;
        }
        // Never connect a virtual-table module or evaluate a generated column.
        // SQLite normalizes the stored prefix of ordinary CREATE TABLE statements.
        if !object.sql.as_deref().is_some_and(|sql| {
            sql.trim_start()
                .to_ascii_uppercase()
                .starts_with("CREATE TABLE ")
        }) {
            return Err("legacy_backup_schema_unsupported".into());
        }
        let mut info = connection
            .prepare(&format!(
                "PRAGMA table_xinfo({})",
                identifier(&object.name)?
            ))
            .map_err(error)?;
        let mut rows = info.query([]).map_err(error)?;
        let mut seen = HashSet::new();
        while let Some(row) = rows.next().map_err(error)? {
            if object.columns.len() >= MAX_COLUMNS {
                return Err("legacy_backup_database_limit".into());
            }
            let name: String = row.get(1).map_err(error)?;
            identifier(&name)?;
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err("legacy_backup_invalid_schema".into());
            }
            let hidden: i64 = row.get(6).map_err(error)?;
            if hidden != 0 {
                return Err("legacy_backup_schema_unsupported".into());
            }
            object.columns.push(SourceColumn {
                name,
                declared_type: row.get(2).map_err(error)?,
                not_null: row.get::<_, i64>(3).map_err(error)? != 0,
                default_sql: row.get(4).map_err(error)?,
                primary_key_order: row.get(5).map_err(error)?,
            });
        }
        if object.columns.is_empty() {
            return Err("legacy_backup_invalid_schema".into());
        }
        if let Some((_, required)) = known.iter().find(|(name, _)| *name == object.name) {
            if required
                .iter()
                .any(|key| !object.columns.iter().any(|c| c.name == *key))
            {
                return Err("legacy_backup_invalid_schema".into());
            }
        }
        let fields = object
            .columns
            .iter()
            .map(|c| identifier(&c.name))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let query = format!(
            "SELECT {fields} FROM {} NOT INDEXED LIMIT {}",
            identifier(&object.name)?,
            MAX_ROWS_PER_TABLE + 1
        );
        let mut statement = connection.prepare(&query).map_err(error)?;
        let mut rows = statement.query([]).map_err(error)?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().map_err(error)? {
            total_rows += 1;
            if values.len() >= MAX_ROWS_PER_TABLE || total_rows > MAX_ROWS {
                return Err("legacy_backup_database_limit".into());
            }
            let mut value = BTreeMap::new();
            for (index, column) in object.columns.iter().enumerate() {
                // Count repeated map keys and per-cell storage as well as values;
                // a wide table of NULL cells must not amplify a tiny database.
                total_bytes += column.name.len() + 16;
                let field = match row.get_ref(index).map_err(error)? {
                    ValueRef::Null => SourceValue::Null,
                    ValueRef::Integer(i) => SourceValue::Integer(i),
                    ValueRef::Real(f) if f.is_finite() => SourceValue::Real(f),
                    ValueRef::Real(_) => return Err("legacy_backup_invalid_data".into()),
                    ValueRef::Text(bytes) => {
                        total_bytes += bytes.len();
                        SourceValue::Text(
                            std::str::from_utf8(bytes)
                                .map_err(|_| "legacy_backup_invalid_data")?
                                .to_owned(),
                        )
                    }
                    ValueRef::Blob(bytes) => {
                        total_bytes += bytes.len();
                        SourceValue::Blob(bytes.to_vec())
                    }
                };
                if total_bytes > MAX_BYTES {
                    return Err("legacy_backup_database_limit".into());
                }
                value.insert(column.name.clone(), field);
            }
            values.push(value);
        }
        let name = object.name.clone();
        classify(&mut result, &name, values)?;
    }
    // Run integrity validation only after rejecting virtual/generated tables;
    // even PRAGMA quick_check may otherwise connect a virtual-table module.
    let check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(error)?;
    if check != "ok" {
        return Err("legacy_backup_invalid_database".into());
    }
    Ok(result)
}

fn integer(row: &SourceRow, key: &str) -> Result<i64, String> {
    match row.get(key) {
        Some(SourceValue::Integer(value)) => Ok(*value),
        _ => Err("legacy_backup_invalid_data".into()),
    }
}
fn text(row: &SourceRow, key: &str) -> Result<String, String> {
    match row.get(key) {
        Some(SourceValue::Text(value)) => Ok(value.clone()),
        _ => Err("legacy_backup_invalid_data".into()),
    }
}
fn optional_text(row: &SourceRow, key: &str) -> Result<Option<String>, String> {
    match row.get(key) {
        None | Some(SourceValue::Null) => Ok(None),
        Some(SourceValue::Text(value)) => Ok(Some(value.clone())),
        _ => Err("legacy_backup_invalid_data".into()),
    }
}
fn id(row: &SourceRow, key: &str) -> Result<i64, String> {
    let value = integer(row, key)?;
    if !(0..=i32::MAX as i64).contains(&value) {
        return Err("legacy_backup_invalid_data".into());
    }
    Ok(value)
}

fn classify(
    database: &mut SourceDatabase,
    table: &str,
    rows: Vec<SourceRow>,
) -> Result<(), String> {
    let mut json_nodes = 0usize;
    let mut ids = HashSet::new();
    for row in rows {
        match table {
            "profiles" => {
                let id = id(&row, "id")?;
                if !ids.insert(id.to_string()) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                let raw = text(&row, "outbound_json")?;
                let (outbound, nodes) =
                    json::parse_counted(&raw).map_err(|_| "legacy_backup_invalid_profile_json")?;
                json_nodes += nodes;
                if json_nodes > 1_000_000 {
                    return Err("legacy_backup_database_limit".into());
                }
                if !outbound.is_object() {
                    return Err("legacy_backup_invalid_profile_json".into());
                }
                database.profiles.push(SourceProfile {
                    id,
                    kind: text(&row, "type")?,
                    name: optional_text(&row, "name")?,
                    group_id: self::id(&row, "gid")?,
                    outbound,
                    columns: row,
                });
            }
            "groups" => {
                let id = id(&row, "id")?;
                if !ids.insert(id.to_string()) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                database.groups.push(SourceGroup {
                    id,
                    name: text(&row, "name")?,
                    columns: row,
                });
            }
            "route_profiles" => {
                let id = id(&row, "id")?;
                if !ids.insert(id.to_string()) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                database.routes.push(SourceRoute {
                    id,
                    name: text(&row, "name")?,
                    columns: row,
                });
            }
            "route_rules" => {
                let route_id = id(&row, "route_profile_id")?;
                let order = id(&row, "rule_order")?;
                if !ids.insert(format!("{route_id}/{order}")) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                database.rules.push(SourceRule {
                    route_id,
                    order,
                    kind: integer(&row, "type")?,
                    columns: row,
                });
            }
            "settings" => {
                let key = text(&row, "key")?;
                if key.is_empty() || key.len() > MAX_KEY_BYTES || !ids.insert(key.clone()) {
                    return Err("legacy_backup_invalid_data".into());
                }
                database.settings.push(SourceSetting {
                    key,
                    value: text(&row, "value")?,
                    columns: row,
                });
            }
            "otp_profiles" => {
                let id = id(&row, "id")?;
                if !ids.insert(id.to_string()) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                text(&row, "name")?;
                text(&row, "secret")?;
                database.otp.push(SourceOtp { id, columns: row });
            }
            "groups_order" => {
                let id = id(&row, "group_id")?;
                integer(&row, "display_order")?;
                if !ids.insert(id.to_string()) {
                    return Err("legacy_backup_duplicate_id".into());
                }
                database.group_order.push(row);
            }
            "entity_ids" => database.entity_ids.push(row),
            _ => database
                .other_tables
                .entry(table.to_owned())
                .or_default()
                .push(row),
        }
    }
    if ![
        "profiles",
        "groups",
        "groups_order",
        "route_profiles",
        "route_rules",
        "settings",
        "otp_profiles",
        "entity_ids",
    ]
    .contains(&table)
    {
        database.other_tables.entry(table.to_owned()).or_default();
    }
    Ok(())
}

#[cfg(test)]
mod protection_tests;
