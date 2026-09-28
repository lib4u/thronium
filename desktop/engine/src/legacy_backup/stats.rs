//! Traffic counted by an older copy. Qt keeps it in `throne_stats.db` beside
//! the library, in tables of its own for servers and for applications, with a
//! minute tier that ages into an hour tier. Thronium keeps hours, so both tiers
//! are folded into the hour they belong to and the two tables stay apart.
use super::*;
use crate::settings::history::{Entry, Names, Scope, DIRECT_PROFILE};
use std::collections::BTreeMap;

/// Qt's `DIRECT_STAT_PROFILE_ID`.
const QT_DIRECT: i64 = -101;
/// Distinct (hour, server) or (hour, application) buckets one import may carry.
const MAX_BUCKETS: usize = 100_000;
/// Servers and applications an imported copy may name.
const MAX_NAMED: usize = 8192;
/// Nothing counted before Throne existed or after this machine's clock.
const EARLIEST: i64 = 1_600_000_000;

#[derive(Clone, Default)]
pub struct Stats {
    /// (hour, Qt profile id) → counted bytes.
    profiles: BTreeMap<(u64, i64), (i64, i64)>,
    /// (hour, process name) → counted bytes.
    applications: BTreeMap<(u64, String), (i64, i64)>,
    /// Qt's `config_meta`: what a server was called when it was counted.
    named: BTreeMap<i64, (String, String)>,
    /// A table held more than this import accepts; what was read is still good.
    pub truncated: bool,
}
impl Stats {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.applications.is_empty()
    }
    pub fn buckets(&self) -> usize {
        self.profiles.len() + self.applications.len()
    }
}

fn hour(bucket: i64, now: i64) -> Option<u64> {
    (EARLIEST..=now.saturating_add(86400))
        .contains(&bucket)
        .then(|| (bucket / 3600 * 3600) as u64)
}
fn counted(value: i64) -> i64 {
    value.clamp(0, i64::MAX / 4)
}
fn text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn tables(connection: &rusqlite::Connection) -> Result<Vec<String>, String> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
        .map_err(|_| "legacy_backup_invalid_database")?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| "legacy_backup_invalid_database")?;
    rows.take(MAX_TABLES)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "legacy_backup_invalid_database".into())
}

pub fn read(bytes: &[u8]) -> Result<Stats, String> {
    let (_directory, connection) = database::connect(bytes)?;
    let present = tables(&connection)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "legacy_backup_read_failed")?
        .as_secs() as i64;
    let mut stats = Stats::default();
    for table in ["config_traffic_minute", "config_traffic_hour"] {
        if !present.iter().any(|name| name == table) {
            continue;
        }
        let mut statement = connection
            .prepare(&format!(
                "SELECT bucket_start, profile_id, up, down FROM \"{table}\""
            ))
            .map_err(|_| "legacy_backup_invalid_schema")?;
        let mut rows = statement
            .query([])
            .map_err(|_| "legacy_backup_invalid_database")?;
        while let Some(row) = rows.next().map_err(|_| "legacy_backup_invalid_database")? {
            let (bucket, profile): (i64, i64) = (
                row.get(0).map_err(|_| "legacy_column_type")?,
                row.get(1).map_err(|_| "legacy_column_type")?,
            );
            let Some(hour) = hour(bucket, now) else {
                continue;
            };
            if stats.profiles.len() >= MAX_BUCKETS && !stats.profiles.contains_key(&(hour, profile))
            {
                stats.truncated = true;
                continue;
            }
            let total = stats.profiles.entry((hour, profile)).or_default();
            total.0 = total
                .0
                .saturating_add(counted(row.get(2).map_err(|_| "legacy_column_type")?));
            total.1 = total
                .1
                .saturating_add(counted(row.get(3).map_err(|_| "legacy_column_type")?));
        }
    }
    for table in ["app_traffic_minute", "app_traffic_hour"] {
        if !present.iter().any(|name| name == table) {
            continue;
        }
        let mut statement = connection
            .prepare(&format!(
                "SELECT bucket_start, process_name, up, down FROM \"{table}\""
            ))
            .map_err(|_| "legacy_backup_invalid_schema")?;
        let mut rows = statement
            .query([])
            .map_err(|_| "legacy_backup_invalid_database")?;
        while let Some(row) = rows.next().map_err(|_| "legacy_backup_invalid_database")? {
            let bucket: i64 = row.get(0).map_err(|_| "legacy_column_type")?;
            let process = text(&row.get::<_, String>(1).unwrap_or_default());
            let Some(hour) = hour(bucket, now) else {
                continue;
            };
            let key = (hour, process);
            if stats.applications.len() >= MAX_BUCKETS && !stats.applications.contains_key(&key) {
                stats.truncated = true;
                continue;
            }
            let total = stats.applications.entry(key).or_default();
            total.0 = total
                .0
                .saturating_add(counted(row.get(2).map_err(|_| "legacy_column_type")?));
            total.1 = total
                .1
                .saturating_add(counted(row.get(3).map_err(|_| "legacy_column_type")?));
        }
    }
    if present.iter().any(|name| name == "config_meta") {
        let mut statement = connection
            .prepare("SELECT profile_id, name, group_name FROM \"config_meta\"")
            .map_err(|_| "legacy_backup_invalid_schema")?;
        let mut rows = statement
            .query([])
            .map_err(|_| "legacy_backup_invalid_database")?;
        while let Some(row) = rows.next().map_err(|_| "legacy_backup_invalid_database")? {
            if stats.named.len() >= MAX_NAMED {
                stats.truncated = true;
                break;
            }
            let id: i64 = row.get(0).map_err(|_| "legacy_column_type")?;
            stats.named.insert(
                id,
                (
                    text(&row.get::<_, String>(1).unwrap_or_default()),
                    text(&row.get::<_, String>(2).unwrap_or_default()),
                ),
            );
        }
    }
    Ok(stats)
}

/// The identifier an imported server keeps when the library has no profile of
/// its own for it: stable, readable in a file, and never a UUID.
fn imported_id(profile: i64) -> String {
    if profile == QT_DIRECT {
        DIRECT_PROFILE.into()
    } else {
        format!("throne-{profile}")
    }
}

/// Turns what was read into buckets Thronium stores. `mapping` is the plan's
/// Qt id → new profile id, so traffic imported together with its servers stays
/// attached to them; anything else keeps its own imported identifier and the
/// name the copy remembered.
pub fn entries(
    stats: &Stats,
    mapping: &BTreeMap<i64, String>,
) -> (Vec<Entry>, Vec<(String, Names)>) {
    let identify = |profile: i64| {
        mapping
            .get(&profile)
            .cloned()
            .filter(|_| profile != QT_DIRECT)
            .unwrap_or_else(|| imported_id(profile))
    };
    let mut entries = Vec::with_capacity(stats.buckets());
    for ((hour, profile), (upload, download)) in &stats.profiles {
        if *upload == 0 && *download == 0 {
            continue;
        }
        entries.push(Entry {
            hour: *hour,
            profile: identify(*profile),
            group: String::new(),
            process: String::new(),
            upload: *upload,
            download: *download,
            scope: Scope::Profiles,
        });
    }
    for ((hour, process), (upload, download)) in &stats.applications {
        if *upload == 0 && *download == 0 {
            continue;
        }
        entries.push(Entry {
            hour: *hour,
            profile: String::new(),
            group: String::new(),
            process: process.clone(),
            upload: *upload,
            download: *download,
            scope: Scope::Applications,
        });
    }
    let names = stats
        .named
        .iter()
        .filter(|(profile, _)| **profile != QT_DIRECT)
        .map(|(profile, (name, group))| {
            (
                identify(*profile),
                Names {
                    profile: name.clone(),
                    group: group.clone(),
                    last_seen: 0,
                },
            )
        })
        .collect();
    (entries, names)
}

#[cfg(test)]
mod stats_tests;
