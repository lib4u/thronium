//! Read-only Throne .thrbackup inventory. This module does not restore a Library.
//! Source DTOs intentionally implement neither Serialize nor Debug: they contain secrets.
pub mod autoselector;
mod container;
pub use container::MAGIC;
mod database;
pub mod external_core;
pub mod icons;
pub(crate) use crate::strict_json as json;
pub mod otp;
pub(crate) mod profile_resources;
pub mod profiles;
pub mod resources;
pub mod routes;
pub mod settings;
mod source;
mod source_settings;
pub mod stats;
pub mod vpn;
pub mod wireguard;
pub use source::*;
use std::{io::Read, path::Path};

pub const MAX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 256 * 1024;
pub const MAX_PARTS: usize = 1024;
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_TABLES: usize = 64;
pub const MAX_COLUMNS: usize = 128;
pub const MAX_ROWS_PER_TABLE: usize = 5000;
pub const MAX_ROWS: usize = 20000;
pub const MAX_FIELD_BYTES: usize = 4 * 1024 * 1024;

/// Name of an imported profile whose Qt row has none, the same wherever it is imported.
pub(crate) fn fallback_profile_name(source_id: i64) -> String {
    format!("Throne #{source_id}")
}
pub fn read(path: &Path) -> Result<SourceArchive, String> {
    if !std::fs::metadata(path)
        .map_err(|_| "legacy_backup_read_failed")?
        .is_file()
    {
        return Err("legacy_backup_read_failed".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // A replacement with a FIFO between metadata and open must not block.
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "legacy_backup_read_failed")?;
    if !file
        .metadata()
        .map_err(|_| "legacy_backup_read_failed")?
        .is_file()
    {
        return Err("legacy_backup_read_failed".into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "legacy_backup_read_failed")?;
    parse(&bytes)
}

/// A Throne library the user chose directly: Qt's `throne.db` holds the same
/// tables the archive carries, without the archive around them.
pub fn read_database(bytes: &[u8]) -> Result<SourceArchive, String> {
    // Everything an archive would mark present lives in this one file; icons
    // and the other archive parts are files it does not have.
    let parts = Parts {
        profiles: true,
        routes: true,
        settings: true,
        otp: true,
        icons: false,
    };
    Ok(SourceArchive {
        container_version: 0,
        content_version: None,
        metadata: serde_json::Value::Null,
        created_at: None,
        parts,
        files: Default::default(),
        database: Some(database::read(bytes, parts)?),
    })
}

pub fn parse(bytes: &[u8]) -> Result<SourceArchive, String> {
    let mut source = container::parse(bytes)?;
    if let Some(bytes) = source.files.get("database").and_then(Option::as_deref) {
        source.database = Some(database::read(bytes, source.parts)?);
    }
    Ok(source)
}

#[cfg(test)]
mod tests;
