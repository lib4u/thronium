use super::*;
use serde_json::Value;
use std::collections::BTreeMap;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(size)
            .ok_or("legacy_backup_invalid_container")?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or("legacy_backup_invalid_container")?;
        self.at = end;
        Ok(bytes)
    }
    fn number(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn blob(&mut self, limit: usize) -> Result<Option<&'a [u8]>, String> {
        let length = self.number()?;
        if length == u32::MAX {
            return Ok(None);
        }
        if length as usize > limit {
            return Err("legacy_backup_limit".into());
        }
        self.take(length as usize).map(Some)
    }
    fn string(&mut self, limit: usize) -> Result<Option<String>, String> {
        let Some(bytes) = self.blob(limit)? else {
            return Ok(None);
        };
        if bytes.len() % 2 != 0 {
            return Err("legacy_backup_invalid_utf16".into());
        }
        let utf16: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        String::from_utf16(&utf16)
            .map(Some)
            .map_err(|_| "legacy_backup_invalid_utf16".into())
    }
}

/// First bytes of a Throne binary backup.
pub const MAGIC: &[u8; 4] = b"THRN";

pub(super) fn parse(bytes: &[u8]) -> Result<SourceArchive, String> {
    if bytes.len() > MAX_BYTES {
        return Err("legacy_backup_limit".into());
    }
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(4)? != MAGIC {
        return Err("legacy_backup_invalid_container".into());
    }
    let container_version = reader.number()?;
    if !matches!(container_version, 1 | 2) {
        return Err("legacy_backup_version_unsupported".into());
    }
    let text = reader
        .string(MAX_METADATA_BYTES)?
        .ok_or("legacy_backup_invalid_metadata")?;
    let metadata: Value = json::parse(&text).map_err(|_| "legacy_backup_invalid_metadata")?;
    let object = metadata
        .as_object()
        .ok_or("legacy_backup_invalid_metadata")?;
    let content_version = object
        .get("backup_version")
        .map(|v| {
            let version = v.as_u64().ok_or("legacy_backup_invalid_metadata")?;
            if !matches!(version, 1 | 2) {
                return Err("legacy_backup_version_unsupported");
            }
            Ok(version as u32)
        })
        .transpose()
        .map_err(str::to_owned)?;
    let created_at = object
        .get("created_at")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("legacy_backup_invalid_metadata")
        })
        .transpose()?;
    let count = reader.number()? as usize;
    if count > MAX_PARTS {
        return Err("legacy_backup_limit".into());
    }
    let mut files = BTreeMap::new();
    for _ in 0..count {
        let key = reader
            .string(MAX_KEY_BYTES)?
            .ok_or("legacy_backup_invalid_container")?;
        if key.is_empty() || key.contains('\0') || files.contains_key(&key) {
            return Err("legacy_backup_invalid_container".into());
        }
        let value = reader.blob(MAX_BYTES)?.map(<[u8]>::to_vec);
        if key == "database" && value.as_ref().is_none_or(Vec::is_empty) {
            return Err("legacy_backup_invalid_database".into());
        }
        files.insert(key, value);
    }
    if reader.at != bytes.len() {
        return Err("legacy_backup_invalid_container".into());
    }
    let has_database = files.contains_key("database");
    let has_icons = files.keys().any(|k| k.starts_with("icons/"));
    let parts = if container_version >= 2 && object.contains_key("parts") {
        let selected = object["parts"]
            .as_object()
            .ok_or("legacy_backup_invalid_metadata")?;
        let flag = |key: &str| -> Result<bool, String> {
            selected
                .get(key)
                .map(|v| {
                    v.as_bool()
                        .ok_or_else(|| "legacy_backup_invalid_metadata".into())
                })
                .unwrap_or(Ok(false))
        };
        Parts {
            profiles: flag("profiles")? && has_database,
            routes: flag("routes")? && has_database,
            settings: flag("settings")? && has_database,
            otp: flag("otp")? && has_database,
            icons: flag("icons")? && has_icons,
        }
    } else {
        Parts {
            profiles: has_database,
            routes: has_database,
            settings: has_database,
            otp: false,
            icons: has_icons,
        }
    };
    Ok(SourceArchive {
        container_version,
        content_version,
        metadata,
        created_at,
        parts,
        files,
        database: None,
    })
}
