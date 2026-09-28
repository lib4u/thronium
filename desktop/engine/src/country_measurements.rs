//! Derived local exit-country observations; never part of a portable library.
use crate::{settings::tests_runtime, store::Library};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const FILE: &str = "exit-countries-v1.json";
const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub country_code: String,
    pub tested_at: u64,
    fingerprint: String,
}
#[derive(Clone, Default)]
pub struct Cache {
    entries: BTreeMap<String, Observation>,
    directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileData {
    version: u32,
    entries: BTreeMap<String, Observation>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn country(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|c| c.is_ascii_uppercase())
}
pub(crate) fn fingerprint(library: &Library, id: &str) -> Option<String> {
    let mut context = tests_runtime::ip_stamp(library, id)?;
    // Dependency order in the library is presentation state. The actual order
    // of chain hops remains encoded in the configs and group policy themselves.
    context[0][2]
        .as_array_mut()?
        .sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
    let bytes = serde_json::to_vec(&context).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}
fn full_fingerprint(base: String, assets: serde_json::Value) -> Option<String> {
    let bytes =
        serde_json::to_vec(&serde_json::json!(["full-xray-country-v1", base, assets])).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}
impl Cache {
    fn fingerprint(&self, library: &Library, id: &str) -> Option<String> {
        let base = fingerprint(library, id)?;
        let profile = library.profiles.iter().find(|p| p.id == id)?;
        if profile.kind != crate::store::ProfileKind::XrayConfig {
            return Some(base);
        }
        if self.directory.as_os_str().is_empty() {
            return None;
        }
        let assets =
            crate::probes::full_xray::asset_identity(&self.directory, library, profile).ok()?;
        full_fingerprint(base, assets)
    }
    pub(crate) fn load(directory: &Path, library: &Library) -> Self {
        let read = || -> Option<Self> {
            let path = directory.join(FILE);
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.is_file() || metadata.len() > MAX_BYTES {
                return None;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            if bytes.len() as u64 > MAX_BYTES {
                return None;
            }
            let mut file: FileData = serde_json::from_slice(&bytes).ok()?;
            if file.version != 1 || file.entries.len() > MAX_ENTRIES {
                return None;
            }
            let now = now();
            if file.entries.iter().any(|(id, entry)| {
                id.is_empty()
                    || id.len() > 512
                    || !country(&entry.country_code)
                    || entry.tested_at == 0
                    || entry.tested_at > now.saturating_add(300)
                    || entry.fingerprint.len() != 64
                    || !entry.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
            }) {
                return None;
            }
            file.entries
                .retain(|id, _| library.profiles.iter().any(|p| &p.id == id));
            Some(Self {
                entries: file.entries,
                directory: directory.to_owned(),
            })
        };
        // Losing a derived observation must not prevent opening the user's servers.
        read().unwrap_or_else(|| Self {
            directory: directory.to_owned(),
            ..Default::default()
        })
    }
    pub(crate) fn current<'a>(&'a self, library: &Library, id: &str) -> Option<&'a Observation> {
        let entry = self.entries.get(id)?;
        (entry.fingerprint == self.fingerprint(library, id)?).then_some(entry)
    }
    pub(crate) fn updated(
        &self,
        library: &Library,
        id: &str,
        code: Option<&str>,
        assets: Option<&crate::probes::full_xray::Context>,
    ) -> Result<Self, String> {
        let base = fingerprint(library, id).ok_or("profile_not_found")?;
        let profile = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("profile_not_found")?;
        // Stamp the assets actually used by this test. A filesystem change
        // between the completion check and persistence must not attach an old
        // result to the new data version. No asset paths are persisted.
        let stamp = if profile.kind == crate::store::ProfileKind::XrayConfig {
            full_fingerprint(base, assets.ok_or("probe_stale")?.identity()).ok_or("probe_stale")?
        } else {
            base
        };
        let mut next = self.clone();
        next.entries
            .retain(|id, _| library.profiles.iter().any(|p| &p.id == id));
        if let Some(code) = code {
            if !country(code) {
                return Err("ip_test_invalid_response".into());
            }
            next.entries.insert(
                id.into(),
                Observation {
                    country_code: code.into(),
                    tested_at: now(),
                    fingerprint: stamp,
                },
            );
            while next.entries.len() > MAX_ENTRIES {
                let oldest = next
                    .entries
                    .iter()
                    .filter(|(stored_id, _)| stored_id.as_str() != id)
                    .min_by_key(|(_, entry)| entry.tested_at)
                    .map(|(id, _)| id.clone())
                    .unwrap();
                next.entries.remove(&oldest);
            }
        } else {
            next.entries.remove(id);
        }
        Ok(next)
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        let write = || -> Result<(), Box<dyn std::error::Error>> {
            let bytes = serde_json::to_vec(&FileData {
                version: 1,
                entries: self.entries.clone(),
            })?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err("country cache limit".into());
            }
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist(directory.join(FILE))?;
            Ok(())
        };
        write().map_err(|_| "country_cache_write_failed".into())
    }
}

#[cfg(test)]
mod tests;
