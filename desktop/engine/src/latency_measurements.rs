//! Local HTTP observations for opt-in initial selector ranking.
use crate::{group_chains, settings, store::Library};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const FILE: &str = "http-latencies-v1.json";
const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Origin {
    #[default]
    Manual,
    CoreAverage,
}
impl Origin {
    fn is_manual(&self) -> bool {
        *self == Self::Manual
    }
}
#[derive(Clone, Debug)]
pub(crate) struct CoreContext {
    fingerprint: String,
    url_hash: String,
}
pub(crate) fn core_context(library: &Library, id: &str, url: &str) -> Option<CoreContext> {
    Some(CoreContext {
        fingerprint: fingerprint(library, id)?,
        url_hash: url_hash(url)?,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    // None is a completed HTTP failure, never a missing or cancelled result.
    pub latency_ms: Option<i32>,
    pub tested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Origin::is_manual")]
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_at_ms: Option<u64>,
    fingerprint: String,
    url_hash: String,
}
#[derive(Clone, Default)]
pub struct Cache {
    entries: BTreeMap<String, Observation>,
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
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn fingerprint(library: &Library, id: &str) -> Option<String> {
    let profile = library.profiles.iter().find(|p| p.id == id)?;
    let mut context = json!([
        group_chains::stamp(library, profile),
        settings::section(library, "presets"),
        settings::section(library, "core"),
        settings::section(library, "security")
    ]);
    context[0][2]
        .as_array_mut()?
        .sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
    Some(digest(&serde_json::to_vec(&context).ok()?))
}
fn url_hash(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(digest(url.as_str().as_bytes()))
}
impl Cache {
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
            let mut data: FileData = serde_json::from_slice(&bytes).ok()?;
            if data.version != 1 || data.entries.len() > MAX_ENTRIES {
                return None;
            }
            if data.entries.iter().any(|(id, e)| {
                id.is_empty()
                    || id.len() > 512
                    || e.latency_ms.is_some_and(|ms| ms < 0)
                    || e.tested_at == 0
                    || e.tested_at > now().saturating_add(300)
                    || match e.origin {
                        Origin::Manual => e
                            .timeout_ms
                            .is_none_or(|v| !crate::probes::TIMEOUT_MS.contains(&v)),
                        Origin::CoreAverage => e.timeout_ms.is_some() || e.observed_at_ms.is_none(),
                    }
                    || e.observed_at_ms.is_some_and(|at| at / 1000 != e.tested_at)
                    || !valid_hash(&e.fingerprint)
                    || !valid_hash(&e.url_hash)
            }) {
                return None;
            }
            data.entries
                .retain(|id, _| library.profiles.iter().any(|p| &p.id == id));
            Some(Self {
                entries: data.entries,
            })
        };
        read().unwrap_or_default()
    }
    pub(crate) fn fresh<'a>(
        &'a self,
        library: &Library,
        id: &str,
        url: &str,
        validity_mins: u32,
    ) -> Option<&'a Observation> {
        self.fresh_at(library, id, url, validity_mins, now())
    }
    fn fresh_at<'a>(
        &'a self,
        library: &Library,
        id: &str,
        url: &str,
        validity_mins: u32,
        at: u64,
    ) -> Option<&'a Observation> {
        if validity_mins == 0 {
            return None;
        }
        let entry = self.entries.get(id)?;
        if entry.fingerprint != fingerprint(library, id)?
            || entry.url_hash != url_hash(url)?
            || at.checked_sub(entry.tested_at)? > u64::from(validity_mins) * 60
        {
            return None;
        }
        Some(entry)
    }
    pub(crate) fn updated(
        &self,
        library: &Library,
        id: &str,
        url: &str,
        timeout_ms: u32,
        latency_ms: Option<i32>,
    ) -> Result<Self, String> {
        if latency_ms.is_some_and(|ms| ms < 0) || !crate::probes::TIMEOUT_MS.contains(&timeout_ms) {
            return Err("probe_invalid_options".into());
        }
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let entry = Observation {
            latency_ms,
            tested_at: at / 1000,
            timeout_ms: Some(timeout_ms),
            origin: Origin::Manual,
            observed_at_ms: Some(at),
            fingerprint: fingerprint(library, id).ok_or("profile_not_found")?,
            url_hash: url_hash(url).ok_or("probe_invalid_url")?,
        };
        Ok(self.with_entry(library, id, entry))
    }
    fn with_entry(&self, library: &Library, id: &str, entry: Observation) -> Self {
        let mut next = self.clone();
        next.prune(library);
        next.insert(id, entry);
        next
    }
    pub(crate) fn prune(&mut self, library: &Library) {
        let ids: std::collections::HashSet<_> =
            library.profiles.iter().map(|p| p.id.as_str()).collect();
        self.entries.retain(|id, _| ids.contains(id.as_str()));
    }
    fn insert(&mut self, id: &str, entry: Observation) {
        self.entries.insert(id.into(), entry);
        while self.entries.len() > MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .filter(|(key, _)| key.as_str() != id)
                .min_by_key(|(_, e)| e.tested_at)
                .map(|(key, _)| key.clone())
                .unwrap();
            self.entries.remove(&oldest);
        }
    }
    pub(crate) fn record_core(
        &mut self,
        library: &Library,
        id: &str,
        context: &CoreContext,
        latency_ms: Option<i32>,
        at_ms: u64,
    ) -> Option<()> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        if at_ms < 1000
            || at_ms > now_ms
            || latency_ms.is_some_and(|ms| ms < 0)
            || fingerprint(library, id)? != context.fingerprint
        {
            return None;
        }
        if self.entries.get(id).is_some_and(|e| {
            // An old file has second precision only; conservatively keep its
            // entire timestamp second rather than replacing a possibly newer test.
            e.observed_at_ms
                .unwrap_or(e.tested_at.saturating_mul(1000).saturating_add(999))
                >= at_ms
        }) {
            return None;
        }
        self.insert(
            id,
            Observation {
                latency_ms,
                tested_at: at_ms / 1000,
                timeout_ms: None,
                origin: Origin::CoreAverage,
                observed_at_ms: Some(at_ms),
                fingerprint: context.fingerprint.clone(),
                url_hash: context.url_hash.clone(),
            },
        );
        Some(())
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        let write = || -> Result<(), Box<dyn std::error::Error>> {
            let bytes = serde_json::to_vec(&FileData {
                version: 1,
                entries: self.entries.clone(),
            })?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err("latency cache limit".into());
            }
            let mut tmp = tempfile::NamedTempFile::new_in(directory)?;
            tmp.write_all(&bytes)?;
            tmp.as_file().sync_all()?;
            tmp.persist(directory.join(FILE))?;
            Ok(())
        };
        write().map_err(|_| "latency_cache_write_failed".into())
    }
}

#[cfg(test)]
mod tests;
