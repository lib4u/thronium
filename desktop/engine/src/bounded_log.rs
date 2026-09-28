//! One bounded on-device JSON log, reused by the measurement journal and the
//! member switch history. It gives monotonic ids, a newest-first view, an
//! atomic save and forgetting by count, size and age; it never knows what a
//! row means. Callers supply the entry type, the file name and the bounds.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// A stored row: it carries an id and a timestamp the log stamps on record,
/// validates itself on load, and normalizes its own text when recorded.
pub(crate) trait LogEntry: Serialize + DeserializeOwned {
    fn id(&self) -> u64;
    fn at(&self) -> u64;
    fn stamp(&mut self, id: u64, at: u64);
    fn valid(&self, now: u64) -> bool;
}

/// The fixed shape of one log: its file, error code and bounds.
pub(crate) trait LogSpec {
    type Entry: LogEntry;
    const FILE: &'static str;
    const WRITE_ERROR: &'static str;
    const MAX_ENTRIES: usize;
    const MAX_BYTES: u64;
    const RETENTION_SECS: u64;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn<E> {
    version: u32,
    next_id: u64,
    entries: Vec<E>,
}
#[derive(Serialize)]
struct FileOut<'a, E> {
    version: u32,
    next_id: u64,
    entries: &'a [E],
}

pub(crate) struct BoundedLog<S: LogSpec> {
    entries: Vec<S::Entry>,
    next_id: u64,
}
impl<S: LogSpec> Default for BoundedLog<S> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 0,
        }
    }
}
impl<S: LogSpec> BoundedLog<S> {
    /// A corrupt, oversized or foreign file yields an empty log, never an error.
    pub(crate) fn load(directory: &Path) -> Self {
        let read = || -> Option<Self> {
            let path = directory.join(S::FILE);
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.is_file() || metadata.len() > S::MAX_BYTES {
                return None;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(S::MAX_BYTES + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            let file: FileIn<S::Entry> = serde_json::from_slice(&bytes).ok()?;
            let now = now();
            if file.version != 1
                || file.entries.len() > S::MAX_ENTRIES
                || file
                    .entries
                    .iter()
                    .any(|e| !e.valid(now) || e.id() >= file.next_id)
            {
                return None;
            }
            let mut log = Self {
                entries: file.entries,
                next_id: file.next_id,
            };
            log.prune(now);
            Some(log)
        };
        read().unwrap_or_default()
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        let write = || -> Result<(), Box<dyn std::error::Error>> {
            let bytes = serde_json::to_vec(&FileOut {
                version: 1,
                next_id: self.next_id,
                entries: &self.entries,
            })?;
            if bytes.len() as u64 > S::MAX_BYTES {
                return Err("log too large".into());
            }
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist(directory.join(S::FILE))?;
            Ok(())
        };
        write().map_err(|_| S::WRITE_ERROR.into())
    }
    /// Appends one row; old, excess and oversized history is dropped first.
    pub(crate) fn record(&mut self, mut entry: S::Entry) -> u64 {
        let now = now();
        self.next_id = self.next_id.max(1);
        entry.stamp(self.next_id, now);
        self.next_id += 1;
        self.entries.push(entry);
        self.prune(now);
        self.next_id - 1
    }
    fn prune(&mut self, now: u64) {
        self.entries
            .retain(|e| e.at().saturating_add(S::RETENTION_SECS) >= now);
        if self.entries.len() > S::MAX_ENTRIES {
            let excess = self.entries.len() - S::MAX_ENTRIES;
            self.entries.drain(..excess);
        }
        while serde_json::to_vec(&self.entries)
            .map(|b| b.len() as u64 > S::MAX_BYTES - 1024)
            .unwrap_or(false)
        {
            self.entries.remove(0);
        }
    }
    /// Publish the empty view only after replacing its on-disk counterpart.
    pub(crate) fn clear_and_save(&mut self, directory: &Path) -> Result<(), String> {
        let empty = Self {
            entries: Vec::new(),
            next_id: self.next_id,
        };
        empty.save(directory)?;
        self.entries.clear();
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    /// Newest first, for the diagnostics page.
    pub(crate) fn view(&self) -> Value {
        let at = now();
        let entries: Vec<_> = self
            .entries
            .iter()
            .rev()
            .filter(|entry| entry.at().saturating_add(S::RETENTION_SECS) >= at)
            .collect();
        json!({
            "total": entries.len(),
            "entries": entries,
            "retentionDays": S::RETENTION_SECS / 86_400,
            "limit": S::MAX_ENTRIES,
        })
    }
}

#[cfg(test)]
mod tests;
