use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
/// What a counted bucket can be read as. Thronium counts a byte once, with the
/// profile that carried it and the application that asked, so its own records
/// answer for both. A copy imported from Qt counted servers and applications in
/// tables of their own, and those rows answer only for their own table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    #[default]
    Both,
    Profiles,
    Applications,
}
impl Scope {
    fn is_both(&self) -> bool {
        *self == Self::Both
    }
    pub fn counts_profiles(&self) -> bool {
        *self != Self::Applications
    }
    pub fn counts_applications(&self) -> bool {
        *self != Self::Profiles
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub hour: u64,
    pub profile: String,
    pub group: String,
    pub process: String,
    pub upload: i64,
    pub download: i64,
    #[serde(default, skip_serializing_if = "Scope::is_both")]
    pub scope: Scope,
}
/// Qt's `DIRECT_STAT_PROFILE_ID`: bytes that left without a server. A profile
/// id is a UUID, so this reserved word can never name one of the user's own.
pub const DIRECT_PROFILE: &str = "direct";
/// What a profile was called when its bytes were counted, so a renamed or
/// deleted profile still reads as itself (Qt's `config_meta`).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Names {
    pub profile: String,
    pub group: String,
    pub last_seen: u64,
}

#[derive(Default)]
pub struct History {
    loaded: bool,
    entries: BTreeMap<String, Entry>,
    names: BTreeMap<String, Names>,
    names_dirty: bool,
    /// Per-profile (upload, download) over the retained entries, rebuilt on
    /// load and pruning so a periodic snapshot never scans the buckets.
    totals: HashMap<String, (i64, i64)>,
    last_write: Option<Instant>,
    dirty: bool,
    /// The stored file could not be read or set aside; it is never overwritten.
    blocked: bool,
}
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
/// Names of profiles no longer in the library still resolve, but the file that
/// remembers them stays small.
const MAX_NAMES: usize = 4096;
fn path(root: &Path) -> PathBuf {
    root.join("traffic-history.json")
}
fn names_path(root: &Path) -> PathBuf {
    root.join("traffic-names.json")
}
impl History {
    pub(crate) fn load(&mut self, root: &Path) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let file = path(root);
        let parsed = match std::fs::metadata(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(BTreeMap::new()),
            Ok(meta) if meta.len() <= MAX_FILE_BYTES => std::fs::read(&file)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok()),
            _ => None,
        };
        match parsed {
            Some(entries) => self.entries = entries,
            // An unreadable history is kept beside a new one instead of being
            // replaced by the next write.
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let aside = root.join(format!("traffic-history.unreadable-{now}.json"));
                self.blocked = std::fs::rename(&file, aside).is_err();
            }
        }
        // Losing the remembered names only costs the stats view its labels, so
        // an unreadable file is simply started over.
        self.names = std::fs::metadata(names_path(root))
            .ok()
            .filter(|meta| meta.len() <= MAX_FILE_BYTES)
            .and_then(|_| std::fs::read(names_path(root)).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        self.rebuild_totals();
    }
    /// Remembers what a profile was called while its bytes are being counted.
    pub fn remember(&mut self, root: &Path, id: &str, profile: &str, group: &str) {
        if id.is_empty() {
            return;
        }
        self.load(root);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entry = self.names.entry(id.to_owned()).or_default();
        if entry.profile != profile || entry.group != group {
            entry.profile = profile.to_owned();
            entry.group = group.to_owned();
            self.names_dirty = true;
        }
        entry.last_seen = now;
        while self.names.len() > MAX_NAMES {
            // The least recently counted name gives way first.
            let oldest = self
                .names
                .iter()
                .filter(|(key, _)| key.as_str() != id)
                .min_by_key(|(_, value)| value.last_seen)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    self.names.remove(&key);
                    self.names_dirty = true;
                }
                None => break,
            }
        }
    }
    pub fn names(&self) -> &BTreeMap<String, Names> {
        &self.names
    }
    fn rebuild_totals(&mut self) {
        self.totals.clear();
        for e in self.entries.values() {
            let total = self.totals.entry(e.profile.clone()).or_default();
            total.0 = total.0.saturating_add(e.upload);
            total.1 = total.1.saturating_add(e.download);
        }
    }
    fn prune(&mut self, since: u64) {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.hour >= since);
        if self.entries.len() != before {
            self.dirty = true;
            self.rebuild_totals();
        }
    }
    pub fn record(
        &mut self,
        root: &Path,
        profile: &str,
        group: &str,
        deltas: Vec<crate::traffic::Delta>,
        days: u64,
    ) {
        self.load(root);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hour = now / 3600 * 3600;
        self.prune(now.saturating_sub(days * 86400));
        for delta in deltas {
            if delta.upload == 0 && delta.download == 0 {
                continue;
            }
            // Qt counts what left without a server apart from the running
            // profile, so the two never inflate each other.
            let (profile, group) = if delta.direct {
                (DIRECT_PROFILE, "")
            } else {
                (profile, group)
            };
            let key = serde_json::to_string(&(hour, profile, group, &delta.process)).unwrap();
            // At the bound the oldest hours give way; current traffic is always kept.
            while !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
                self.evict_oldest();
            }
            let e = self.entries.entry(key).or_insert_with(|| Entry {
                hour,
                profile: profile.into(),
                group: group.into(),
                process: delta.process.clone(),
                ..Default::default()
            });
            e.upload = e.upload.saturating_add(delta.upload);
            e.download = e.download.saturating_add(delta.download);
            let total = self.totals.entry(profile.to_owned()).or_default();
            total.0 = total.0.saturating_add(delta.upload);
            total.1 = total.1.saturating_add(delta.download);
            self.dirty = true;
        }
        if self.last_write.is_none_or(|t| t.elapsed().as_secs() >= 30) {
            let _ = self.flush(root);
        }
    }
    /// Takes over buckets counted by an older copy. Their rows answer for one
    /// table only, so they keep keys of their own and are replaced rather than
    /// added: importing the same copy twice leaves the same history, and what
    /// Thronium counted itself is never touched.
    pub fn import(
        &mut self,
        root: &Path,
        entries: Vec<Entry>,
        names: Vec<(String, Names)>,
    ) -> Result<usize, String> {
        self.load(root);
        let mut merged = 0;
        for entry in entries {
            if entry.upload == 0 && entry.download == 0 || entry.scope == Scope::Both {
                continue;
            }
            let key = serde_json::to_string(&(
                entry.hour,
                &entry.profile,
                &entry.group,
                &entry.process,
                &entry.scope,
            ))
            .map_err(|_| "history_write_failed")?;
            while !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
                self.evict_oldest();
            }
            self.entries.insert(key, entry);
            merged += 1;
            self.dirty = true;
        }
        for (id, value) in names {
            let stored = self.names.entry(id).or_default();
            if stored.profile.is_empty() {
                stored.profile = value.profile;
            }
            if stored.group.is_empty() {
                stored.group = value.group;
            }
            self.names_dirty = true;
        }
        while self.names.len() > MAX_NAMES {
            let Some(oldest) = self
                .names
                .iter()
                .min_by_key(|(_, value)| value.last_seen)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.names.remove(&oldest);
        }
        self.rebuild_totals();
        self.flush(root)?;
        Ok(merged)
    }
    fn evict_oldest(&mut self) {
        // Keys start with the hour, and hours have the same number of digits.
        if let Some((_, old)) = self.entries.pop_first() {
            if let Some(total) = self.totals.get_mut(&old.profile) {
                total.0 = total.0.saturating_sub(old.upload);
                total.1 = total.1.saturating_sub(old.download);
            }
            self.dirty = true;
        }
    }
    /// Upload and download credited to a profile within the retained window.
    pub fn profile_totals(&self, id: &str) -> Option<(i64, i64)> {
        self.totals.get(id).copied()
    }
    fn flush_names(&mut self, root: &Path) {
        if !self.names_dirty {
            return;
        }
        let write = || -> Option<()> {
            let bytes = serde_json::to_vec(&self.names).ok()?;
            let mut temp = tempfile::NamedTempFile::new_in(root).ok()?;
            temp.write_all(&bytes).ok()?;
            temp.as_file().sync_all().ok()?;
            temp.persist(names_path(root)).ok()?;
            Some(())
        };
        // Labels are derived data: failing to store them never fails a write of
        // the counted bytes themselves.
        self.names_dirty = write().is_none();
    }
    pub fn flush(&mut self, root: &Path) -> Result<(), String> {
        self.flush_names(root);
        if !self.dirty {
            return Ok(());
        }
        if self.blocked {
            return Err("history_write_failed".into());
        }
        let bytes = serde_json::to_vec(&self.entries).map_err(|_| "history_write_failed")?;
        let mut temp = tempfile::NamedTempFile::new_in(root).map_err(|_| "history_write_failed")?;
        temp.write_all(&bytes)
            .and_then(|_| temp.as_file().sync_all())
            .map_err(|_| "history_write_failed")?;
        temp.persist(path(root))
            .map_err(|_| "history_write_failed")?;
        self.last_write = Some(Instant::now());
        self.dirty = false;
        Ok(())
    }
    pub fn read(&mut self, root: &Path, days: u64) -> Vec<&Entry> {
        self.load(root);
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(days * 86400);
        self.prune(since);
        let _ = self.flush(root);
        self.entries.values().collect()
    }
    /// Qt's per-profile "Reset traffic": the profile keeps its history hours
    /// for other profiles, only its own counted bytes are forgotten.
    pub fn reset_profiles(&mut self, root: &Path, ids: &[String]) -> Result<(), String> {
        self.load(root);
        let before = self.entries.len();
        self.entries.retain(|_, e| !ids.contains(&e.profile));
        if self.entries.len() == before {
            return Ok(());
        }
        self.dirty = true;
        self.rebuild_totals();
        self.flush(root)
    }
    pub fn clear(&mut self, root: &Path) -> Result<(), String> {
        self.load(root);
        // Clearing is an explicit choice to replace even an unreadable file.
        self.blocked = false;
        self.entries.clear();
        self.totals.clear();
        self.names.clear();
        self.names_dirty = true;
        self.dirty = true;
        self.flush(root)
    }
}
