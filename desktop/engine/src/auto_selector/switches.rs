//! Bounded local history of auto-selector member switches: when the running
//! pool changed which member carries traffic, from which member to which. It
//! keeps member and pool names the app already shows, never tags, keys or
//! wire data, and forgets entries by count, size and age. Measurement,
//! membership and traffic histories stay separate models sharing the table UI.
use serde::{Deserialize, Serialize};
use serde_json::Value;

const FILE: &str = "switch-history-v1.json";
const ERROR: &str = "switch_history_write_failed";
const MAX_ENTRIES: usize = 500;
const MAX_BYTES: u64 = 256 * 1024;
const RETENTION_SECS: u64 = 7 * 24 * 3600;
const MAX_TEXT: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub at: u64,
    pub pool_id: String,
    pub pool_name: String,
    /// The member traffic moved away from; empty for the pool's first selection.
    #[serde(default)]
    pub from_name: String,
    pub to_name: String,
}
impl Entry {
    fn valid(&self, now: u64) -> bool {
        let text = |s: &str| s.len() <= MAX_TEXT;
        self.at > 0
            && self.at <= now.saturating_add(300)
            && !self.pool_id.is_empty()
            && text(&self.pool_id)
            && text(&self.pool_name)
            && text(&self.from_name)
            && !self.to_name.is_empty()
            && text(&self.to_name)
    }
}

/// The switch history is a bounded on-device log of pool member switches.
pub struct Spec;
impl crate::bounded_log::LogSpec for Spec {
    type Entry = Entry;
    const FILE: &'static str = FILE;
    const WRITE_ERROR: &'static str = ERROR;
    const MAX_ENTRIES: usize = MAX_ENTRIES;
    const MAX_BYTES: u64 = MAX_BYTES;
    const RETENTION_SECS: u64 = RETENTION_SECS;
}
impl crate::bounded_log::LogEntry for Entry {
    fn id(&self) -> u64 {
        self.id
    }
    fn at(&self) -> u64 {
        self.at
    }
    fn stamp(&mut self, id: u64, at: u64) {
        self.pool_id.truncate(MAX_TEXT);
        self.pool_name.truncate(MAX_TEXT);
        self.from_name.truncate(MAX_TEXT);
        self.to_name.truncate(MAX_TEXT);
        self.id = id;
        self.at = at;
    }
    fn valid(&self, now: u64) -> bool {
        self.valid(now)
    }
}
pub(crate) type Journal = crate::bounded_log::BoundedLog<Spec>;

impl crate::Engine {
    /// Resolves a pool tag and member tags to the names the app shows and
    /// records one switch. A failed write is logged, never returned.
    pub(crate) fn record_member_switch(&mut self, pool_tag: &str, from_tag: &str, to_tag: &str) {
        let member_name = |tag: &str| -> String {
            if tag.is_empty() {
                return String::new();
            }
            self.store
                .library
                .profiles
                .iter()
                .find(|p| super::runtime::member_tag(pool_tag, &p.id) == tag)
                .map(|p| p.name.clone())
                .or_else(|| {
                    self.selector_rebuild
                        .former_member_name(pool_tag, tag)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| tag.to_owned())
        };
        let owner = super::runtime::owner(&self.store.library, self.running.as_deref(), pool_tag);
        let entry = Entry {
            id: 0,
            at: 0,
            pool_id: owner
                .map(|p| p.0.to_owned())
                .unwrap_or_else(|| pool_tag.to_owned()),
            pool_name: owner
                .map(|p| p.1.to_owned())
                .unwrap_or_else(|| pool_tag.to_owned()),
            from_name: member_name(from_tag),
            to_name: member_name(to_tag),
        };
        self.switch_history.record(entry);
        if self.switch_history.save(&self.data_dir).is_err() {
            self.logs.event("warn", ERROR, None);
        }
    }
    pub fn switch_history(&self) -> Value {
        self.switch_history.view()
    }
    pub fn clear_switch_history(&mut self) -> Result<(), String> {
        self.switch_history.clear_and_save(&self.data_dir)
    }
}
