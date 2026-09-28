//! Bounded journal of measurement runs: what was measured, through which path
//! and pool member, with which outcome. It keeps result values and error codes
//! only — never URLs, credentials, keys or response bodies — and forgets entries
//! by count, size and age. Latency, IP and speed runs, manual or periodic, share
//! it with the direct internet check; membership and traffic histories stay
//! separate models.
use super::{Kind, Measurement, Status};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const FILE: &str = "measurement-journal-v1.json";
const ERROR: &str = "measurement_journal_write_failed";
const MAX_ENTRIES: usize = 500;
const MAX_BYTES: u64 = 1024 * 1024;
const RETENTION_SECS: u64 = 7 * 24 * 3600;
const MAX_TEXT: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub at: u64,
    /// `latency`, `ip`, `speed` or `internet`.
    pub kind: String,
    /// `single` for the diagnostics dialog, `batch` for the queue.
    pub source: String,
    pub profile_id: String,
    pub profile_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_origin: Option<crate::auto_selector::MemberOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<String>,
    /// An error code, never free text from a core or a service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Entry {
    /// A finished batch row, as the queue leaves it.
    pub(crate) fn from_measurement(m: &Measurement, source: super::Source) -> Self {
        Self {
            id: 0,
            at: 0,
            kind: kind_name(m.kind).into(),
            source: match source {
                super::Source::Manual => "batch",
                super::Source::Periodic => "periodic",
                super::Source::AutoSelect => "auto-select",
            }
            .into(),
            profile_id: m.profile_id.clone(),
            profile_name: m.name.clone(),
            member_id: m.member_id.clone(),
            member_name: m.member_name.clone(),
            member_origin: m.member_origin,
            transport: m.transport.clone(),
            status: status_name(m.status).into(),
            latency_ms: m.latency_ms,
            ip: m.ip.clone(),
            country_code: m.country_code.clone(),
            download: m.download.clone(),
            upload: m.upload.clone(),
            error: m.error.clone(),
        }
    }
    fn valid(&self, now: u64) -> bool {
        let text = |s: &str| !s.is_empty() && s.len() <= MAX_TEXT;
        let code = |s: Option<&str>| {
            s.is_none_or(|s| {
                text(s)
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'-')
            })
        };
        self.at > 0
            && self.at <= now.saturating_add(300)
            && matches!(self.kind.as_str(), "latency" | "ip" | "speed" | "internet")
            && matches!(
                self.source.as_str(),
                "single" | "batch" | "periodic" | "auto-select"
            )
            && text(&self.profile_id)
            && self.profile_name.len() <= MAX_TEXT
            && code(Some(&self.status))
            && code(self.error.as_deref())
            && [
                &self.member_id,
                &self.member_name,
                &self.transport,
                &self.ip,
                &self.country_code,
                &self.download,
                &self.upload,
            ]
            .iter()
            .all(|v| v.as_ref().is_none_or(|s| s.len() <= MAX_TEXT))
    }
}

pub(crate) fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Latency => "latency",
        Kind::Ip => "ip",
        Kind::Speed => "speed",
    }
}
fn status_name(status: Status) -> &'static str {
    match status {
        Status::Queued => "queued",
        Status::Testing => "testing",
        Status::Ok => "ok",
        Status::Error => "error",
        Status::Cancelled => "cancelled",
        Status::Stale => "stale",
        Status::Unsupported => "unsupported",
        Status::ConnectedOnly => "connected-only",
        Status::AuthRequired => "auth-required",
    }
}
/// The measurement journal is a bounded on-device log of finished runs.
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
    /// The error is reduced to a known code here, whatever the caller passed.
    fn stamp(&mut self, id: u64, at: u64) {
        self.id = id;
        self.at = at;
        self.error = self.error.take().map(super::execute::safe_error);
    }
    fn valid(&self, now: u64) -> bool {
        self.valid(now)
    }
}
pub(crate) type Journal = crate::bounded_log::BoundedLog<Spec>;

impl crate::Engine {
    /// Records a run and persists the journal; a failed write is reported in the app log, never to the caller.
    pub fn record_measurement(&mut self, entry: Entry) {
        self.measurement_journal.record(entry);
        if self.measurement_journal.save(&self.data_dir).is_err() {
            self.logs.event("warn", ERROR, None);
        }
    }
    pub fn measurement_journal(&self) -> Value {
        self.measurement_journal.view()
    }
    pub fn clear_measurement_journal(&mut self) -> Result<(), String> {
        self.measurement_journal.clear_and_save(&self.data_dir)
    }
}
