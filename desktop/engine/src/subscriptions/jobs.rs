//! FIFO subscription jobs. The native host owns scheduling, leases and commits;
//! the webview supplies parsed drafts using the same parser as manual imports.
use super::*;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub kept: usize,
    pub unchanged: usize,
    /// Rows the parser could not turn into a profile, and changed servers the
    /// Core rejected. The remaining rows are still imported, as in the Qt
    /// client; the update is never discarded.
    #[serde(default)]
    pub skipped: usize,
    /// Imported rows that carry untransferred parameters.
    #[serde(default)]
    pub warned: usize,
}
/// Rows the worker could not import verbatim. Counted, never silently dropped.
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Omitted {
    #[serde(default)]
    pub skipped: usize,
    #[serde(default)]
    pub warned: usize,
}
impl Omitted {
    pub fn any(self) -> bool {
        self.skipped + self.warned > 0
    }
}
impl Counts {
    fn of(changes: &[Change]) -> Self {
        let mut c = Self::default();
        for change in changes {
            match change.action.as_str() {
                "added" => c.added += 1,
                "updated" => c.updated += 1,
                "removed" => c.removed += 1,
                "kept" => c.kept += 1,
                "unchanged" => c.unchanged += 1,
                "rejected" => c.skipped += 1,
                _ => {}
            }
        }
        c
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Queued,
    Downloading,
    /// Preparing the routing lists (geosite/geoip) the changed servers need.
    Geodata,
    /// The Core checks the changed configurations; no traffic is sent.
    Checking,
    Updated,
    Unchanged,
    NeedsReview,
    Error,
    Cancelled,
}
impl Status {
    fn active(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Downloading | Self::Geodata | Self::Checking
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastUpdate {
    pub at: u64,
    pub status: Status,
    pub error: Option<String>,
    pub counts: Counts,
}
impl LastUpdate {
    /// Omitted rows keep the applied update visible for review instead of
    /// failing it: the profiles that parsed are already in the library.
    pub(super) fn of(changes: &[Change], omitted: Omitted) -> Self {
        let mut counts = Counts::of(changes);
        counts.skipped += omitted.skipped;
        counts.warned = omitted.warned;
        let status = if omitted.any() || counts.skipped > 0 {
            Status::NeedsReview
        } else if counts.added + counts.updated + counts.removed == 0 {
            Status::Unchanged
        } else {
            Status::Updated
        };
        Self {
            at: now(),
            status,
            error: None,
            counts,
        }
    }
    /// An applied update that left something out for a registered reason.
    pub(super) fn reviewed(mut self, reason: Option<&'static str>) -> Self {
        if let Some(reason) = reason {
            self.status = Status::NeedsReview;
            self.error = Some(reason.into());
        }
        self
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub batch_id: String,
    pub group_id: String,
    pub group_name: String,
    pub scheduled: bool,
    pub status: Status,
    pub checked: usize,
    pub total: usize,
    pub created_at: u64,
    pub finished_at: Option<u64>,
    pub error: Option<String>,
    pub counts: Counts,
    #[serde(skip)]
    owner: Option<String>,
    #[serde(skip)]
    touched: Instant,
    #[serde(skip)]
    ticket: Option<String>,
    #[serde(skip)]
    source: Value,
    #[serde(skip)]
    validation: Vec<String>,
    /// Provider routing failed the check; the update turns it off.
    #[serde(skip)]
    routing_failed: bool,
}
#[derive(Default)]
pub struct Queue {
    pub jobs: Vec<Job>,
    manual: HashMap<String, (String, Instant)>,
}
/// Most subscription updates waiting or running at once.
pub const MAX_JOBS: usize = 200;
impl Queue {
    pub(crate) fn busy(&self) -> bool {
        !self.manual.is_empty() || self.jobs.iter().any(|j| j.status.active())
    }
}
mod schedule;
#[cfg(test)]
mod tests;
mod validation;
mod worker;
pub use schedule::*;
pub use validation::{ValidationRequest, Validator, Verdict};
const LEASE: Duration = Duration::from_secs(90);
fn source(group: &Group) -> Value {
    json!([group.name, group.subscription.as_ref().map(|s| &s.settings)])
}
