//! FIFO subscription jobs. The native host owns scheduling, leases and commits;
//! the webview supplies parsed drafts using the same parser as manual imports.
use super::*;
use crate::transport::Rpc;
use std::path::PathBuf;

pub struct ValidationRequest {
    core: PathBuf,
    directory: PathBuf,
    proxy: Option<String>,
    profile: Profile,
    library: crate::store::Library,
    pub checked: usize,
    last: bool,
}
#[derive(Default)]
pub struct Validator {
    rpc: Mutex<Option<Rpc>>,
    active: Mutex<Option<(String, watch::Sender<bool>)>>,
}
impl Validator {
    pub async fn cancel(&self, id: &str) {
        let active = self.active.lock().await;
        if let Some((current, sender)) = &*active {
            if current == id {
                let _ = sender.send(true);
            }
        } else if let Ok(mut rpc) = self.rpc.try_lock() {
            rpc.take();
        }
    }
    pub async fn check(&self, id: &str, input: ValidationRequest) -> Result<(), String> {
        let (sender, mut cancelled) = watch::channel(false);
        {
            let mut active = self.active.lock().await;
            if active.is_some() {
                return Err("subscription_download_busy".into());
            }
            *active = Some((id.into(), sender));
        }
        let mut holder = self.rpc.lock().await;
        let result = tokio::select! {
            biased;
            _=cancelled.changed()=>Err("subscription_job_cancelled".into()),
            result=async {
                crate::geodata::prepare(&input.profile,&input.library,&input.directory,input.proxy.as_deref(),crate::geodata::Fetch::Download).await?;
                let request=Engine::build_with_library(&input.profile,&input.library,&input.directory)?;
                if holder.as_mut().is_none_or(|rpc|!rpc.is_alive()) {
                    *holder=Some(Rpc::spawn(&input.core,&input.directory).await?);
                }
                let rpc=holder.as_mut().unwrap();
                crate::check_config(rpc,&request).await.map_err(|(_,error)|error)
            }=>result.map_err(|_|"subscription_configuration_rejected".into()),
        };
        if result.is_err() || input.last {
            holder.take();
        }
        drop(holder);
        *self.active.lock().await = None;
        result
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub kept: usize,
    pub unchanged: usize,
    /// Rows the parser could not turn into a profile. The remaining rows are
    /// still imported, as in the Qt client; the update is never discarded.
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
    Checking,
    Updated,
    Unchanged,
    NeedsReview,
    Error,
    Cancelled,
}
impl Status {
    fn active(self) -> bool {
        matches!(self, Self::Queued | Self::Downloading | Self::Checking)
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
        counts.skipped = omitted.skipped;
        counts.warned = omitted.warned;
        let status = if omitted.any() {
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
mod worker;
pub use schedule::*;
const LEASE: Duration = Duration::from_secs(90);
fn source(group: &Group) -> Value {
    json!([group.name, group.subscription.as_ref().map(|s| &s.settings)])
}
