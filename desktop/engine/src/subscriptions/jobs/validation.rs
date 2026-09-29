//! Configuration checks of an automatic update, run by the host without the
//! Engine lock. The changed servers are checked together: their assets are
//! prepared once and the Core checks one pool that holds all of them. Only a
//! failing pool is narrowed down, by halves, to the servers the Core rejects
//! on their own; those are left out of the update and counted, the rest are
//! saved. Provider routing that makes servers fail is turned off and reported
//! instead of blocking the update.
use super::*;
use crate::geodata::{self, Fetch};
use crate::proto::LoadConfigReq;
use crate::store::{Library, Profile, ProfileKind};
use crate::transport::Rpc;
use std::future::Future;
use std::path::PathBuf;

/// Id of the pool a check builds; it never exists in the library.
const POOL_ID: &str = "thronium-subscription-check";

pub struct ValidationRequest {
    core: PathBuf,
    directory: PathBuf,
    proxy: Option<String>,
    /// The library as the update would leave it: new metadata, new profiles.
    library: Library,
    group_id: String,
    /// The added and updated servers, in subscription order.
    candidates: Vec<Profile>,
}
impl ValidationRequest {
    pub(super) fn new(
        engine: &Engine,
        library: Library,
        group_id: String,
        candidates: Vec<Profile>,
    ) -> Result<Self, String> {
        Ok(Self {
            core: engine.core.clone(),
            directory: engine.data_dir.clone(),
            proxy: engine.settings_download_proxy()?,
            library,
            group_id,
            candidates,
        })
    }
    fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }
}

/// What a check decided. Rejected servers keep their saved version or are not
/// added, and are counted as skipped; nothing is dropped silently.
#[derive(Debug, Default, PartialEq)]
pub struct Verdict {
    pub rejected: Vec<String>,
    pub routing_failed: bool,
}

/// The Core check of one built request. The outer error stops the whole
/// update (no Core); the inner one rejects the request.
pub(crate) trait Checker {
    async fn check(&mut self, request: &LoadConfigReq) -> Result<Result<(), String>, String>;
}
/// One disposable Core for the whole update, restarted if it exits.
struct CoreChecker<'a> {
    core: &'a std::path::Path,
    directory: &'a std::path::Path,
    rpc: Option<Rpc>,
}
impl Checker for CoreChecker<'_> {
    async fn check(&mut self, request: &LoadConfigReq) -> Result<Result<(), String>, String> {
        if self.rpc.as_mut().is_none_or(|rpc| !rpc.is_alive()) {
            self.rpc = Some(Rpc::spawn(self.core, self.directory).await?);
        }
        let rpc = self.rpc.as_mut().unwrap();
        Ok(crate::check_config(rpc, request)
            .await
            .map_err(|_| "subscription_configuration_rejected".to_string()))
    }
}

#[derive(Default)]
pub struct Validator {
    active: Mutex<Option<(String, watch::Sender<bool>)>>,
}
impl Validator {
    pub async fn cancel(&self, id: &str) {
        if let Some((current, sender)) = &*self.active.lock().await {
            if current == id {
                let _ = sender.send(true);
            }
        }
    }
    /// Checks the update. `stage` is told when asset preparation and the Core
    /// check begin, so the job shows what it is waiting for.
    pub async fn check<F: Future<Output = ()>>(
        &self,
        id: &str,
        input: ValidationRequest,
        stage: impl FnMut(Status) -> F,
    ) -> Result<Verdict, String> {
        let (sender, mut cancelled) = watch::channel(false);
        {
            let mut active = self.active.lock().await;
            if active.is_some() {
                return Err("subscription_download_busy".into());
            }
            *active = Some((id.into(), sender));
        }
        let mut core = CoreChecker {
            core: &input.core,
            directory: &input.directory,
            rpc: None,
        };
        let result = tokio::select! {
            biased;
            _ = cancelled.changed() => Err("subscription_job_cancelled".into()),
            result = run(&input, &mut core, stage) => result,
        };
        drop(core);
        *self.active.lock().await = None;
        // Raw details stay here; a stage that failed keeps its own code.
        result.map_err(|error| {
            crate::ipc::registered(&error)
                .unwrap_or("subscription_update_failed")
                .into()
        })
    }
}

/// Servers one pass rejected, and the first error it met.
#[derive(Default)]
struct Pass {
    rejected: Vec<String>,
    cause: Option<String>,
}
impl Pass {
    fn reject(&mut self, id: &str, error: String) {
        self.rejected.push(id.into());
        self.cause.get_or_insert(error);
    }
}

pub(crate) async fn run<C: Checker, F: Future<Output = ()>>(
    input: &ValidationRequest,
    checker: &mut C,
    mut stage: impl FnMut(Status) -> F,
) -> Result<Verdict, String> {
    let mut pass = check_pass(input, &input.library, checker, &mut stage).await?;
    let mut routing_failed = false;
    if !pass.rejected.is_empty()
        && input
            .candidates
            .iter()
            .any(|p| geodata::enabled(p, &input.library))
    {
        // Provider routing is blamed only when the group does better without it.
        let mut library = input.library.clone();
        if let Some(s) = library
            .groups
            .iter_mut()
            .find(|g| g.id == input.group_id)
            .and_then(|g| g.subscription.as_mut())
        {
            s.settings.use_provider_routing = false;
        }
        let fallback = check_pass(input, &library, checker, &mut stage).await?;
        if fallback.rejected.len() < pass.rejected.len() {
            pass = fallback;
            routing_failed = true;
        }
    }
    if pass.rejected.len() == input.candidates.len() {
        // Nothing would change but removals: fail and keep the saved profiles.
        return Err(pass
            .cause
            .unwrap_or_else(|| "subscription_configuration_rejected".into()));
    }
    Ok(Verdict {
        rejected: pass.rejected,
        routing_failed,
    })
}

async fn check_pass<C: Checker, F: Future<Output = ()>>(
    input: &ValidationRequest,
    library: &Library,
    checker: &mut C,
    stage: &mut impl FnMut(Status) -> F,
) -> Result<Pass, String> {
    stage(Status::Geodata).await;
    let mut pass = Pass::default();
    let stub = pool(input, &[]);
    let (pooled, single): (Vec<_>, Vec<_>) = input
        .candidates
        .iter()
        .partition(|p| pooled(library, &stub, p));
    // A failed download is attempted once; later servers use what is cached.
    let mut fetch = Fetch::Download;
    let mut ready = vec![];
    for chunk in pooled.chunks(crate::auto_selector::MAX_MEMBERS) {
        // Pool members share their assets: the routing lists of the group.
        let pool = pool(input, chunk);
        match geodata::prepare(&pool, library, &input.directory, input.proxy(), fetch).await {
            Ok(()) => ready.extend(chunk.iter().copied()),
            Err(error) => {
                if error.starts_with("geodata_") {
                    fetch = Fetch::Cached { stale: true };
                    pass.cause.get_or_insert(error);
                }
                ready.extend(prepare_each(input, library, chunk, &mut fetch, &mut pass).await);
            }
        }
    }
    let single = prepare_each(input, library, &single, &mut fetch, &mut pass).await;
    stage(Status::Checking).await;
    for chunk in ready.chunks(crate::auto_selector::MAX_MEMBERS) {
        narrow(input, library, chunk, checker, &mut pass).await?;
    }
    for profile in single {
        if let Err(error) = check_one(input, library, profile, checker).await? {
            pass.reject(&profile.id, error);
        }
    }
    Ok(pass)
}

/// Checks `set` as one pool; a rejected pool is split until each rejected
/// server was checked alone, exactly as it would start.
async fn narrow<C: Checker>(
    input: &ValidationRequest,
    library: &Library,
    set: &[&Profile],
    checker: &mut C,
    pass: &mut Pass,
) -> Result<(), String> {
    let mut pending = vec![set.to_vec()];
    while let Some(set) = pending.pop() {
        if let [profile] = set[..] {
            if let Err(error) = check_one(input, library, profile, checker).await? {
                pass.reject(&profile.id, error);
            }
            continue;
        }
        let pool = pool(input, &set);
        let accepted = match Engine::build_with_library(&pool, library, &input.directory) {
            Ok(request) => checker.check(&request).await?.is_ok(),
            Err(_) => false,
        };
        if !accepted {
            let (first, second) = set.split_at(set.len() / 2);
            pending.push(second.to_vec());
            pending.push(first.to_vec());
        }
    }
    Ok(())
}

async fn check_one<C: Checker>(
    input: &ValidationRequest,
    library: &Library,
    profile: &Profile,
    checker: &mut C,
) -> Result<Result<(), String>, String> {
    match Engine::build_with_library(profile, library, &input.directory) {
        Ok(request) => checker.check(&request).await,
        Err(error) => Ok(Err(error)),
    }
}

async fn prepare_each<'a>(
    input: &ValidationRequest,
    library: &Library,
    profiles: &[&'a Profile],
    fetch: &mut Fetch,
    pass: &mut Pass,
) -> Vec<&'a Profile> {
    let mut ready = vec![];
    for profile in profiles {
        match geodata::prepare(profile, library, &input.directory, input.proxy(), *fetch).await {
            Ok(()) => ready.push(*profile),
            Err(error) => {
                if error.starts_with("geodata_") {
                    *fetch = Fetch::Cached { stale: true };
                }
                pass.reject(&profile.id, error);
            }
        }
    }
    ready
}

/// A pool of the group's servers, built like one the user saves in the group.
fn pool(input: &ValidationRequest, members: &[&Profile]) -> Profile {
    let mut config = crate::auto_selector::default_pool_config();
    config["members"] = json!(members.iter().map(|p| &p.id).collect::<Vec<_>>());
    Profile {
        vpn_policy: None,
        id: POOL_ID.into(),
        name: POOL_ID.into(),
        group_id: input.group_id.clone(),
        favorite: false,
        kind: ProfileKind::AutoSelector,
        config,
    }
}

/// Single outbounds a pool can hold on the route the group gives them. Full
/// configurations, VPN endpoints and the like are checked alone.
fn pooled(library: &Library, pool: &Profile, profile: &Profile) -> bool {
    matches!(
        profile.kind,
        ProfileKind::SingBoxOutbound | ProfileKind::XrayOutbound
    ) && crate::auto_selector::member_route_eligible(library, pool, profile)
}

impl Engine {
    /// Everything the host needs to check the changed servers without the
    /// Engine lock: the library as the update would leave it.
    pub fn subscription_job_check_request(
        &mut self,
        id: &str,
        owner: &str,
    ) -> Result<ValidationRequest, String> {
        let i = self.job_index(id, owner)?;
        let job = &self.subscription_jobs.jobs[i];
        if job.status != Status::Geodata || job.checked != 0 || job.total == 0 {
            return Err("subscription_job_state".into());
        }
        let token = job.ticket.as_ref().ok_or("subscription_expired")?;
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.stamp != self.subscription_stamp(&job.group_id)? {
            return Err("subscription_changed".into());
        }
        let plan = ticket
            .plan
            .as_ref()
            .ok_or("subscription_invalid_profiles")?;
        let candidates: Vec<_> = job
            .validation
            .iter()
            .map(|id| plan.profiles.iter().find(|p| p.id == *id).cloned())
            .collect::<Option<_>>()
            .ok_or("subscription_invalid_profiles")?;
        let mut library = self.store.library.clone();
        library.profiles.retain(|p| p.group_id != ticket.group_id);
        library.profiles.extend(plan.profiles.iter().cloned());
        library
            .groups
            .iter_mut()
            .find(|g| g.id == ticket.group_id)
            .ok_or("group_not_found")?
            .subscription
            .as_mut()
            .ok_or("subscription_missing")?
            .metadata = ticket.metadata.clone();
        let request = ValidationRequest::new(self, library, ticket.group_id.clone(), candidates)?;
        self.keep_job_alive(i);
        Ok(request)
    }
    /// The host reports which stage of the check runs: routing lists or the Core.
    pub fn subscription_job_stage(
        &mut self,
        id: &str,
        owner: &str,
        status: Status,
    ) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        let job = &mut self.subscription_jobs.jobs[i];
        let checking = |s: Status| matches!(s, Status::Geodata | Status::Checking);
        if !checking(job.status) || !checking(status) || job.checked != 0 {
            return Err("subscription_job_state".into());
        }
        job.status = status;
        self.keep_job_alive(i);
        Ok(())
    }
    /// Records the check: rejected servers leave the plan, provider routing
    /// that failed is turned off when the update is applied.
    pub fn subscription_job_checked(
        &mut self,
        id: &str,
        owner: &str,
        verdict: Verdict,
    ) -> Result<(), String> {
        let i = self.job_index(id, owner)?;
        let job = &self.subscription_jobs.jobs[i];
        if !matches!(job.status, Status::Geodata | Status::Checking)
            || job.checked != 0
            || verdict
                .rejected
                .iter()
                .any(|id| !job.validation.contains(id))
            || verdict.rejected.len() >= job.total
        {
            return Err("subscription_job_state".into());
        }
        let token = job.ticket.clone().ok_or("subscription_expired")?;
        let ticket = self
            .subscription_tickets
            .get_mut(&token)
            .ok_or("subscription_expired")?;
        let plan = ticket
            .plan
            .as_mut()
            .ok_or("subscription_invalid_profiles")?;
        plan.reject(&verdict.rejected, &self.store.library.profiles);
        ticket.review = if verdict.routing_failed {
            Some("subscription_provider_routing_failed")
        } else if !verdict.rejected.is_empty() {
            Some("subscription_profiles_rejected")
        } else {
            None
        };
        let job = &mut self.subscription_jobs.jobs[i];
        job.routing_failed = verdict.routing_failed;
        job.checked = job.total;
        job.status = Status::Checking;
        self.keep_job_alive(i);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) async fn check_subscription_job(
        &mut self,
        id: &str,
        owner: &str,
    ) -> Result<(), String> {
        let request = self.subscription_job_check_request(id, owner)?;
        let verdict = Validator::default()
            .check(id, request, |_| std::future::ready(()))
            .await?;
        self.subscription_job_checked(id, owner, verdict)
    }
}

impl Plan {
    /// Leaves servers the Core rejected out of the update: a new server is not
    /// added and an updated one keeps its saved version. Both count as skipped.
    fn reject(&mut self, ids: &[String], saved: &[Profile]) {
        for change in self.changes.iter_mut().filter(|c| ids.contains(&c.id)) {
            let previous = saved.iter().find(|p| p.id == change.id);
            match (change.action.as_str(), previous) {
                ("updated", Some(previous)) => {
                    if let Some(p) = self.profiles.iter_mut().find(|p| p.id == change.id) {
                        *p = previous.clone();
                    }
                }
                ("added" | "updated", _) => {
                    self.profiles.retain(|p| p.id != change.id);
                    self.managed_ids.retain(|id| *id != change.id);
                }
                _ => continue,
            }
            change.action = "rejected".into();
        }
    }
}
