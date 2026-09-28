//! Read existing Core health only for the exact opted-in running request.
use crate::{
    latency_measurements::{self, Cache, CoreContext},
    proto,
    store::{Library, Profile, ProfileKind},
    Engine,
};
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn request_hash(request: &proto::LoadConfigReq) -> [u8; 32] {
    Sha256::digest(request.encode_to_vec()).into()
}
fn owner_hash(library: &Library, profile: &Profile) -> [u8; 32] {
    Sha256::digest(
        json!([
            profile.kind,
            profile.group_id,
            profile.config,
            crate::group_chains::policy(library, profile)
        ])
        .to_string()
        .as_bytes(),
    )
    .into()
}
#[derive(Clone)]
struct Member {
    id: String,
    context: CoreContext,
    supplied_warm: bool,
    last_probe_ms: u64,
}
#[derive(Clone)]
struct Group {
    owner: String,
    owner_hash: [u8; 32],
    members: BTreeMap<String, Member>,
}
#[derive(Clone, Default)]
pub(crate) struct State {
    request: Option<[u8; 32]>,
    groups: BTreeMap<String, Group>,
    captured_at_ms: u64,
    ignore_before_ms: u64,
    last_poll: Option<Instant>,
    read_failed: bool,
    write_failed: bool,
    /// The member tag each pool tag last had selected, to notice a switch and
    /// to measure a running pool through the member that carries traffic.
    pub(crate) last_selected: BTreeMap<String, String>,
    /// Every pool tag of the running request, polled for its selection even
    /// when no pool persists health.
    pub(super) pools: BTreeSet<String>,
}
impl State {
    pub(crate) fn capture(
        library: &Library,
        selected: &str,
        request: &proto::LoadConfigReq,
    ) -> Self {
        let Ok(core) = serde_json::from_str::<Value>(request.core_config.as_deref().unwrap_or(""))
        else {
            return Self::default();
        };
        // A missing or complete user configuration has no Thronium pools.
        if library
            .profiles
            .iter()
            .find(|p| p.id == selected)
            .is_none_or(|p| matches!(p.kind, ProfileKind::SingBoxConfig | ProfileKind::XrayConfig))
        {
            return Self::default();
        }
        let mut state = Self {
            captured_at_ms: now_ms(),
            ..Default::default()
        };
        for super::runtime::CompiledPool {
            tag,
            group,
            owner,
            owner_id: id,
        } in super::runtime::compiled_pools(library, selected, &core)
        {
            state.pools.insert(tag.into());
            let Some(owner) = owner.filter(|p| p.config["member_source"]["persist_health"] == true)
            else {
                continue;
            };
            let link = group["url"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(crate::probes::DEFAULT_TEST_URL);
            // Core does not trim its URL. Do not attribute a malformed Core URL
            // to a valid normalized manual-test URL.
            if link != link.trim() {
                continue;
            }
            let prefix = super::runtime::member_tag(tag, "");
            let mut members = BTreeMap::new();
            for member_tag in group["outbounds"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let Some(id) = member_tag.strip_prefix(&prefix) else {
                    continue;
                };
                let Some(member) = library
                    .profiles
                    .iter()
                    .find(|p| p.id == id && super::member_kind(p.kind))
                else {
                    continue;
                };
                if crate::group_chains::policy(library, owner)
                    != crate::group_chains::policy(library, member)
                {
                    continue;
                }
                let Some(context) = latency_measurements::core_context(library, id, link) else {
                    continue;
                };
                let supplied_warm = group["warm"]
                    .as_array()
                    .is_some_and(|entries| entries.iter().any(|e| e["tag"] == member_tag));
                members.insert(
                    member_tag.into(),
                    Member {
                        id: id.into(),
                        context,
                        supplied_warm,
                        last_probe_ms: 0,
                    },
                );
            }
            if !members.is_empty() {
                state.groups.insert(
                    tag.into(),
                    Group {
                        owner: id.into(),
                        owner_hash: owner_hash(library, owner),
                        members,
                    },
                );
            }
        }
        if !state.groups.is_empty() {
            state.request = Some(request_hash(request));
        }
        state
    }
    pub(crate) fn clear_before(&mut self, at_ms: u64) {
        self.ignore_before_ms = self.ignore_before_ms.max(at_ms);
    }
    fn take(
        &mut self,
        library: &Library,
        reply: proto::QueryAutoSelectorsResponse,
        at_ms: u64,
    ) -> Option<Cache> {
        let mut cache = library.latency_measurements.clone();
        cache.prune(library);
        let mut changed = false;
        for group in reply.groups {
            if group.suspended != Some(false)
                || group.rounds_completed.unwrap_or(0) <= 0
                || !matches!(group.phase.as_deref(), Some("ready" | "probing"))
            {
                continue;
            }
            let Some(scope) = self.groups.get_mut(group.tag.as_deref().unwrap_or("")) else {
                continue;
            };
            let Some(owner) = library.profiles.iter().find(|p| p.id == scope.owner) else {
                continue;
            };
            if owner_hash(library, owner) != scope.owner_hash {
                continue;
            }
            for member in group.members {
                let Some(target) = scope.members.get_mut(member.tag.as_deref().unwrap_or(""))
                else {
                    continue;
                };
                // Supplied warm may itself count as a probe. Requiring an extra
                // probe is conservative when Core discarded an expired hint.
                if member.probes.unwrap_or(0) <= i32::from(target.supplied_warm)
                    || member.samples.unwrap_or(0) <= 0
                {
                    continue;
                }
                let Ok(probe_ms) = u64::try_from(member.last_probe_ms.unwrap_or(0)) else {
                    continue;
                };
                if probe_ms <= self.captured_at_ms
                    || probe_ms <= self.ignore_before_ms
                    || probe_ms <= target.last_probe_ms
                    || probe_ms > at_ms
                {
                    continue;
                }
                let value = match member.state.as_deref() {
                    Some("ok" | "degraded") => match member.average_ms.filter(|v| *v >= 0) {
                        Some(ms) => Some(ms),
                        None => continue,
                    },
                    Some("dead") => None,
                    _ => continue,
                };
                if cache
                    .record_core(library, &target.id, &target.context, value, probe_ms)
                    .is_some()
                {
                    changed = true;
                }
                target.last_probe_ms = probe_ms;
            }
        }
        changed.then_some(cache)
    }
}
impl Engine {
    pub(crate) async fn collect_selector_health(&mut self) {
        if self.running.is_none() || self.tun_reconnecting || self.recovery.pending() {
            return;
        }
        let Some(active) = &self.active_connection else {
            return;
        };
        // Health persistence needs the exact opted-in request and captured
        // groups; switch history only needs a running pool. Poll for either.
        let health_ready = !self.selector_health.groups.is_empty()
            && self.selector_health.request == Some(request_hash(&active.request));
        let main_pool = self
            .running
            .as_deref()
            .and_then(|id| self.profile(id).ok())
            .is_some_and(|p| p.kind == ProfileKind::AutoSelector);
        if !health_ready && !main_pool && self.selector_health.pools.is_empty() {
            return;
        }
        if self
            .selector_health
            .last_poll
            .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
        {
            return;
        }
        self.selector_health.last_poll = Some(Instant::now());
        let Some(rpc) = &mut self.rpc else { return };
        let reply = match rpc
            .call::<_, proto::QueryAutoSelectorsResponse>("QueryAutoSelectors", proto::EmptyReq {})
            .await
        {
            Ok(reply) => {
                self.selector_health.read_failed = false;
                reply
            }
            Err(_) => {
                if !self.selector_health.read_failed {
                    self.logs.event("warn", "selector_health_read_failed", None);
                }
                self.selector_health.read_failed = true;
                return;
            }
        };
        self.accept_selector_health(reply, health_ready);
    }
    fn accept_selector_health(
        &mut self,
        reply: proto::QueryAutoSelectorsResponse,
        health_ready: bool,
    ) {
        self.observe_quick_selection(&reply);
        // Member selection and switch history do not depend on the latency
        // cache: a failed cache write must not drop or repeat a switch.
        for (pool_tag, from_tag, to_tag) in self.selector_health.detect_switches(&reply) {
            self.record_member_switch(&pool_tag, &from_tag, &to_tag);
        }
        if !health_ready {
            return;
        }
        let mut state = self.selector_health.clone();
        if let Some(cache) = state.take(&self.store.library, reply, now_ms()) {
            if self.store.save_latency_measurements(cache).is_err() {
                if !self.selector_health.write_failed {
                    self.logs.event("warn", "latency_cache_write_failed", None);
                }
                // Observations stay unconsumed so the same real probe is retried.
                self.selector_health.write_failed = true;
                return;
            }
            state.write_failed = false;
        }
        self.selector_health = state;
    }
}
impl State {
    /// Compares each pool's selected member against the last one seen and
    /// returns the switches, updating the remembered selection. The pool's
    /// first non-empty selection is reported with an empty origin.
    fn detect_switches(
        &mut self,
        reply: &proto::QueryAutoSelectorsResponse,
    ) -> Vec<(String, String, String)> {
        let mut switches = Vec::new();
        for group in &reply.groups {
            let Some(tag) = group.tag.as_deref().filter(|t| !t.is_empty()) else {
                continue;
            };
            let selected = group.selected.clone().unwrap_or_default();
            if selected.is_empty() {
                continue;
            }
            if self.last_selected.get(tag).map(String::as_str) != Some(selected.as_str()) {
                let from = self.last_selected.insert(tag.to_owned(), selected.clone());
                switches.push((tag.to_owned(), from.unwrap_or_default(), selected));
            }
        }
        switches
    }
}
#[cfg(test)]
mod tests;
