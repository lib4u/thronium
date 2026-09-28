//! Opt-in rebuilding of the exact exhausted running selector request.
mod monitor;
mod observation;
mod subscription;
use super::ConnectionMeasurements;
use crate::{
    proto,
    store::{Library, ProfileKind},
    Engine,
};
use monitor::{Monitor, Observation};
pub use monitor::{
    FIRST_RETRY_MS as RECHECK_FIRST_RETRY_MS, GRACE_MS as RECHECK_GRACE_MS,
    MAX_ATTEMPTS as RECHECK_ATTEMPTS,
};
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

fn request_hash(request: &proto::LoadConfigReq) -> [u8; 32] {
    Sha256::digest(request.encode_to_vec()).into()
}
// Saving subscription controls materializes their defaults in Library.settings.
// They govern future downloads/reconciliation, not the active connection. Keep
// other and unknown settings in the guard; route/owner/request guards stay exact.
fn connection_settings(library: &Library) -> BTreeMap<&str, &Value> {
    let subscription_fields: BTreeSet<_> = crate::settings::fields()
        .iter()
        .filter(|f| f.section == "subscriptions")
        .map(|f| f.id.as_str())
        .collect();
    library
        .settings
        .iter()
        .filter(|(id, _)| !subscription_fields.contains(id.as_str()))
        .map(|(id, value)| (id.as_str(), value))
        .collect()
}
fn context(library: &Library, id: &str) -> Option<Value> {
    let selected = library.profiles.iter().find(|p| p.id == id)?;
    let roots = crate::vless::roots(library, selected).ok()?;
    let mut owners = library
        .profiles
        .iter()
        .filter(|p| roots.contains(&p.id))
        .collect::<Vec<_>>();
    owners.sort_by(|a, b| a.id.cmp(&b.id));
    Some(json!([
        owners
            .into_iter()
            .map(|p| json!([
                p.id,
                p.kind,
                p.group_id,
                p.config,
                p.vpn_policy,
                crate::group_chains::policy(library, p),
                crate::geodata::enabled(p, library),
                crate::geodata::provider(p, library)
            ]))
            .collect::<Vec<_>>(),
        library.routing,
        connection_settings(library),
        library.preferences.connection_mode,
        library.preferences.inbound_port,
        library.preferences.tun,
        library.preferences.vless_core,
        library.preferences.vless_overrides
    ]))
}
#[derive(Clone)]
struct Pool {
    id: String,
    members: BTreeMap<String, String>,
    monitor: Monitor,
    on_exhaustion: bool,
    on_subscription: bool,
    applied: BTreeMap<String, String>,
    names: BTreeMap<String, String>,
    subscription: subscription::Pending,
}
#[derive(Clone)]
pub(crate) struct State {
    generation: String,
    request: Option<[u8; 32]>,
    context: Option<Value>,
    id: String,
    pools: BTreeMap<String, Pool>,
    origin: Instant,
    read_failed: bool,
    claimed: Option<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            generation: uuid::Uuid::new_v4().to_string(),
            request: None,
            context: None,
            id: String::new(),
            pools: BTreeMap::new(),
            origin: Instant::now(),
            read_failed: false,
            claimed: None,
        }
    }
}
/// Created from an owned running generation; never accepted from serialized IPC.
pub struct Ticket {
    pub id: String,
    generation: String,
    token: String,
    groups: Vec<String>,
    subscription_versions: BTreeMap<String, String>,
}
impl State {
    pub(crate) fn capture(library: &Library, id: &str, request: &proto::LoadConfigReq) -> Self {
        let mut state = Self::default();
        let Some(profile) = library.profiles.iter().find(|p| p.id == id) else {
            return state;
        };
        if matches!(
            profile.kind,
            ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
        ) {
            return state;
        }
        let Ok(core) = serde_json::from_str::<Value>(request.core_config.as_deref().unwrap_or(""))
        else {
            return state;
        };
        for pool in super::runtime::compiled_pools(library, id, &core) {
            let (tag, outbound) = (pool.tag, pool.group);
            let Some(owner) = pool.owner else {
                continue;
            };
            let preflight = owner.config["member_source"]["measure_before_connect"] == true;
            let on_exhaustion =
                preflight && owner.config["member_source"]["rebuild_on_exhaustion"] == true;
            let on_subscription =
                preflight && owner.config["member_source"]["rebuild_on_subscription"] == true;
            let prefix = super::runtime::member_tag(tag, "");
            let mut members: BTreeMap<String, String> = BTreeMap::new();
            let Some(tags) = outbound["outbounds"].as_array() else {
                continue;
            };
            for member in tags {
                let Some(tag) = member.as_str() else { continue };
                if let Some(id) = tag
                    .strip_prefix(&prefix)
                    .filter(|id| library.profiles.iter().any(|p| p.id == *id))
                {
                    members.insert(tag.into(), id.into());
                }
            }
            if !members.is_empty() && members.len() == tags.len() {
                let applied = members
                    .values()
                    .filter_map(|id| {
                        subscription::member_signature(library, id)
                            .map(|signature| (id.clone(), signature))
                    })
                    .collect();
                let names = members
                    .iter()
                    .filter_map(|(tag, id)| {
                        library
                            .profiles
                            .iter()
                            .find(|p| &p.id == id)
                            .map(|p| (tag.clone(), p.name.clone()))
                    })
                    .collect();
                state.pools.insert(
                    tag.into(),
                    Pool {
                        id: owner.id.clone(),
                        members,
                        monitor: Monitor::default(),
                        on_exhaustion,
                        on_subscription,
                        applied,
                        names,
                        subscription: Default::default(),
                    },
                );
            }
        }
        if !state.pools.is_empty() {
            state.id = id.into();
            state.request = Some(request_hash(request));
            state.context = context(library, id);
        }
        state
    }
    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn unknown(&mut self) {
        let now = self.now();
        for pool in self.pools.values_mut() {
            pool.monitor.observe(now, Observation::Unknown);
        }
    }
    pub(crate) fn status(&self, tag: &str) -> Value {
        self.pools
            .get(tag)
            .filter(|p| p.on_exhaustion)
            .map(|p| {
                json!({"attempts":p.monitor.attempts,"limit":monitor::MAX_ATTEMPTS,
            "paused":p.monitor.cancelled || p.monitor.attempts>=monitor::MAX_ATTEMPTS})
            })
            .unwrap_or(Value::Null)
    }
}
impl Engine {
    fn selector_rebuild_scope_current(&self) -> bool {
        self.running.as_deref() == Some(self.selector_rebuild.id.as_str())
            && self.store.library.selected.as_ref() == self.running.as_ref()
            && self.active_connection.as_ref().is_some_and(|active| {
                self.selector_rebuild.request == Some(request_hash(&active.request))
            })
            && self.selector_rebuild.context
                == context(&self.store.library, &self.selector_rebuild.id)
            && self.routing_revision == Some(self.store.library.routing.revision)
            && !self.tun_reconnecting
            && !self.recovery.pending()
    }
    pub fn selector_rebuild_current(&self, ticket: &Ticket) -> bool {
        ticket.generation == self.selector_rebuild.generation
            && ticket.id == self.selector_rebuild.id
            && self
                .selector_rebuild
                .claimed
                .as_ref()
                .is_none_or(|token| token == &ticket.token)
            && self.selector_rebuild_scope_current()
            && ticket.groups.iter().all(|tag| {
                self.selector_rebuild.pools.get(tag).is_some_and(|p| {
                    if let Some(version) = ticket.subscription_versions.get(tag) {
                        p.on_subscription
                            && p.subscription.pending
                            && !p.subscription.cancelled
                            && &p.subscription.version == version
                    } else {
                        p.on_exhaustion && !p.monitor.cancelled
                    }
                })
            })
    }
    /// Called by the background scheduler, never depends on window polling.
    pub async fn selector_rebuild_tick(&mut self) -> Option<Ticket> {
        if !self
            .selector_rebuild
            .pools
            .values()
            .any(|p| p.on_exhaustion || p.on_subscription && p.subscription.pending)
            || self.selector_rebuild.claimed.is_some()
        {
            return None;
        }
        if !self.selector_rebuild_scope_current() {
            self.selector_rebuild.unknown();
            return None;
        }
        if !self.probe_queue_free() {
            self.selector_rebuild.unknown();
            return None;
        }
        if self
            .selector_rebuild
            .pools
            .values()
            .any(|p| p.on_subscription && p.subscription.pending)
        {
            // A single Core request is replaced as a whole. Never apply another
            // pool's pending update indirectly while it is cancelled or backing off.
            let ticket = self.subscription_rebuild_ticket()?;
            if !self.selector_rebuild_interface_available().await {
                return None;
            }
            return Some(ticket);
        }
        let reply = self
            .rpc
            .as_mut()?
            .call::<_, proto::QueryAutoSelectorsResponse>("QueryAutoSelectors", proto::EmptyReq {})
            .await;
        let reply = match reply {
            Ok(r) => {
                self.selector_rebuild.read_failed = false;
                r
            }
            Err(_) => {
                if !self.selector_rebuild.read_failed {
                    self.logs
                        .event("warn", "selector_rebuild_health_unreadable", None);
                }
                self.selector_rebuild.read_failed = true;
                self.selector_rebuild.unknown();
                return None;
            }
        };
        let now = self.selector_rebuild.now();
        let mut groups = Vec::new();
        for (tag, pool) in &mut self.selector_rebuild.pools {
            if !pool.on_exhaustion {
                continue;
            }
            let mut matches = reply
                .groups
                .iter()
                .filter(|g| g.tag.as_deref() == Some(tag));
            let group = matches.next();
            let observation = if matches.next().is_some() {
                Observation::Unknown
            } else {
                observation::classify(
                    &pool.members.keys().cloned().collect::<BTreeSet<_>>(),
                    group,
                )
            };
            if pool.monitor.observe(now, observation) {
                groups.push(tag.clone());
            }
        }
        if groups.is_empty() {
            return None;
        }
        if !self.selector_rebuild_interface_available().await {
            self.selector_rebuild.unknown();
            return None;
        }
        Some(Ticket {
            id: self.selector_rebuild.id.clone(),
            generation: self.selector_rebuild.generation.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            groups,
            subscription_versions: BTreeMap::new(),
        })
    }
    async fn selector_rebuild_interface_available(&mut self) -> bool {
        let Some(rpc) = self.rpc.as_mut() else {
            return false;
        };
        rpc.call::<_, proto::GetDefaultInterfaceResponse>("GetDefaultInterface", proto::EmptyReq {})
            .await
            .is_ok_and(|r| r.name.is_some_and(|name| !name.is_empty()) && r.index.unwrap_or(0) > 0)
    }
    /// Claim only after the app coordinator is available. No cache is invalidated:
    /// completed forced measurements replace observations through the normal path.
    pub fn prepare_selector_rebuild(
        &mut self,
        ticket: &Ticket,
    ) -> Result<ConnectionMeasurements, String> {
        if !self.selector_rebuild_current(ticket)
            || self.selector_rebuild.claimed.is_some()
            || ticket.groups.iter().any(|tag| {
                self.selector_rebuild.pools.get(tag).is_none_or(|p| {
                    if ticket.subscription_versions.contains_key(tag) {
                        p.subscription.attempts >= monitor::MAX_ATTEMPTS
                    } else {
                        p.monitor.attempts >= monitor::MAX_ATTEMPTS
                    }
                })
            })
        {
            return Err("selector_measurements_stale".into());
        }
        if !self.probe_queue_free() {
            return Err("probe_busy".into());
        }
        let now = self.selector_rebuild.now();
        for tag in &ticket.groups {
            let pool = self.selector_rebuild.pools.get_mut(tag).unwrap();
            if ticket.subscription_versions.contains_key(tag) {
                pool.subscription.attempted(now);
            } else {
                pool.monitor.attempted(now);
            }
        }
        self.selector_rebuild.claimed = Some(ticket.token.clone());
        let result = (|| {
            let mut plan = self
                .connection_measurements(&ticket.id)?
                .ok_or("selector_measurements_stale")?;
            for tag in &ticket.groups {
                let pool = self
                    .selector_rebuild
                    .pools
                    .get(tag)
                    .ok_or("selector_measurements_stale")?;
                if !ticket.subscription_versions.contains_key(tag) {
                    self.force_selector_measurements(
                        &mut plan,
                        &pool.id,
                        &pool.members.values().cloned().collect::<Vec<_>>(),
                    )?;
                } else if pool.subscription.attempts > 1 {
                    self.force_failed_selector_measurements(&mut plan, &pool.id)?;
                }
            }
            Ok(plan)
        })();
        if result.is_err() {
            self.selector_rebuild.claimed = None;
        }
        self.logs.event(
            "info",
            if ticket.subscription_versions.is_empty() {
                "selector_rebuild_started"
            } else {
                "selector_subscription_applying"
            },
            None,
        );
        result
    }

    pub async fn connect_rebuilt(
        &mut self,
        ticket: &Ticket,
        plan: &ConnectionMeasurements,
    ) -> Result<(), String> {
        if self.selector_rebuild.claimed.as_ref() != Some(&ticket.token)
            || !self.selector_rebuild_current(ticket)
        {
            return Err("selector_measurements_stale".into());
        }
        let previous = self.selector_rebuild.clone();
        if !ticket.subscription_versions.is_empty() {
            let library = self.ranked_connection_library(plan)?;
            for tag in &ticket.groups {
                let pool = self
                    .selector_rebuild
                    .pools
                    .get(tag)
                    .ok_or("selector_measurements_stale")?;
                if !Self::selector_library_has_http_success(&library, &pool.id)? {
                    return Err("selector_subscription_unavailable".into());
                }
            }
            self.connect_using_library(
                &ticket.id,
                Some(library),
                crate::vpn_auth::otp::Intent::Background,
            )
            .await?;
        } else {
            self.connect_measured(plan).await?;
        }
        // A checked Start captures a new generation. Preserve bounded retry state
        // only for the same pool identities in this successful automatic transition.
        self.selector_rebuild.origin = previous.origin;
        for pool in self.selector_rebuild.pools.values_mut() {
            if let Some(old) = previous.pools.values().find(|old| old.id == pool.id) {
                pool.monitor = old.monitor.clone();
            }
        }
        self.logs.event("info", "selector_rebuild_finished", None);
        Ok(())
    }
    pub fn finish_selector_rebuild(&mut self, ticket: &Ticket, cancelled: bool) {
        if ticket.generation != self.selector_rebuild.generation
            || self.selector_rebuild.claimed.as_ref() != Some(&ticket.token)
        {
            return;
        }
        self.selector_rebuild.claimed = None;
        if cancelled {
            for tag in &ticket.groups {
                if let Some(pool) = self.selector_rebuild.pools.get_mut(tag) {
                    if let Some(version) = ticket.subscription_versions.get(tag) {
                        if &pool.subscription.version == version {
                            pool.subscription.cancelled = true;
                        }
                    } else {
                        pool.monitor.cancel();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
