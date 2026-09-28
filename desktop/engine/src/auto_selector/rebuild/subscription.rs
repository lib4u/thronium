//! Scoped replacement of active ordinary members by a committed subscription.
use super::*;
use std::collections::HashSet;
#[derive(Clone, Default)]
pub(super) struct Pending {
    pub version: String,
    pub pending: bool,
    pub attempts: u8,
    pub cancelled: bool,
    pub last_attempt: Option<u64>,
}
pub(super) fn member_signature(library: &Library, id: &str) -> Option<String> {
    let profile = library.profiles.iter().find(|p| p.id == id)?;
    Some(crate::geodata::digest(
        json!([
            crate::latency_measurements::fingerprint(library, id)?,
            profile.vpn_policy,
            crate::geodata::enabled(profile, library),
            crate::geodata::provider(profile, library)
        ])
        .to_string()
        .as_bytes(),
    ))
}
impl Engine {
    /// Every actual active pool using this member must opt in. Normal roots,
    /// explicit chains and group hops retain their existing edit/delete guards.
    pub(crate) fn selector_member_subscription_allowed(&self, id: &str) -> bool {
        if !self.selector_rebuild_scope_current() {
            return false;
        }
        let library = &self.store.library;
        let Some(member) = library.profiles.iter().find(|p| p.id == id) else {
            return false;
        };
        if !crate::auto_selector::member_kind(member.kind)
            || !crate::settings::tests_runtime::supported(library, member, &Default::default())
            // Diagnostics now cover endpoints that pools still cannot wrap.
            || crate::chains::flatten(member, &library.profiles).is_err()
        {
            return false;
        }
        let linked = self
            .selector_rebuild
            .pools
            .values()
            .filter(|pool| pool.members.values().any(|member| member == id))
            .collect::<Vec<_>>();
        if linked.is_empty()
            || linked.iter().any(|pool| {
                !pool.on_subscription
                    || library
                        .profiles
                        .iter()
                        .find(|p| p.id == pool.id)
                        .is_none_or(|p| {
                            super::super::source_group(p) != Some(member.group_id.as_str())
                        })
            })
        {
            return false;
        }
        let ids = HashSet::from([id.to_string()]);
        if crate::group_chains::referenced(library, &ids, None)
            || crate::references::referenced_outside(&library.profiles, &ids)
        {
            return false;
        }
        let Some(selected) = self
            .running
            .as_ref()
            .and_then(|id| library.profiles.iter().find(|p| &p.id == id))
        else {
            return false;
        };
        let Ok(roots) = crate::vless::roots(library, selected) else {
            return false;
        };
        roots.iter().all(|root| {
            library
                .profiles
                .iter()
                .find(|p| &p.id == root)
                .is_some_and(|p| {
                    p.kind == ProfileKind::AutoSelector
                        || !crate::group_chains::dependencies(
                            library,
                            &HashSet::from([root.clone()]),
                        )
                        .contains(id)
                })
        })
    }
}

impl Pending {
    pub fn update(&mut self, version: String, pending: bool) {
        if self.version != version || !pending {
            self.attempts = 0;
            self.last_attempt = None;
        }
        self.version = version;
        self.pending = pending;
        // Explicit cancellation belongs to this running generation, even if a
        // later automatic subscription download contains another version.
    }
    pub fn ready(&self, now: u64) -> bool {
        self.pending
            && !self.cancelled
            && self.attempts < monitor::MAX_ATTEMPTS
            && self
                .last_attempt
                .is_none_or(|at| now.saturating_sub(at) >= monitor::retry_delay_ms(self.attempts))
    }
    pub fn attempted(&mut self, now: u64) {
        self.attempts = self.attempts.saturating_add(1).min(monitor::MAX_ATTEMPTS);
        self.last_attempt = Some(now);
    }
    fn status(&self) -> Value {
        json!({"pending":self.pending,"attempts":self.attempts,"limit":monitor::MAX_ATTEMPTS,
        "paused":self.cancelled || self.attempts>=monitor::MAX_ATTEMPTS})
    }
}
fn desired_version(library: &Library, group: &str) -> String {
    let mut profiles = library
        .profiles
        .iter()
        .filter(|p| p.group_id == group)
        .collect::<Vec<_>>();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    crate::geodata::digest(
        json!(profiles
            .iter()
            .map(|p| json!([
                p.id,
                p.name,
                p.kind,
                p.config,
                p.vpn_policy,
                crate::geodata::enabled(p, library),
                crate::geodata::provider(p, library)
            ]))
            .collect::<Vec<_>>())
        .to_string()
        .as_bytes(),
    )
}
impl State {
    pub(crate) fn subscription_status(&self, tag: &str) -> Value {
        self.pools
            .get(tag)
            .filter(|p| p.on_subscription)
            .map(|p| p.subscription.status())
            .unwrap_or(Value::Null)
    }
    pub(crate) fn former_member_name(&self, tag: &str, member: &str) -> Option<&str> {
        self.pools.get(tag)?.names.get(member).map(String::as_str)
    }
}
impl Engine {
    /// Read actual Store state after the commit result, including a possible
    /// post-rename durability error. A failed pre-rename write cannot queue work.
    pub(crate) fn note_selector_subscription_commit(&mut self, group: &str) {
        let library = &self.store.library;
        let version = desired_version(library, group);
        for pool in self
            .selector_rebuild
            .pools
            .values_mut()
            .filter(|p| p.on_subscription)
        {
            let Some(owner) = library.profiles.iter().find(|p| p.id == pool.id) else {
                continue;
            };
            if super::super::source_group(owner) != Some(group) {
                continue;
            }
            let eligible = Self::selector_candidate_ids(library, owner);
            let still_eligible = eligible
                .as_ref()
                .is_ok_and(|ids| pool.applied.keys().all(|id| ids.contains(id)));
            let changed = !still_eligible
                || pool.applied.iter().any(|(id, signature)| {
                    member_signature(library, id).as_ref() != Some(signature)
                });
            pool.subscription.update(version.clone(), changed);
        }
    }
    pub fn selector_subscription_update(&self) -> Value {
        let pools = self
            .selector_rebuild
            .pools
            .values()
            .filter(|p| p.on_subscription && p.subscription.pending)
            .map(|p| {
                let name = self
                    .store
                    .library
                    .profiles
                    .iter()
                    .find(|profile| profile.id == p.id)
                    .map(|p| p.name.as_str())
                    .unwrap_or("");
                json!({"profileId":p.id,"name":name,"status":p.subscription.status()})
            })
            .collect::<Vec<_>>();
        if pools.is_empty() || self.running.as_deref() != Some(self.selector_rebuild.id.as_str()) {
            Value::Null
        } else {
            json!({"profileId":self.selector_rebuild.id,"pools":pools})
        }
    }
    pub(super) fn subscription_rebuild_ticket(&self) -> Option<Ticket> {
        let pending = self
            .selector_rebuild
            .pools
            .iter()
            .filter(|(_, p)| p.on_subscription && p.subscription.pending)
            .collect::<Vec<_>>();
        if pending.is_empty()
            || pending
                .iter()
                .any(|(_, p)| !p.subscription.ready(self.selector_rebuild.now()))
        {
            return None;
        }
        Some(Ticket {
            id: self.selector_rebuild.id.clone(),
            generation: self.selector_rebuild.generation.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            groups: pending.iter().map(|(tag, _)| (*tag).clone()).collect(),
            subscription_versions: pending
                .iter()
                .map(|(tag, p)| ((*tag).clone(), p.subscription.version.clone()))
                .collect(),
        })
    }
}
