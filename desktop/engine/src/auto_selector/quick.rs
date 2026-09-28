//! Quick-pool route eligibility and reconnect memory, separate from manual pools.
use crate::{
    group_chains, proto,
    store::{Library, Profile},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
pub(crate) mod config;
const FILE: &str = "auto-select-memory-v1.json";
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutoSelectOptions {
    pub failover: bool,
    pub source_group_id: Option<String>,
}

#[derive(Default)]
pub struct AutoSelectSettingsUpdate {
    pub failover: Option<bool>,
    /// None preserves the source; Some(None) explicitly chooses all groups.
    pub source_group_id: Option<Option<String>>,
    /// New dialogs compare these fields too; older config-only callers retain them.
    pub previous_options: Option<AutoSelectOptions>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Remembered {
    member: String,
    context: String,
    /// Fixed lifetime since the full sweep. A cheap recheck does not extend it.
    verified_at_ms: u64,
}
#[derive(Default)]
pub(crate) struct State {
    remembered: Option<Remembered>,
    applied_context: Option<String>,
    pub(crate) epoch: u64,
}
fn now() -> u64 {
    super::health::now_ms()
}

pub(crate) fn context(library: &Library) -> String {
    let prefs = &library.preferences;
    let effective = config::normalize(&prefs.auto_select.config)
        .unwrap_or_else(|_| prefs.auto_select.config.clone());
    // No names, icons, latency rows or UI preferences: only connection inputs.
    let input = json!([
        [
            json!(prefs.auto_select.enabled),
            effective,
            json!(prefs.auto_select.failover),
            json!(prefs.auto_select.source_group_id)
        ],
        prefs.connection_mode,
        prefs.inbound_port,
        prefs.tun,
        prefs.vless_core,
        prefs.vless_overrides,
        library.routing,
        library.settings,
        library
            .profiles
            .iter()
            .filter(|p| p.id != super::AUTO_SELECT_ID)
            .map(|p| json!([p.id, p.kind, p.group_id, p.config, p.vpn_policy]))
            .collect::<Vec<_>>(),
        library
            .groups
            .iter()
            .map(|g| json!([g.id, g.proxy_chain]))
            .collect::<Vec<_>>()
    ]);
    format!("{:x}", Sha256::digest(input.to_string().as_bytes()))
}

pub(crate) fn hops<'a>(library: &'a Library, profile: &'a Profile) -> Option<Vec<&'a Profile>> {
    let hops =
        group_chains::sequence(library, profile, &group_chains::policy(library, profile)).ok()?;
    // Quick select must always lead through a proxy. Direct remains available to
    // explicitly configured manual chains and pools.
    if hops.is_empty()
        || hops.iter().any(|p| {
            !super::hop_eligible(p) || crate::profile_descriptor::infrastructure_outbound(&p.config)
        })
    {
        return None;
    }
    Some(hops)
}

impl State {
    pub(crate) fn load(directory: &Path) -> Self {
        let read = || -> Option<Remembered> {
            let path = directory.join(FILE);
            let meta = std::fs::symlink_metadata(&path).ok()?;
            if !meta.is_file() || meta.len() > 2048 {
                return None;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(2049)
                .read_to_end(&mut bytes)
                .ok()?;
            let entry: Remembered = serde_json::from_slice(&bytes).ok()?;
            (entry.member.len() <= 512
                && entry.context.len() == 64
                && entry.verified_at_ms > 0
                && now()
                    .checked_sub(entry.verified_at_ms)
                    .is_some_and(|age| age < 86_400_000))
            .then_some(entry)
        };
        Self {
            remembered: read(),
            ..Default::default()
        }
    }
    fn save(&self, directory: &Path) -> std::io::Result<()> {
        let Some(entry) = &self.remembered else {
            return match std::fs::remove_file(directory.join(FILE)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                result => result,
            };
        };
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&serde_json::to_vec(entry)?)?;
        file.as_file().sync_all()?;
        file.persist(directory.join(FILE)).map_err(|e| e.error)?;
        Ok(())
    }
    pub(crate) fn candidate(
        &self,
        context: &str,
        ttl_ms: u32,
        members: &[String],
    ) -> Option<String> {
        let entry = self.remembered.as_ref()?;
        (ttl_ms > 0
            && entry.context == context
            && members.contains(&entry.member)
            && now().checked_sub(entry.verified_at_ms)? < u64::from(ttl_ms))
        .then(|| entry.member.clone())
    }
}
impl Engine {
    /// A scoped optimistic update cannot overwrite unrelated preferences or a
    /// newer configurator's values while this dialog was open.
    pub fn save_auto_select_settings(
        &mut self,
        previous: &serde_json::Value,
        config: serde_json::Value,
        update: AutoSelectSettingsUpdate,
    ) -> Result<(), String> {
        let current = &self.store.library.preferences.auto_select;
        if !config::equivalent(&current.config, previous)
            || update.previous_options.as_ref().is_some_and(|old| {
                old.failover != current.failover || old.source_group_id != current.source_group_id
            })
        {
            return Err("auto_select_settings_changed".into());
        }
        let mut preferences = self.store.library.preferences.clone();
        preferences.auto_select.config = config;
        if let Some(failover) = update.failover {
            preferences.auto_select.failover = failover;
        }
        if let Some(source) = update.source_group_id {
            preferences.auto_select.source_group_id = source;
        }
        self.preferences(preferences)
    }

    pub(crate) async fn remember_quick_before_disconnect(&mut self) {
        if self.running.as_deref() != Some(super::AUTO_SELECT_ID)
            || self.quick_select.remembered.is_none()
        {
            return;
        }
        let Some(rpc) = self.rpc.as_mut() else { return };
        // The Core is about to stop. Do not let a best-effort status read add
        // the regular 30-second RPC timeout to Disconnect.
        if let Ok(reply) = rpc
            .call_with_timeout::<_, proto::QueryAutoSelectorsResponse>(
                "QueryAutoSelectors",
                proto::EmptyReq {},
                std::time::Duration::from_secs(2),
            )
            .await
        {
            self.observe_quick_selection(&reply);
        }
    }
    pub(crate) fn clear_quick_memory(&mut self) {
        self.quick_select.remembered = None;
        self.quick_select.epoch = self.quick_select.epoch.wrapping_add(1);
        self.persist_quick_memory();
    }
    fn quick_memory_enabled(&self) -> bool {
        let prefs = &self.store.library.preferences.auto_select;
        prefs.enabled
            && prefs.config["reuse_ttl"]
                .as_str()
                .and_then(config::duration_ms)
                != Some(0)
    }
    pub(crate) fn clear_disabled_quick_memory(&mut self) {
        if !self.quick_memory_enabled() && self.quick_select.remembered.is_some() {
            self.clear_quick_memory();
        }
    }
    fn persist_quick_memory(&self) {
        if self.quick_select.save(&self.data_dir).is_err() {
            self.logs
                .event("warn", "auto_select_memory_write_failed", None);
        }
    }
    pub(crate) fn remember_quick_connection(&mut self, member: String, reused: bool) {
        let context = context(&self.store.library);
        self.quick_select.applied_context = Some(context.clone());
        if !self.quick_memory_enabled() {
            self.clear_disabled_quick_memory();
            return;
        }
        let verified_at_ms = if reused {
            self.quick_select
                .remembered
                .as_ref()
                .map_or_else(now, |m| m.verified_at_ms)
        } else {
            now()
        };
        self.quick_select.remembered = Some(Remembered {
            member,
            context,
            verified_at_ms,
        });
        self.persist_quick_memory();
    }
    /// Remember the actual carrier without renewing the sweep's expiry. WARP
    /// reaches its endpoint over UDP even when applications send TCP traffic.
    pub(crate) fn observe_quick_selection(&mut self, reply: &proto::QueryAutoSelectorsResponse) {
        if self.running.as_deref() != Some(super::AUTO_SELECT_ID) {
            return;
        }
        let Some(entry) = &self.quick_select.remembered else {
            return;
        };
        if entry.context != context(&self.store.library) {
            return;
        }
        let Some(group) = reply.groups.iter().find(|g| {
            g.tag
                .as_deref()
                .is_some_and(|tag| super::runtime::logical_tag(tag) == "proxy")
        }) else {
            return;
        };
        let selected = if group.tag.as_deref() == Some(crate::settings::warp::BASE_TAG)
            || self.active_connection.as_ref().is_some_and(|active| {
                crate::settings::warp::routing::final_uses_explicit_warp(&active.request)
            }) {
            group
                .selected_udp
                .as_deref()
                .filter(|tag| !tag.is_empty())
                .or(group.selected.as_deref())
        } else {
            group.selected.as_deref()
        };
        let Some(selected) = selected else { return };
        let member = self
            .store
            .library
            .profiles
            .iter()
            .find(|p| super::member_tag("proxy", &p.id) == selected);
        if let Some(member) = member.filter(|p| p.id != entry.member) {
            if let Some(entry) = self.quick_select.remembered.as_mut() {
                entry.member = member.id.clone();
                self.persist_quick_memory();
            }
        }
    }
    pub(crate) fn quick_needs_reconnect(&self) -> bool {
        self.running.as_deref() == Some(super::AUTO_SELECT_ID)
            && self
                .quick_select
                .applied_context
                .as_ref()
                .is_some_and(|c| c != &context(&self.store.library))
    }
}
