//! Resolve generated pool identities after the settings WARP exit wraps them.
//! Keep the actual Core tag for RPC actions; member tags retain their original
//! compiler namespace. Never infer this from settings that may have changed
//! since the running request was built.
use crate::{
    proto,
    store::{Library, Profile, ProfileKind},
    Engine,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The member each running pool currently sends traffic through, by profile
/// id. Empty while nothing runs; the virtual quick pool is not a library row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolSelection(BTreeMap<String, String>);
impl PoolSelection {
    pub fn member(&self, pool: &str) -> Option<&str> {
        self.0.get(pool).map(String::as_str)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl Engine {
    /// Resolved from the last selector poll: pools of the running request,
    /// including auxiliary routing pools, mapped to the selected member.
    pub fn pool_selection(&self) -> PoolSelection {
        let mut selection = PoolSelection::default();
        let Some(running) = self.running.as_deref() else {
            return selection;
        };
        for (tag, selected) in &self.selector_health.last_selected {
            let Some(id) = owner_id(tag, running) else {
                continue;
            };
            let Some(member) = selected.strip_prefix(&member_tag(tag, "")) else {
                continue;
            };
            if id != super::AUTO_SELECT_ID
                && self.store.library.profiles.iter().any(|p| p.id == member)
            {
                selection.0.insert(id.to_owned(), member.to_owned());
            }
        }
        selection
    }
}

pub(super) fn logical_tag(tag: &str) -> &str {
    if tag == crate::settings::warp::BASE_TAG {
        "proxy"
    } else {
        tag
    }
}

pub(super) fn owner_id<'a>(tag: &'a str, selected: &'a str) -> Option<&'a str> {
    match logical_tag(tag) {
        "proxy" => Some(selected),
        tag => tag.strip_prefix("thronium-route-"),
    }
}

/// A pool of a compiled request: its tag, its compiled group and the stored
/// auto-selector profile that owns it, when one does (the quick pool does not).
pub(super) struct CompiledPool<'a> {
    pub tag: &'a str,
    pub group: &'a Value,
    pub owner_id: &'a str,
    pub owner: Option<&'a Profile>,
}
/// Every auto-selector group of `core`, built for `selected`. A complete user
/// configuration owns its own tags, so it has none of Thronium's pools.
pub(super) fn compiled_pools<'a>(
    library: &'a Library,
    selected: &'a str,
    core: &'a Value,
) -> Vec<CompiledPool<'a>> {
    let Some(profile) = library.profiles.iter().find(|p| p.id == selected) else {
        return Vec::new();
    };
    if matches!(
        profile.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        return Vec::new();
    }
    core["outbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|group| group["type"] == "auto-selector")
        .filter_map(|group| {
            let tag = group["tag"].as_str()?;
            let owner_id = owner_id(tag, selected)?;
            Some(CompiledPool {
                tag,
                group,
                owner_id,
                owner: library
                    .profiles
                    .iter()
                    .find(|p| p.id == owner_id && p.kind == ProfileKind::AutoSelector),
            })
        })
        .collect()
}

pub(super) fn member_tag(pool: &str, id: &str) -> String {
    super::member_tag(logical_tag(pool), id)
}

pub(super) fn owner<'a>(
    library: &'a Library,
    selected: Option<&'a str>,
    tag: &'a str,
) -> Option<(&'a str, &'a str)> {
    let id = owner_id(tag, selected.unwrap_or(""))?;
    // Quick select is virtual: Store deliberately removes it from persisted profiles.
    if id == super::AUTO_SELECT_ID {
        return Some((id, "auto-select"));
    }
    library
        .profiles
        .iter()
        .find(|p| p.id == id && p.kind == ProfileKind::AutoSelector)
        .map(|p| (p.id.as_str(), p.name.as_str()))
}

/// Why the core moved the selection, as one of its own fixed reasons. An
/// unknown reason is dropped rather than shown as core text.
fn switch_reason(reason: &str) -> &'static str {
    match reason {
        "initial" => "initial",
        "pinned by user" => "pinned",
        "balance rotation" => "balance",
        "best available" => "best",
        "failover succeeded" => "failover",
        "fallback: no qualified member" => "fallback-unqualified",
        "fallback: every member is cooling down" => "fallback-cooldown",
        _ => "",
    }
}
/// Why a member last failed, as a probe code the window already translates.
/// The core's own message never reaches the window.
fn member_error(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if error.is_empty() {
        ""
    } else if lower.contains("timeout") || lower.contains("deadline exceeded") {
        "probe_timeout"
    } else if lower.contains("refused") {
        "probe_connection_refused"
    } else if lower.contains("unreachable") || lower.contains("no route") {
        "probe_unreachable"
    } else if lower.contains("certificate") || lower.contains("tls") {
        "probe_tls_failed"
    } else if lower.contains("dns") || lower.contains("lookup") || lower.contains("resolve") {
        "probe_dns_failed"
    } else {
        "probe_failed"
    }
}

impl Engine {
    pub(super) fn selector_status(&self, reply: proto::QueryAutoSelectorsResponse) -> Value {
        let needs_reconnect = self.quick_needs_reconnect();
        let result: Vec<_> = reply
            .groups
            .into_iter()
            .map(|group| {
                let tag = group.tag.as_deref().unwrap_or("");
                let owner = owner(&self.store.library, self.running.as_deref(), tag);
                let profile_id = owner.map(|(id, _)| id);
                let members: Vec<_> = group
                    .members
                    .into_iter()
                    .map(|member| {
                        let actual = member.tag.as_deref().unwrap_or("");
                        let profile = self
                            .store
                            .library
                            .profiles
                            .iter()
                            .find(|profile| actual == member_tag(tag, &profile.id));
                        let name = profile
                            .map(|profile| profile.name.as_str())
                            .or_else(|| self.selector_rebuild.former_member_name(tag, actual))
                            .unwrap_or(actual);
                        json!({
                            "tag": actual,
                            "profileId": profile.map(|profile| &profile.id),
                            "name": name,
                            "rank": member.rank.unwrap_or(0),
                            "state": member.state.unwrap_or_default(),
                            "selected": member.selected.unwrap_or(false),
                            "selectedUdp": member.selected_udp.unwrap_or(false),
                            "qualified": member.qualified.unwrap_or(false),
                            "active": member.active.unwrap_or(false),
                            "averageMs": member.average_ms.unwrap_or(0),
                            "deviationMs": member.deviation_ms.unwrap_or(0),
                            "minMs": member.min_ms.unwrap_or(0),
                            "maxMs": member.max_ms.unwrap_or(0),
                            "samples": member.samples.unwrap_or(0),
                            "failures": member.failures.unwrap_or(0),
                            "probes": member.probes.unwrap_or(0),
                            "dialTotal": member.dial_total.unwrap_or(0),
                            "dialFailures": member.dial_fail.unwrap_or(0),
                            "lastOkMs": member.last_ok_ms.unwrap_or(0),
                            "lastProbeMs": member.last_probe_ms.unwrap_or(0),
                            "cooldownUntilMs": member.cooldown_until_ms.unwrap_or(0),
                            "lastError": member_error(member.last_error.as_deref().unwrap_or(""))
                        })
                    })
                    .collect();
                json!({
                    "tag": tag,
                    "profileId": profile_id,
                    "name": owner.map(|(_, name)| name).unwrap_or(tag),
                    "needsReconnect": profile_id == Some(super::AUTO_SELECT_ID) && needs_reconnect,
                    "rebuild": self.selector_rebuild.status(tag),
                    "subscriptionUpdate": self.selector_rebuild.subscription_status(tag),
                    "phase": group.phase.unwrap_or_default(),
                    "selected": group.selected.unwrap_or_default(),
                    "selectedUdp": group.selected_udp.unwrap_or_default(),
                    "pinned": group.pinned.unwrap_or_default(),
                    "balance": group.balance.unwrap_or(false),
                    "balanceMode": group.balance_mode.unwrap_or_default(),
                    "suspended": group.suspended.unwrap_or(false),
                    "membersTotal": group.members_total.unwrap_or(0),
                    "membersProbed": group.members_probed.unwrap_or(0),
                    "membersAlive": group.members_alive.unwrap_or(0),
                    "membersQualified": group.members_qualified.unwrap_or(0),
                    "membersCooldown": group.members_cooldown.unwrap_or(0),
                    "suspendedSinceMs": group.suspended_since_ms.unwrap_or(0),
                    "probesInFlight": group.probes_in_flight.unwrap_or(0),
                    "roundsCompleted": group.rounds_completed.unwrap_or(0),
                    "lastRoundMs": group.last_round_ms.unwrap_or(0),
                    "nextRoundMs": group.next_round_ms.unwrap_or(0),
                    "lastSwitchMs": group.last_switch_ms.unwrap_or(0),
                    "lastSwitchReason": switch_reason(group.last_switch_reason.as_deref().unwrap_or("")),
                    "members": members
                })
            })
            .collect();
        json!(result)
    }
}

#[cfg(test)]
mod tests;
