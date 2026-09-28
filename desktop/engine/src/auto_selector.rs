//! The pinned upstream auto-selector runs its own health checks and failover.
use crate::{
    chains, config, core_result, proto, references,
    store::{Library, Profile, ProfileKind},
    vpn_auth::otp,
    Engine,
};
use serde_json::{json, Value};
use std::collections::HashSet;
pub const MAX_MEMBERS: usize = 500;
/// Longest time a saved HTTP result ranks pool members, in minutes (7 days).
pub const MAX_RESULT_VALIDITY_MINUTES: u32 = 10_080;
/// Most candidates a dynamic pool keeps after filters, before it is built.
pub const MAX_CANDIDATES: usize = 3000;
/// Startup limit a dynamic pool gets when the user turns the limit on.
pub const SUGGESTED_BUILD_LIMIT: usize = 300;
/// Candidate pool size a dynamic pool gets when the user turns the cap on.
pub const SUGGESTED_POOL_CAP: usize = 1000;

/// Whether a profile can be a pool member: a real single or chained outbound
/// the disposable core can build and measure, never a nested pool. A complete
/// Xray configuration is a member with its own instance, as in Qt; a complete
/// sing-box configuration is not. The chain compiler decides which protocols
/// qualify, so eligibility follows configuration and context, not a list.
pub const AUTO_SELECT_ID: &str = "auto-select";
pub(crate) const AUTO_SELECT_MIN: usize = 2;
pub use quick::config::{
    MAX_REUSE_TTL_MS as QUICK_MAX_REUSE_TTL_MS, TIMEOUT_MS as QUICK_TIMEOUT_MS,
};
pub use quick::{AutoSelectOptions, AutoSelectSettingsUpdate};
pub use rebuild::{RECHECK_ATTEMPTS, RECHECK_FIRST_RETRY_MS, RECHECK_GRACE_MS};

/// Default health settings for the quick auto-select pool. Balancing stays off
/// until the user turns it on in the configurator.
pub fn default_quick_config() -> Value {
    json!({
        "url": crate::probes::DEFAULT_TEST_URL,
        "interval": "120s",
        "bench_interval": "600s",
        "watch_interval": "15s",
        "timeout": "5s",
        "concurrency": 12,
        "tolerance": 100,
        "dial_retries": 2,
        "reuse_ttl": "30m"
    })
}

/// A new pool profile before the user picks members: the quick pool health
/// settings plus the balancing values Qt gives a manual pool.
pub fn default_pool_config() -> Value {
    let mut config = default_quick_config();
    if let Some(object) = config.as_object_mut() {
        object.extend([
            ("type".into(), json!("auto-selector")),
            ("members".into(), json!([])),
            ("active_size".into(), json!(8)),
            ("sampling".into(), json!(10)),
            ("expected".into(), json!(3)),
            ("interrupt_exist_connections".into(), json!(true)),
        ]);
    }
    config
}

/// Profile kinds a pool can hold as members: single outbounds, and complete
/// Xray configurations that resolve to one outbound. Building a pool, saving
/// its health and measurements, and subscription rebuilds all use this list.
pub(crate) fn member_kind(kind: ProfileKind) -> bool {
    matches!(
        kind,
        ProfileKind::SingBoxOutbound | ProfileKind::XrayOutbound | ProfileKind::XrayConfig
    )
}
pub fn member_eligible(profile: &Profile, profiles: &[Profile]) -> bool {
    profile.kind != ProfileKind::AutoSelector
        && chains::flatten(profile, profiles)
            .is_ok_and(|hops| hops.iter().all(|hop| hop_eligible(hop)))
}
/// A hop every pool member may pass through: no endpoint that opens its own
/// VPN session when the pool starts (Qt keeps them out of pools as well), and
/// no external core — a pool switches between servers, and the program a person
/// runs is started by a connection, not chosen by a measurement.
pub(crate) fn hop_eligible(hop: &Profile) -> bool {
    !chains::is_vpn_endpoint(hop) && hop.kind != ProfileKind::ExternalCore
}
/// The group proxy a member is sent through: the quick pool follows each
/// member's own group, a saved pool its root's group.
fn member_policy(
    library: &Library,
    pool: &Profile,
    member: &Profile,
) -> crate::group_chains::GroupChain {
    crate::group_chains::policy(
        library,
        if pool.id == AUTO_SELECT_ID {
            member
        } else {
            pool
        },
    )
}
/// The member's actual route, group proxy hops included.
fn member_route<'a>(
    library: &'a Library,
    pool: &Profile,
    member: &'a Profile,
) -> Result<Vec<&'a Profile>, String> {
    if member.kind == ProfileKind::AutoSelector {
        return Err("selector_member_unsupported".into());
    }
    crate::group_chains::sequence(library, member, &member_policy(library, pool, member))
}
/// Eligibility on the route the pool really uses: a VPN endpoint set as the
/// group proxy would otherwise open one VPN session per member.
pub(crate) fn member_route_eligible(library: &Library, pool: &Profile, member: &Profile) -> bool {
    member_route(library, pool, member).is_ok_and(|hops| hops.iter().all(|hop| hop_eligible(hop)))
}
/// Checked when the pool is built, after group proxies are known: every member
/// route binds its fixed endpoint ports when the core starts, selected or not,
/// so a fixed-port group proxy cannot be shared by several members.
pub(crate) fn validate_routes(library: &Library, pool: &Profile) -> Result<(), String> {
    let mut fixed_ports = HashSet::new();
    for id in references::members(pool)? {
        let member = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("selector_profile_missing")?;
        let hops = member_route(library, pool, member)?;
        if !hops.iter().all(|hop| hop_eligible(hop)) {
            return Err("selector_member_unsupported".into());
        }
        for port in hops
            .iter()
            .filter(|hop| chains::is_endpoint(hop))
            .filter_map(|hop| hop.config["listen_port"].as_u64().filter(|p| *p > 0))
        {
            if !fixed_ports.insert(port) {
                return Err("selector_member_port_conflict".into());
            }
        }
    }
    Ok(())
}
mod dynamic;
pub(crate) mod quick;
mod runtime;
pub use dynamic::{ConnectionMeasurementPool, ConnectionMeasurements};
pub use runtime::PoolSelection;
pub(crate) mod health;
pub mod history;
pub(crate) mod rebuild;
pub mod switches;
mod warm;
pub(crate) use dynamic::{materialize, resolve, source_group, validate_saved};
pub use rebuild::Ticket as RebuildTicket;
pub(crate) use warm::apply as apply_warm;
#[cfg(test)]
mod dynamic_tests;
mod members;
#[cfg(test)]
mod switches_tests;
#[cfg(test)]
mod tests;

pub fn validate(profile: &Profile, profiles: &[Profile]) -> Result<(), String> {
    if profile.config.get("member_source").is_some() {
        return Err("invalid_selector_source".into());
    }
    let members = references::members(profile)?;
    let mut seen = HashSet::new();
    let mut fixed_ports = HashSet::new();
    for id in &members {
        if !seen.insert(id) {
            return Err("invalid_selector_members".into());
        }
        let p = profiles
            .iter()
            .find(|p| p.id == *id)
            .ok_or("selector_profile_missing")?;
        if !member_eligible(p, profiles) {
            return Err("selector_member_unsupported".into());
        }
        // Every member's endpoints bind when the core starts, selected or not:
        // two fixed UDP ports in one pool cannot both be owned.
        for port in chains::flatten(p, profiles)
            .into_iter()
            .flatten()
            .filter(|hop| chains::is_endpoint(hop))
            .filter_map(|hop| hop.config["listen_port"].as_u64().filter(|p| *p > 0))
        {
            if !fixed_ports.insert(port) {
                return Err("selector_member_port_conflict".into());
            }
        }
    }
    if profile.config.get("pinned_profile").is_some_and(|v| {
        !v.is_string()
            || v.as_str()
                .is_some_and(|s| !s.is_empty() && !members.contains(&s))
    }) {
        return Err("invalid_selector_pin".into());
    }
    generated_fields(profile)
}
fn generated_fields(profile: &Profile) -> Result<(), String> {
    // These keys contain generated core tags, not portable library references.
    if [
        "outbounds",
        "pinned",
        "warm",
        crate::group_chains::MEMBER_HOPS,
    ]
    .iter()
    .any(|key| profile.config.get(key).is_some())
    {
        return Err("selector_generated_fields".into());
    }
    Ok(())
}
/// Which member an isolated pool measurement went through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberOrigin {
    /// The member the running pool currently sends traffic through (Qt's live test).
    Running,
    Pinned,
    First,
}
/// The member an isolated measurement of a pool stands for: the member the
/// running pool selected, otherwise the pinned member, otherwise the first
/// fixed member. Results name it; a member's exit is never presented as the
/// pool's. A dynamic pool is measurable only while it runs.
pub fn measured_member<'a>(
    library: &'a crate::store::Library,
    pool: &Profile,
    selection: &PoolSelection,
) -> Result<(&'a Profile, MemberOrigin), String> {
    let members = references::members(pool)?;
    let pinned = pool.config["pinned_profile"]
        .as_str()
        .filter(|s| !s.is_empty());
    let (id, origin) = if let Some(id) = selection.member(&pool.id) {
        (id, MemberOrigin::Running)
    } else if let Some(id) = pinned {
        (id, MemberOrigin::Pinned)
    } else if let Some(id) = members.first() {
        (*id, MemberOrigin::First)
    } else {
        return Err("probe_unsupported".into());
    };
    library
        .profiles
        .iter()
        .find(|p| p.id == id)
        .map(|p| (p, origin))
        .ok_or_else(|| "selector_profile_missing".into())
}

pub fn member_tag(group: &str, id: &str) -> String {
    format!("thronium-selector-{group}-{id}")
}
/// Compile the pool into `core`/`xray` and return the complete Xray
/// configurations its members run as separate instances.
pub(crate) fn append(
    profile: &Profile,
    profiles: &[Profile],
    core: &mut Value,
    xray: &mut Value,
    tag: &str,
    sources: &mut otp::Build,
) -> Result<Vec<Value>, String> {
    let mapped = profile.config.get(crate::group_chains::MEMBER_HOPS);
    // Runtime maps are produced only after validating the unmodified selector.
    // Store/import validation rejects this private field in persisted profiles.
    if mapped.is_none() {
        validate(profile, profiles)?;
    }
    let ids = references::members(profile)?;
    if let Some(mapped) = mapped {
        if mapped
            .as_object()
            .is_none_or(|m| m.len() != ids.len() || ids.iter().any(|id| !m.contains_key(*id)))
        {
            return Err("invalid_selector_members".into());
        }
    }
    let mut tags = vec![];
    let mut full = vec![];
    for id in ids {
        let member = profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("selector_profile_missing")?;
        let hops = match mapped {
            Some(mapped) => mapped[id].clone(),
            None => json!(chains::flatten(member, profiles)?
                .into_iter()
                .map(|p| &p.id)
                .collect::<Vec<_>>()),
        };
        let node = Profile {
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":hops}),
            ..member.clone()
        };
        let member_tag = member_tag(tag, id);
        full.extend(chains::append(
            &node,
            profiles,
            core,
            xray,
            &member_tag,
            sources,
        )?);
        tags.push(member_tag);
    }
    let mut group = profile.config.clone();
    let object = group.as_object_mut().ok_or("invalid_selector_members")?;
    object.remove(crate::group_chains::MEMBER_HOPS);
    object.remove("members");
    object.remove("member_source");
    object.remove("pinned_profile");
    // Thronium's remembered-selection lifetime; the editor seeds every new pool
    // with it, and the pinned Core refuses the unknown field.
    object.remove("reuse_ttl");
    group["type"] = json!("auto-selector");
    group["tag"] = json!(tag);
    group["outbounds"] = json!(tags);
    if let Some(pin) = profile.config["pinned_profile"]
        .as_str()
        .filter(|v| !v.is_empty())
    {
        group["pinned"] = json!(member_tag(tag, pin));
    }
    let outbounds = core["outbounds"]
        .as_array_mut()
        .ok_or("invalid_chain_configuration")?;
    if outbounds.iter().any(|p| p["tag"] == tag) {
        return Err("chain_tag_conflict".into());
    }
    outbounds.push(group);
    Ok(full)
}
pub fn build(
    profile: &Profile,
    profiles: &[Profile],
    port: u16,
) -> Result<proto::LoadConfigReq, String> {
    build_with_sources(profile, profiles, port, &mut otp::Build::default())
}
pub(crate) fn build_with_sources(
    profile: &Profile,
    profiles: &[Profile],
    port: u16,
    sources: &mut otp::Build,
) -> Result<proto::LoadConfigReq, String> {
    let placeholder = Profile {
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        ..profile.clone()
    };
    let mut request = config::build(&placeholder, port, None)?;
    let mut core: Value = serde_json::from_str(request.core_config.as_deref().unwrap())
        .map_err(|_| "invalid_configuration")?;
    core["outbounds"]
        .as_array_mut()
        .unwrap()
        .retain(|o| o["tag"] != "proxy");
    let mut xray = json!({"inbounds":[],"outbounds":[]});
    let full = append(profile, profiles, &mut core, &mut xray, "proxy", sources)?;
    if xray["outbounds"].as_array().is_some_and(|v| !v.is_empty()) {
        request.need_xray = Some(true);
        request.xray_config = Some(xray.to_string());
    }
    // Eager instances: a failing member fails Start, where rollback exists.
    request.xray_full_configs = full.iter().map(Value::to_string).collect();
    request.xray_full_idle_seconds = Some(0);
    request.core_config = Some(core.to_string());
    Ok(request)
}

impl Engine {
    pub async fn auto_selectors(&mut self) -> Result<Value, String> {
        if self.running.is_none() {
            return Ok(json!([]));
        }
        let Some(rpc) = &mut self.rpc else {
            return Ok(json!([]));
        };
        let reply: proto::QueryAutoSelectorsResponse = rpc
            .call("QueryAutoSelectors", proto::EmptyReq {})
            .await
            .map_err(|_| "selector_status_failed")?;
        self.observe_quick_selection(&reply);
        Ok(self.selector_status(reply))
    }

    pub async fn auto_selector_action(
        &mut self,
        tag: &str,
        action: &str,
        member: &str,
    ) -> Result<(), String> {
        if !matches!(action, "select" | "recheck") {
            return Err("invalid_selector_action".into());
        }
        let current = self.auto_selectors().await?;
        let group = current
            .as_array()
            .and_then(|groups| groups.iter().find(|g| g["tag"] == tag))
            .ok_or("selector_not_running")?;
        if action == "select"
            && !member.is_empty()
            && !group["members"]
                .as_array()
                .is_some_and(|m| m.iter().any(|v| v["tag"] == member))
        {
            return Err("invalid_selector_pin".into());
        }
        let response: proto::ErrorResp = self
            .rpc
            .as_mut()
            .ok_or("selector_not_running")?
            .call(
                "AutoSelectorAction",
                proto::AutoSelectorActionRequest {
                    tag: Some(tag.into()),
                    action: Some(action.into()),
                    member: Some(member.into()),
                },
            )
            .await
            .map_err(|_| "selector_action_failed")?;
        core_result(response).map_err(|_| "selector_action_failed".into())
    }
}
