//! Qt numeric route destinations: built-in outbounds or a profile of the same
//! selected import. Endpoint-kind profiles (WireGuard, Tailscale) are ordinary
//! targets the native compiler emits under `endpoints`; a VPN carrying its own
//! routing policy needs that policy compiled and is refused explicitly.
use super::Result;
use crate::{
    legacy_backup::profiles::ProfilePlan,
    store::{Profile, ProfileKind},
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn target(v: &Value, profiles: Option<&ProfilePlan>) -> Result<String> {
    if let Some(s) = v.as_str() {
        return if matches!(s, "proxy" | "direct" | "warp-bypass") {
            Ok(s.into())
        } else {
            Err("legacy_route_target_unsupported")
        };
    }
    match v.as_i64().ok_or("legacy_route_structure")? {
        -1 => Ok("proxy".into()),
        -2 => Ok("direct".into()),
        -5 => Ok("warp-bypass".into()),
        id if id >= 0 => {
            let plan = profiles.ok_or("legacy_route_reference_missing")?;
            let mapped = plan
                .profile_ids
                .get(&id)
                .ok_or("legacy_route_reference_missing")?;
            let profile = plan
                .profiles
                .iter()
                .find(|p| &p.id == mapped)
                .ok_or("legacy_route_reference_missing")?;
            validate_target_dependencies(profile, plan)?;
            Ok(format!("profile:{mapped}"))
        }
        _ => Err("legacy_route_target_unsupported"),
    }
}
/// Every profile a target depends on, including group front/landing hops.
fn dependencies<'a>(profile: &'a Profile, plan: &'a ProfilePlan) -> Result<Vec<&'a Profile>> {
    let mut pending = vec![profile.id.as_str()];
    if let Some(group) = plan.groups.iter().find(|g| g.id == profile.group_id) {
        pending.extend(group.proxy_chain.ids());
    }
    let mut visited = BTreeSet::new();
    let mut result = vec![];
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        if visited.len() > 1000 {
            return Err("legacy_route_limit");
        }
        let p = plan
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("legacy_route_reference_missing")?;
        pending
            .extend(crate::references::members(p).map_err(|_| "legacy_route_reference_missing")?);
        result.push(p);
    }
    Ok(result)
}
fn validate_target_dependencies(profile: &Profile, plan: &ProfilePlan) -> Result<()> {
    for p in dependencies(profile, plan)? {
        if !matches!(
            p.kind,
            ProfileKind::SingBoxOutbound
                | ProfileKind::XrayOutbound
                | ProfileKind::Chain
                | ProfileKind::AutoSelector
        ) {
            return Err("legacy_route_target_unsupported");
        }
        if p.vpn_policy.is_some() {
            return Err("legacy_route_endpoint_unsupported");
        }
    }
    Ok(())
}
/// Endpoint-kind profiles a converted preset reaches through its references,
/// recorded so the runtime knows the preset was compiled endpoint-aware.
pub(super) fn endpoint_targets(documents: &[&Value], plan: Option<&ProfilePlan>) -> Vec<String> {
    let Some(plan) = plan else { return vec![] };
    let mut referenced = BTreeSet::new();
    for document in documents {
        collect(document, &mut referenced, 0);
    }
    let mut result = BTreeSet::new();
    for id in referenced {
        let Some(profile) = plan.profiles.iter().find(|p| p.id == id) else {
            continue;
        };
        for p in dependencies(profile, plan).unwrap_or_default() {
            if crate::chains::is_endpoint(p) {
                result.insert(p.id.clone());
            }
        }
    }
    result.into_iter().collect()
}
fn collect(value: &Value, result: &mut BTreeSet<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    match value {
        Value::String(s) => {
            if let Some(id) = s.strip_prefix("profile:") {
                result.insert(id.to_owned());
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect(v, result, depth + 1)),
        Value::Object(map) => map.values().for_each(|v| collect(v, result, depth + 1)),
        _ => {}
    }
}
