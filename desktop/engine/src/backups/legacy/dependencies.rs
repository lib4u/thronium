//! Merge-time dependencies between imported sections: endpoint-aware presets
//! may reference VPN profiles whose policy they compiled, rules that name
//! custom inbounds need those listeners in the merged library, and profile
//! resource kinds decide the Library version.
use crate::{
    legacy_backup::{profiles::ProfilePlan, routes::RoutePlan},
    routing::resources::Kind,
    settings,
    store::Library,
};
use std::collections::HashSet;

/// Profiles whose tunnel DNS and gates the imported presets carry themselves,
/// including the hops of a chain endpoint.
pub(super) fn carried_endpoints(plan: &ProfilePlan, routes: &RoutePlan) -> HashSet<String> {
    let mut result = HashSet::new();
    for preset in &routes.presets {
        let Some(constraints) = preset
            .legacy_constraints
            .as_ref()
            .filter(|c| c.endpoint_aware())
        else {
            continue;
        };
        for id in &constraints.endpoints {
            result.insert(id.clone());
            if let Some(profile) = plan.profiles.iter().find(|p| &p.id == id) {
                if let Ok(members) = crate::references::members(profile) {
                    result.extend(members.into_iter().map(str::to_owned));
                }
            }
        }
    }
    result
}

/// Every custom inbound tag a preset names must exist after settings merge:
/// from the selected inbound category or the current library.
pub(super) fn inbound_tags(next: &Library, routes: &RoutePlan) -> Result<(), String> {
    let available: HashSet<String> = settings::value(next, "custom_inbound")
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|inbound| inbound["tag"].as_str().map(str::to_owned))
        .collect();
    let missing = routes.presets.iter().any(|preset| {
        preset
            .legacy_constraints
            .as_ref()
            .is_some_and(|c| c.inbound_tags.iter().any(|tag| !available.contains(tag)))
    });
    if missing {
        return Err("legacy_route_inbound_requires_settings".into());
    }
    Ok(())
}

/// Hosts/rule-set packs need version 6 readers; PEM/text inputs need version 7;
/// an Xray list named by `ext:` needs version 8.
pub(super) fn resource_version(next: &mut Library) {
    if next.routing_resources.is_empty() {
        return;
    }
    let minimum = if next.routing_resources.kinds().any(Kind::asset) {
        8
    } else if next.routing_resources.kinds().any(Kind::profile_only) {
        7
    } else {
        6
    };
    next.version = next.version.max(minimum);
}
