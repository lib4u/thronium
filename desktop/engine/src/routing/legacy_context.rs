//! First-generation imported policies own their DNS and ordered route rules.
//! Reject incompatible overlays before CheckConfig/Start can replace a session.
use crate::{
    settings,
    store::{Library, Profile, ProfileKind},
    system_proxy::ConnectionMode,
};
use std::collections::HashSet;

/// Tags of the library's additional inbounds, as the runtime will emit them.
fn custom_inbound_tags(library: &Library) -> HashSet<String> {
    settings::value(library, "custom_inbound")
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|inbound| inbound["tag"].as_str().map(str::to_owned))
        .collect()
}

/// Safe public codes only: no setting values, endpoint addresses or credentials.
pub fn conflicts(library: &Library, preset: &crate::routing::RoutingProfile) -> Vec<&'static str> {
    let mut result = Vec::new();
    for (key, code) in [
        ("enable_dns_routing", "legacy_routing_dns_follow_conflict"),
        ("enable_dns_server", "legacy_routing_dns_listener_conflict"),
        ("adblock_enable", "legacy_routing_adblock_conflict"),
        ("enable_redirect", "legacy_routing_redirect_conflict"),
        ("use_mozilla_certs", "legacy_routing_certificates_conflict"),
    ] {
        if settings::boolean(library, key) {
            result.push(code);
        }
    }
    let constraints = preset.legacy_constraints.as_ref();
    if constraints.is_some_and(|c| c.warp_enabled) {
        if !settings::boolean(library, "enable_warp") {
            result.push("legacy_routing_warp_required");
        }
    } else if settings::warp::routing::enabled_for_preset(library, preset) {
        result.push("legacy_routing_warp_conflict");
    }
    if settings::integer(library, "core_dns_in_port") > 0 {
        result.push("legacy_routing_core_dns_conflict");
    }
    let inbounds = custom_inbound_tags(library);
    match constraints.filter(|c| c.endpoint_aware()) {
        // Rules were converted against the source inbound list: each named
        // custom tag must exist here, other additional inbounds are harmless.
        Some(c) => {
            if c.inbound_tags.iter().any(|tag| !inbounds.contains(tag)) {
                result.push("legacy_routing_inbound_missing");
            }
        }
        None if !inbounds.is_empty() => result.push("legacy_routing_inbounds_conflict"),
        None => {}
    }
    if !settings::string(library, "core_box_underlying_dns").is_empty()
        && preset.dns["servers"]
            .as_array()
            .is_some_and(|servers| servers.iter().any(|server| server["type"] == "local"))
    {
        result.push("legacy_routing_local_dns_conflict");
    }
    if library.preferences.connection_mode == ConnectionMode::Tun {
        result.push("legacy_routing_tun_unsupported");
    }
    result
}

/// Profiles whose tunnel policy the active endpoint-aware preset compiled
/// itself: listed auxiliary endpoints and the hops of listed chains.
pub(crate) fn carried_endpoints(library: &Library) -> HashSet<String> {
    let mut result = HashSet::new();
    let Some(constraints) = library
        .routing
        .active()
        .ok()
        .and_then(|p| p.legacy_constraints.as_ref())
        .filter(|c| c.endpoint_aware())
    else {
        return result;
    };
    for id in &constraints.endpoints {
        result.insert(id.clone());
        if let Some(chain) = library
            .profiles
            .iter()
            .find(|p| &p.id == id && p.kind == ProfileKind::Chain)
        {
            if let Ok(hops) = crate::chains::flatten(chain, &library.profiles) {
                result.extend(hops.iter().map(|p| p.id.clone()));
            }
        }
    }
    result
}

pub(crate) fn validate(library: &Library, selected: &Profile) -> Result<(), String> {
    // Full JSON configurations already own their complete policy. The routing
    // page explicitly identifies that separate mode; presets do not affect it.
    if matches!(
        selected.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        return Ok(());
    }
    let Some(constraints) = library.routing.active()?.legacy_constraints.as_ref() else {
        return Ok(());
    };
    if !constraints.valid() {
        return Err("invalid_routing".into());
    }
    if let Some(code) = conflicts(library, library.routing.active()?).first() {
        return Err((*code).into());
    }
    if constraints.endpoint_aware() {
        // Endpoint targets, auxiliary tunnels and their DNS are part of the
        // converted preset; the native compiler emits them like any other.
        return Ok(());
    }
    // Includes auxiliary route targets, chains, selectors and group front/landing
    // hops. A nonselected endpoint elsewhere in the library is irrelevant.
    let ids = crate::vless::relevant(library, selected)?;
    if std::iter::once(selected)
        .chain(library.profiles.iter().filter(|p| ids.contains(&p.id)))
        .any(crate::chains::is_endpoint)
    {
        return Err("legacy_routing_endpoint_unsupported".into());
    }
    Ok(())
}

#[cfg(test)]
mod endpoint_tests;
#[cfg(test)]
mod tests;
