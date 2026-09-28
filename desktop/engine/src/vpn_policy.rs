//! Application-owned primary VPN routing/DNS policy. Never embed this metadata
//! in an endpoint JSON or infer it from an imported core tag.
use crate::{
    proto::LoadConfigReq,
    store::{Library, Profile, ProfileKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const DNS_TAG: &str = "thronium-vpn-dns-proxy";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub only_advertised_routes: bool,
    pub use_tunnel_dns: bool,
    pub block_outside_dns: bool,
}

/// Missing draft metadata must not erase an existing profile's policy. An
/// explicit JSON null is a different, intentional edit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Edit {
    #[default]
    Keep,
    Set(Option<Policy>),
}
impl<'de> Deserialize<'de> for Edit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<Policy>::deserialize(deserializer).map(Self::Set)
    }
}
impl Edit {
    pub(crate) fn resolve(self, existing: Option<Policy>) -> Option<Policy> {
        match self {
            Self::Keep => existing,
            Self::Set(policy) => policy,
        }
    }
}

pub(crate) fn protocol(profile: &Profile) -> Option<&'static str> {
    crate::vpn_endpoint::profile_protocol(profile)
}
pub(crate) fn validate_profile(profile: &Profile) -> Result<(), String> {
    let Some(policy) = profile.vpn_policy else {
        return Ok(());
    };
    // A Tailscale node has no tunnel routes or DNS of Thronium's making: only
    // Qt's `globalDNS`, which `use_tunnel_dns` carries.
    if crate::routing::tailscale::is_node(profile) {
        return if policy.only_advertised_routes || policy.block_outside_dns {
            Err("vpn_policy_profile_unsupported".into())
        } else {
            Ok(())
        };
    }
    if protocol(profile).is_none() {
        return Err("vpn_policy_profile_unsupported".into());
    }
    Ok(())
}

// Store currently migrates through Value, whose object representation collapses
// duplicates. Decode just our typed metadata from original bytes first.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireProfile {
    #[serde(default)]
    vpn_policy: Option<Policy>,
}
#[derive(Deserialize)]
struct WireLibrary {
    #[serde(default)]
    profiles: Vec<WireProfile>,
}
#[derive(Deserialize)]
struct WireBackup {
    library: WireLibrary,
}
pub(crate) fn validate_wire(bytes: &[u8], backup: bool) -> Result<(), String> {
    let library = if backup {
        serde_json::from_slice::<WireBackup>(bytes).map(|v| v.library)
    } else {
        serde_json::from_slice::<WireLibrary>(bytes)
    }
    .map_err(|_| "vpn_policy_invalid")?;
    // Read the field so this narrow validator stays warning-free. Actual
    // profile-kind and Library-version validation is done on the whole model.
    let _ = library.profiles.iter().any(|p| p.vpn_policy.is_some());
    Ok(())
}

/// The hop whose policy shapes the connection: the exit of the physical
/// sequence when it is a VPN profile with a policy. Qt applies gating and
/// tunnel DNS to the addressable exit only; a policy on an earlier hop is
/// ignored there as well, because that hop only carries the next hop's dial.
pub(crate) fn carrier<'a>(hops: &[&'a Profile]) -> Option<&'a Profile> {
    hops.last()
        .copied()
        .filter(|p| protocol(p).is_some() && p.vpn_policy.is_some())
}

pub(crate) fn validate_context(library: &Library, selected: &Profile) -> Result<(), String> {
    validate_profile(selected)?;
    if matches!(
        selected.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        return Ok(());
    }
    if selected.vpn_policy.is_none() && !library.profiles.iter().any(|p| p.vpn_policy.is_some()) {
        return Ok(());
    }
    let hops = if selected.kind == ProfileKind::AutoSelector {
        vec![]
    } else {
        crate::group_chains::sequence(
            library,
            selected,
            &crate::group_chains::policy(library, selected),
        )?
    };
    // Auxiliary targets outside the physical sequence keep their explicit
    // refusal unless an endpoint-aware imported preset compiled their tunnel
    // DNS and gate itself (Qt auxiliary endpoints are never route-gated).
    let needed = crate::vless::relevant(library, selected)?;
    let carried = crate::routing::legacy_context::carried_endpoints(library);
    if library.profiles.iter().any(|p| {
        needed.contains(&p.id)
            && p.id != selected.id
            && p.vpn_policy.is_some()
            // A node that is not the selected profile never generates DNS.
            && !crate::routing::tailscale::is_node(p)
            && !hops.iter().any(|hop| hop.id == p.id)
            && !carried.contains(&p.id)
    }) {
        return Err("vpn_policy_context_unsupported".into());
    }
    let Some(carrier) = carrier(&hops) else {
        return Ok(());
    };
    if carrier
        .config
        .get("detour")
        .is_some_and(|v| !v.is_null() && v != "")
        || crate::geodata::enabled(carrier, library)
        || library.routing.active()?.legacy_constraints.is_some()
        || crate::settings::warp::routing::enabled_for(library)
        || [
            "vpn_l3_bridge",
            "vpn_auto_redirect",
            "enable_dns_server",
            "enable_dns_routing",
        ]
        .iter()
        .any(|key| crate::settings::boolean(library, key))
    {
        return Err("vpn_policy_context_unsupported".into());
    }
    Ok(())
}

fn tagged(value: &Value, tag: &str) -> bool {
    value["tag"] == tag
        || value["tag"]
            .as_array()
            .is_some_and(|items| items.iter().any(|v| v == tag))
}
fn array_mut<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, String> {
    if value.get(key).is_none() {
        value[key] = json!([]);
    }
    value[key].as_array_mut().ok_or("vpn_policy_invalid".into())
}

pub(crate) fn apply(request: &mut LoadConfigReq, profile: &Profile) -> Result<(), String> {
    let Some(policy) = profile.vpn_policy else {
        return Ok(());
    };
    // A Tailscale node carries only `globalDNS`, which its generated DNS reads.
    if crate::routing::tailscale::is_node(profile) {
        return Ok(());
    }
    let protocol = protocol(profile).ok_or("vpn_policy_profile_unsupported")?;
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    let endpoints = core["endpoints"]
        .as_array()
        .ok_or("vpn_policy_context_unsupported")?;
    if endpoints.iter().filter(|p| tagged(p, "proxy")).count() != 1
        || !endpoints
            .iter()
            .any(|p| tagged(p, "proxy") && p["type"] == profile.config["type"])
        || core["outbounds"]
            .as_array()
            .is_some_and(|items| items.iter().any(|p| tagged(p, "proxy")))
    {
        return Err("vpn_policy_context_unsupported".into());
    }
    if !core["route"].is_object() || !core["dns"].is_object() {
        return Err("vpn_policy_invalid".into());
    }
    let gated = policy.only_advertised_routes;
    if policy.use_tunnel_dns || gated {
        let servers = core["dns"]["servers"]
            .as_array()
            .ok_or("vpn_policy_dns_unsupported")?;
        if servers.iter().any(|server| {
            tagged(server, DNS_TAG)
                || (matches!(server["type"].as_str(), Some("openvpn" | "openconnect"))
                    && server["endpoint"] == "proxy")
        }) {
            return Err("vpn_policy_tag_conflict".into());
        }
        if gated && !policy.block_outside_dns {
            let direct: Vec<_> = servers.iter().filter(|s| tagged(s, "dns-direct")).collect();
            if direct.len() != 1
                || !matches!(
                    direct[0]["type"].as_str(),
                    Some("local" | "udp" | "tcp" | "tls" | "https" | "quic" | "h3")
                )
                || direct[0]
                    .get("detour")
                    .is_some_and(|v| !v.is_null() && v != "direct")
                || direct[0]
                    .get("domain_resolver")
                    .is_some_and(|v| !v.is_null())
            {
                return Err("vpn_policy_dns_unsupported".into());
            }
        }
        let mut server = json!({"type":protocol,"tag":DNS_TAG,"endpoint":"proxy"});
        if gated {
            server["accept_default_resolvers"] = json!(true);
            server["accept_search_domain"] = json!(true);
        }
        array_mut(&mut core["dns"], "servers")?.push(server);
        array_mut(&mut core["dns"], "rules")?.insert(
            0,
            json!({"preferred_by":[DNS_TAG],"action":"route","server":DNS_TAG}),
        );
        if gated {
            core["dns"]["final"] = json!(if policy.block_outside_dns {
                DNS_TAG
            } else {
                "dns-direct"
            });
        }
    }
    if gated && core["route"]["final"] == "proxy" {
        let rules = array_mut(&mut core["route"], "rules")?;
        rules.push(json!({"preferred_by":["proxy"],"action":"route","outbound":"proxy"}));
        rules.push(json!({"action":"reject"}));
    }
    request.core_config = Some(core.to_string());
    Ok(())
}

#[cfg(test)]
mod tests;
