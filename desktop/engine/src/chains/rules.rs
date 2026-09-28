//! Which profiles may be chain hops and where. The rules mirror Qt's chain
//! scan: any sing-box or Xray outbound, any userspace endpoint (WireGuard,
//! OpenVPN, OpenConnect, Tailscale) in any position, one complete Xray
//! configuration as the first hop only, never a complete sing-box
//! configuration, a pool or a system-owned interface.
use super::MAX_HOPS;
use crate::{
    references::members,
    store::{Profile, ProfileKind},
};
use serde_json::Value;
use std::collections::HashSet;

/// sing-box outbound types emitted under `endpoints`; they share the outbound
/// tag namespace and are addressed like outbounds.
pub const ENDPOINT_TYPES: [&str; 4] = [
    "wireguard",
    "tailscale",
    crate::vpn_endpoint::OPENVPN,
    crate::vpn_endpoint::OPENCONNECT,
];
/// Endpoints that hold their own authenticated session with a VPN service.
/// Qt keeps them out of auto-selector pools: a pool starts every member's
/// session at once and may spend interactive credentials in the background.
const VPN_ENDPOINT_TYPES: [&str; 3] = [
    "tailscale",
    crate::vpn_endpoint::OPENVPN,
    crate::vpn_endpoint::OPENCONNECT,
];
/// Keys that pin a local UDP port; sing-box refuses them together with `detour`.
const FIXED_PORT_KEYS: [&str; 2] = ["listen_port", "dtls_local_port"];
/// Keys that hand the interface to the host instead of the userspace stack.
const SYSTEM_KEYS: [&str; 2] = ["system", "system_interface"];

pub(crate) fn is_endpoint_type(config: &Value) -> bool {
    config["type"]
        .as_str()
        .is_some_and(|t| ENDPOINT_TYPES.contains(&t))
}
/// A sing-box endpoint hop: emitted under `endpoints`, addressed like an outbound.
pub(crate) fn is_endpoint(p: &Profile) -> bool {
    p.kind == ProfileKind::SingBoxOutbound && is_endpoint_type(&p.config)
}
pub(crate) fn is_vpn_endpoint(p: &Profile) -> bool {
    p.kind == ProfileKind::SingBoxOutbound
        && p.config["type"]
            .as_str()
            .is_some_and(|t| VPN_ENDPOINT_TYPES.contains(&t))
}
fn flag(config: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        config
            .get(*key)
            .is_some_and(|v| !v.is_null() && v != false && v != "" && v != 0)
    })
}

pub fn flatten<'a>(
    profile: &'a Profile,
    profiles: &'a [Profile],
) -> Result<Vec<&'a Profile>, String> {
    fn visit<'a>(
        p: &'a Profile,
        all: &'a [Profile],
        stack: &mut HashSet<String>,
        out: &mut Vec<&'a Profile>,
    ) -> Result<(), String> {
        if p.kind == ProfileKind::Chain {
            if stack.len() >= MAX_HOPS || !stack.insert(p.id.clone()) {
                return Err("chain_cycle".into());
            }
            for id in members(p)? {
                let member = all
                    .iter()
                    .find(|p| p.id == id)
                    .ok_or("chain_profile_missing")?;
                visit(member, all, stack, out)?;
            }
            stack.remove(&p.id);
        } else {
            match p.kind {
                ProfileKind::SingBoxOutbound | ProfileKind::XrayOutbound => {
                    // A system interface is owned by the host, not by a chain.
                    if is_endpoint(p) && flag(&p.config, &SYSTEM_KEYS) {
                        return Err("chain_endpoint_context_unsupported".into());
                    }
                }
                ProfileKind::XrayConfig | ProfileKind::ExternalCore => {}
                // One sing-box instance per connection: a complete sing-box
                // configuration cannot run beside the managed core.
                ProfileKind::SingBoxConfig => return Err("chain_full_config_unsupported".into()),
                _ => return Err("chain_hop_unsupported".into()),
            }
            out.push(p);
            if out.len() > MAX_HOPS {
                return Err("chain_too_long".into());
            }
        }
        Ok(())
    }
    let mut result = vec![];
    visit(profile, profiles, &mut HashSet::new(), &mut result)?;
    validate_sequence(&result)?;
    Ok(result)
}

/// Validate the complete physical path, including group front/landing hops.
pub(crate) fn validate_sequence(result: &[&Profile]) -> Result<(), String> {
    if result.len() > MAX_HOPS {
        return Err("chain_too_long".into());
    }
    // Qt allows one complete Xray configuration per chain and only where sing-box
    // dials it directly: the first physical hop. Any later position would need the
    // instance's own outbounds rewritten to dial through the earlier hops.
    let full: Vec<usize> = result
        .iter()
        .enumerate()
        .filter(|(_, p)| p.kind == ProfileKind::XrayConfig)
        .map(|(i, _)| i)
        .collect();
    if full.len() > 1 {
        return Err("chain_full_config_limit".into());
    }
    if full.first().is_some_and(|&i| i != 0) {
        return Err("chain_full_config_position".into());
    }
    // Qt allows one external core per chain, and only as the first physical
    // hop: its server is local, so nothing may be dialled before it, and the
    // hops after it are carried by the core the person runs themselves.
    let external: Vec<usize> = result
        .iter()
        .enumerate()
        .filter(|(_, p)| p.kind == ProfileKind::ExternalCore)
        .map(|(i, _)| i)
        .collect();
    if external.len() > 1 {
        return Err("external_chain_limit".into());
    }
    if external.first().is_some_and(|&i| i != 0) {
        return Err("external_chain_position".into());
    }
    if !external.is_empty() && !full.is_empty() {
        return Err("external_chain_full_config".into());
    }
    // sing-box refuses a fixed local port together with `detour`: it belongs
    // to the device-side hop only.
    if result
        .iter()
        .skip(1)
        .any(|p| is_endpoint(p) && flag(&p.config, &FIXED_PORT_KEYS))
    {
        return Err("chain_endpoint_listen_port_unsupported".into());
    }
    Ok(())
}
