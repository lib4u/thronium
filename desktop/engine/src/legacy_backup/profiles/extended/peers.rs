//! Tailscale endpoints and Direct outbounds, which have no server of their own.
use super::*;

pub(crate) fn tailscale(source: &SourceProfile, report: &mut Vec<Issue>) -> Converted {
    let mut config = source.outbound.clone();
    keys(
        &config,
        &[
            "type",
            "tag",
            "state_directory",
            "auth_key",
            "control_url",
            "ephemeral",
            "hostname",
            "accept_routes",
            "exit_node",
            "exit_node_allow_lan_access",
            "advertise_routes",
            "advertise_exit_node",
            "globalDNS",
        ],
    )?;
    if config["type"] != "tailscale" {
        return Err("legacy_profile_discriminator");
    }
    strings(
        &config,
        &[
            "tag",
            "state_directory",
            "auth_key",
            "control_url",
            "hostname",
            "exit_node",
        ],
    )?;
    booleans(
        &config,
        &[
            "ephemeral",
            "accept_routes",
            "exit_node_allow_lan_access",
            "advertise_exit_node",
            "globalDNS",
        ],
    )?;
    if config.get("advertise_routes").is_some_and(|v| {
        !v.as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
    }) {
        return Err("legacy_profile_structure");
    }
    let object = config.as_object_mut().ok_or("legacy_profile_structure")?;
    // The node state stays with Throne; this profile signs in as a new node.
    if object
        .remove("state_directory")
        .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
    {
        report.push(pi(source, "legacy_tailscale_state_omitted"));
    }
    // Build never sends globalDNS: it selects Throne's generated Tailscale DNS,
    // which the imported profile carries as its policy instead.
    object.remove("globalDNS");
    Ok((ProfileKind::SingBoxOutbound, config))
}
pub(crate) fn direct(source: &SourceProfile) -> Converted {
    let config = source.outbound.clone();
    keys(
        &config,
        &[
            "type",
            "tag",
            "reuse_addr",
            "connect_timeout",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
            "bind_interface",
            "inet4_bind_address",
            "inet6_bind_address",
        ],
    )?;
    if config["type"] != "direct" {
        return Err("legacy_profile_discriminator");
    }
    dial(&config)?;
    Ok((ProfileKind::SingBoxOutbound, config))
}
