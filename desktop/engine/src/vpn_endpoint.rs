//! Primary VPN endpoints: the sing-box endpoint type and the protocol name
//! that VPN policies, one-time codes and credentials use for it. Every place
//! that recognises an OpenVPN or OpenConnect profile asks here.
use crate::store::{Profile, ProfileKind};

pub const OPENVPN: &str = "openvpn-client";
pub const OPENCONNECT: &str = "openconnect";
const TYPES: [(&str, &str); 2] = [(OPENVPN, "openvpn"), (OPENCONNECT, "openconnect")];

/// The VPN protocol of a sing-box endpoint type.
pub fn protocol(endpoint_type: &str) -> Option<&'static str> {
    TYPES
        .iter()
        .find(|(kind, _)| *kind == endpoint_type)
        .map(|(_, protocol)| *protocol)
}
/// The sing-box endpoint type of a VPN protocol.
pub fn endpoint_type(protocol: &str) -> Option<&'static str> {
    TYPES
        .iter()
        .find(|(_, name)| *name == protocol)
        .map(|(kind, _)| *kind)
}
/// The VPN protocol of a stored profile; a VPN is always a sing-box outbound.
pub fn profile_protocol(profile: &Profile) -> Option<&'static str> {
    if profile.kind != ProfileKind::SingBoxOutbound {
        return None;
    }
    profile.config["type"].as_str().and_then(protocol)
}
/// Whether a compiled endpoint is a primary VPN endpoint.
pub fn is_vpn(endpoint: &serde_json::Value) -> bool {
    endpoint["type"].as_str().and_then(protocol).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_types_and_protocols_map_both_ways() {
        for (kind, name) in TYPES {
            assert_eq!(protocol(kind), Some(name));
            assert_eq!(endpoint_type(name), Some(kind));
        }
        assert_eq!(protocol("wireguard"), None);
        assert_eq!(endpoint_type("openvpn-client"), None);
    }
}

/// Whether an OpenConnect endpoint asks the core to run a host-check program
/// (CSD, HIP or TNCC wrapper).
#[cfg(any(target_os = "windows", test))]
fn runs_host_wrapper(endpoint: &serde_json::Value) -> bool {
    endpoint["type"] == "openconnect-client"
        && ["csd", "hip", "tncc"].iter().any(|key| {
            endpoint[*key]["wrapper_path"]
                .as_str()
                .is_some_and(|path| !path.is_empty())
        })
}

/// Windows: the core would start a wrapper directly, so a `.cmd` would pass
/// its arguments through cmd.exe's own parsing and a `.ps1` would not run at
/// all. Such a profile is refused with its own code before the core starts.
#[cfg(target_os = "windows")]
pub(crate) fn refuse_host_wrappers(request: &crate::proto::LoadConfigReq) -> Result<(), String> {
    let Some(config) = request.core_config.as_deref() else {
        return Ok(());
    };
    let config: serde_json::Value =
        serde_json::from_str(config).map_err(|_| "invalid_configuration")?;
    let endpoints = config["endpoints"].as_array().into_iter().flatten();
    let outbounds = config["outbounds"].as_array().into_iter().flatten();
    if endpoints.chain(outbounds).any(runs_host_wrapper) {
        return Err("vpn_host_check_platform_unsupported".into());
    }
    Ok(())
}

#[cfg(test)]
mod wrapper_tests {
    use serde_json::json;
    #[test]
    fn only_a_named_host_check_program_counts_as_a_wrapper() {
        for (endpoint, runs) in [
            (
                json!({"type":"openconnect-client","csd":{"wrapper_path":"C:\\csd.cmd"}}),
                true,
            ),
            (
                json!({"type":"openconnect-client","hip":{"wrapper_path":"/usr/bin/hip"}}),
                true,
            ),
            (
                json!({"type":"openconnect-client","tncc":{"wrapper_path":"tncc"}}),
                true,
            ),
            (
                json!({"type":"openconnect-client","csd":{"wrapper_path":""}}),
                false,
            ),
            (json!({"type":"openconnect-client","csd":{}}), false),
            (json!({"type":"openconnect-client"}), false),
            (
                json!({"type":"openvpn-client","csd":{"wrapper_path":"x"}}),
                false,
            ),
        ] {
            assert_eq!(super::runs_host_wrapper(&endpoint), runs, "{endpoint}");
        }
    }
}
