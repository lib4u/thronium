//! The TUN listener each system gets, and the system DNS mode it asks the
//! managed side for.
use super::{effective_stack, Settings, SystemDns, INTERFACE, RULE_PRIORITY};
use serde_json::{json, Value};

const IPV4_ADDRESS: &str = super::IPV4_ADDRESS;
const IPV6_ADDRESS: &str = super::IPV6_ADDRESS;
/// Where Windows sends DNS while the service keeps the default interface
/// pointed here, as Qt-Throne does.
pub(crate) const DNS_INBOUND: &str = "dns-in";
pub(crate) const DNS_LISTEN: &str = "127.1.1.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum System {
    Linux,
    Windows,
}

impl System {
    pub(crate) fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// Adds the TUN inbound and DNS capture to `config`; returns the system DNS
/// mode for the managed side, if any applies here.
pub(crate) fn add(
    config: &mut Value,
    settings: &Settings,
    system: System,
) -> Result<Option<String>, String> {
    let mut addresses = vec![IPV4_ADDRESS];
    if settings.ipv6 {
        addresses.push(IPV6_ADDRESS)
    }
    let mut excludes = vec![
        "127.0.0.0/8".to_owned(),
        "255.255.255.255/32".to_owned(),
        "::1/128".to_owned(),
    ];
    excludes.extend(settings.exclude_addresses.clone());
    excludes.sort();
    excludes.dedup();
    let stack = effective_stack(settings.stack, config);
    let inbound = match system {
        System::Linux => json!({
            "type":"tun", "tag":INTERFACE, "interface_name":INTERFACE,
            "address":addresses, "mtu":settings.mtu, "stack":stack,
            "auto_route":true, "auto_redirect":false, "iproute2_rule_index":RULE_PRIORITY,
            // The managed supervisor applies and verifies per-link system DNS.
            // Keep the dependency's asynchronous resolver mutation disabled.
            "dns_mode":"disabled", "strict_route":settings.strict_route,
            "route_exclude_address":excludes
        }),
        // No policy rules or nftables here. With capture on, sing-tun gives the
        // adapter the TUN's own DNS address, and strict route has WFP block
        // port 53 everywhere else.
        System::Windows => json!({
            "type":"tun", "tag":INTERFACE, "interface_name":INTERFACE,
            "address":addresses, "mtu":settings.mtu, "stack":stack,
            "auto_route":true, "strict_route":settings.strict_route,
            "dns_mode": if settings.dns_hijack {"hijack"} else {"disabled"},
            "route_exclude_address":excludes
        }),
    };
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or("invalid_configuration")?;
    inbounds.push(inbound);
    let mode = match (system, settings.system_dns) {
        (System::Linux, SystemDns::Resolved) => Some("resolved"),
        (System::Linux, SystemDns::Resolvconf) => Some("resolvconf"),
        (System::Windows, SystemDns::Interface) => Some("interface"),
        _ => None,
    };
    // The local DNS server setting may already listen there; then it is the
    // one Windows is pointed at.
    let mut dns_inbound = DNS_INBOUND.to_owned();
    if mode == Some("interface") {
        match inbounds
            .iter()
            .find(|i| i["listen"] == DNS_LISTEN && i["listen_port"] == 53)
        {
            Some(existing) => {
                dns_inbound = existing["tag"]
                    .as_str()
                    .ok_or("invalid_configuration")?
                    .to_owned()
            }
            None => inbounds.push(json!({
                "type":"direct", "tag":DNS_INBOUND, "listen":DNS_LISTEN, "listen_port":53
            })),
        }
    }
    config["route"]["auto_detect_interface"] = json!(true);
    let rules = config["route"]["rules"]
        .as_array_mut()
        .ok_or("invalid_configuration")?;
    if settings.dns_hijack {
        rules.insert(
            0,
            json!({"inbound":[INTERFACE], "port":53, "action":"hijack-dns"}),
        );
    }
    if mode == Some("interface") {
        rules.insert(0, json!({"inbound":[dns_inbound], "action":"hijack-dns"}));
    }
    Ok(mode.map(str::to_owned))
}
