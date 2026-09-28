//! Translate Happ policy for managed outbounds. Full JSON owns its own policy.
//! Upstream keys (dev-docs/routing.md) plus the provider header fields
//! RouteOrder/UseChunkFiles; DomainStrategy maps Xray resolution timing onto
//! positioned sing-box `resolve` actions.
use super::provider_routing::ProviderRouting;
use crate::{geodata::Assets, proto::LoadConfigReq};
use serde_json::{json, Value};
use std::net::IpAddr;
mod dns;
#[cfg(test)]
mod tests;

/// Keys this build translates. A provider that adds its own key keeps the
/// known part of its policy; the ignored names reach the subscription card
/// through `ProviderRouting::summary`, so nothing is dropped silently.
pub(super) const KNOWN_KEYS: [&str; 22] = [
    "Name",
    "GlobalProxy",
    "RemoteDNSType",
    "RemoteDNSDomain",
    "RemoteDNSIP",
    "DomesticDNSType",
    "DomesticDNSDomain",
    "DomesticDNSIP",
    "Geoipurl",
    "Geositeurl",
    "LastUpdated",
    "DnsHosts",
    "DirectSites",
    "DirectIp",
    "ProxySites",
    "ProxyIp",
    "BlockSites",
    "BlockIp",
    "DomainStrategy",
    "FakeDNS",
    "RouteOrder",
    "UseChunkFiles",
];

pub(crate) fn apply(
    request: &mut LoadConfigReq,
    provider: &ProviderRouting,
    assets: &Assets,
) -> Result<(), String> {
    if provider.error.is_some() {
        return Err("subscription_routing_invalid".into());
    }
    let c = &provider.config;
    // Unknown keys are ignored, as in the Qt client: an unrecognised extension
    // must not discard the policy the user already accepted for this group.
    c.as_object().ok_or("subscription_routing_invalid")?;
    // Chunked site/IP lists live in separate downloads; the inline lists
    // would be incomplete without them.
    if boolean(&c["UseChunkFiles"], false)? {
        return Err("subscription_chunk_files_unsupported".into());
    }
    let fake_dns = boolean(&c["FakeDNS"], false)?;
    let order = c["RouteOrder"]
        .as_str()
        .unwrap_or("block-proxy-direct")
        .split('-')
        .collect::<Vec<_>>();
    if order.len() != 3
        || ["block", "proxy", "direct"]
            .iter()
            .any(|a| order.iter().filter(|v| *v == a).count() != 1)
    {
        return Err("subscription_routing_unsupported".into());
    }
    let strategy = c["DomainStrategy"].as_str().unwrap_or("IPIfNonMatch");
    if !matches!(strategy, "AsIs" | "IPIfNonMatch" | "IPOnDemand") {
        return Err("subscription_domain_strategy_unsupported".into());
    }
    let mut sets = vec![];
    let mut traffic = vec![json!({"action":"sniff"})];
    let mut dns_rules = vec![];
    let mut ip_rules = vec![];
    let mut first_ip_rule = None;
    for action in order {
        let prefix = match action {
            "direct" => "Direct",
            "proxy" => "Proxy",
            _ => "Block",
        };
        for (suffix, sites) in [("Sites", true), ("Ip", false)] {
            let entries = match c.get(format!("{prefix}{suffix}")) {
                None => vec![],
                Some(Value::Array(a)) => a.clone(),
                _ => return Err("subscription_routing_invalid".into()),
            };
            for entry in entries {
                let value = entry
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or("subscription_routing_invalid")?;
                let mut rule = condition(value, sites, assets, &mut sets)?;
                if sites {
                    let mut dns = rule.clone();
                    if action == "block" {
                        dns["action"] = json!("reject")
                    } else {
                        dns["action"] = json!("route");
                        dns["server"] = json!(if action == "direct" {
                            "dns-direct"
                        } else {
                            "dns-remote"
                        })
                    }
                    dns_rules.push(dns);
                }
                if action == "block" {
                    rule["action"] = json!("reject")
                } else {
                    rule["action"] = json!("route");
                    rule["outbound"] = json!(action)
                }
                if !sites {
                    first_ip_rule.get_or_insert(traffic.len());
                    ip_rules.push(rule.clone())
                }
                traffic.push(rule);
            }
        }
    }
    match strategy {
        // Xray resolves once no site rule matched: literal IP rules first,
        // then the same IP rules again for resolved destinations.
        "IPIfNonMatch" if !ip_rules.is_empty() => {
            traffic.push(json!({"action":"resolve"}));
            traffic.extend(ip_rules);
        }
        // Xray resolves as soon as an IP rule is evaluated: one resolve in
        // RouteOrder position, before the first IP rule.
        "IPOnDemand" => {
            if let Some(index) = first_ip_rule {
                traffic.insert(index, json!({"action":"resolve"}));
            }
        }
        _ => {}
    }
    let mut servers = vec![
        dns::server(c, "Domestic", "dns-direct", "direct")?,
        dns::server(c, "Remote", "dns-remote", "proxy")?,
    ];
    // Order as Throne's generated DNS: hosts, FakeIP, then domain policies.
    let mut head = vec![];
    if let Some((server, rule)) = dns::hosts(c)? {
        servers.push(server);
        head.push(rule);
    }
    if fake_dns {
        let (server, rule) = dns::fake_ip();
        servers.push(server);
        head.push(rule);
    }
    head.extend(dns_rules);
    let dns_rules = head;
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    dns::pin_resolvers(&mut core, c);
    // Internal chain bridge rules precede policy, as in the client routing compiler.
    let mut rules = core["route"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    rules.extend(traffic);
    core["route"] = json!({"final":if boolean(&c["GlobalProxy"],true)? {"proxy"}else{"direct"},"auto_detect_interface":true,"default_domain_resolver":"dns-direct","rules":rules,"rule_set":sets});
    core["dns"] =
        json!({"servers":servers,"rules":dns_rules,"final":"dns-remote","reverse_mapping":true});
    if fake_dns {
        core["dns"]["independent_cache"] = json!(true);
    }
    request.core_config = Some(core.to_string());
    Ok(())
}
fn boolean(value: &Value, default: bool) -> Result<bool, String> {
    match value {
        Value::Null => Ok(default),
        Value::Bool(v) => Ok(*v),
        Value::String(v) if v == "true" => Ok(true),
        Value::String(v) if v == "false" => Ok(false),
        _ => Err("subscription_routing_invalid".into()),
    }
}
fn condition(
    value: &str,
    sites: bool,
    assets: &Assets,
    sets: &mut Vec<Value>,
) -> Result<Value, String> {
    if value.starts_with(if sites { "geosite:" } else { "geoip:" }) {
        let set = assets.rule_set(value)?;
        let tag = set["tag"].clone();
        if !sets.iter().any(|s| s["tag"] == tag) {
            sets.push(set)
        }
        return Ok(json!({"rule_set":[tag]}));
    }
    if !sites {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(a, p)| (a, Some(p)));
        let address: IpAddr = address
            .parse()
            .map_err(|_| "subscription_routing_unsupported")?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        let bits = prefix
            .map(str::parse::<u8>)
            .transpose()
            .map_err(|_| "subscription_routing_unsupported")?
            .unwrap_or(max);
        if bits > max {
            return Err("subscription_routing_unsupported".into());
        }
        return Ok(json!({"ip_cidr":[format!("{address}/{bits}")]}));
    }
    let (key, value) = if let Some(v) = value.strip_prefix("domain:") {
        ("domain_suffix", v)
    } else if let Some(v) = value.strip_prefix("full:") {
        ("domain", v)
    } else if let Some(v) = value.strip_prefix("regexp:") {
        ("domain_regex", v)
    } else if let Some(v) = value.strip_prefix("keyword:") {
        ("domain_keyword", v)
    } else if value.contains(':') {
        return Err("subscription_routing_unsupported".into());
    } else {
        ("domain_keyword", value)
    };
    if value.is_empty() {
        return Err("subscription_routing_invalid".into());
    }
    let mut rule = json!({});
    rule[key] = json!([value]);
    Ok(rule)
}
