use super::{dns, inbounds::Inbounds, validate::*, *};
pub(super) mod structured;
const MATCH: &[&str] = &[
    "rule_set",
    "inbound",
    "ip_version",
    "network",
    "protocol",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "source_ip_is_private",
    "ip_cidr",
    "ip_is_private",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "wifi_ssid",
    "wifi_bssid",
    "invert",
];
const ACTION: &[&str] = &[
    "action",
    "outbound",
    "override_address",
    "override_port",
    "method",
    "no_drop",
    "override_destination",
    "strategy",
    "server",
    "timeout",
    "disable_cache",
    "rewrite_ttl",
    "client_subnet",
    "sniffer",
    "rcode",
    "answer",
    "ns",
    "extra",
];
fn match_field(key: &str, v: &Value, is_dns: bool, inbounds: &Inbounds) -> Result<()> {
    if is_dns && matches!(key, "ip_cidr" | "ip_is_private") {
        return Err("legacy_route_field_unsupported");
    }
    match key {
        "source_ip_is_private" | "ip_is_private" | "invert" => {
            bool_value(v)?;
        }
        "ip_version" => {
            if !matches!(v.as_i64(), Some(4 | 6)) {
                return Err("legacy_route_structure");
            }
        }
        "source_port" | "port" => {
            for p in list(v)? {
                port(p)?
            }
        }
        "source_port_range" | "port_range" => {
            for s in strings(v)? {
                let (start, end) = s.split_once(':').ok_or("legacy_route_structure")?;
                let start = if start.is_empty() {
                    1
                } else {
                    start.parse::<u16>().map_err(|_| "legacy_route_structure")?
                };
                let end = if end.is_empty() {
                    65535
                } else {
                    end.parse::<u16>().map_err(|_| "legacy_route_structure")?
                };
                if start == 0 || end == 0 || start > end {
                    return Err("legacy_route_structure");
                }
            }
        }
        "source_ip_cidr" | "ip_cidr" => {
            if is_dns && key == "ip_cidr" {
                return Err("legacy_route_field_unsupported");
            }
            for s in strings(v)? {
                cidr(s)?
            }
        }
        "domain_regex" | "process_path_regex" => {
            for s in strings(v)? {
                regexp(s)?
            }
        }
        "network" => {
            for s in strings(v)? {
                if !matches!(s, "tcp" | "udp") && !(s == "icmp" && !is_dns) {
                    return Err("legacy_route_structure");
                }
            }
        }
        "protocol" => {
            for s in strings(v)? {
                if !matches!(
                    s,
                    "tls"
                        | "http"
                        | "quic"
                        | "dns"
                        | "stun"
                        | "bittorrent"
                        | "dtls"
                        | "ssh"
                        | "rdp"
                        | "ntp"
                ) {
                    return Err("legacy_route_structure");
                }
            }
        }
        "inbound" => {
            for s in strings(v)? {
                inbounds.check(s)?;
            }
        }
        "query_type" => {
            for t in list(v)? {
                if !t.as_u64().is_some_and(|n| n <= 65535)
                    && !matches!(
                        t.as_str(),
                        Some(
                            "A" | "AAAA"
                                | "CNAME"
                                | "MX"
                                | "TXT"
                                | "NS"
                                | "SOA"
                                | "PTR"
                                | "SRV"
                                | "HTTPS"
                                | "SVCB"
                                | "ANY"
                        )
                    )
                {
                    return Err("legacy_route_structure");
                }
            }
        }
        _ => {
            strings(v)?;
        }
    }
    Ok(())
}
/// Cross-rule context of one conversion: profile references, the DNS the
/// rule may name and the inbound listeners it may match.
#[derive(Clone, Copy)]
pub(super) struct Context<'a> {
    pub profiles: Option<&'a ProfilePlan>,
    pub dns: &'a Value,
    pub inbounds: &'a Inbounds,
}
pub(super) fn validate(
    v: &mut Value,
    context: Context<'_>,
    nested: bool,
    depth: usize,
) -> Result<()> {
    validate_rule(v, context, nested, depth, false)
}
pub(super) fn validate_dns(
    v: &mut Value,
    dns: &Value,
    inbounds: &Inbounds,
    nested: bool,
    depth: usize,
) -> Result<()> {
    let context = Context {
        profiles: None,
        dns,
        inbounds,
    };
    validate_rule(v, context, nested, depth, true)
}
fn validate_rule(
    v: &mut Value,
    context: Context<'_>,
    nested: bool,
    depth: usize,
    is_dns: bool,
) -> Result<()> {
    let Context {
        profiles,
        dns,
        inbounds,
    } = context;
    if depth > 32 {
        return Err("legacy_route_limit");
    }
    let logical = match v.get("type") {
        None => false,
        Some(t) => match string(t)? {
            "" | "default" => false,
            "logical" => true,
            _ => return Err("legacy_route_structure"),
        },
    };
    let obj = v.as_object().ok_or("legacy_route_structure")?;
    for (key, value) in obj {
        if key == "type" {
            continue;
        }
        if logical && matches!(key.as_str(), "mode" | "rules" | "invert") {
            continue;
        }
        if !logical && is_dns && key == "preferred_by" {
            dns::preferred_by(value, dns)?;
            continue;
        }
        if !logical && (MATCH.contains(&key.as_str()) || is_dns && key == "query_type") {
            match_field(key, value, is_dns, inbounds)?;
            continue;
        }
        if !nested && ACTION.contains(&key.as_str()) {
            continue;
        }
        return Err(if key == "rule_set" {
            "legacy_route_ruleset_unsupported"
        } else {
            "legacy_route_field_unsupported"
        });
    }
    if logical {
        if !matches!(v["mode"].as_str(), Some("and" | "or")) {
            return Err("legacy_route_structure");
        }
        if let Some(invert) = v.get("invert") {
            bool_value(invert)?;
        }
        let children = v["rules"].as_array_mut().ok_or("legacy_route_structure")?;
        if children.is_empty() || children.len() > 1000 {
            return Err("legacy_route_limit");
        }
        for child in children {
            validate_rule(child, context, true, depth + 1, is_dns)?
        }
    }
    if nested {
        return Ok(());
    }
    let action_value = v
        .get("action")
        .map(string)
        .transpose()?
        .unwrap_or("route")
        .to_owned();
    let action = action_value.as_str();
    let allowed: &[&str] = if is_dns {
        match action {
            "route" => &[
                "server",
                "strategy",
                "timeout",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
            ],
            "route-options" => &[
                "strategy",
                "timeout",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
            ],
            "reject" => &["method", "no_drop"],
            "predefined" => &["rcode", "answer", "ns", "extra"],
            _ => return Err("legacy_route_action_unsupported"),
        }
    } else {
        match action {
            "route" => &["outbound", "override_address", "override_port"],
            "route-options" => &["override_address", "override_port"],
            "reject" => &["method", "no_drop"],
            "hijack-dns" => &[],
            "sniff" => &["override_destination", "sniffer", "timeout"],
            "resolve" => &[
                "server",
                "strategy",
                "timeout",
                "disable_cache",
                "rewrite_ttl",
                "client_subnet",
            ],
            _ => return Err("legacy_route_action_unsupported"),
        }
    };
    for key in ACTION {
        if *key != "action" && v.get(*key).is_some() && !allowed.contains(key) {
            return Err("legacy_route_action_unsupported");
        }
    }
    if action == "route" {
        if is_dns {
            dns::tag(v.get("server").ok_or("legacy_dns_reference_missing")?, dns)?;
        } else {
            v["outbound"] = json!(target(
                v.get("outbound").ok_or("legacy_route_reference_missing")?,
                profiles
            )?);
        }
    }
    if action == "route-options" && !allowed.iter().any(|k| v.get(*k).is_some()) {
        return Err("legacy_route_action_unsupported");
    }
    for key in allowed {
        let Some(value) = v.get(*key) else { continue };
        match *key {
            "outbound" => {}
            "server" => {
                dns::tag(value, dns)?;
            }
            "strategy" => strategy(string(value)?)?,
            "override_address" => host(nonempty(value)?)?,
            "override_port" => port(value)?,
            "method" => {
                if !matches!(value.as_str(), Some("default" | "drop" | "reply" | "")) {
                    return Err("legacy_route_action_unsupported");
                }
            }
            "no_drop" | "override_destination" | "disable_cache" => {
                bool_value(value)?;
            }
            "timeout" => duration(value)?,
            "rewrite_ttl" => {
                if !value.as_u64().is_some_and(|n| n <= u32::MAX as u64) {
                    return Err("legacy_route_structure");
                }
            }
            "client_subnet" => cidr(nonempty(value)?)?,
            "sniffer" => {
                for s in strings(value)? {
                    if !matches!(
                        s,
                        "tls"
                            | "http"
                            | "quic"
                            | "dns"
                            | "stun"
                            | "bittorrent"
                            | "dtls"
                            | "ssh"
                            | "rdp"
                            | "ntp"
                    ) {
                        return Err("legacy_route_structure");
                    }
                }
            }
            "rcode" | "answer" | "ns" | "extra" => dns::predefined::field(key, value)?,
            _ => unreachable!(),
        }
    }
    if v["method"] == "drop" && v["no_drop"] == true {
        return Err("legacy_route_action_unsupported");
    }
    Ok(())
}
