use super::{inbounds::Inbounds, rules, validate::*, *};
use std::net::IpAddr;
pub(super) mod predefined;
mod synthetic;
pub(super) fn tag<'a>(v: &'a Value, dns: &Value) -> Result<&'a str> {
    let name = nonempty(v)?;
    if !dns["servers"]
        .as_array()
        .ok_or("legacy_dns_invalid")?
        .iter()
        .any(|s| s["tag"] == name)
    {
        return Err("legacy_dns_reference_missing");
    }
    Ok(name)
}
pub(super) fn preferred_by(value: &Value, dns: &Value) -> Result<()> {
    for name in strings(value)? {
        tag(&Value::String(name.into()), dns)?;
        if !dns["servers"].as_array().is_some_and(|servers| {
            servers.iter().any(|server| {
                server["tag"] == name && matches!(server["type"].as_str(), Some("hosts" | "local"))
            })
        }) {
            return Err("legacy_route_runtime_unsupported");
        }
    }
    Ok(())
}
pub(super) fn resolver<'a>(v: &'a Value, dns: &Value) -> Result<&'a str> {
    if v.is_string() {
        return tag(v, dns);
    }
    object_keys(
        v,
        &[
            "server",
            "strategy",
            "disable_cache",
            "rewrite_ttl",
            "client_subnet",
        ],
    )?;
    let name = tag(v.get("server").ok_or("legacy_dns_reference_missing")?, dns)?;
    if let Some(v) = v.get("strategy") {
        strategy(string(v)?)?
    }
    if let Some(v) = v.get("disable_cache") {
        bool_value(v)?;
    }
    if let Some(v) = v.get("rewrite_ttl") {
        if !v.as_u64().is_some_and(|n| n <= u32::MAX as u64) {
            return Err("legacy_dns_invalid");
        }
    }
    if let Some(v) = v.get("client_subnet") {
        cidr(nonempty(v)?)?
    }
    Ok(name)
}
pub(super) fn validate(v: &Value, inbounds: &Inbounds) -> Result<()> {
    object_keys(
        v,
        &[
            "servers",
            "rules",
            "final",
            "strategy",
            "timeout",
            "disable_cache",
            "disable_expire",
            "independent_cache",
            "cache_capacity",
            "reverse_mapping",
            "client_subnet",
            "optimistic",
        ],
    )?;
    let servers = v["servers"].as_array().ok_or("legacy_dns_invalid")?;
    if servers.is_empty() || servers.len() > 100 {
        return Err("legacy_dns_invalid");
    }
    let mut names = BTreeSet::new();
    for server in servers {
        let name = nonempty(&server["tag"])?;
        if name.len() > 256 || name.starts_with("profile:") || !names.insert(name) {
            return Err("legacy_dns_invalid");
        }
    }
    let mut links = BTreeMap::new();
    for server in servers {
        if synthetic::validate(server)? {
            continue;
        }
        object_keys(
            server,
            &[
                "type",
                "tag",
                "server",
                "server_port",
                "detour",
                "domain_resolver",
                "tls",
                "path",
                "method",
                "headers",
                "connect_timeout",
            ],
        )?;
        let kind = nonempty(&server["type"])?;
        if !matches!(kind, "udp" | "tcp" | "tls" | "https" | "quic" | "h3") {
            return Err("legacy_dns_transport_unsupported");
        }
        let address = nonempty(&server["server"])?;
        host(address)?;
        if let Some(port_value) = server.get("server_port") {
            port(port_value)?
        }
        if let Some(detour) = server.get("detour") {
            if !matches!(detour.as_str(), Some("proxy" | "direct" | "warp-bypass")) {
                return Err("legacy_dns_reference_missing");
            }
        }
        if let Some(value) = server.get("domain_resolver") {
            links.insert(server["tag"].as_str().unwrap(), resolver(value, v)?);
        } else if address.parse::<IpAddr>().is_err() {
            return Err("legacy_dns_reference_missing");
        }
        if let Some(value) = server.get("connect_timeout") {
            duration(value)?
        }
        if let Some(tls) = server.get("tls") {
            if matches!(kind, "udp" | "tcp") {
                return Err("legacy_dns_invalid");
            }
            object_keys(
                tls,
                &[
                    "enabled",
                    "disable_sni",
                    "server_name",
                    "insecure",
                    "alpn",
                    "min_version",
                    "max_version",
                ],
            )?;
            for key in ["enabled", "disable_sni", "insecure"] {
                if let Some(value) = tls.get(key) {
                    bool_value(value)?;
                }
            }
            if let Some(value) = tls.get("server_name") {
                host(nonempty(value)?)?
            }
            if let Some(value) = tls.get("alpn") {
                strings(value)?;
            }
            for key in ["min_version", "max_version"] {
                if let Some(value) = tls.get(key) {
                    if !matches!(value.as_str(), Some("1.0" | "1.1" | "1.2" | "1.3")) {
                        return Err("legacy_dns_invalid");
                    }
                }
            }
            if let (Some(min), Some(max)) = (tls.get("min_version"), tls.get("max_version")) {
                if min.as_str() > max.as_str() {
                    return Err("legacy_dns_invalid");
                }
            }
        }
        for key in ["path", "method", "headers"] {
            let Some(value) = server.get(key) else {
                continue;
            };
            if !matches!(kind, "https" | "h3") {
                return Err("legacy_dns_invalid");
            }
            match key {
                "path" => {
                    if !nonempty(value)?.starts_with('/') {
                        return Err("legacy_dns_invalid");
                    }
                }
                "method" => {
                    if !matches!(value.as_str(), Some("GET" | "POST")) {
                        return Err("legacy_dns_invalid");
                    }
                }
                "headers" => {
                    let headers = value.as_object().ok_or("legacy_dns_invalid")?;
                    if headers.len() > 100 {
                        return Err("legacy_dns_invalid");
                    };
                    for (name, value) in headers {
                        if name.is_empty()
                            || !name.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
                            })
                        {
                            return Err("legacy_dns_invalid");
                        };
                        strings(value)?;
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    // A hostname bootstrap cycle cannot be made portable by the destination DNS.
    for start in names {
        let mut current = start;
        let mut seen = BTreeSet::new();
        while let Some(next) = links.get(current) {
            if !seen.insert(current) {
                return Err("legacy_dns_reference_cycle");
            };
            current = next;
        }
    }
    // Explicit final removes the dependence on first-server ordering/defaults.
    tag(v.get("final").ok_or("legacy_dns_reference_missing")?, v)?;
    if let Some(value) = v.get("strategy") {
        strategy(string(value)?)?
    }
    if let Some(value) = v.get("timeout") {
        duration(value)?
    }
    for key in [
        "disable_cache",
        "disable_expire",
        "independent_cache",
        "reverse_mapping",
    ] {
        if let Some(value) = v.get(key) {
            bool_value(value)?;
        }
    }
    if let Some(value) = v.get("cache_capacity") {
        if !value.as_u64().is_some_and(|n| n <= 1_000_000) {
            return Err("legacy_dns_invalid");
        }
    }
    if let Some(value) = v.get("client_subnet") {
        cidr(nonempty(value)?)?
    }
    if let Some(value) = v.get("optimistic") {
        if !value.is_boolean() {
            object_keys(value, &["enabled", "timeout"])?;
            if let Some(v) = value.get("enabled") {
                bool_value(v)?;
            }
            if let Some(v) = value.get("timeout") {
                duration(v)?
            }
        }
    }
    if let Some(value) = v.get("rules") {
        let array = value.as_array().ok_or("legacy_dns_invalid")?;
        if array.len() > 1000 {
            return Err("legacy_route_limit");
        }
        for rule in array {
            rules::validate_dns(&mut rule.clone(), v, inbounds, false, 0)?
        }
    }
    Ok(())
}
