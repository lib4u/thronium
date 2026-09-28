//! DNS transports without a remote server address. File-backed custom hosts
//! need a separate resource import; default system hosts and inline records do not.
use super::super::{validate::*, Result};
use serde_json::Value;
use std::net::IpAddr;

pub(super) fn validate(server: &Value) -> Result<bool> {
    match server["type"].as_str() {
        Some("local") => {
            object_keys(server, &["type", "tag", "prefer_go", "neighbor_domain"])?;
            if let Some(value) = server.get("prefer_go") {
                bool_value(value)?;
            }
            if let Some(value) = server.get("neighbor_domain") {
                for domain in strings(value)? {
                    host(domain)?;
                }
            }
        }
        Some("hosts") => {
            object_keys(server, &["type", "tag", "path", "predefined"])?;
            if server.get("path").is_some_and(|value| {
                let valid =
                    |v: &Value| v.as_str().is_some_and(crate::routing::resources::reference);
                value
                    .as_array()
                    .map_or_else(|| !valid(value), |paths| paths.iter().any(|v| !valid(v)))
            }) {
                return Err("legacy_route_runtime_unsupported");
            }
            if let Some(value) = server.get("predefined") {
                let records = value.as_object().ok_or("legacy_dns_invalid")?;
                if records.len() > 1000 {
                    return Err("legacy_route_limit");
                }
                for (domain, values) in records {
                    host(domain)?;
                    for address in strings(values)? {
                        address
                            .parse::<IpAddr>()
                            .map_err(|_| "legacy_dns_invalid")?;
                    }
                }
            }
        }
        Some("fakeip") => {
            object_keys(server, &["type", "tag", "inet4_range", "inet6_range"])?;
            if server.get("inet4_range").is_none() && server.get("inet6_range").is_none() {
                return Err("legacy_dns_invalid");
            }
            for (field, ipv4) in [("inet4_range", true), ("inet6_range", false)] {
                if let Some(value) = server.get(field) {
                    let value = nonempty(value)?;
                    cidr(value)?;
                    let (ip, _) = value.split_once('/').ok_or("legacy_dns_invalid")?;
                    if ip
                        .parse::<IpAddr>()
                        .map_err(|_| "legacy_dns_invalid")?
                        .is_ipv4()
                        != ipv4
                    {
                        return Err("legacy_dns_invalid");
                    }
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
