//! Qt's generated DNS for the local/system-proxy subset. No I/O or core starts.
//! Source: generate.cpp buildDNSSection/buildDnsObj/ParsePredefinedDNS and
//! RouteProfile.cpp get_direct_sites/get_proxy_sites. The caller enforces Parts,
//! route/profile dependency support, and imported-policy runtime constraints.
use crate::legacy_backup::{profiles::Issue, SourceDatabase, SourceRoute, SourceValue};
use serde_json::{json, Value};
use std::{collections::BTreeMap, net::IpAddr};
mod servers;
use servers::server;
type Result<T> = std::result::Result<T, &'static str>;

fn value<'a>(db: &'a SourceDatabase, key: &str) -> Result<Option<&'a str>> {
    let key = crate::legacy_backup::source_settings::key(key);
    let mut rows = db.settings.iter().filter(|row| row.key == key);
    let value = rows.next().map(|row| row.value.as_str());
    if rows.next().is_some() {
        return Err("legacy_dns_generated_settings_invalid");
    }
    Ok(value)
}
fn setting<'a>(db: &'a SourceDatabase, key: &str, default: &'a str) -> Result<&'a str> {
    Ok(value(db, key)?.unwrap_or(default))
}
fn boolean(value: &str) -> Result<bool> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("legacy_dns_generated_settings_invalid"),
    }
}
fn flag(db: &SourceDatabase, key: &str, default: bool) -> Result<bool> {
    boolean(setting(db, key, if default { "true" } else { "false" })?)
}
fn disable_ipv6(db: &SourceDatabase, side: &str) -> Result<bool> {
    let old = value(db, &format!("{side}_dns_strategy"))?
        .map(|s| match s {
            "ipv4_only" => Ok(true),
            "" | "as_is" | "prefer_ipv4" | "prefer_ipv6" | "ipv6_only" => Ok(false),
            _ => Err("legacy_dns_generated_settings_invalid"),
        })
        .transpose()?;
    let current = value(db, &format!("{side}_dns_disable_ipv6"))?
        .map(boolean)
        .transpose()?;
    if let (Some(old), Some(current)) = (old, current) {
        if old != current {
            return Err("legacy_dns_strategy_alias_conflict");
        }
    }
    Ok(current.or(old).unwrap_or(false))
}

/// Source getDirectDomainStrategy: an explicit DNS object disables the IPv6 cap.
pub fn direct_strategy(db: &SourceDatabase) -> Result<String> {
    let strategy = setting(db, "default_domain_strategy", "")?;
    super::validate::strategy(strategy).map_err(|_| "legacy_dns_generated_settings_invalid")?;
    if !flag(db, "use_dns_object", false)? && disable_ipv6(db, "direct")? {
        return Ok("ipv4_only".into());
    }
    Ok(strategy.into())
}

/// Source getXrayOutboundDomainStrategy distinguishes a family cap from force.
pub fn xray_strategy(db: &SourceDatabase) -> Result<String> {
    Ok(match direct_strategy(db)?.as_str() {
        "prefer_ipv4" => "UseIPv4v6",
        "prefer_ipv6" => "UseIPv6v4",
        "ipv6_only" => "ForceIPv6",
        "ipv4_only" if setting(db, "default_domain_strategy", "")? == "ipv4_only" => "ForceIPv4",
        "ipv4_only" => "UseIPv4",
        _ => "UseIP",
    }
    .into())
}
fn array(raw: &str) -> Result<Vec<String>> {
    let value: Value =
        serde_json::from_str(raw).map_err(|_| "legacy_dns_generated_settings_invalid")?;
    let values = value
        .as_array()
        .filter(|a| a.len() <= 4096)
        .ok_or("legacy_dns_generated_limit")?;
    values
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| s.len() <= 65536)
                .map(str::to_owned)
                .ok_or("legacy_dns_generated_settings_invalid")
        })
        .collect()
}
fn field(row: &BTreeMap<String, SourceValue>, key: &str) -> Result<Vec<String>> {
    match row.get(key) {
        None | Some(SourceValue::Null) => Ok(vec![]),
        Some(SourceValue::Text(raw)) if raw.is_empty() => Ok(vec![]),
        Some(SourceValue::Text(raw)) => array(raw),
        _ => Err("legacy_column_type"),
    }
}

fn predefined(lines: Vec<String>) -> Result<Vec<Value>> {
    let mut entries: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    let mut indices = BTreeMap::new();
    for raw in lines {
        let line = raw.split('#').next().unwrap();
        if line.trim().is_empty() {
            continue;
        }
        if !line.is_ascii() {
            return Err("legacy_dns_predefined_unsupported");
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 2 || fields[0].contains('%') {
            return Err("legacy_dns_predefined_unsupported");
        }
        let ip = fields[0]
            .parse::<IpAddr>()
            .map_err(|_| "legacy_dns_predefined_unsupported")?;
        for domain in &fields[1..] {
            let domain = domain
                .to_ascii_lowercase()
                .trim_end_matches('.')
                .to_string();
            if domain.is_empty()
                || domain.len() > 253
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
            {
                return Err("legacy_dns_predefined_unsupported");
            }
            let index = *indices.entry(domain.clone()).or_insert_with(|| {
                entries.push((domain, vec![], vec![]));
                entries.len() - 1
            });
            let bucket = if ip.is_ipv4() {
                &mut entries[index].1
            } else {
                &mut entries[index].2
            };
            let text = qt_address(ip);
            if !bucket.contains(&text) {
                bucket.push(text);
            }
            if entries.len() > 4096 {
                return Err("legacy_dns_generated_limit");
            }
        }
    }
    let mut rules = Vec::new();
    for (domain, v4, v6) in entries {
        for (family, addresses) in [("A", v4), ("AAAA", v6)] {
            let mut rule = json!({"domain":domain,"action":"predefined","query_type":family,"rcode":if addresses.is_empty(){"NXDOMAIN"}else{"NOERROR"}});
            if !addresses.is_empty() {
                rule["answer"] = json!(addresses
                    .iter()
                    .map(|a| format!("*. IN {family} {a}"))
                    .collect::<Vec<_>>());
            }
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn qt_address(ip: IpAddr) -> String {
    // QHostAddress::toString uses dotted notation for IPv4-compatible IPv6
    // whose low 32-bit value is at least 65536; smaller values remain hex.
    // Qt oracle covers ::1:0, ::192.0.2.6, ::ffff and IPv4-mapped addresses.
    if let IpAddr::V6(v6) = ip {
        let bytes = v6.octets();
        if bytes[..12].iter().all(|b| *b == 0) && (bytes[12] != 0 || bytes[13] != 0) {
            return format!("::{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15]);
        }
    }
    ip.to_string()
}
fn append(rules: &mut Vec<Value>, conditions: Value, server: &str, disable_v6: bool) {
    if disable_v6 {
        let mut guard = conditions.clone();
        guard["query_type"] = json!(["AAAA"]);
        guard["action"] = json!("predefined");
        rules.push(guard);
    }
    let mut route = conditions;
    route["action"] = json!("route");
    route["server"] = json!(server);
    rules.push(route);
}
fn selectors(db: &SourceDatabase, route: &SourceRoute, target: i64) -> Result<Vec<Value>> {
    let mut sets = vec![];
    let mut result = json!({"domain":[],"domain_suffix":[],"domain_keyword":[],"domain_regex":[]});
    let mut rows: Vec<_> = db
        .rules
        .iter()
        .filter(|rule| rule.route_id == route.id)
        .collect();
    rows.sort_by_key(|rule| rule.order);
    let mut any = false;
    for row in rows {
        let id = match row.columns.get("outbound_id") {
            None => -2,
            Some(SourceValue::Integer(id)) => *id,
            _ => return Err("legacy_column_type"),
        };
        let action = match row.columns.get("action") {
            None => "route",
            Some(SourceValue::Text(s)) => s.as_str(),
            _ => return Err("legacy_column_type"),
        };
        if id != target || action != "route" {
            continue;
        }
        // Qt projects only named geosite sets into DNS, in a separate rule
        // before inline domains. Combining the two would change OR into AND.
        for tag in field(&row.columns, "rule_set_json")? {
            if tag.starts_with("geosite-") {
                if sets.len() >= 1000 {
                    return Err("legacy_dns_generated_limit");
                }
                sets.push(json!(tag));
            }
        }
        for key in ["domain", "domain_suffix", "domain_keyword", "domain_regex"] {
            for original in field(&row.columns, &format!("{key}_json"))? {
                let value = original.trim();
                if value.is_empty() {
                    continue;
                }
                if value.len() > 2048 || !value.is_ascii() || value.chars().any(char::is_control) {
                    return Err("legacy_dns_selector_unsupported");
                }
                result[key].as_array_mut().unwrap().push(json!(value));
                any = true;
                if result[key].as_array().unwrap().len() > 4096 {
                    return Err("legacy_dns_generated_limit");
                }
            }
        }
    }
    let mut selectors = vec![];
    if !sets.is_empty() {
        selectors.push(json!({"rule_set":sets}));
    }
    if any {
        selectors.push(result);
    }
    Ok(selectors)
}
fn report(route: &SourceRoute, code: &str) -> Issue {
    Issue {
        code: code.into(),
        entity: Some("route".into()),
        source_id: Some(route.id),
        name: Some(
            route
                .name
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect(),
        ),
    }
}

pub fn build(
    db: &SourceDatabase,
    route: &SourceRoute,
    report_out: &mut Vec<Issue>,
) -> Result<Value> {
    if flag(db, "use_dns_object", false)? {
        return Err("legacy_dns_generated_mode_required");
    }
    flag(db, "enable_warp", false)?;
    for key in [
        "enable_dns_server",
        "adblock_enable",
        "enable_redirect",
        "vpn_l3_bridge",
        "use_mozilla_certs",
    ] {
        if flag(db, key, false)? {
            return Err("legacy_dns_generated_dependency_unsupported");
        }
    }
    for row in db.rules.iter().filter(|rule| rule.route_id == route.id) {
        for tag in field(&row.columns, "rule_set_json")? {
            super::rule_sets::source(db, &tag)?;
        }
    }
    let mut remote = server(
        setting(db, "remote_dns", "https://8.8.8.8/dns-query")?,
        true,
    )?;
    remote["tag"] = json!("dns-remote");
    remote["domain_resolver"] = json!("dns-local");
    remote["detour"] = json!("proxy");
    let mut direct = server(setting(db, "direct_dns", "localhost")?, false)?;
    direct["tag"] = json!("dns-direct");
    direct["domain_resolver"] = json!("dns-local");
    let bootstrap = setting(db, "core_box_underlying_dns", "")?;
    let mut local = server(
        if bootstrap.is_empty() {
            "local"
        } else {
            bootstrap
        },
        false,
    )?;
    // Qt emits no resolver for the bootstrap itself. The pinned DNS transport
    // requires an explicit resolver for hostname addresses, so only a literal
    // IP or the system-local transport is usable without inventing a dependency.
    if local["type"] != "local"
        && local["server"]
            .as_str()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .is_none()
    {
        return Err("legacy_dns_bootstrap_hostname_unsupported");
    }
    local["tag"] = json!("dns-local");
    let direct_v6 = disable_ipv6(db, "direct")?;
    let remote_v6 = disable_ipv6(db, "remote")?;
    let final_direct = match setting(db, "dns_final_out", "remote")? {
        "direct" => true,
        "remote" => false,
        _ => return Err("legacy_dns_generated_settings_invalid"),
    };
    let mut rules = if flag(db, "dns_predefined_enable", true)? {
        predefined(array(setting(
            db,
            "dns_predefined_rules",
            "[\"127.0.0.1 localhost\"]",
        )?)?)?
    } else {
        vec![]
    };
    // Preserve Qt's order: predefined records, the system hosts gate, FakeIP,
    // projected domain policies, then the source's final resolver.
    let mut servers = vec![remote, direct];
    if flag(db, "dns_use_hosts", false)? {
        servers.push(json!({"tag":"dns-hosts","type":"hosts"}));
        rules.push(json!({"preferred_by":["dns-hosts"],"query_type":["A","AAAA"],"action":"route","server":"dns-hosts","disable_cache":true}));
    }
    let fakeip = flag(db, "fakedns", false)?;
    if fakeip {
        let mut server = json!({"tag":"dns-fake","type":"fakeip","inet4_range":"198.18.0.0/15"});
        if !flag(db, "fakeip_disable_ipv6", false)? {
            server["inet6_range"] = json!("fc00::/18");
        }
        servers.push(server);
        rules.push(json!({"query_type":["A","AAAA"],"action":"route","server":"dns-fake"}));
    }
    servers.push(local);
    let mut projected = false;
    if flag(db, "enable_dns_routing", true)? {
        for conditions in selectors(db, route, -2)? {
            append(&mut rules, conditions, "dns-direct", direct_v6);
            projected = true;
        }
        if final_direct {
            for conditions in selectors(db, route, -1)? {
                append(&mut rules, conditions, "dns-remote", remote_v6);
                projected = true;
            }
        }
    }
    append(
        &mut rules,
        json!({}),
        if final_direct {
            "dns-direct"
        } else {
            "dns-remote"
        },
        if final_direct { direct_v6 } else { remote_v6 },
    );
    let capacity = setting(db, "dns_cache_capacity", "65536")?;
    if capacity.is_empty() || !capacity.bytes().all(|b| b.is_ascii_digit()) {
        return Err("legacy_dns_generated_settings_invalid");
    }
    let capacity = capacity
        .parse::<u32>()
        .ok()
        .filter(|n| *n <= 1_000_000)
        .ok_or("legacy_dns_generated_limit")?;
    let mut dns = json!({"servers":servers,"rules":rules,"cache_capacity":capacity});
    if fakeip {
        dns["independent_cache"] = json!(true);
    }
    let disable_cache = flag(db, "dns_disable_cache", false)?;
    let disable_expire = flag(db, "dns_disable_expire", false)?;
    if disable_cache {
        dns["disable_cache"] = json!(true);
    }
    if disable_expire {
        dns["disable_expire"] = json!(true);
    }
    if flag(db, "dns_reverse_mapping", false)? {
        dns["reverse_mapping"] = json!(true);
    }
    let query_timeout = setting(db, "dns_query_timeout", "")?;
    if !query_timeout.is_empty() {
        super::validate::duration(&json!(query_timeout))
            .map_err(|_| "legacy_dns_generated_settings_invalid")?;
        dns["timeout"] = json!(query_timeout);
    }
    let optimistic = flag(db, "dns_optimistic", false)?;
    let optimistic_timeout = setting(db, "dns_optimistic_timeout", "")?;
    if !optimistic_timeout.is_empty() {
        super::validate::duration(&json!(optimistic_timeout))
            .map_err(|_| "legacy_dns_generated_settings_invalid")?;
    }
    if optimistic && !disable_cache && !disable_expire {
        dns["optimistic"] = if optimistic_timeout.is_empty() {
            json!(true)
        } else {
            json!({"enabled":true,"timeout":optimistic_timeout})
        };
    }
    report_out.push(report(route, "legacy_dns_generated_local_modes"));
    if crate::routing::legacy_dns::adaptive(&dns) {
        report_out.push(report(route, "legacy_dns_xray_remote_upgrade"));
    }
    if projected {
        report_out.push(report(route, "legacy_dns_selector_projection"));
    }
    if optimistic && (disable_cache || disable_expire) {
        report_out.push(report(route, "legacy_dns_optimistic_suppressed"));
    }
    Ok(dns)
}

#[cfg(test)]
mod tests;
