use super::{boolean as b, integer as n, string as s, value as v};
use crate::store::{Library, ProfileKind};
use serde_json::{json, Value};
#[cfg(test)]
mod tests;
fn array<'a>(object: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, String> {
    if object.get(key).is_none_or(Value::is_null) {
        object[key] = json!([]);
    }
    object[key]
        .as_array_mut()
        .ok_or("invalid_configuration".into())
}
fn inbound(core: &mut Value, entry: Value) -> Result<(), String> {
    let entries = array(core, "inbounds")?;
    if entries.iter().any(|i| i["tag"] == entry["tag"]) {
        return Err("route_tag_conflict".into());
    }
    entries.push(entry);
    Ok(())
}

pub fn apply(core: &mut Value, l: &Library, kind: &ProfileKind) -> Result<(), String> {
    if n(l, "core_dns_in_port") > 0 {
        inbound(
            core,
            json!({"type":"direct","tag":"settings-core-dns","listen":"127.0.0.1","listen_port":n(l,"core_dns_in_port")}),
        )?;
        array(&mut core["route"], "rules")?.insert(
            0,
            json!({"inbound":["settings-core-dns"],"action":"hijack-dns"}),
        );
    }

    if b(l, "enable_redirect") {
        inbound(
            core,
            json!({"type":"direct","tag":"settings-redirect","listen":s(l,"redirect_listen_address"),"listen_port":n(l,"redirect_listen_port")}),
        )?;
        let rules = array(&mut core["route"], "rules")?;
        rules.insert(
            0,
            json!({"inbound":["settings-redirect"],"action":"sniff","override_destination":true}),
        );
    }
    if b(l, "enable_dns_server") {
        inbound(
            core,
            json!({"type":"direct","tag":"settings-dns-in","listen":if b(l,"dns_server_listen_lan"){"0.0.0.0"}else{"127.1.1.1"},"listen_port":n(l,"dns_server_listen_port")}),
        )?;
        array(&mut core["route"], "rules")?.insert(
            0,
            json!({"inbound":["settings-dns-in"],"action":"hijack-dns"}),
        );
        let mut conditions = json!({});
        for entry in v(l, "dns_server_rules").as_array().into_iter().flatten() {
            let value = entry.as_str().ok_or("settings_invalid:dns_server_rules")?;
            let (key, value) = if let Some(v) = value.strip_prefix("domain:") {
                ("domain", v)
            } else if let Some(v) = value.strip_prefix("regex:") {
                ("domain_regex", v)
            } else if let Some(v) = value.strip_prefix("ruleset:") {
                ("rule_set", v)
            } else if let Some(v) = value.strip_prefix("suffix:") {
                ("domain_suffix", v)
            } else {
                ("domain_suffix", value)
            };
            array(&mut conditions, key)?.push(json!(value));
        }
        // A rule-set selector is separate: different condition types are combined with AND.
        for (key, values) in conditions.as_object().into_iter().flatten() {
            for (q, record, ip) in [
                ("A", "A", s(l, "dns_v4_resp")),
                ("AAAA", "AAAA", s(l, "dns_v6_resp")),
            ] {
                let mut rule = json!({"action":"predefined","query_type":[q],"rcode":"NOERROR","answer":[format!("*. IN {record} {ip}")]});
                rule[key] = values.clone();
                array(&mut core["dns"], "rules")?.insert(0, rule);
            }
        }
    }
    if b(l, "adblock_enable") {
        let tag = "settings-adblock";
        let sets = array(&mut core["route"], "rule_set")?;
        if sets.iter().any(|s| s["tag"] == tag) {
            return Err("route_tag_conflict".into());
        }
        sets.push(json!({"tag":tag,"type":"remote","format":"binary","url":s(l,"adblock_ruleset_url"),"download_detour":"direct"}));
        let rules = array(&mut core["route"], "rules")?;
        rules.insert(
            crate::routing::builtin::first_decision(rules),
            json!({"rule_set":[tag],"action":"reject"}),
        );
    }
    super::warp::routing::apply(core, l)?;
    let verbatim = *kind != ProfileKind::XrayConfig
        && l.routing
            .active()?
            .legacy_constraints
            .as_ref()
            .is_some_and(|c| c.raw_verbatim);
    for set in core
        .get_mut("route")
        .and_then(|route| route.get_mut("rule_set"))
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if !verbatim && set["type"] == "remote" {
            if n(l, "route_auto_update") > 0 {
                set["update_interval"] = json!(format!("{}m", n(l, "route_auto_update")));
            }
            if let Some(url) = set["url"].as_str() {
                set["url"] = json!(super::network::mirror(url, &s(l, "ruleset_mirror")));
            }
        }
    }
    if !s(l, "core_box_underlying_dns").is_empty() {
        let parsed = dns_server(&s(l, "core_box_underlying_dns"))?;
        for server in array(&mut core["dns"], "servers")? {
            if server["type"] == "local" {
                let tag = server["tag"].clone();
                *server = parsed.clone();
                server["tag"] = tag;
            }
        }
    }
    Ok(())
}

pub fn dns_server(input: &str) -> Result<Value, String> {
    if matches!(input, "local" | "localhost") {
        return Ok(json!({"type":"local"}));
    }
    let address = if input.contains("://") {
        input.to_owned()
    } else if input.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("udp://[{input}]")
    } else {
        format!("udp://{input}")
    };
    let url =
        reqwest::Url::parse(&address).map_err(|_| "settings_invalid:core_box_underlying_dns")?;
    let kind = url.scheme();
    if !matches!(kind, "udp" | "tcp" | "tls" | "https" | "h3" | "quic")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("settings_invalid:core_box_underlying_dns".into());
    }
    let mut server = json!({"type":kind,"server":url.host_str().ok_or("settings_invalid:core_box_underlying_dns")?.trim_matches(['[',']'])});
    if let Some(port) = url.port() {
        server["server_port"] = json!(port);
    }
    if matches!(kind, "https" | "h3") {
        server["path"] = json!(if url.path().len() > 1 {
            url.path()
        } else {
            "/dns-query"
        });
    }
    if matches!(kind, "tls" | "https" | "h3" | "quic") {
        server["tls"] = json!({"enabled":true});
    }
    Ok(server)
}

/// Explicit DNS rules keep priority. Only pure domain selectors can be mirrored;
/// retaining every condition avoids broadening process/IP-dependent routes.
pub fn follow_routing(core: &mut Value, l: &Library) -> Result<(), String> {
    if !b(l, "enable_dns_routing") {
        return Ok(());
    }
    let mut derived = vec![];
    let mut resolvers: Vec<Value> = vec![];
    for rule in core["route"]["rules"].as_array().into_iter().flatten() {
        let Some(out) = rule["outbound"].as_str().filter(|s| {
            matches!(
                *s,
                "direct" | "proxy" | super::warp::BASE_TAG | super::warp::routing::EXIT_TAG
            )
        }) else {
            continue;
        };
        let Some(object) = rule.as_object() else {
            continue;
        };
        if !object.keys().all(|key| {
            matches!(
                key.as_str(),
                "action"
                    | "outbound"
                    | "domain"
                    | "domain_suffix"
                    | "domain_keyword"
                    | "domain_regex"
                    | "rule_set"
                    | "invert"
            )
        }) {
            continue;
        }
        if ![
            "domain",
            "domain_suffix",
            "domain_keyword",
            "domain_regex",
            "rule_set",
        ]
        .iter()
        .any(|k| object.contains_key(*k))
        {
            continue;
        }
        let key = if out == "direct" {
            "dns_routing_direct"
        } else {
            "dns_routing_proxy"
        };
        let mut tag = s(l, key);
        let servers = core["dns"]["servers"]
            .as_array()
            .ok_or("invalid_configuration")?;
        let source = servers
            .iter()
            .find(|server| server["tag"] == tag)
            .ok_or_else(|| format!("settings_invalid:{key}"))?;
        if let Some(server) = super::warp::routing::dns_target(source, out) {
            if servers.iter().any(|s| s["tag"] == server["tag"]) {
                return Err("route_tag_conflict".into());
            }
            tag = server["tag"]
                .as_str()
                .ok_or("invalid_configuration")?
                .to_owned();
            if !resolvers.iter().any(|s| s["tag"] == tag) {
                resolvers.push(server);
            }
        }
        let mut dns = rule.clone();
        dns.as_object_mut().unwrap().remove("outbound");
        dns["action"] = json!("route");
        dns["server"] = json!(tag);
        derived.push(dns);
    }
    array(&mut core["dns"], "servers")?.extend(resolvers);
    array(&mut core["dns"], "rules")?.extend(derived);
    Ok(())
}
