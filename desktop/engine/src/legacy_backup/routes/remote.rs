//! Reuse the archive converter for remote Qt rules. Downloads never materialize
//! remote endpoint/profile declarations or consult local profiles by display name.
use super::*;
use crate::routing::source::Source;
use base64::{engine::general_purpose, Engine as _};

// Only DNS/routing inputs, never unrelated credentials or application settings.
const SETTINGS: &[&str] = &[
    "ruleset_mirror",
    "use_dns_object",
    "dns_object",
    "remote_dns",
    "direct_dns",
    "core_box_underlying_dns",
    "direct_dns_strategy",
    "remote_dns_strategy",
    "direct_dns_disable_ipv6",
    "remote_dns_disable_ipv6",
    "default_domain_strategy",
    "resolve_domain_strategy",
    "enable_stats",
    "enable_warp",
    "dns_predefined_enable",
    "dns_predefined_rules",
    "dns_use_hosts",
    "fakedns",
    "fakeip_disable_ipv6",
    "enable_dns_routing",
    "dns_final_out",
    "dns_cache_capacity",
    "dns_disable_cache",
    "dns_disable_expire",
    "dns_reverse_mapping",
    "dns_query_timeout",
    "dns_optimistic",
    "dns_optimistic_timeout",
];

pub(super) fn source(db: &SourceDatabase, row: &SourceRoute) -> Result<Option<Value>> {
    let remote = boolean(&row.columns, "is_remote")?;
    let auto_update = boolean(&row.columns, "auto_update")?;
    let url = text(&row.columns, "remote_url")?;
    let updated = integer(&row.columns, "remote_last_update", 0)?;
    if !remote {
        if auto_update || !url.is_empty() || updated != 0 {
            return Err("legacy_route_source_unsupported");
        }
        return Ok(None);
    }
    if boolean(&row.columns, "is_raw")? || updated < 0 {
        return Err("legacy_route_source_unsupported");
    }
    let keys: BTreeSet<_> = SETTINGS
        .iter()
        .map(|key| super::super::source_settings::key(key))
        .collect();
    let explicit_dns = setting_bool(db, "use_dns_object", false)?;
    let mut saved = BTreeMap::new();
    for setting in &db.settings {
        if setting.key == "dns_object" && !explicit_dns {
            continue;
        }
        if keys.contains(setting.key.as_str())
            && saved
                .insert(setting.key.clone(), setting.value.clone())
                .is_some()
        {
            return Err("legacy_route_settings_invalid");
        }
    }
    let value = serde_json::to_value(Source {
        url: url.into(),
        imported_at: updated as u64,
        auto_update,
        legacy_settings: Some(saved),
        dns_customized: false,
        update_notes: Vec::new(),
    })
    .map_err(|_| "legacy_route_source_unsupported")?;
    Source::parse(&value).map_err(|_| "legacy_route_source_unsupported")?;
    Ok(Some(value))
}

fn outbound(value: Option<&Value>, default: i64) -> Result<i64> {
    match value {
        None => Ok(default),
        Some(value) => match value.as_str() {
            Some("proxy") => Ok(-1),
            Some("direct") => Ok(-2),
            Some("block") => Ok(-3),
            Some("warp-bypass") => Ok(-5),
            _ => match value.as_i64() {
                Some(n @ (-1 | -2 | -3 | -5)) => Ok(n),
                _ => Err("legacy_route_target_unsupported"),
            },
        },
    }
}
fn shared_rule(value: &Value, index: usize) -> Result<super::super::SourceRule> {
    let object = value.as_object().ok_or("legacy_route_structure")?;
    let tokens = [
        "custom",
        "simple_address_proxy",
        "simple_address_bypass",
        "simple_address_block",
        "simple_process_name_proxy",
        "simple_process_name_bypass",
        "simple_process_name_block",
        "simple_process_path_proxy",
        "simple_process_path_bypass",
        "simple_process_path_block",
        "simple_address_warp_bypass",
        "simple_process_name_warp_bypass",
        "simple_process_path_warp_bypass",
    ];
    let kind = tokens
        .iter()
        .position(|&token| {
            value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("custom")
                == token
        })
        .ok_or("legacy_route_type_unsupported")? as i64;
    let mut columns = BTreeMap::new();
    columns.insert(
        "outbound_id".into(),
        SourceValue::Integer(outbound(value.get("outbound"), -2)?),
    );
    for (key, value) in object {
        let target = match key.as_str() {
            "type" | "outbound" => continue,
            "method" => "reject_method",
            "override_destination" => "sniff_override_dest",
            _ => key,
        };
        let array = matches!(
            target,
            "inbound"
                | "domain"
                | "domain_suffix"
                | "domain_keyword"
                | "domain_regex"
                | "source_ip_cidr"
                | "ip_cidr"
                | "source_port"
                | "port"
                | "source_port_range"
                | "port_range"
                | "process_name"
                | "process_path"
                | "process_path_regex"
                | "wifi_ssid"
                | "wifi_bssid"
                | "rule_set"
        );
        if array {
            let values = if let Some(values) = value.as_array() {
                values.clone()
            } else {
                vec![value.clone()]
            };
            let strings = values
                .iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s.clone()),
                    Value::Number(n) if matches!(target, "port" | "source_port") => {
                        Ok(n.to_string())
                    }
                    _ => Err("legacy_route_structure"),
                })
                .collect::<Result<Vec<_>>>()?;
            columns.insert(
                format!("{target}_json"),
                SourceValue::Text(json!(strings).to_string()),
            );
        } else {
            let v = match value {
                Value::Bool(b) => SourceValue::Integer(i64::from(*b)),
                Value::String(s) => SourceValue::Text(s.clone()),
                Value::Number(n) if matches!(target, "ip_version" | "override_port") => {
                    SourceValue::Text(n.to_string())
                }
                _ => return Err("legacy_route_structure"),
            };
            columns.insert(target.into(), v);
        }
    }
    Ok(super::super::SourceRule {
        route_id: 1,
        order: index as i64,
        kind,
        columns,
    })
}

pub(crate) fn refresh(
    current: &RoutingProfile,
    bytes: &[u8],
    now: u64,
) -> std::result::Result<RoutingProfile, String> {
    let metadata = Source::parse(current.source.as_ref().ok_or("routing_source_missing")?)?;
    let text = std::str::from_utf8(bytes).map_err(|_| "routing_import_invalid")?;
    convert(current, Some(metadata), &document(text)?, now)
}

/// A new routing profile from Throne route text: a `throne://route/` link, a
/// `throne-route-profile` document or a bare rule list. The first import and
/// every later update of the same source go through one converter. With a
/// `url` the profile keeps its source for updates.
pub(crate) fn import(
    text: &str,
    name: &str,
    url: Option<&str>,
    now: u64,
) -> std::result::Result<RoutingProfile, String> {
    let document = document(text)?;
    let metadata = url
        .map(|url| Source::parse(&json!({"url": url, "importedAt": now})))
        .transpose()?;
    let base = RoutingProfile {
        name: document
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(name)
            .into(),
        ..RoutingProfile::default()
    };
    convert(&base, metadata, &document, now)
}

/// The route document inside a link or file: JSON, or JSON in any Base64 alphabet.
fn document(text: &str) -> std::result::Result<Value, String> {
    let raw = text.trim();
    let raw = if raw
        .get(..15)
        .is_some_and(|p| p.eq_ignore_ascii_case("throne://route/"))
    {
        &raw[15..]
    } else {
        raw
    };
    match parse(raw) {
        Ok(value) => Ok(value),
        Err(_) => {
            let decoded = [
                general_purpose::URL_SAFE_NO_PAD,
                general_purpose::URL_SAFE,
                general_purpose::STANDARD,
            ]
            .iter()
            .find_map(|encoding| encoding.decode(raw).ok())
            .ok_or("routing_import_invalid")?;
            Ok(parse(
                std::str::from_utf8(&decoded).map_err(|_| "routing_import_invalid")?,
            )?)
        }
    }
}

fn convert(
    current: &RoutingProfile,
    mut metadata: Option<Source>,
    document: &Value,
    now: u64,
) -> std::result::Result<RoutingProfile, String> {
    let rules = if let Some(array) = document.as_array() {
        if array.is_empty() {
            return Err("routing_import_invalid".into());
        }
        array
    } else {
        object_keys(
            document,
            &[
                "kind",
                "v",
                "name",
                "rules",
                "default_outbound",
                "endpoints",
                "raw",
            ],
        )
        .map_err(|_| "routing_import_unsupported")?;
        if document["kind"] != "throne-route-profile" {
            return Err("routing_import_unsupported".into());
        }
        if document["v"] != 1 {
            return Err("routing_import_version".into());
        }
        if document.get("raw").is_some_and(|v| v != false)
            || document.get("endpoints").is_some_and(|v| v != &json!([]))
        {
            return Err("routing_import_unsupported".into());
        }
        document["rules"]
            .as_array()
            .ok_or("routing_import_invalid")?
    };
    if rules.len() > crate::routing::MAX_RULES {
        return Err("legacy_route_limit".into());
    }
    let legacy_settings = metadata.as_ref().and_then(|m| m.legacy_settings.as_ref());
    let dns_customized = metadata.as_ref().is_some_and(|m| m.dns_customized);
    let mut db = SourceDatabase::default();
    if let Some(saved) = legacy_settings {
        db.settings = saved
            .iter()
            .map(|(key, value)| super::super::SourceSetting {
                key: key.clone(),
                value: value.clone(),
                columns: BTreeMap::new(),
            })
            .collect();
    }
    db.rules = rules
        .iter()
        .enumerate()
        .map(|(i, v)| shared_rule(v, i))
        .collect::<Result<Vec<_>>>()?;
    let row = SourceRoute {
        id: 1,
        name: current.name.clone(),
        columns: BTreeMap::from([(
            "default_outbound_id".into(),
            SourceValue::Integer(outbound(document.get("default_outbound"), -1)?),
        )]),
    };
    let mut report = vec![];
    let dns = if dns_customized
        || legacy_settings.is_none()
        || setting_bool(&db, "use_dns_object", false)?
    {
        current.dns.clone()
    } else {
        generated_dns::build(&db, &row, &mut report)?
    };
    let inbounds = super::inbounds::Inbounds::parse(&db)?;
    let mut next = convert_one(
        &row,
        &db,
        &dns,
        None,
        &inbounds,
        &mut report,
        Some(&current.route),
    )?;
    next.id = current.id.clone();
    next.mode = current.mode.clone();
    if legacy_settings.is_none() || dns_customized {
        next.legacy_constraints = current.legacy_constraints.clone();
    }
    next.source = match metadata.as_mut() {
        Some(metadata) => {
            metadata.imported_at = now;
            // The review of a first import showed what was left out; an update keeps
            // those notes (not the informational ones repeated by every update).
            metadata.update_notes = report
                .iter()
                .map(|issue| issue.code.clone())
                .filter(|code| code.ends_with("_omitted"))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .take(32)
                .collect();
            Some(serde_json::to_value(metadata).map_err(|_| "invalid_routing")?)
        }
        None => None,
    };
    Ok(next)
}

#[cfg(test)]
mod tests;
