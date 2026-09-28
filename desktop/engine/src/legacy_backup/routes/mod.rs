//! Pure additive route/DNS conversion. No library writes, core starts or network I/O.
//! All source values stay private; reports contain only bounded entity names and codes.
mod dns;
mod endpoints;
pub mod generated_dns;
mod inbounds;
pub(crate) mod remote;
mod rule_sets;
mod rules;
mod targets;
mod validate;
use super::{
    profiles::{Issue, ProfilePlan},
    SourceArchive, SourceDatabase, SourceRoute, SourceRow, SourceValue,
};
use crate::routing::{LegacyRoutingConstraints, Routing, RoutingProfile, Rule};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use targets::target;
use validate::*;

#[derive(Clone)]
pub struct RoutePlan {
    pub resources: crate::routing::resources::Pack,
    pub presets: Vec<RoutingProfile>,
    pub route_ids: BTreeMap<i64, String>,
    pub selected: Option<String>,
    pub report: Vec<Issue>,
}
pub(super) type Result<T> = std::result::Result<T, &'static str>;
fn issue(code: &str, route: Option<&SourceRoute>) -> Issue {
    Issue {
        code: code.into(),
        entity: Some("route".into()),
        source_id: route.map(|r| r.id),
        name: route.map(|r| {
            r.name
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect()
        }),
    }
}
pub(super) fn text<'a>(row: &'a SourceRow, key: &str) -> Result<&'a str> {
    match row.get(key) {
        None | Some(SourceValue::Null) => Ok(""),
        Some(SourceValue::Text(s)) => Ok(s),
        _ => Err("legacy_column_type"),
    }
}
pub(super) fn integer(row: &SourceRow, key: &str, default: i64) -> Result<i64> {
    match row.get(key) {
        None => Ok(default),
        Some(SourceValue::Integer(n)) => Ok(*n),
        _ => Err("legacy_column_type"),
    }
}
pub(super) fn boolean(row: &SourceRow, key: &str) -> Result<bool> {
    match integer(row, key, 0)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("legacy_column_type"),
    }
}
pub(super) fn setting<'a>(db: &'a SourceDatabase, key: &str, default: &'a str) -> Result<&'a str> {
    let key = crate::legacy_backup::source_settings::key(key);
    let mut rows = db.settings.iter().filter(|s| s.key == key);
    let value = rows.next().map_or(default, |s| s.value.as_str());
    if rows.next().is_some() {
        return Err("legacy_route_settings_invalid");
    }
    Ok(value)
}
fn setting_bool(db: &SourceDatabase, key: &str, default: bool) -> Result<bool> {
    match setting(db, key, if default { "true" } else { "false" })? {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("legacy_route_settings_invalid"),
    }
}
pub(super) fn row_keys(row: &SourceRow, allowed: &[&str]) -> Result<()> {
    if row.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err("legacy_route_field_unsupported")
    } else {
        Ok(())
    }
}
pub(super) fn parse(s: &str) -> Result<Value> {
    super::json::parse(s).map_err(|_| "legacy_route_json_invalid")
}
pub(super) fn new_rule(name: String, config: Value) -> Rule {
    Rule {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        enabled: true,
        config,
        simple: None,
    }
}
/// Does not read routes/settings whose archive parts were not selected. Any
/// unsupported row rejects the entire operation, never returns a partial plan.
pub fn convert(
    source: &SourceArchive,
    profiles: Option<&ProfilePlan>,
) -> std::result::Result<RoutePlan, Vec<Issue>> {
    let fail = |code| vec![issue(code, None)];
    if !source.parts.routes || !source.parts.settings {
        return Err(fail("legacy_route_parts_required"));
    }
    let db = source
        .database
        .as_ref()
        .ok_or_else(|| fail("legacy_database_missing"))?;
    if db.routes.is_empty() || db.routes.len() > 99 {
        return Err(fail("legacy_route_limit"));
    }
    let mut ids = BTreeSet::new();
    if db.routes.iter().any(|r| r.id < 0 || !ids.insert(r.id)) {
        return Err(fail("legacy_route_structure"));
    }
    let mut orders = BTreeSet::new();
    if db
        .rules
        .iter()
        .any(|r| r.order < 0 || !ids.contains(&r.route_id) || !orders.insert((r.route_id, r.order)))
    {
        return Err(fail("legacy_route_structure"));
    }
    let explicit_dns = setting_bool(db, "use_dns_object", false).map_err(fail)?;
    let inbounds = inbounds::Inbounds::parse(db).map_err(fail)?;
    let setup = (|| -> Result<Option<Value>> {
        for key in [
            "adblock_enable",
            "enable_dns_server",
            "enable_redirect",
            "vpn_l3_bridge",
            "use_mozilla_certs",
        ] {
            if setting_bool(db, key, false)? {
                return Err("legacy_route_runtime_unsupported");
            }
        }
        strategy(setting(db, "default_domain_strategy", "")?)?;
        strategy(setting(db, "resolve_domain_strategy", "")?)?;
        setting_bool(db, "enable_stats", true)?;
        if explicit_dns {
            let value = parse(setting(db, "dns_object", "")?).map_err(|_| "legacy_dns_invalid")?;
            dns::validate(&value, &inbounds)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    })()
    .map_err(fail)?;
    let mut plan = RoutePlan {
        resources: Default::default(),
        presets: vec![],
        route_ids: BTreeMap::new(),
        selected: None,
        report: vec![],
    };
    let mut errors = vec![];
    let mut routes = db.routes.iter().collect::<Vec<_>>();
    routes.sort_by_key(|r| r.id);
    let references = if source.parts.profiles {
        profiles
    } else {
        None
    };
    let mut planned_bytes = 0usize;
    for route in routes {
        let converted = (|| {
            let generated;
            let dns = match setup.as_ref() {
                Some(dns) => dns,
                None => {
                    generated = generated_dns::build(db, route, &mut plan.report)?;
                    &generated
                }
            };
            convert_one(
                route,
                db,
                dns,
                references,
                &inbounds,
                &mut plan.report,
                None,
            )
        })();
        match converted {
            Ok(preset) => {
                // Bound repeated DNS materialization before accumulating another
                // clone for each source preset; final validation also counts the
                // enclosing Routing and the destination library.
                planned_bytes = planned_bytes.saturating_add(
                    serde_json::to_vec(&preset)
                        .map_err(|_| fail("legacy_route_limit"))?
                        .len(),
                );
                if planned_bytes > crate::routing::MAX_PROFILE_BYTES {
                    return Err(fail("legacy_route_limit"));
                }
                plan.route_ids.insert(route.id, preset.id.clone());
                plan.presets.push(preset);
            }
            Err(code) => errors.push(issue(code, Some(route))),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let selected = setting(db, "current_route_id", "1")
        .map_err(fail)?
        .parse::<i64>()
        .map_err(|_| fail("legacy_route_settings_invalid"))?;
    plan.selected = plan.route_ids.get(&selected).cloned();
    if plan.selected.is_none() {
        plan.report
            .push(issue("legacy_route_selected_missing", None))
    }
    let mut check = Routing::default();
    check.profiles.extend(plan.presets.clone());
    check.validate().map_err(|code| vec![issue(&code, None)])?;
    Ok(plan)
}
fn convert_one(
    row: &SourceRoute,
    db: &SourceDatabase,
    dns: &Value,
    profiles: Option<&ProfilePlan>,
    inbounds: &inbounds::Inbounds,
    report: &mut Vec<Issue>,
    inherited_route: Option<&Value>,
) -> Result<RoutingProfile> {
    row_keys(
        &row.columns,
        &[
            "id",
            "name",
            "default_outbound_id",
            "is_raw",
            "raw_route",
            "prevent_modifications",
            "is_remote",
            "remote_url",
            "auto_update",
            "remote_last_update",
            "endpoint_profile_ids",
            "inner_hop_endpoint_ids",
            "created_at",
            "updated_at",
        ],
    )?;
    if row.name.trim().is_empty() || row.name.len() > 512 || row.name.chars().any(char::is_control)
    {
        return Err("legacy_route_structure");
    }
    let source = remote::source(db, row)?;
    if source.is_some() {
        report.push(issue("legacy_route_remote_updates", Some(row)));
    }
    let endpoints = endpoints::parse_row(row, profiles)?;
    let explicit_dns = setting_bool(db, "use_dns_object", false)?;
    // Qt adds tunnel DNS servers only to its generated DNS; an explicit object
    // is emitted verbatim (generate.cpp buildDNSSection).
    let mut dns = dns.clone();
    if !explicit_dns && endpoints.tunnel_dns(&mut dns)? {
        report.push(issue("legacy_route_endpoint_tunnel_dns", Some(row)));
    }
    let context = rules::Context {
        profiles,
        dns: &dns,
        inbounds,
    };
    let raw = boolean(&row.columns, "is_raw")?;
    // Qt consults this flag only for a raw route; it never makes an editor readonly.
    let prevent_modifications = boolean(&row.columns, "prevent_modifications")?;
    let raw_verbatim = raw && prevent_modifications;
    let mut rules = vec![];
    let mut route = if raw {
        if db.rules.iter().any(|r| r.route_id == row.id) {
            report.push(issue("legacy_route_inactive_rules_omitted", Some(row)));
        }
        let mut value = parse(text(&row.columns, "raw_route")?)?;
        if value.as_object().is_none_or(|object| object.is_empty()) {
            return Err("legacy_route_structure");
        }
        object_keys(
            &value,
            &[
                "rules",
                "rule_set",
                "final",
                "find_process",
                "auto_detect_interface",
                "default_domain_resolver",
            ],
        )?;
        for key in ["find_process", "auto_detect_interface"] {
            if let Some(v) = value.get(key) {
                bool_value(v)?;
            }
        }
        if let Some(v) = value.get("rules") {
            for (i, config) in v
                .as_array()
                .ok_or("legacy_route_structure")?
                .iter()
                .enumerate()
            {
                let mut config = config.clone();
                rules::validate(&mut config, context, false, 0)?;
                rules.push(new_rule(format!("{} · {}", row.name, i + 1), config));
            }
        }
        // Qt appends every endpoint gate after the raw rules, verbatim or not.
        endpoints.append_missing(&mut rules, &BTreeSet::new(), row, report);
        value
            .as_object_mut()
            .ok_or("legacy_route_structure")?
            .remove("rules");
        let final_tag = match value.get("final") {
            Some(v) => target(v, profiles)?,
            None if raw_verbatim => String::new(),
            None => "proxy".into(),
        };
        if !final_tag.is_empty() {
            value["final"] = json!(final_tag);
        }
        value
    } else {
        if !text(&row.columns, "raw_route")?.is_empty() {
            return Err("legacy_route_field_unsupported");
        }
        rules.push(new_rule("Throne · sniff".into(), json!({"action":"sniff"})));
        let resolve = setting(db, "resolve_domain_strategy", "")?;
        if !resolve.is_empty() {
            rules.push(new_rule(
                "Throne · resolve".into(),
                json!({"inbound":["mixed-in"],"action":"resolve","strategy":resolve}),
            ));
            report.push(issue("legacy_route_tun_guarded", Some(row)));
        }
        rules.push(new_rule(
            "Throne · hijack-dns".into(),
            json!({"protocol":"dns","action":"hijack-dns"}),
        ));
        let mut source_rules = db
            .rules
            .iter()
            .filter(|r| r.route_id == row.id)
            .collect::<Vec<_>>();
        source_rules.sort_by_key(|r| r.order);
        let mut carried = BTreeSet::new();
        for rule in source_rules {
            if rule.kind == 13 {
                if let Some(gate) = endpoints.positioned(rule, &mut carried, row, report)? {
                    rules.push(gate);
                }
                continue;
            }
            if let Some(config) = rules::structured::structured(rule, context)? {
                let name = text(&rule.columns, "name")?;
                let name = if name.trim().is_empty() {
                    format!("Throne · {}:{}", row.id, rule.order)
                } else {
                    name.into()
                };
                if name.len() > 512 || name.chars().any(char::is_control) {
                    return Err("legacy_route_structure");
                }
                rules.push(new_rule(name, config));
            } else {
                report.push(issue("legacy_route_empty_rule_omitted", Some(row)))
            }
        }
        // SyncEndpointRules order: user rules, then gates without a positioned row.
        endpoints.append_missing(&mut rules, &carried, row, report);
        let final_tag = match integer(&row.columns, "default_outbound_id", -1)? {
            -1 => "proxy",
            -2 => "direct",
            -5 => "warp-bypass",
            -3 => {
                rules.push(new_rule(
                    "Throne · reject".into(),
                    json!({"action":"reject"}),
                ));
                "direct"
            }
            _ => return Err("legacy_route_target_unsupported"),
        };
        let mut route = inherited_route
            .cloned()
            .unwrap_or_else(|| json!({"rule_set":[]}));
        route["final"] = json!(final_tag);
        route
    };
    rule_sets::materialize(&mut route, &rules, context, db, raw)?;
    if rules.len() > 1000 {
        return Err("legacy_route_limit");
    }
    endpoints.check_targets(&rules, &route)?;
    if !raw_verbatim
        && route.get("find_process").is_none()
        && setting_bool(db, "enable_stats", true)?
    {
        route["find_process"] = json!(true)
    }
    if !raw_verbatim && route.get("default_domain_resolver").is_none() {
        route["default_domain_resolver"] =
            json!({"server":"dns-direct","strategy":generated_dns::direct_strategy(db)?})
    }
    if let Some(resolver) = route.get("default_domain_resolver") {
        dns::resolver(resolver, &dns)?;
    }
    if raw_verbatim {
        report.push(issue("legacy_route_raw_verbatim", Some(row)));
    }
    let warp_enabled = setting_bool(db, "enable_warp", false)?;
    let adaptive_dns = !explicit_dns && crate::routing::legacy_dns::adaptive(&dns);
    let mut endpoint_ids = endpoints.ids();
    let documents: Vec<&Value> = rules
        .iter()
        .map(|r| &r.config)
        .chain([&route, &dns])
        .collect();
    for id in targets::endpoint_targets(&documents, profiles) {
        if !endpoint_ids.contains(&id) {
            endpoint_ids.push(id);
        }
    }
    let inbound_tags = inbounds.used(&rules, &dns);
    let endpoint_aware = !endpoint_ids.is_empty() || !inbound_tags.is_empty();
    Ok(RoutingProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name: row.name.clone(),
        mode: "rules".into(),
        rules,
        route,
        dns,
        source,
        legacy_constraints: Some(LegacyRoutingConstraints {
            warp_enabled,
            version: if endpoint_aware {
                6
            } else if raw_verbatim {
                5
            } else if adaptive_dns {
                4
            } else if warp_enabled {
                3
            } else {
                2
            },
            xray_dns_strategy: Some(generated_dns::xray_strategy(db)?),
            raw_verbatim,
            adaptive_dns: (raw_verbatim || endpoint_aware) && adaptive_dns,
            endpoints: endpoint_ids,
            inbound_tags,
        }),
    })
}
#[cfg(test)]
mod endpoint_tests;
#[cfg(test)]
mod tests;
