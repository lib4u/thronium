//! Qt auxiliary endpoints: OpenVPN/OpenConnect profiles, or chains ending in
//! one, that run beside the started profile and are reached only through
//! `preferred_by` gates (generate.cpp calculatePrerequisites, RouteProfile.cpp
//! SyncEndpointRules). Auxiliary tunnels are never route-gated; only their
//! `use_tunnel_dns` adds a DNS server. Translated to `profile:` references the
//! native routing compiler already emits under `endpoints`.
use super::{integer, issue, new_rule, parse, text, Result, SourceRoute};
use crate::{
    legacy_backup::{
        profiles::{Issue, ProfilePlan},
        SourceRule, SourceValue,
    },
    routing::Rule,
    store::{Profile, ProfileKind},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(super) struct Endpoint {
    source_id: i64,
    id: String,
    name: String,
    protocol: &'static str,
    tunnel_dns: bool,
    /// The endpoint and every chain hop: none may also be an ordinary target.
    members: Vec<String>,
    /// Qt's inner hops: the VPN nodes a chain endpoint carries before its exit,
    /// each addressable on its own so a route may prefer it.
    inner: Vec<InnerHop>,
}
pub(super) struct InnerHop {
    id: String,
    name: String,
    protocol: &'static str,
    tunnel_dns: bool,
}
#[derive(Default)]
pub(super) struct Endpoints(Vec<Endpoint>);

fn ids(row: &SourceRoute, key: &str) -> Result<Vec<i64>> {
    let value = text(&row.columns, key)?;
    if value.is_empty() {
        return Ok(vec![]);
    }
    let list = parse(value)?;
    let list = list.as_array().ok_or("legacy_route_structure")?;
    if list.len() > 64 {
        return Err("legacy_route_limit");
    }
    let mut seen = BTreeSet::new();
    list.iter()
        .map(|v| match v.as_i64() {
            Some(id) if id >= 0 && seen.insert(id) => Ok(id),
            _ => Err("legacy_route_structure"),
        })
        .collect()
}
fn reference(id: &str) -> String {
    format!("profile:{id}")
}
fn find<'a>(plan: &'a ProfilePlan, id: &str) -> Result<&'a Profile> {
    plan.profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or("legacy_route_reference_missing")
}
fn protocol(profile: &Profile) -> Result<&'static str> {
    crate::vpn_endpoint::profile_protocol(profile).ok_or("legacy_route_endpoint_unsupported")
}

pub(super) fn parse_row(row: &SourceRoute, profiles: Option<&ProfilePlan>) -> Result<Endpoints> {
    let listed = ids(row, "endpoint_profile_ids")?;
    let inner = ids(row, "inner_hop_endpoint_ids")?;
    if listed.is_empty() {
        // Qt reads inner-hop flags only for listed endpoints; orphans have no effect.
        return Ok(Endpoints::default());
    }
    let plan = profiles.ok_or("legacy_route_reference_missing")?;
    let mut result = Vec::new();
    for source_id in listed {
        let id = plan
            .profile_ids
            .get(&source_id)
            .ok_or("legacy_route_reference_missing")?;
        let profile = find(plan, id)?;
        let mut members = vec![id.clone()];
        // Qt reads the inner-hop flag only for a listed endpoint.
        let addressable = inner.contains(&source_id);
        let mut inner_hops = Vec::new();
        let exit = if profile.kind == ProfileKind::Chain {
            let hops = crate::references::members(profile)
                .map_err(|_| "legacy_route_reference_missing")?;
            let mut exit = None;
            for hop in hops {
                // Qt: no hop may be an extra core, a full config, a chain or Xray.
                let hop = find(plan, hop)?;
                if hop.kind != ProfileKind::SingBoxOutbound {
                    return Err("legacy_route_endpoint_unsupported");
                }
                members.push(hop.id.clone());
                // The previous hop is an inner one once a later hop follows it;
                // only a node that advertises routes can be preferred.
                if let Some(previous) = exit {
                    if addressable {
                        if let Some(protocol) = crate::vpn_endpoint::profile_protocol(previous) {
                            inner_hops.push(InnerHop {
                                id: previous.id.clone(),
                                name: previous.name.clone(),
                                protocol,
                                tunnel_dns: previous.vpn_policy.is_none_or(|p| p.use_tunnel_dns),
                            });
                        }
                    }
                }
                exit = Some(hop);
            }
            exit.ok_or("legacy_route_endpoint_unsupported")?
        } else {
            profile
        };
        let protocol = protocol(exit)?;
        if plan.groups.iter().any(|group| {
            group
                .proxy_chain
                .ids()
                .any(|hop| members.iter().any(|m| m == hop))
        }) {
            return Err("legacy_route_endpoint_unsupported");
        }
        result.push(Endpoint {
            source_id,
            id: id.clone(),
            name: profile.name.clone(),
            protocol,
            tunnel_dns: exit.vpn_policy.is_none_or(|p| p.use_tunnel_dns),
            members,
            inner: inner_hops,
        });
    }
    Ok(Endpoints(result))
}

impl Endpoints {
    pub(super) fn ids(&self) -> Vec<String> {
        self.0.iter().map(|e| e.id.clone()).collect()
    }
    fn gate(id: &str) -> Value {
        let tag = reference(id);
        json!({"preferred_by":[tag],"action":"route","outbound":tag})
    }
    /// Qt type-13 row: the user-positioned gate of a listed endpoint. A row
    /// whose endpoint left the list is skipped like Qt's build does.
    pub(super) fn positioned(
        &self,
        row: &SourceRule,
        carried: &mut BTreeSet<i64>,
        route: &SourceRoute,
        report: &mut Vec<Issue>,
    ) -> Result<Option<Rule>> {
        for (key, value) in &row.columns {
            let inert = match key.as_str() {
                "route_profile_id" | "rule_order" | "name" | "type" | "outbound_id" => true,
                "action" => matches!(text(&row.columns, key)?, "" | "route"),
                _ => match value {
                    SourceValue::Null => true,
                    SourceValue::Integer(n) => *n == 0,
                    SourceValue::Text(s) => s.trim().is_empty(),
                    _ => false,
                },
            };
            if !inert {
                return Err("legacy_route_field_unsupported");
            }
        }
        let target = integer(&row.columns, "outbound_id", -2)?;
        let Some(endpoint) = self
            .0
            .iter()
            .find(|e| e.source_id == target)
            .filter(|_| carried.insert(target))
        else {
            report.push(issue("legacy_route_endpoint_rule_omitted", Some(route)));
            return Ok(None);
        };
        let name = text(&row.columns, "name")?;
        let name = if name.trim().is_empty() {
            format!("{} route prefer", endpoint.name)
        } else {
            name.to_owned()
        };
        Ok(Some(new_rule(name, Self::gate(&endpoint.id))))
    }
    /// Qt appends one gate per endpoint without a positioned rule after the
    /// user rules (structured) or after the raw rules, in list order.
    pub(super) fn append_missing(
        &self,
        rules: &mut Vec<Rule>,
        carried: &BTreeSet<i64>,
        route: &SourceRoute,
        report: &mut Vec<Issue>,
    ) {
        for endpoint in &self.0 {
            if !carried.contains(&endpoint.source_id) {
                rules.push(new_rule(
                    format!("{} route prefer", endpoint.name),
                    Self::gate(&endpoint.id),
                ));
                report.push(issue("legacy_route_endpoint_rule_added", Some(route)));
            }
            // A Qt inner hop is never a positioned row: its gate is always the
            // appended one, right behind the endpoint that carries it.
            for hop in &endpoint.inner {
                rules.push(new_rule(
                    format!("{} route prefer", hop.name),
                    Self::gate(&hop.id),
                ));
                report.push(issue("legacy_route_endpoint_rule_added", Some(route)));
            }
        }
    }
    /// Generated DNS only (generate.cpp buildDNSSection): a tunnel server
    /// before `dns-local` and a head rule for each endpoint with tunnel DNS.
    pub(super) fn tunnel_dns(&self, dns: &mut Value) -> Result<bool> {
        let mut head = 0;
        let mut index = 0;
        let carried = self.0.iter().flat_map(|endpoint| {
            std::iter::once((endpoint.tunnel_dns, endpoint.protocol, endpoint.id.as_str())).chain(
                endpoint
                    .inner
                    .iter()
                    .map(|hop| (hop.tunnel_dns, hop.protocol, hop.id.as_str())),
            )
        });
        for (tunnel_dns, protocol, id) in carried {
            index += 1;
            if !tunnel_dns {
                continue;
            }
            let tag = format!("dns-vpn-{index}");
            let server = json!({"type":protocol,"tag":tag,"endpoint":reference(id)});
            let servers = dns["servers"].as_array_mut().ok_or("legacy_dns_invalid")?;
            let position = servers
                .iter()
                .position(|s| s["tag"] == "dns-local")
                .unwrap_or(servers.len());
            servers.insert(position, server);
            if dns.get("rules").is_none() {
                dns["rules"] = json!([]);
            }
            dns["rules"]
                .as_array_mut()
                .ok_or("legacy_dns_invalid")?
                .insert(
                    head,
                    json!({"preferred_by":[tag],"action":"route","server":tag}),
                );
            head += 1;
        }
        Ok(head > 0)
    }
    /// Qt refuses an endpoint (or a hop of it) that is also an ordinary route
    /// destination or a group front/landing proxy.
    pub(super) fn check_targets(&self, rules: &[Rule], route: &Value) -> Result<()> {
        let mut used = BTreeSet::new();
        for rule in rules
            .iter()
            .filter(|r| r.config.get("preferred_by").is_none())
        {
            targets(&rule.config, &mut used, 0);
        }
        targets(route, &mut used, 0);
        if self
            .0
            .iter()
            .flat_map(|e| e.members.iter())
            .any(|member| used.contains(member))
        {
            return Err("legacy_route_endpoint_unsupported");
        }
        Ok(())
    }
}
fn targets(value: &Value, used: &mut BTreeSet<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "outbound" | "final" | "detour" | "download_detour"
                ) {
                    if let Some(id) = value.as_str().and_then(|s| s.strip_prefix("profile:")) {
                        used.insert(id.to_owned());
                    }
                }
                targets(value, used, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                targets(item, used, depth + 1);
            }
        }
        _ => {}
    }
}
