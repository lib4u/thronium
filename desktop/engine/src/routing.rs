use crate::{
    proto::LoadConfigReq,
    store::{Profile, ProfileKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
/// Most routing profiles a library keeps.
pub const MAX_PROFILES: usize = 100;
/// Most simple rules one routing profile holds.
pub const MAX_RULES: usize = 1000;
/// Largest routing section, and largest routing profile or remote routing
/// list read from a file or URL.
pub const MAX_PROFILE_BYTES: usize = 4 * 1024 * 1024;
/// Largest category database (geoip/geosite) read from a file or URL.
pub const MAX_CATEGORY_DATABASE_BYTES: usize = 128 * 1024 * 1024;
/// Largest Xray geodata asset (geoip.dat, geosite.dat) a profile or test uses.
pub const MAX_GEODATA_ASSET_BYTES: usize = 64 * 1024 * 1024;
pub(crate) mod builtin;
pub mod legacy_context;
pub(crate) mod legacy_dns;
pub mod resources;
pub(crate) mod rule_sets;
pub mod source;
pub(crate) mod tailscale;

/// Imported policy requirements, independent of the editable route/DNS JSON.
/// Unknown versions are rejected instead of silently dropping their guarantees.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyRoutingConstraints {
    pub version: u8,
    #[serde(default, skip_serializing_if = "warp_disabled")]
    pub warp_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_dns_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "warp_disabled")]
    pub raw_verbatim: bool,
    #[serde(default, skip_serializing_if = "warp_disabled")]
    pub adaptive_dns: bool,
    /// Version 6: profile IDs the preset uses as auxiliary tunnels (OpenVPN,
    /// OpenConnect, a chain ending in one) or as endpoint-kind route targets.
    /// Their tunnel DNS and gates are compiled into the preset itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Version 6: custom inbound tags the rules name; the library must define them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_tags: Vec<String>,
}
fn warp_disabled(value: &bool) -> bool {
    !value
}
impl LegacyRoutingConstraints {
    pub fn valid(&self) -> bool {
        ((matches!(self.version, 1 | 2) && !self.warp_enabled
            || self.version == 3 && self.warp_enabled
            || self.version == 4)
            && !self.raw_verbatim
            && !self.adaptive_dns
            && self.endpoints.is_empty()
            && self.inbound_tags.is_empty()
            || self.version == 5 && self.endpoints.is_empty() && self.inbound_tags.is_empty()
            || self.version == 6)
            && self.xray_dns_strategy.as_deref().is_none_or(|s| {
                matches!(
                    s,
                    "UseIP" | "UseIPv4v6" | "UseIPv6v4" | "UseIPv4" | "ForceIPv4" | "ForceIPv6"
                )
            })
    }
    pub(crate) fn adapt_remote_dns(&self) -> bool {
        self.version == 4 || matches!(self.version, 5 | 6) && self.adaptive_dns
    }
    /// Endpoint and inbound dependencies are declared by the preset itself.
    pub(crate) fn endpoint_aware(&self) -> bool {
        self.version >= 6
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub config: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingProfile {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub rules: Vec<Rule>,
    pub route: Value,
    pub dns: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_constraints: Option<LegacyRoutingConstraints>,
}
impl RoutingProfile {
    /// The untouched Default profile: no client policy of its own.
    pub(crate) fn baseline(&self) -> bool {
        let baseline = Self::default();
        self.id == baseline.id
            && self.mode == baseline.mode
            && !self.rules.iter().any(|r| r.enabled)
            && self.route == baseline.route
            && self.dns == baseline.dns
    }
}
impl Default for RoutingProfile {
    fn default() -> Self {
        Self {
            id: "default".into(),
            name: "Default".into(),
            mode: "rules".into(),
            rules: vec![],
            route: json!({"final":"proxy", "auto_detect_interface":true, "find_process":true, "default_domain_resolver":"dns-direct"}),
            dns: json!({"servers":[{"type":"local", "tag":"dns-direct"}], "final":"dns-direct"}),
            source: None,
            legacy_constraints: None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Routing {
    pub revision: u64,
    pub active: String,
    pub profiles: Vec<RoutingProfile>,
}
impl Default for Routing {
    fn default() -> Self {
        Self {
            revision: 0,
            active: "default".into(),
            profiles: vec![RoutingProfile::default()],
        }
    }
}
impl Routing {
    /// Subscription policy is the default only while the client policy is untouched.
    pub(crate) fn customized(&self) -> bool {
        self.active().map_or(true, |active| !active.baseline())
    }
    pub fn active(&self) -> Result<&RoutingProfile, String> {
        self.profiles
            .iter()
            .find(|p| p.id == self.active)
            .ok_or("routing_profile_missing".into())
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.profiles.is_empty()
            || self.profiles.len() > MAX_PROFILES
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_PROFILE_BYTES
        {
            return Err("invalid_routing".into());
        }
        self.active()?;
        let mut ids = HashSet::new();
        for profile in &self.profiles {
            if let Some(value) = &profile.source {
                source::Source::parse(value)?;
            }
            if profile.id.is_empty()
                || !ids.insert(&profile.id)
                || profile.name.trim().is_empty()
                || profile.name.len() > crate::store::MAX_NAME_BYTES
                || !matches!(profile.mode.as_str(), "rules" | "all" | "direct")
                || !profile.route.is_object()
                || !profile.dns.is_object()
                || profile.route.get("rules").is_some()
                || profile.rules.len() > MAX_RULES
                || profile
                    .legacy_constraints
                    .as_ref()
                    .is_some_and(|c| !c.valid())
            {
                return Err("invalid_routing".into());
            }
            let mut rules = HashSet::new();
            for rule in &profile.rules {
                if rule.id.is_empty()
                    || !rules.insert(&rule.id)
                    || rule.name.trim().is_empty()
                    || rule.name.len() > crate::store::MAX_NAME_BYTES
                    || !rule.config.is_object()
                {
                    return Err("invalid_routing".into());
                }
            }
        }
        Ok(())
    }
}

fn push(config: &mut Value, key: &str, value: Value) -> Result<(), String> {
    if config.get(key).is_none() {
        config[key] = json!([]);
    }
    config[key]
        .as_array_mut()
        .ok_or("invalid_configuration")?
        .push(value);
    Ok(())
}
fn free_port(
    used: &mut HashSet<u16>,
    guards: &mut Vec<std::net::TcpListener>,
) -> Result<u16, String> {
    let (port, guard) = crate::loopback_ports::claim(used).ok_or("bridge_port_unavailable")?;
    used.insert(port);
    guards.push(guard);
    Ok(port)
}

// Profile IDs are app references; generated tags remain independent of display names.
// Full sing-box configurations own their routing and are kept completely opaque.
pub fn apply(
    request: &mut LoadConfigReq,
    profile: &Profile,
    routing: &RoutingProfile,
    profiles: &[Profile],
) -> Result<(), String> {
    apply_with_sources(
        request,
        profile,
        routing,
        profiles,
        &mut crate::vpn_auth::otp::Build::default(),
        &HashMap::new(),
    )
}

/// `aliases` name the renamed copies a group wrapper compiles, so a route that
/// prefers a node of a chain still finds it under the profile the person wrote.
pub(crate) fn apply_with_sources(
    request: &mut LoadConfigReq,
    profile: &Profile,
    routing: &RoutingProfile,
    profiles: &[Profile],
    sources: &mut crate::vpn_auth::otp::Build,
    aliases: &HashMap<String, String>,
) -> Result<(), String> {
    if matches!(
        profile.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        return Ok(());
    }
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|e| e.to_string())?;
    let mut route = routing.route.clone();
    route["rules"] = if routing.mode == "rules" {
        json!(routing
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| &r.config)
            .collect::<Vec<_>>())
    } else {
        json!([])
    };
    if routing.mode != "rules" {
        route["final"] = json!(if routing.mode == "direct" {
            "direct"
        } else {
            "proxy"
        });
    }
    let mut dns = routing.dns.clone();
    let mut needed = BTreeSet::new();
    references(&route, &mut needed);
    references(&dns, &mut needed);
    needed.remove(&profile.id);
    // A node this route names inside a chain it already carries is that chain's
    // own hop: Qt's inner hops. The chain compiler says under which tag it laid
    // the hop down, so nothing here guesses a tag or builds a second tunnel.
    let mut inner: BTreeMap<String, String> = BTreeMap::new();
    for id in &needed {
        let target = profiles
            .iter()
            .find(|p| &p.id == id)
            .ok_or("route_target_missing")?;
        if target.kind != ProfileKind::Chain {
            continue;
        }
        let hops = crate::chains::flatten(target, profiles)?;
        let tags = crate::chains::hop_tags(&hops, &format!("thronium-route-{id}"));
        for (hop, tag) in hops.iter().zip(tags) {
            let origin = aliases.get(&hop.id).unwrap_or(&hop.id);
            if origin != id && needed.contains(origin) {
                inner.insert(origin.clone(), tag);
            }
        }
    }
    needed.retain(|id| !inner.contains_key(id));
    let mut xray: Value = request
        .xray_config
        .as_ref()
        .map(|s| serde_json::from_str(s))
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| json!({"inbounds":[], "outbounds":[]}));
    let mut used_ports: HashSet<u16> = core["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["listen_port"].as_u64().map(|n| n as u16))
        .collect();
    used_ports.extend(
        xray["inbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["port"].as_u64().map(|n| n as u16)),
    );
    let mut port_guards = Vec::new();
    for id in needed {
        let auxiliary = profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("route_target_missing")?;
        let tag = format!("thronium-route-{id}");
        let mut outbound = auxiliary.config.clone();
        match auxiliary.kind {
            ProfileKind::Chain | ProfileKind::AutoSelector => {
                let full = if auxiliary.kind == ProfileKind::AutoSelector {
                    crate::auto_selector::append(
                        auxiliary, profiles, &mut core, &mut xray, &tag, sources,
                    )?
                } else {
                    crate::chains::append(auxiliary, profiles, &mut core, &mut xray, &tag, sources)?
                };
                request
                    .xray_full_configs
                    .extend(full.iter().map(Value::to_string));
                if xray["outbounds"].as_array().is_some_and(|v| !v.is_empty()) {
                    request.need_xray = Some(true);
                }
            }
            ProfileKind::SingBoxOutbound => {
                outbound["tag"] = json!(tag);
                let key = if crate::chains::is_endpoint_type(&outbound) {
                    "endpoints"
                } else {
                    "outbounds"
                };
                if key == "endpoints" {
                    sources.emit(auxiliary, &tag, &outbound)?;
                }
                push(&mut core, key, outbound)?;
            }
            ProfileKind::XrayOutbound => {
                let port = free_port(&mut used_ports, &mut port_guards)?;
                if xray["outbounds"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|o| o["tag"] == tag))
                {
                    return Err("route_tag_conflict".into());
                }
                outbound["tag"] = json!(tag);
                push(&mut xray, "outbounds", outbound)?;
                push(
                    &mut xray,
                    "inbounds",
                    json!({"tag":tag, "listen":"127.0.0.1", "port":port, "protocol":"socks", "settings":{"auth":"noauth", "udp":true}}),
                )?;
                if xray.get("routing").is_none() {
                    xray["routing"] = json!({"rules":[]});
                }
                if xray["routing"].get("rules").is_none() {
                    xray["routing"]["rules"] = json!([]);
                }
                xray["routing"]["rules"]
                    .as_array_mut()
                    .ok_or("invalid_xray_routing")?
                    .insert(
                        0,
                        json!({"type":"field", "inboundTag":[tag], "outboundTag":tag}),
                    );
                push(
                    &mut core,
                    "outbounds",
                    json!({"type":"socks", "tag":tag, "server":"127.0.0.1", "server_port":port, "version":"5"}),
                )?;
                request.need_xray = Some(true);
            }
            _ => return Err("route_target_requires_outbound".into()),
        }
    }
    rewrite(&mut route, &profile.id, &inner);
    rewrite(&mut dns, &profile.id, &inner);
    // Internal authenticated bridge inbounds must reach their hop before global user rules.
    let mut internal = core["route"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if routing
        .legacy_constraints
        .as_ref()
        .is_some_and(|c| c.raw_verbatim)
    {
        // A verbatim preset cannot silently drop authenticated bridge routes.
        // Such a composition needs explicit source ingress mapping first.
        if !internal.is_empty() {
            return Err("legacy_routing_verbatim_bridge_conflict".into());
        }
    } else {
        let rules = route["rules"].as_array().cloned().unwrap_or_default();
        // Before anything the person wrote and before the built-in rules, as in
        // Qt: whatever the external core sends on its own leaves directly.
        if let Some(external) = crate::external_core::runtime::carrier(profiles, profile) {
            let (own_route, own_dns) = crate::external_core::runtime::own_traffic_rules(external)?;
            internal.push(own_route);
            if !dns["rules"].is_array() {
                dns["rules"] = json!([]);
            }
            dns["rules"]
                .as_array_mut()
                .ok_or("invalid_configuration")?
                .insert(0, own_dns);
        }
        if routing.legacy_constraints.is_none() {
            internal.extend(builtin::for_rules(&rules));
        }
        internal.extend(rules);
        route["rules"] = json!(internal);
    }
    core["route"] = route;
    if routing
        .legacy_constraints
        .as_ref()
        .is_some_and(LegacyRoutingConstraints::adapt_remote_dns)
    {
        legacy_dns::apply(
            &mut dns,
            request.need_xray == Some(true) || !request.xray_full_configs.is_empty(),
        );
    }
    tailscale::apply(&mut dns, profile);
    core["dns"] = dns;
    if request.need_xray == Some(true) {
        request.xray_config = Some(xray.to_string());
    }
    request.core_config = Some(core.to_string());
    Ok(())
}

mod references;
#[cfg(test)]
mod tests;
pub use references::*;
