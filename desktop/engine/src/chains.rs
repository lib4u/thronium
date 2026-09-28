//! Chains are stored in connection order: device -> first hop -> ... -> exit.
//! Compiled sing-box detours and Xray dialerProxy links point toward the previous hop.
//! A complete Xray configuration may be the first hop only: it runs as its own
//! instance and the next hop dials through its managed socks inbound, as in Qt.
//! A userspace endpoint (WireGuard, OpenVPN, OpenConnect, Tailscale) is a hop
//! like any sing-box outbound: it is emitted under `endpoints`, dials through
//! the previous hop with `detour`, and the next hop detours into it; a fixed
//! local port only fits the first hop. OTP-bound endpoints are announced to the
//! shared source registry exactly where their tag is emitted.
use crate::{
    config,
    proto::LoadConfigReq,
    store::{Profile, ProfileKind},
    vpn_auth::otp,
};
use serde_json::{json, Value};
use std::{collections::HashSet, net::TcpListener};

pub const MAX_HOPS: usize = 16;
mod rules;
#[cfg(test)]
mod tests;
pub use rules::{flatten, ENDPOINT_TYPES};
pub(crate) use rules::{is_endpoint, is_endpoint_type, is_vpn_endpoint, validate_sequence};
fn push(root: &mut Value, key: &str, value: Value) -> Result<(), String> {
    if root.get(key).is_none() {
        root[key] = json!([]);
    }
    // Outbounds and endpoints share one tag namespace in sing-box.
    if let Some(tag) = value["tag"].as_str() {
        for list in ["outbounds", "endpoints"] {
            if root[list]
                .as_array()
                .is_some_and(|items| items.iter().any(|v| v["tag"] == tag))
            {
                return Err("chain_tag_conflict".into());
            }
        }
    }
    root[key]
        .as_array_mut()
        .ok_or("invalid_chain_configuration")?
        .push(value);
    Ok(())
}
fn rule(root: &mut Value, key: &str, value: Value) -> Result<(), String> {
    if root.get(key).is_none() {
        root[key] = json!({});
    }
    let routing = root[key]
        .as_object_mut()
        .ok_or("invalid_chain_configuration")?;
    routing
        .entry("rules")
        .or_insert(json!([]))
        .as_array_mut()
        .ok_or("invalid_chain_configuration")?
        .insert(0, value);
    Ok(())
}

struct Builder<'a> {
    core: &'a mut Value,
    xray: &'a mut Value,
    /// Complete Xray configurations that run as their own instances.
    full: Vec<Value>,
    ports: Vec<TcpListener>,
    used: HashSet<u16>,
}
impl Builder<'_> {
    fn port(&mut self) -> Result<u16, String> {
        let (port, guard) =
            crate::loopback_ports::claim(&self.used).ok_or("bridge_port_unavailable")?;
        self.used.insert(port);
        self.ports.push(guard);
        Ok(port)
    }
    fn credentials(&mut self) -> Result<(u16, String), String> {
        Ok((self.port()?, uuid::Uuid::new_v4().simple().to_string()))
    }
    /// The outbound of one core that dials an authenticated loopback socks inbound.
    fn dialer(&mut self, in_xray: bool, tag: &str, port: u16, auth: &str) -> Result<(), String> {
        if in_xray {
            push(
                self.xray,
                "outbounds",
                json!({"tag":tag,"protocol":"socks","settings":{"address":"127.0.0.1","port":port,"user":auth,"pass":auth}}),
            )
        } else {
            push(
                self.core,
                "outbounds",
                json!({"tag":tag,"type":"socks","server":"127.0.0.1","server_port":port,"version":"5","username":auth,"password":auth}),
            )
        }
    }
    /// Create an authenticated bridge whose client belongs to the opposite core.
    fn bridge(&mut self, target_xray: bool, target: &str, tag: &str) -> Result<(), String> {
        let (port, auth) = self.credentials()?;
        let inbound = format!("{tag}-in");
        if target_xray {
            push(
                self.xray,
                "inbounds",
                json!({"tag":inbound,"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":auth,"pass":auth}],"udp":true}}),
            )?;
            rule(
                self.xray,
                "routing",
                json!({"type":"field","inboundTag":[inbound],"outboundTag":target}),
            )?;
        } else {
            push(
                self.core,
                "inbounds",
                json!({"tag":inbound,"type":"socks","listen":"127.0.0.1","listen_port":port,"users":[{"username":auth,"password":auth}]}),
            )?;
            rule(
                self.core,
                "route",
                json!({"inbound":[inbound],"action":"route","outbound":target}),
            )?;
        }
        self.dialer(!target_xray, tag, port, &auth)
    }
    /// Run a complete Xray configuration as its own instance behind one managed
    /// socks inbound; `tag` names the outbound that dials it from the chosen core.
    /// The user's outbounds, routing and DNS stay theirs and are not rewritten.
    fn full_instance(
        &mut self,
        config: &Value,
        dial_from_xray: bool,
        tag: &str,
    ) -> Result<(), String> {
        let (port, auth) = self.credentials()?;
        let inbound = json!({"tag":"thronium-in","listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":auth,"pass":auth}],"udp":true}});
        self.full
            .push(config::managed_xray_inbound(config, inbound)?);
        self.dialer(dial_from_xray, tag, port, &auth)
    }
}

/// Loopback ports a new bridge or instance must not reuse: every inbound, and
/// the loopback dialers of complete Xray instances of earlier pool members,
/// which listen in their own configuration and whose bind guard is already
/// released, so the OS may offer that port again.
fn reserved_ports(core: &Value, xray: &Value) -> HashSet<u16> {
    let mut used = HashSet::new();
    for (root, key) in [(core, "listen_port"), (xray, "port")] {
        used.extend(
            root["inbounds"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v[key].as_u64().and_then(|p| u16::try_from(p).ok())),
        );
    }
    let loopback = |address: &Value| address.as_str() == Some("127.0.0.1");
    used.extend(
        core["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|o| loopback(&o["server"]))
            .chain(
                xray["outbounds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|o| loopback(&o["settings"]["address"])),
            )
            .filter_map(|o| {
                o["server_port"]
                    .as_u64()
                    .or(o["settings"]["port"].as_u64())
                    .and_then(|p| u16::try_from(p).ok())
            }),
    );
    used
}

/// Compile the chain into `core`/`xray` and return the complete Xray
/// configurations it needs as separate instances. Endpoint hops are announced
/// to `sources` under their emitted tag so bound OTP automation follows them.
/// The tag this compiler gives each hop of a chain laid down under `tag`. The
/// single place that names a hop: a route that sends traffic to a node inside a
/// chain asks here instead of guessing a prefix.
pub(crate) fn hop_tags(hops: &[&Profile], tag: &str) -> Vec<String> {
    (0..hops.len())
        .map(|i| {
            if i + 1 == hops.len()
                && matches!(
                    hops[i].kind,
                    ProfileKind::SingBoxOutbound
                        | ProfileKind::XrayConfig
                        | ProfileKind::ExternalCore
                )
            {
                tag.into()
            } else {
                format!("thronium-chain-{tag}-{i}")
            }
        })
        .collect()
}
pub(crate) fn append(
    profile: &Profile,
    profiles: &[Profile],
    core: &mut Value,
    xray: &mut Value,
    tag: &str,
    sources: &mut otp::Build,
) -> Result<Vec<Value>, String> {
    let hops = flatten(profile, profiles)?;
    let tags = hop_tags(&hops, tag);
    let used = reserved_ports(core, xray);
    let mut builder = Builder {
        core,
        xray,
        full: vec![],
        ports: vec![],
        used,
    };
    for (i, p) in hops.iter().enumerate() {
        let is_xray = p.kind == ProfileKind::XrayOutbound;
        if p.kind == ProfileKind::XrayConfig {
            // Always the first hop: the next hop's core owns the dialing outbound.
            let next_xray = hops
                .get(i + 1)
                .is_some_and(|next| next.kind == ProfileKind::XrayOutbound);
            builder.full_instance(&p.config, next_xray, &tags[i])?;
            continue;
        }
        let previous = if i == 0 {
            None
        } else if hops[i - 1].kind == ProfileKind::XrayConfig
            || is_xray == (hops[i - 1].kind == ProfileKind::XrayOutbound)
        {
            Some(tags[i - 1].clone())
        } else {
            let bridge = format!("thronium-chain-{tag}-bridge-{i}");
            builder.bridge(!is_xray, &tags[i - 1], &bridge)?;
            Some(bridge)
        };
        let mut outbound = if p.kind == ProfileKind::ExternalCore {
            crate::external_core::parse(&p.config)?.socks_outbound(&tags[i])?
        } else {
            p.config.clone()
        };
        outbound["tag"] = json!(tags[i]);
        if is_xray {
            if previous.is_some() || outbound.get("streamSettings").is_some() {
                let stream = outbound
                    .as_object_mut()
                    .ok_or("invalid_chain_configuration")?
                    .entry("streamSettings")
                    .or_insert(json!({}))
                    .as_object_mut()
                    .ok_or("invalid_chain_configuration")?;
                let sockopt = stream
                    .entry("sockopt")
                    .or_insert(json!({}))
                    .as_object_mut()
                    .ok_or("invalid_chain_configuration")?;
                sockopt.remove("dialerProxy");
                if let Some(previous) = previous {
                    sockopt.insert("dialerProxy".into(), json!(previous));
                }
            }
            push(builder.xray, "outbounds", outbound)?;
        } else {
            outbound
                .as_object_mut()
                .ok_or("invalid_chain_configuration")?
                .remove("detour");
            if let Some(previous) = previous {
                outbound["detour"] = json!(previous);
            }
            let endpoint = is_endpoint(p);
            if endpoint {
                sources.emit(p, &tags[i], &outbound)?;
            }
            push(
                builder.core,
                if endpoint { "endpoints" } else { "outbounds" },
                outbound,
            )?;
        }
    }
    if hops
        .last()
        .is_some_and(|p| p.kind == ProfileKind::XrayOutbound)
    {
        builder.bridge(true, tags.last().unwrap(), tag)?;
    }
    Ok(builder.full)
}

pub fn build(profile: &Profile, profiles: &[Profile], port: u16) -> Result<LoadConfigReq, String> {
    build_with_sources(profile, profiles, port, &mut otp::Build::default())
}

pub(crate) fn build_with_sources(
    profile: &Profile,
    profiles: &[Profile],
    port: u16,
    sources: &mut otp::Build,
) -> Result<LoadConfigReq, String> {
    let placeholder = Profile {
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        ..profile.clone()
    };
    let mut request = config::build(&placeholder, port, None)?;
    let mut core: Value = serde_json::from_str(request.core_config.as_deref().unwrap())
        .map_err(|_| "invalid_chain_configuration")?;
    core["outbounds"]
        .as_array_mut()
        .unwrap()
        .retain(|o| o["tag"] != "proxy");
    let mut xray = json!({"inbounds":[],"outbounds":[]});
    let full = append(profile, profiles, &mut core, &mut xray, "proxy", sources)?;
    if xray["outbounds"].as_array().is_some_and(|v| !v.is_empty()) {
        request.need_xray = Some(true);
        request.xray_config = Some(xray.to_string());
    }
    // Eager start: a failing instance fails Start, where rollback exists, rather
    // than the first connection through it.
    request.xray_full_configs = full.iter().map(Value::to_string).collect();
    request.xray_full_idle_seconds = Some(0);
    request.core_config = Some(core.to_string());
    Ok(request)
}
