//! Subscription identity is distinct from display data and probe targets.
use crate::store::{Profile, ProfileKind};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// Canonical keys ignore map ordering but preserve every array element and value.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}
pub(super) fn content(profile: &Profile) -> String {
    canonical(&json!([profile.kind, profile.config])).to_string()
}
pub(super) fn identity(profile: &Profile) -> String {
    let Some(c) = egress(profile) else {
        return content(profile);
    };
    let xray = matches!(
        profile.kind,
        ProfileKind::XrayOutbound | ProfileKind::XrayConfig
    );
    let protocol = c.get("type").or(c.get("protocol"));
    if protocol.and_then(Value::as_str) == Some("wireguard") {
        // Multi-peer topology belongs to identity, not private/PSK material.
        // Unknown legacy layouts retain exact-content matching.
        if let Some(peers) = c["peers"].as_array().filter(|p| !p.is_empty()) {
            let peers: Option<Vec<_>> = peers
                .iter()
                .map(|p| {
                    let address = p["address"].as_str().filter(|s| !s.is_empty())?;
                    let port = p["port"].as_u64().filter(|p| (1..=65535).contains(p))?;
                    Some(json!([address, port, p["allowed_ips"]]))
                })
                .collect();
            if let Some(peers) = peers {
                return canonical(&json!([profile.kind, protocol, peers])).to_string();
            }
        }
        return content(profile);
    }
    let endpoint = if xray {
        let settings = &c["settings"];
        if settings["address"].is_string() {
            Some(settings)
        } else {
            settings["vnext"]
                .as_array()
                .or(settings["servers"].as_array())
                .filter(|items| items.len() == 1)
                .and_then(|items| items.first())
        }
    } else {
        Some(c)
    };
    let Some(endpoint) = endpoint else {
        return content(profile);
    };
    let server = &endpoint[if xray { "address" } else { "server" }];
    if !server.as_str().is_some_and(|s| !s.is_empty()) {
        return content(profile);
    }
    let mut key = json!({"kind":profile.kind, "type":protocol, "server":server,
        "port":endpoint[if xray { "port" } else { "server_port" }]});
    if xray {
        let s = &c["streamSettings"];
        let tls = if s["security"] == "reality" {
            &s["realitySettings"]
        } else {
            &s["tlsSettings"]
        };
        key["transport"] = json!([
            s["network"],
            s["security"],
            tls["serverName"],
            tls["fingerprint"]
        ]);
    } else {
        key["transport"] = c["transport"]["type"].clone();
        let tls = &c["tls"];
        if tls["enabled"] == true {
            key["tls"] = json!([
                true,
                tls["disable_sni"].as_bool().unwrap_or(false),
                tls["server_name"].as_str().unwrap_or(""),
                tls["utls"]["enabled"] == true,
                tls["utls"]["fingerprint"],
                tls["ech"]["enabled"] == true,
                tls["reality"]["enabled"] == true
            ]);
        }
        if matches!(c["type"].as_str(), Some("hysteria" | "hysteria2")) {
            key["hopping"] = json!([c["server_ports"], c.get("obfs").is_some()]);
        }
    }
    canonical(&key).to_string()
}

// Match Qt's explicit/default egress without treating a display descriptor as
// a subscription fingerprint. Unresolved/cyclic selectors stay content-only.
fn egress(profile: &Profile) -> Option<&Value> {
    match profile.kind {
        ProfileKind::SingBoxConfig => {
            let outbounds = profile.config["outbounds"].as_array()?;
            let mut tag = profile.config["route"]["final"].as_str().unwrap_or("");
            for _ in 0..5 {
                let target = if tag.is_empty() {
                    outbounds.first()?
                } else {
                    outbounds.iter().find(|o| o["tag"] == tag)?
                };
                match target["type"].as_str()? {
                    "selector" | "urltest" => {
                        tag = target["default"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .or_else(|| target["outbounds"].as_array()?.first()?.as_str())?;
                    }
                    "direct" | "block" | "dns" => return None,
                    _ => return Some(target),
                }
            }
            None
        }
        ProfileKind::XrayConfig => profile.config["outbounds"].as_array()?.iter().find(|o| {
            o["protocol"].is_string() && !crate::profile_descriptor::infrastructure_outbound(o)
        }),
        ProfileKind::SingBoxOutbound | ProfileKind::XrayOutbound => Some(&profile.config),
        _ => None,
    }
}
