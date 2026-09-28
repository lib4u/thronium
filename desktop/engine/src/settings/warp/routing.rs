//! Compile portable WARP destinations into one runtime graph. The WARP exit is
//! settings-owned, never an extra saved profile or an automatic-pool candidate.
use super::BASE_TAG;
use crate::{
    settings::{boolean, string, value},
    store::Library,
};
use serde_json::{json, Value};

pub(crate) const TARGET: &str = "warp";
pub(crate) const BYPASS: &str = "warp-bypass";
pub(crate) const EXIT_TAG: &str = "settings-warp-exit";

// DNS `final` selects a DNS server, not an outbound. Only route.final is a
// destination; arbitrary strings such as domain names and headers stay intact.
fn targets(value: &mut Value, resolve: &mut impl FnMut(&str) -> Option<&'static str>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "outbound" | "detour" | "download_detour" | "endpoint"
                ) {
                    if let Some(target) = value.as_str().and_then(&mut *resolve) {
                        *value = json!(target);
                    }
                }
                targets(value, resolve);
            }
        }
        Value::Array(values) => {
            for value in values {
                targets(value, resolve);
            }
        }
        _ => {}
    }
}
fn references(core: &mut Value, resolve: &mut impl FnMut(&str) -> Option<&'static str>) {
    if let Some(target) = core["route"]["final"].as_str().and_then(&mut *resolve) {
        core["route"]["final"] = json!(target);
    }
    targets(core, resolve);
}

fn references_warp(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (matches!(
                key.as_str(),
                "outbound" | "detour" | "download_detour" | "endpoint"
            ) && value == TARGET)
                || references_warp(value)
        }),
        Value::Array(values) => values.iter().any(references_warp),
        _ => false,
    }
}

/// Unsupported composition guards must cover explicit routes as well as the
/// global switch. Disabled rules and a DNS server named `warp` are not exits.
pub(crate) fn enabled_for(library: &Library) -> bool {
    library
        .routing
        .active()
        .is_ok_and(|route| enabled_for_preset(library, route))
}
pub(crate) fn enabled_for_preset(
    library: &Library,
    route: &crate::routing::RoutingProfile,
) -> bool {
    boolean(library, "enable_warp")
        || references_warp(&route.dns)
        || references_warp(&route.route)
        || (route.mode == "rules"
            && (route.route["final"] == TARGET
                || route
                    .rules
                    .iter()
                    .any(|rule| rule.enabled && references_warp(&rule.config))))
}

pub(crate) fn apply(core: &mut Value, library: &Library) -> Result<(), String> {
    let global = boolean(library, "enable_warp");
    let requested = core["route"]["final"] == TARGET || references_warp(core);
    if global || requested {
        // Global settings were already validated when saved. Explicit routes
        // also require credentials while the global toggle is off.
        if !global {
            super::validate(library)?;
        }
        let exit = if global { "proxy" } else { EXIT_TAG };
        let base = if global { BASE_TAG } else { "proxy" };
        for key in ["outbounds", "endpoints"] {
            if core[key]
                .as_array()
                .into_iter()
                .flatten()
                .any(|o| o["tag"] == EXIT_TAG || o["tag"] == BASE_TAG)
            {
                return Err("route_tag_conflict".into());
            }
        }
        let mut found = false;
        for key in ["outbounds", "endpoints"] {
            for outbound in core[key].as_array_mut().into_iter().flatten() {
                if outbound["tag"] == "proxy" {
                    // Direct's implicit UDP fragmentation default makes an
                    // otherwise empty direct outbound usable as a WG detour.
                    if outbound["type"] == "direct"
                        && outbound.get("udp_fragment").is_none_or(Value::is_null)
                    {
                        outbound["udp_fragment"] = json!(true);
                    }
                    outbound["tag"] = json!(base);
                    found = true;
                }
                if global && outbound["detour"] == "proxy" {
                    outbound["detour"] = json!(base);
                }
            }
        }
        if !found {
            return Err("settings_invalid:enable_warp".into());
        }
        let url = reqwest::Url::parse(&format!("udp://{}", string(library, "warp_ep")))
            .map_err(|_| "settings_invalid:warp_ep")?;
        let host = url
            .host_str()
            .ok_or("settings_invalid:warp_ep")?
            .trim_matches(['[', ']']);
        let reserved = value(library, "warp_reserved")
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| v.as_str().unwrap_or("").parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "settings_invalid:warp_reserved")?;
        let mut peer = json!({"address":host,"port":url.port().unwrap_or(2408),"public_key":string(library,"warp_public_key"),"allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":super::PERSISTENT_KEEPALIVE_SECONDS});
        if !reserved.is_empty() {
            peer["reserved"] = json!(reserved);
        }
        if core.get("endpoints").is_none_or(Value::is_null) {
            core["endpoints"] = json!([]);
        }
        core["endpoints"].as_array_mut().ok_or("invalid_configuration")?.push(json!({"type":"wireguard","tag":exit,"system":false,"mtu":super::MTU,"address":value(library,"warp_ifc_addrs"),"private_key":string(library,"warp_private_key"),"detour":base,"peers":[peer]}));
    }
    references(core, &mut |target| match target {
        TARGET => Some(if global { "proxy" } else { EXIT_TAG }),
        BYPASS => Some(if global { BASE_TAG } else { "proxy" }),
        _ => None,
    });
    Ok(())
}

/// Derive a resolver for the two explicit VPN paths without changing the
/// user's shared DNS server or its explicit rules. Local/synthetic resolvers
/// perform no outbound query and retain their original behavior.
pub(crate) fn dns_target(server: &Value, outbound: &str) -> Option<Value> {
    let suffix = match outbound {
        BASE_TAG => "bypass",
        EXIT_TAG => "exit",
        _ => return None,
    };
    if !matches!(
        server["type"].as_str(),
        Some("udp" | "tcp" | "tls" | "https" | "h3" | "quic")
    ) {
        return None;
    }
    let mut derived = server.clone();
    derived["tag"] = json!(format!("settings-warp-dns-{suffix}"));
    derived["detour"] = json!(outbound);
    Some(derived)
}

/// Inspect the retained request, since editable settings may have changed.
pub(crate) fn final_uses_explicit_warp(request: &crate::proto::LoadConfigReq) -> bool {
    request
        .core_config
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .is_some_and(|core| {
            core["route"]["final"] == EXIT_TAG
                && core["endpoints"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|endpoint| {
                        endpoint["tag"] == EXIT_TAG
                            && endpoint["type"] == "wireguard"
                            && endpoint["detour"] == "proxy"
                    })
        })
}

#[cfg(test)]
mod tests;
