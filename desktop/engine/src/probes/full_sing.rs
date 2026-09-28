//! Route-preserving disposable checks of a complete sing-box client.
use crate::{
    proto,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};

pub(crate) fn supported(library: &Library, profile: &Profile) -> bool {
    profile.kind == ProfileKind::SingBoxConfig
        && profile.vpn_policy.is_none()
        && !crate::group_chains::policy(library, profile).enabled()
        && client_shape(&profile.config)
}
fn inbound(config: &Value) -> Option<&Value> {
    let list = config["inbounds"].as_array()?;
    list.iter()
        .find(|i| matches!(i["type"].as_str(), Some("socks" | "mixed")))
        .or(list.first())
}
/// Top-level sections a disposable check never inherits: they would bind the
/// host's own listeners or files. The rest of the client's JSON is kept, as Qt
/// keeps it, and the core decides what it accepts.
const DISPOSED: [&str; 3] = ["experimental", "services", "network_namespaces"];
fn inbound_tag(config: &Value) -> &str {
    inbound(config)
        .and_then(|i| i["tag"].as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("thronium-client-test")
}
/// Userspace endpoints the disposable core can own: WireGuard, OpenVPN and
/// OpenConnect with unique tags, never a host interface or a named device.
fn endpoints_shape(value: Option<&Value>) -> bool {
    let Some(endpoints) = value.filter(|v| !v.is_null()) else {
        return true;
    };
    let Some(endpoints) = endpoints.as_array() else {
        return false;
    };
    let mut tags = std::collections::HashSet::new();
    endpoints.iter().all(|endpoint| {
        (endpoint["type"] == "wireguard" || crate::vpn_endpoint::is_vpn(endpoint))
            && endpoint["tag"]
                .as_str()
                .is_some_and(|tag| !tag.is_empty() && tags.insert(tag))
    })
}
/// The disposable core owns no host device, so an endpoint of the tested client
/// runs in userspace for the check, as it does for every other measurement.
fn userspace_endpoints(config: &mut Value) {
    for endpoint in config["endpoints"].as_array_mut().into_iter().flatten() {
        if let Some(object) = endpoint.as_object_mut() {
            for key in ["system", "system_interface", "name"] {
                object.remove(key);
            }
        }
    }
}
pub(crate) fn client_shape(config: &Value) -> bool {
    let Some(object) = config.as_object() else {
        return false;
    };
    if !endpoints_shape(object.get("endpoints")) {
        return false;
    }
    let Some(outbounds) = config["outbounds"].as_array().filter(|a| !a.is_empty()) else {
        return false;
    };
    if outbounds.iter().any(|o| {
        !matches!(
            o["type"].as_str(),
            Some(
                "direct"
                    | "socks"
                    | "http"
                    | "shadowsocks"
                    | "shadowsocksr"
                    | "vmess"
                    | "vless"
                    | "trojan"
                    | "hysteria"
                    | "hysteria2"
                    | "tuic"
                    | "shadowtls"
                    | "anytls"
                    | "ssh"
                    | "naive"
                    | "snell"
                    | "mieru"
                    | "juicity"
                    | "trusttunnel"
            )
        ) || o.as_object().is_some_and(|o| {
            o.keys().any(|k| {
                ["type", "tag"]
                    .iter()
                    .any(|known| k.eq_ignore_ascii_case(known) && k != known)
            })
        })
    }) {
        return false;
    }
    match object.get("inbounds") {
        None | Some(Value::Array(_)) => {}
        _ => return false,
    }
    if object
        .get("inbounds")
        .and_then(Value::as_array)
        .is_some_and(|list| {
            list.iter()
                .any(|i| i.get("tag").is_some_and(|v| !v.is_string()))
        })
    {
        return false;
    }
    if config["dns"].as_object().is_some_and(|o| {
        o.keys()
            .any(|k| k.eq_ignore_ascii_case("rules") && k != "rules")
    }) {
        return false;
    }
    if config["route"].as_object().is_some_and(|r| {
        r.keys().any(|k| {
            ["rules", "rule_set"]
                .iter()
                .any(|known| k.eq_ignore_ascii_case(known) && k != known)
                || matches!(
                    k.to_ascii_lowercase().as_str(),
                    "geoip" | "geosite" | "dhcp_lease_files"
                )
        })
    }) {
        return false;
    }
    if let Some(sets) = config["route"].get("rule_set") {
        let Some(sets) = sets.as_array() else {
            return false;
        };
        if sets.iter().any(|set| {
            set["type"] != "inline"
                || set.as_object().is_none_or(|o| {
                    o.keys()
                        .any(|k| !matches!(k.as_str(), "type" | "tag" | "rules"))
                })
        }) {
            return false;
        }
    }
    true
}

pub(crate) fn request(
    profile: &Profile,
    url: &str,
    timeout_ms: u32,
) -> Result<proto::TestReq, String> {
    if !client_shape(&profile.config) {
        return Err("probe_full_config_unsupported".into());
    }
    let (port, _listener) =
        crate::loopback_ports::claim(&Default::default()).ok_or("probe_configuration_failed")?;
    let tag = format!("thronium-client-probe-{}", uuid::Uuid::new_v4());
    let mut config = profile.config.clone();
    config["log"] = json!({"level":"warn","disabled":false});
    config["inbounds"] = json!([{"type":"socks","tag":inbound_tag(&profile.config),"listen":"127.0.0.1","listen_port":port}]);
    if let Some(object) = config.as_object_mut() {
        for key in DISPOSED {
            object.remove(key);
        }
    }
    userspace_endpoints(&mut config);
    // The test dials this SOCKS outbound, whose connection enters the original
    // client's router. Choosing the source final outbound directly would bypass
    // DNS/route/inline-rule-set policy even if their JSON remained in the box.
    // Append without changing the original default outbound order or route.final.
    config["outbounds"].as_array_mut().unwrap().push(
        json!({"type":"socks","tag":tag,"server":"127.0.0.1","server_port":port,"version":"5"}),
    );
    // The client's own VPN endpoints are readiness dependencies of the test.
    let vpn_endpoint_tags = super::vpn::endpoint_tags(&config);
    Ok(proto::TestReq {
        config: Some(config.to_string()),
        outbound_tags: vec![tag],
        vpn_status_timeout_ms: (!vpn_endpoint_tags.is_empty())
            .then_some(super::VPN_STATUS_TIMEOUT_MS),
        vpn_endpoint_tags,
        use_default_outbound: Some(false),
        test_current: Some(false),
        need_xray: Some(false),
        url: Some(url.into()),
        max_concurrency: Some(1),
        test_timeout_ms: Some(timeout_ms as i32),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests;
