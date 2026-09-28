//! Defaults for the generated Xray instance. Complete JSON instances own their settings.
use super::{boolean as b, integer as n, string as s, value as v};
use crate::{
    proto::LoadConfigReq,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};

fn inherit(object: &mut Value, key: &str, value: Value) {
    if object.get(key).is_none() {
        object[key] = value;
    }
}

pub(super) fn validate(library: &Library) -> Result<(), String> {
    if b(library, "xray_api_enabled") {
        let port = n(library, "xray_api_port");
        let mixed = !b(library, "disable_mixed_inbound")
            && !b(library, "random_inbound_port")
            && port == library.preferences.inbound_port as i64;
        let other = [
            ("core_box_api_enabled", "core_box_api_port"),
            ("core_box_clash_enabled", "core_box_clash_api"),
            ("enable_dns_server", "dns_server_listen_port"),
            ("enable_redirect", "redirect_listen_port"),
        ]
        .iter()
        .any(|(enabled, key)| b(library, enabled) && n(library, key) == port);
        let custom = super::value(library, "custom_inbound");
        let custom = custom
            .as_array()
            .into_iter()
            .flatten()
            .any(|i| i["listen_port"].as_i64() == Some(port));
        if mixed || other || custom {
            return Err(super::invalid("xray_api_port"));
        }
    }
    Ok(())
}

pub(super) fn prepare_outbound(outbound: &mut Value, library: &Library) {
    // XHTTP has its own multiplexing; Vision cannot carry TCP Mux requests.
    let vision = outbound["settings"]["flow"]
        .as_str()
        .is_some_and(|f| f.starts_with("xtls-rprx-vision"))
        || outbound["settings"]["vnext"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|server| {
                server["users"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|user| {
                        user["flow"]
                            .as_str()
                            .is_some_and(|f| f.starts_with("xtls-rprx-vision"))
                    })
            });
    if matches!(
        outbound["protocol"].as_str(),
        Some("vless" | "vmess" | "trojan")
    ) && outbound.get("mux").is_none()
        && b(library, "xray_mux_default_on")
        && outbound["streamSettings"]["network"] != "xhttp"
    {
        outbound["mux"] = json!({
            "enabled": true,
            "concurrency": if vision { -1 } else { n(library, "xray_mux_concurrency") },
            "xudpConcurrency": n(library, "xray_mux_xudp_concurrency"),
            "xudpProxyUDP443": s(library, "xray_mux_udp443"),
        });
    }

    let mut defaults = serde_json::Map::new();
    match s(library, "xray_tcp_fast_open").as_str() {
        "enabled" => {
            defaults.insert("tcpFastOpen".into(), json!(true));
        }
        "disabled" => {
            defaults.insert("tcpFastOpen".into(), json!(false));
        }
        _ => {}
    }
    for (key, setting) in [
        ("tcpKeepAliveIdle", "xray_tcp_keep_alive_idle"),
        ("tcpKeepAliveInterval", "xray_tcp_keep_alive_interval"),
        ("tcpUserTimeout", "xray_tcp_user_timeout"),
    ] {
        if n(library, setting) != 0 {
            defaults.insert(key.into(), v(library, setting));
        }
    }
    if b(library, "xray_tcp_mptcp") {
        defaults.insert("tcpMptcp".into(), json!(true));
    }
    if !defaults.is_empty() {
        // Invalid profile objects remain invalid and are reported by CheckConfig.
        if outbound
            .get("streamSettings")
            .is_some_and(|v| !v.is_object())
        {
            return;
        }
        if outbound.get("streamSettings").is_none() {
            outbound["streamSettings"] = json!({});
        }
        let stream = &mut outbound["streamSettings"];
        if stream.get("sockopt").is_some_and(|v| !v.is_object()) {
            return;
        }
        if stream.get("sockopt").is_none() {
            stream["sockopt"] = json!({});
        }
        for (key, value) in defaults {
            inherit(&mut stream["sockopt"], &key, value);
        }
    }
}

pub(super) fn apply(
    request: &mut LoadConfigReq,
    profile: &Profile,
    library: &Library,
) -> Result<(), String> {
    if matches!(
        profile.kind,
        ProfileKind::XrayConfig | ProfileKind::SingBoxConfig
    ) {
        return Ok(());
    }
    // xray_full_configs contains user-owned instances, including routing targets.
    let Some(input) = &mut request.xray_config else {
        return Ok(());
    };
    let mut config: Value = serde_json::from_str(input).map_err(|_| "invalid_configuration")?;
    config["log"] = json!({
        "loglevel": s(library, "xray_log_level"),
        "access": if b(library, "xray_access_log") { "" } else { "none" },
        "dnsLog": b(library, "xray_dns_log"),
        "maskAddress": s(library, "xray_log_mask_address"),
    });
    if b(library, "xray_policy_enabled") {
        config["policy"] = json!({"levels":{"0":{
            "handshake": n(library, "xray_policy_handshake"),
            "connIdle": n(library, "xray_policy_conn_idle"),
            "uplinkOnly": n(library, "xray_policy_uplink_only"),
            "downlinkOnly": n(library, "xray_policy_downlink_only"),
            "bufferSize": n(library, "xray_policy_buffer_size"),
        }}});
    }
    if b(library, "xray_api_enabled") {
        let port = n(library, "xray_api_port");
        if config["inbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|i| i["port"].as_i64() == Some(port))
        {
            return Err("xray_api_port_conflict".into());
        }
        config["api"] = json!({"tag":"thronium-xray-api", "listen":format!("127.0.0.1:{port}"), "services":["StatsService", "ReflectionService"]});
        config["stats"] = json!({});
        if !config["policy"].is_object() {
            config["policy"] = json!({});
        }
        config["policy"]["system"] = json!({
            "statsInboundUplink": b(library, "xray_stats_inbounds"),
            "statsInboundDownlink": b(library, "xray_stats_inbounds"),
            "statsOutboundUplink": b(library, "xray_stats_outbounds"),
            "statsOutboundDownlink": b(library, "xray_stats_outbounds"),
        });
    }
    *input = config.to_string();
    Ok(())
}

#[cfg(test)]
mod tests;
