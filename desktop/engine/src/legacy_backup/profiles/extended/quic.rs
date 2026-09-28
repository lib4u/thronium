//! Hysteria 1/2 fields and QUIC defaults as their Qt Build applies them.
use super::*;

pub(crate) fn hysteria(config: &mut Value) -> Result<(), &'static str> {
    strings(config, &["hop_interval", "obfs", "auth", "auth_str"])?;
    counts(
        config,
        &["up_mbps", "down_mbps", "recv_window_conn", "recv_window"],
    )?;
    booleans(config, &["disable_mtu_discovery"])
}
pub(crate) fn hysteria2(config: &mut Value) -> Result<(), &'static str> {
    strings(
        config,
        &[
            "hop_interval",
            "hop_interval_max",
            "password",
            "bbr_profile",
        ],
    )?;
    counts(config, &["up_mbps", "down_mbps"])?;
    booleans(config, &["disable_chrome_parrot"])?;
    if let Some(obfs) = config.get("obfs").cloned() {
        keys(
            &obfs,
            &["type", "password", "min_packet_size", "max_packet_size"],
        )?;
        strings(&obfs, &["type", "password"])?;
        counts(&obfs, &["min_packet_size", "max_packet_size"])?;
        let password = obfs["password"].clone();
        config["obfs"] = match obfs["type"].as_str() {
            Some("gecko") => json!({"type":"gecko","password":password,
                "min_packet_size":obfs["min_packet_size"],"max_packet_size":obfs["max_packet_size"]}),
            // Build falls back to salamander for any other type.
            _ => json!({"type":"salamander","password":password}),
        };
    }
    let object = config.as_object_mut().ok_or("legacy_profile_structure")?;
    if !object.contains_key("hop_interval") {
        object.remove("hop_interval_max");
    }
    if object
        .get("bbr_profile")
        .and_then(Value::as_str)
        .is_some_and(|p| !BBR_PROFILES.contains(&p))
    {
        object.remove("bbr_profile");
    }
    if let Some(realm) = object.get("realm") {
        keys(
            realm,
            &[
                "server_url",
                "token",
                "realm_id",
                "stun_servers",
                "ip_version",
                "port_mapping",
                "http_client",
            ],
        )?;
        if ["server", "server_port", "server_ports"]
            .iter()
            .any(|key| object.contains_key(*key))
        {
            return Err("legacy_profile_structure");
        }
    }
    Ok(())
}
/// `QUICFields::Build`: absent per-profile values take the source's global ones.
pub(crate) fn quic_defaults(config: &mut Value, defaults: &Defaults) -> Result<(), &'static str> {
    strings(
        config,
        &[
            "idle_timeout",
            "keep_alive_period",
            "stream_receive_window",
            "connection_receive_window",
        ],
    )?;
    counts(config, &["max_concurrent_streams", "initial_packet_size"])?;
    booleans(config, &["disable_path_mtu_discovery"])?;
    for (key, setting) in [
        ("idle_timeout", "h2_idle_timeout"),
        ("keep_alive_period", "h2_keep_alive_period"),
        ("stream_receive_window", "h2_stream_receive_window"),
        ("connection_receive_window", "h2_connection_receive_window"),
    ] {
        let value = defaults.string(setting, "").trim();
        if config.get(key).is_none() && !value.is_empty() {
            config[key] = json!(value);
        }
    }
    for (key, setting) in [
        ("max_concurrent_streams", "h2_max_concurrent_streams"),
        ("initial_packet_size", "quic_initial_packet_size"),
    ] {
        let value = defaults.integer(setting, 0);
        if config.get(key).is_none() && value > 0 {
            config[key] = json!(value);
        }
    }
    if config.get("disable_path_mtu_discovery").is_none()
        && defaults.boolean("quic_disable_path_mtu_discovery")
    {
        config["disable_path_mtu_discovery"] = json!(true);
    }
    Ok(())
}
