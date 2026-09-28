//! Ordinary Throne outbounds and Xray VLESS profiles converted to configurations.
use super::*;
use outbound::{multiplex, tls};

pub(super) fn ordinary(
    source: &SourceProfile,
    defaults: &Defaults,
) -> Result<(ProfileKind, Value), &'static str> {
    let mut config = source.outbound.clone();
    let common = [
        "type",
        "tag",
        "server",
        "server_port",
        "reuse_addr",
        "connect_timeout",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
    ];
    let specific: &[&str] = match source.kind.as_str() {
        "socks" => &["username", "password", "version", "uot"],
        "http" => &["username", "password", "path", "headers", "tls"],
        "shadowsocks" => &[
            "method",
            "password",
            "plugin",
            "plugin_opts",
            "udp_over_tcp",
            "multiplex",
        ],
        "vmess" => &[
            "uuid",
            "security",
            "alter_id",
            "global_padding",
            "authenticated_length",
            "packet_encoding",
            "tls",
            "transport",
            "multiplex",
        ],
        "vless" => &[
            "uuid",
            "flow",
            "packet_encoding",
            "tls",
            "transport",
            "multiplex",
        ],
        "trojan" => &["password", "tls", "transport", "multiplex"],
        _ => return Err("legacy_profile_type_unsupported"),
    };
    let allowed: Vec<_> = common.into_iter().chain(specific.iter().copied()).collect();
    keys(&config, &allowed)?;
    if config["type"].as_str() != Some(source.kind.as_str()) {
        return Err("legacy_profile_discriminator");
    }
    if !config["server"]
        .as_str()
        .is_some_and(|s| !s.trim().is_empty())
        || !config["server_port"]
            .as_u64()
            .is_some_and(|p| (1..=65535).contains(&p))
    {
        return Err("legacy_profile_structure");
    }
    for key in [
        "reuse_addr",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
    ] {
        optional_bool(&config, key)?;
    }
    for key in [
        "uot",
        "udp_over_tcp",
        "global_padding",
        "authenticated_length",
    ] {
        optional_bool(&config, key)?;
    }
    if config
        .get("alter_id")
        .is_some_and(|v| !v.as_u64().is_some_and(|n| n <= u32::MAX as u64))
    {
        return Err("legacy_profile_structure");
    }
    if matches!(source.kind.as_str(), "vless" | "vmess")
        && !config["uuid"]
            .as_str()
            .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok())
    {
        return Err("legacy_profile_structure");
    }
    for key in [
        "tag",
        "connect_timeout",
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "username",
        "password",
        "uuid",
        "flow",
        "packet_encoding",
        "security",
        "method",
        "plugin",
        "plugin_opts",
        "version",
        "path",
    ] {
        optional_string(&config, key)?;
    }
    if let Some(transport) = config.get("transport") {
        keys(
            transport,
            &[
                "type",
                "path",
                "max_early_data",
                "early_data_header_name",
                "method",
                "headers",
                "host",
                "idle_timeout",
                "ping_timeout",
                "service_name",
            ],
        )?;
        if !matches!(
            transport["type"].as_str(),
            Some("ws" | "http" | "httpupgrade" | "grpc")
        ) {
            return Err("legacy_profile_transport_unsupported");
        }
    }
    if source.kind == "shadowsocks"
        && (config["plugin"].as_str().is_some_and(|v| !v.is_empty())
            || config["plugin_opts"]
                .as_str()
                .is_some_and(|v| !v.is_empty()))
    {
        return Err("legacy_profile_external_core_unsupported");
    }
    tls(&mut config, defaults)?;
    if matches!(
        source.kind.as_str(),
        "shadowsocks" | "vmess" | "vless" | "trojan"
    ) {
        multiplex(&mut config, defaults)?;
    }
    Ok((ProfileKind::SingBoxOutbound, config))
}
pub(super) fn xray_vless(
    source: &SourceProfile,
    defaults: &Defaults,
) -> Result<(ProfileKind, Value), &'static str> {
    let mut config = source.outbound.clone();
    keys(
        &config,
        &["tag", "protocol", "settings", "streamSettings", "mux"],
    )?;
    if config["protocol"] != "vless" {
        return Err("legacy_profile_discriminator");
    }
    keys(
        &config["settings"],
        &["address", "port", "id", "encryption", "flow"],
    )?;
    if !config["settings"]["address"]
        .as_str()
        .is_some_and(|s| !s.is_empty())
        || !config["settings"]["port"]
            .as_u64()
            .is_some_and(|p| (1..=65535).contains(&p))
        || !config["settings"]["id"].is_string()
    {
        return Err("legacy_profile_structure");
    }
    if let Some(stream) = config.get("streamSettings") {
        keys(
            stream,
            &[
                "network",
                "security",
                "finalmask",
                "rawSettings",
                "tlsSettings",
                "realitySettings",
                "xhttpSettings",
                "wsSettings",
                "httpupgradeSettings",
                "grpcSettings",
            ],
        )?;
        if !matches!(
            stream["network"].as_str(),
            Some("raw" | "tcp" | "xhttp" | "ws" | "httpupgrade" | "grpc")
        ) || !matches!(
            stream["security"].as_str(),
            Some("" | "none" | "tls" | "reality")
        ) {
            return Err("legacy_profile_transport_unsupported");
        }
        for key in [
            "finalmask",
            "rawSettings",
            "tlsSettings",
            "realitySettings",
            "xhttpSettings",
            "wsSettings",
            "httpupgradeSettings",
            "grpcSettings",
        ] {
            if let Some(value) = stream.get(key) {
                object(value)?;
            }
        }
    }
    let mux = config.get("mux").cloned().unwrap_or_else(|| json!({}));
    keys(&mux, &["enabled", "concurrency", "xudpConcurrency"])?;
    if optional_bool(&mux, "enabled")?.unwrap_or_else(|| defaults.boolean("xray_mux_default_on")) {
        return Err("legacy_profile_xray_mux_unsupported");
    }
    config["mux"] = json!({"enabled":false});
    // Upstream xrayStreamSetting::Build returns ExportToJson directly. Freeze
    // absent fingerprint/allowInsecure defaults, without invoking its unused TLS Build.
    for key in ["tlsSettings", "realitySettings"] {
        if let Some(tls) = config
            .get_mut("streamSettings")
            .and_then(|s| s.get_mut(key))
        {
            let tls = tls.as_object_mut().ok_or("legacy_profile_structure")?;
            tls.entry("fingerprint").or_insert(json!(""));
            if key == "tlsSettings" {
                tls.entry("allowInsecure").or_insert(json!(false));
            }
        }
    }
    Ok((ProfileKind::XrayOutbound, config))
}
