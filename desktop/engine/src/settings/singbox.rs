//! Additional sing-box defaults; profile-owned values are never overwritten.
use super::{boolean as b, integer as n, string as s};
use crate::{
    proto::LoadConfigReq,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn inherit(o: &mut Value, key: &str, value: Value) {
    if o.get(key).is_none() {
        o[key] = value;
    }
}

pub(super) fn prepare_outbound(o: &mut Value, l: &Library) {
    // Match the pinned core's ordinary outbound DialerOptions. Do not modify
    // endpoints, selectors, unknown custom protocols or generated Xray bridges.
    if !matches!(
        o["type"].as_str(),
        Some(
            "direct"
                | "socks"
                | "http"
                | "shadowsocks"
                | "vmess"
                | "trojan"
                | "vless"
                | "shadowtls"
                | "ssh"
                | "anytls"
                | "snell"
                | "hysteria"
                | "hysteria2"
                | "tuic"
                | "juicity"
                | "trusttunnel"
                | "tor"
                | "naive"
                | "mieru"
        )
    ) {
        return;
    }
    // With a detour these fields are ignored by the core; the detour profile
    // receives its own inherited defaults instead.
    if o["detour"].as_str().is_some_and(|v| !v.is_empty()) {
        return;
    }
    for (key, setting) in [
        ("connect_timeout", "singbox_connect_timeout"),
        ("tcp_keep_alive", "singbox_tcp_keep_alive_idle"),
        ("tcp_keep_alive_interval", "singbox_tcp_keep_alive_interval"),
    ] {
        if key != "connect_timeout"
            && (o["disable_tcp_keep_alive"] == true
                || (o.get("disable_tcp_keep_alive").is_none()
                    && s(l, "singbox_tcp_keep_alive") == "disabled"))
        {
            continue;
        }
        if n(l, setting) > 0 {
            inherit(o, key, json!(format!("{}s", n(l, setting))));
        }
    }
    for (key, setting, inverse) in [
        ("tcp_fast_open", "singbox_tcp_fast_open", false),
        ("tcp_multi_path", "singbox_tcp_multi_path", false),
        ("disable_tcp_keep_alive", "singbox_tcp_keep_alive", true),
        ("udp_fragment", "singbox_udp_fragment", false),
    ] {
        let value = match s(l, setting).as_str() {
            "enabled" => !inverse,
            "disabled" => inverse,
            _ => continue,
        };
        // A profile's keepalive timings imply enabled keepalive unless it
        // explicitly disables it. Preserve that choice as a group.
        if key == "disable_tcp_keep_alive"
            && value
            && (o.get("tcp_keep_alive").is_some() || o.get("tcp_keep_alive_interval").is_some())
        {
            continue;
        }
        if key == "tcp_fast_open" && value && o["tls_fragment"]["enabled"] == true {
            continue;
        }
        inherit(o, key, json!(value));
    }
}

pub(super) fn mux_limits(mux: &mut Value, l: &Library) {
    if ["max_streams", "max_connections", "min_streams"]
        .iter()
        .any(|key| mux.get(key).is_some())
    {
        return;
    }
    if s(l, "singbox_mux_limits") == "connections" {
        mux["max_connections"] = json!(n(l, "singbox_mux_max_connections"));
        mux["min_streams"] = json!(n(l, "singbox_mux_min_streams"));
    } else {
        mux["max_streams"] = json!(n(l, "mux_concurrency"));
    }
}

pub(crate) fn configure_cache(
    request: &mut LoadConfigReq,
    profile: &Profile,
    l: &Library,
    directory: &Path,
) -> Result<(), String> {
    if profile.kind == ProfileKind::SingBoxConfig || !b(l, "singbox_cache_enabled") {
        return Ok(());
    }
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    // Keep all data, including FakeIP, isolated across DNS/routing policies.
    // A different proxy's DNS server with the same tag must not reuse answers.
    // Building a preview does not create/open a database. CheckConfig only
    // constructs the core; its cache opens when the connection starts.
    let identity = json!([profile.id, core["dns"], core["route"]]);
    let hash = format!("{:x}", Sha256::digest(identity.to_string().as_bytes()));
    let directory = std::path::absolute(directory).map_err(|_| "invalid_configuration")?;
    if !core["experimental"].is_object() {
        core["experimental"] = json!({});
    }
    core["experimental"]["cache_file"] = json!({
        "enabled": true,
        "path": directory.join(format!("sing-box-cache-{hash}.db")),
        "store_fakeip": b(l, "singbox_cache_store_fakeip"),
        "store_dns": b(l, "singbox_cache_store_dns"),
    });
    request.core_config = Some(core.to_string());
    Ok(())
}

#[cfg(test)]
mod tests;
