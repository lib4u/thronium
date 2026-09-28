//! Qt WireGuard/AWG ExportToJson -> current userspace WireGuard endpoint JSON.
//! No archive/store/network access. The caller owns profile/group ID conversion.
//!
//! Source: src/configs/outbounds/wireguard.cpp (ExportToJson, Peer::Build,
//! FixAddress), include/configs/outbounds/wireguard.h (MTU default 1420).
//! Pinned sing-box option/wireguard.go calls the legacy worker_count field workers.
//! This does not migrate WARP account generation, system interfaces or wrappers.
use super::SourceProfile;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::{collections::BTreeSet, net::IpAddr, sync::OnceLock};

pub const MAX_PEERS: usize = 256;
const MAX_PREFIXES: usize = 1024;
type Result<T> = std::result::Result<T, &'static str>;
fn known(value: &Value, fields: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or("legacy_wireguard_structure")?;
    if map.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("legacy_wireguard_field_unsupported");
    }
    Ok(())
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("legacy_wireguard_structure")
}
fn uint(value: &Value, max: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n <= max)
        .ok_or("legacy_wireguard_value_unsupported")
}
fn key(value: &Value) -> Result<()> {
    let text = value.as_str().ok_or("legacy_wireguard_key_invalid")?;
    if text.len() != 44
        || STANDARD
            .decode(text)
            .ok()
            .filter(|bytes| bytes.len() == 32)
            .is_none()
    {
        return Err("legacy_wireguard_key_invalid");
    }
    Ok(())
}
fn prefix(value: &str, expand_bare: bool) -> Result<String> {
    if !expand_bare && value != value.trim() {
        return Err("legacy_wireguard_prefix_invalid");
    }
    let value = value.trim();
    let (address, bits) = match value.split_once('/') {
        Some((ip, bits)) => (ip, Some(bits)),
        None if expand_bare => (value, None),
        None => return Err("legacy_wireguard_prefix_invalid"),
    };
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| "legacy_wireguard_prefix_invalid")?;
    let maximum = if ip.is_ipv4() { 32u8 } else { 128 };
    match bits {
        Some(bits) => {
            if bits.parse::<u8>().ok().is_none_or(|n| n > maximum) {
                return Err("legacy_wireguard_prefix_invalid");
            }
            Ok(value.into())
        }
        None => Ok(format!("{value}/{maximum}")),
    }
}
fn prefixes(value: &Value, expand: bool) -> Result<Vec<Value>> {
    let items = value
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= MAX_PREFIXES)
        .ok_or("legacy_wireguard_prefix_invalid")?;
    items
        .iter()
        .map(|value| {
            prefix(
                value.as_str().ok_or("legacy_wireguard_prefix_invalid")?,
                expand,
            )
            .map(Value::String)
        })
        .collect()
}
fn host(value: &str) -> Result<()> {
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value.is_empty()
        || value.len() > 253
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || ":/\\@?#[]%".contains(c))
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        })
    {
        return Err("legacy_wireguard_peer_invalid");
    }
    Ok(())
}
fn range(value: &Value, number_allowed: bool) -> Result<()> {
    if value.is_number() && number_allowed {
        uint(value, u32::MAX as u64)?;
        return Ok(());
    }
    let text = value
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 32)
        .ok_or("legacy_wireguard_range_invalid")?;
    let (lo, hi) = text.split_once('-').unwrap_or((text, text));
    let parse = |s: &str| {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse::<u32>().ok()
        } else {
            None
        }
    };
    if !matches!((parse(lo),parse(hi)),(Some(lo),Some(hi)) if lo<=hi) {
        return Err("legacy_wireguard_range_invalid");
    }
    Ok(())
}
fn duration(value: &Value) -> Result<()> {
    let text = value
        .as_str()
        .filter(|s| s.len() <= 128)
        .ok_or("legacy_wireguard_duration_invalid")?;
    if text == "0" {
        return Ok(());
    }
    static TOKENS: OnceLock<regex::Regex> = OnceLock::new();
    let tokens = TOKENS.get_or_init(|| {
        regex::Regex::new(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)").unwrap()
    });
    let mut end = 0;
    let mut nanos = 0f64;
    for capture in tokens.captures_iter(text) {
        let matched = capture.get(0).unwrap();
        if matched.start() != end {
            return Err("legacy_wireguard_duration_invalid");
        }
        end = matched.end();
        let multiplier = match &capture[2] {
            "ns" => 1.,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => unreachable!(),
        };
        nanos += capture[1]
            .parse::<f64>()
            .map_err(|_| "legacy_wireguard_duration_invalid")?
            * multiplier;
    }
    if end == 0 || end != text.len() || !nanos.is_finite() || nanos > i64::MAX as f64 {
        return Err("legacy_wireguard_duration_invalid");
    }
    Ok(())
}
fn amnezia(value: &Value) -> Result<()> {
    known(
        value,
        &[
            "jc",
            "jmin",
            "jmax",
            "s1",
            "s2",
            "s3",
            "s4",
            "h1",
            "h2",
            "h3",
            "h4",
            "i1",
            "i2",
            "i3",
            "i4",
            "i5",
            "header_protection_key",
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
            "random_trailers",
            "disable_cookies",
        ],
    )?;
    for field in ["jc", "jmin", "jmax"] {
        if let Some(value) = value.get(field) {
            uint(value, i32::MAX as u64)?;
        }
    }
    // The pinned WireGuard UAPI parses packet padding as uint16.
    for field in ["s1", "s2", "s3", "s4"] {
        if let Some(value) = value.get(field) {
            uint(value, u16::MAX as u64)?;
        }
    }
    if let (Some(min), Some(max)) = (value["jmin"].as_u64(), value["jmax"].as_u64()) {
        if min > max {
            return Err("legacy_wireguard_range_invalid");
        }
    }
    for field in ["h1", "h2", "h3", "h4"] {
        if let Some(value) = value.get(field) {
            range(value, false)?;
        }
    }
    for field in ["i1", "i2", "i3", "i4", "i5"] {
        if let Some(value) = value.get(field) {
            let text = value.as_str().ok_or("legacy_wireguard_structure")?;
            if text.len() > 65536 || text.chars().any(char::is_control) {
                return Err("legacy_wireguard_signature_unsupported");
            }
        }
    }
    if let Some(value) = value.get("header_protection_key") {
        key(value)?;
    }
    for field in [
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
    ] {
        if let Some(value) = value.get(field) {
            range(value, true)?;
        }
    }
    for field in ["random_trailers", "disable_cookies"] {
        if value.get(field).is_some_and(|v| !v.is_boolean()) {
            return Err("legacy_wireguard_structure");
        }
    }
    Ok(())
}

pub fn convert(source: &SourceProfile) -> Result<Value> {
    if source.kind != "wireguard" || source.outbound["type"] != "wireguard" {
        return Err("legacy_wireguard_type_unsupported");
    }
    let mut result = source.outbound.clone();
    known(
        &result,
        &[
            "type",
            "tag",
            "private_key",
            "address",
            "mtu",
            "system",
            "worker_count",
            "workers",
            "udp_timeout",
            "peers",
            "amnezia_wg",
            "reuse_addr",
            "connect_timeout",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
            "bind_interface",
            "inet4_bind_address",
            "inet6_bind_address",
        ],
    )?;
    // Qt's "Use System Interface": the endpoint runs on a kernel interface the
    // Core owns instead of the userspace stack. It is imported as written; the
    // contexts that cannot own such an interface refuse it on their own.
    let system = match result.get("system") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("legacy_wireguard_structure"),
    };
    result["system"] = json!(system);
    key(&result["private_key"])?;
    result["address"] = Value::Array(prefixes(&result["address"], true)?);
    if let Some(mtu) = result.get("mtu") {
        uint(mtu, 65535)?;
    } else {
        result["mtu"] = json!(1420);
    }
    if result.get("workers").is_some() && result.get("worker_count").is_some() {
        return Err("legacy_wireguard_alias_conflict");
    }
    if let Some(workers) = result.as_object_mut().unwrap().remove("worker_count") {
        result["workers"] = workers;
    }
    if let Some(workers) = result.get("workers") {
        uint(workers, 1024)?;
    }
    for field in ["udp_timeout", "connect_timeout"] {
        if let Some(value) = result.get(field) {
            duration(value)?;
        }
    }
    for field in [
        "reuse_addr",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
    ] {
        if result.get(field).is_some_and(|value| !value.is_boolean()) {
            return Err("legacy_wireguard_structure");
        }
    }
    for field in ["tag", "bind_interface"] {
        if let Some(value) = result.get(field) {
            let value = value.as_str().ok_or("legacy_wireguard_structure")?;
            if value.len() > 4096 || value.chars().any(char::is_control) {
                return Err("legacy_wireguard_structure");
            }
        }
    }
    for (field, v4) in [("inet4_bind_address", true), ("inet6_bind_address", false)] {
        if let Some(value) = result.get(field) {
            let ip = value
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .ok_or("legacy_wireguard_structure")?;
            if ip.is_ipv4() != v4 {
                return Err("legacy_wireguard_structure");
            }
        }
    }
    if let Some(value) = result.get("amnezia_wg") {
        amnezia(value)?;
    }
    let peers = result
        .get_mut("peers")
        .and_then(Value::as_array_mut)
        .filter(|peers| !peers.is_empty() && peers.len() <= MAX_PEERS)
        .ok_or("legacy_wireguard_peer_limit")?;
    let mut peer_keys = BTreeSet::new();
    for peer in peers {
        known(
            peer,
            &[
                "address",
                "port",
                "public_key",
                "pre_shared_key",
                "reserved",
                "persistent_keepalive_interval",
                "allowed_ips",
            ],
        )?;
        host(string(peer, "address")?)?;
        if uint(&peer["port"], 65535)? == 0 {
            return Err("legacy_wireguard_peer_invalid");
        }
        key(&peer["public_key"])?;
        if !peer_keys.insert(string(peer, "public_key")?.to_owned()) {
            return Err("legacy_wireguard_duplicate_peer");
        }
        if let Some(value) = peer.get("pre_shared_key") {
            if value.as_str() != Some("") {
                key(value)?;
            }
        }
        if let Some(value) = peer.get("reserved") {
            let bytes = value
                .as_array()
                .filter(|values| values.is_empty() || values.len() == 3)
                .ok_or("legacy_wireguard_reserved_invalid")?;
            if bytes.iter().any(|v| v.as_u64().is_none_or(|n| n > 255)) {
                return Err("legacy_wireguard_reserved_invalid");
            }
        }
        if let Some(value) = peer.get("persistent_keepalive_interval") {
            range(value, true)?;
        }
        if let Some(value) = peer.get("allowed_ips") {
            prefixes(value, false)?;
        } else {
            peer["allowed_ips"] = json!(["0.0.0.0/0", "::/0"]);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
