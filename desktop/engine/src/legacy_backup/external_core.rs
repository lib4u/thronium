//! Qt extracore ExportToJson -> the existing opaque external-core profile DTO.
//! Pure data conversion: no filesystem, process, network, shlex, or archive scope.
//! The caller owns Parts, profile/group graphs, library names, and public reports.
use super::SourceProfile;
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// The host can supervise an external core (Linux, Windows).
    Supported,
    Unsupported,
}

/// The returned config contains private launch data; expose it only through the
/// explicit profile editor/export, never a public migration preview.
pub fn convert(source: &SourceProfile, platform: Platform) -> Result<Value, &'static str> {
    if platform != Platform::Supported {
        return Err("legacy_external_platform_unsupported");
    }
    let input = source
        .outbound
        .as_object()
        .ok_or("legacy_profile_structure")?;
    if source.kind != "extracore" || input.get("type").and_then(Value::as_str) != Some("extracore")
    {
        return Err("legacy_profile_discriminator");
    }
    if input.keys().any(|key| {
        ![
            "type",
            "name",
            "socks_address",
            "socks_port",
            "extra_core_path",
            "extra_core_args",
            "extra_core_conf",
            "no_logs",
        ]
        .contains(&key.as_str())
    }) {
        return Err("legacy_profile_field_unsupported");
    }
    // Inspect borrowed values before allocating a normalized copy. Present null
    // or wrong types must not receive Qt's lossy toString/toBool defaults.
    for (key, maximum, error) in [
        ("name", 512, "legacy_external_name_invalid"),
        ("socks_address", 32, "legacy_external_address_unsupported"),
        (
            "extra_core_path",
            crate::external_core::MAX_PATH_BYTES,
            "legacy_external_path_invalid",
        ),
        (
            "extra_core_args",
            crate::external_core::MAX_ARGS_BYTES,
            "legacy_external_args_invalid",
        ),
        (
            "extra_core_conf",
            crate::external_core::MAX_CONFIG_BYTES,
            "legacy_external_config_invalid",
        ),
    ] {
        if let Some(value) = input.get(key) {
            let value = value.as_str().ok_or("legacy_profile_structure")?;
            if value.len() > maximum {
                return Err(error);
            }
        }
    }
    let port = input
        .get("socks_port")
        .ok_or("legacy_external_port_invalid")?;
    if !port.is_i64() && !port.is_u64() {
        return Err("legacy_profile_structure");
    }
    let port = port
        .as_u64()
        .filter(|port| (1024..=65535).contains(port))
        .ok_or("legacy_external_port_invalid")?;
    let no_logs = match input.get("no_logs") {
        None => false,
        Some(value) => value.as_bool().ok_or("legacy_profile_structure")?,
    };
    // Exact defaults from extracore.h and value-initializing OutboundFactory.
    // Omitted socks_port initializes to zero and is deliberately rejected above.
    let output = json!({"type":"extracore",
        "name":input.get("name").and_then(Value::as_str).unwrap_or(""),
        "socks_address":input.get("socks_address").and_then(Value::as_str).unwrap_or("127.0.0.1"),
        "socks_port":port,
        "extra_core_path":input.get("extra_core_path").and_then(Value::as_str).unwrap_or(""),
        "extra_core_args":input.get("extra_core_args").and_then(Value::as_str).unwrap_or(""),
        "extra_core_conf":input.get("extra_core_conf").and_then(Value::as_str).unwrap_or(""),
        "no_logs":no_logs});
    crate::external_core::parse(&output).map_err(|error| match error.as_str() {
        "external_name_invalid" => "legacy_external_name_invalid",
        "external_address_unsupported" => "legacy_external_address_unsupported",
        "external_port_invalid" => "legacy_external_port_invalid",
        "external_path_invalid" => "legacy_external_path_invalid",
        "external_args_invalid" => "legacy_external_args_invalid",
        "external_config_invalid" => "legacy_external_config_invalid",
        _ => "legacy_profile_structure",
    })?;
    Ok(output)
}

#[cfg(test)]
mod tests;
