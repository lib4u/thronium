//! Pure external-core profile data. This does not launch, stat, read, or resolve a path.
//! The exact args/config strings are private until an explicit editor/export request.
pub(crate) mod runtime;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_ARGS_BYTES: usize = 32 * 1024;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_NAME_BYTES: usize = 512;
/// Local SOCKS5 ports an external core may listen on.
pub const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;

fn present_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// Opaque configuration may contain credentials. Deliberately no Debug.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_name"
    )]
    pub name: Option<String>,
    pub socks_address: String,
    pub socks_port: u16,
    pub extra_core_path: String,
    pub extra_core_args: String,
    pub extra_core_conf: String,
    pub no_logs: bool,
}
impl Draft {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind != "extracore" {
            return Err("external_profile_invalid".into());
        }
        if self
            .name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control))
        {
            return Err("external_name_invalid".into());
        }
        if self.socks_address != "127.0.0.1" {
            return Err("external_address_unsupported".into());
        }
        if self.socks_port < 1024 {
            return Err("external_port_invalid".into());
        }
        // No host filesystem is accessed. Existence, executable permission,
        // canonicalization and shlex belong to Go runtime.
        if self.extra_core_path.len() > MAX_PATH_BYTES
            || !absolute(&self.extra_core_path)
            || self.extra_core_path.chars().any(char::is_control)
        {
            return Err("external_path_invalid".into());
        }
        if self.extra_core_args.len() > MAX_ARGS_BYTES || self.extra_core_args.contains('\0') {
            return Err("external_args_invalid".into());
        }
        if self.extra_core_conf.len() > MAX_CONFIG_BYTES || self.extra_core_conf.contains('\0') {
            return Err("external_config_invalid".into());
        }
        Ok(())
    }
    /// This is only the sing-box adapter. The caller must retain the external
    /// launch data separately; this object is not a complete portable export.
    pub fn socks_outbound(&self, tag: &str) -> Result<Value, String> {
        self.validate()?;
        if tag.is_empty() || tag.len() > 128 || tag.chars().any(char::is_control) {
            return Err("external_profile_invalid".into());
        }
        Ok(
            json!({"type":"socks", "tag":tag, "server":self.socks_address,
            "server_port":self.socks_port, "version":"5"}),
        )
    }
}

/// An absolute path of either system, so a library (or a Qt backup) moves
/// between them intact; the core refuses the other system's form at launch.
/// Windows: a drive path or a UNC share, never a device path such as `\\?\` or
/// `\\.\`, and never one relative to the current drive or directory.
fn absolute(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let separator = |c: char| c == '\\' || c == '/';
    let mut chars = path.chars();
    if let (Some(drive), Some(':'), Some(next)) = (chars.next(), chars.next(), chars.next()) {
        return drive.is_ascii_alphabetic() && separator(next);
    }
    let Some(unc) = path.strip_prefix("\\\\") else {
        return false;
    };
    let mut parts = unc.split(separator);
    matches!(
        (parts.next(), parts.next()),
        (Some(server), Some(share)) if !server.is_empty() && !share.is_empty() && server != "?" && server != "."
    )
}

/// Check borrowed string lengths before cloning the caller's JSON value.
/// Missing, unknown, null and wrongly typed fields never receive guessed defaults.
pub fn parse(value: &Value) -> Result<Draft, String> {
    let fields = value.as_object().ok_or("external_profile_invalid")?;
    if fields.keys().any(|key| {
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
        return Err("external_profile_invalid".into());
    }
    for (key, max, error) in [
        ("type", 9, "external_profile_invalid"),
        ("name", MAX_NAME_BYTES, "external_name_invalid"),
        ("socks_address", 9, "external_address_unsupported"),
        ("extra_core_path", MAX_PATH_BYTES, "external_path_invalid"),
        ("extra_core_args", MAX_ARGS_BYTES, "external_args_invalid"),
        (
            "extra_core_conf",
            MAX_CONFIG_BYTES,
            "external_config_invalid",
        ),
    ] {
        if key == "name" && !fields.contains_key(key) {
            continue;
        }
        if !fields
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() <= max)
        {
            return Err(error.into());
        }
    }
    if !fields
        .get("socks_port")
        .and_then(Value::as_u64)
        .is_some_and(|n| u16::try_from(n).is_ok_and(|n| PORTS.contains(&n)))
    {
        return Err("external_port_invalid".into());
    }
    let draft: Draft =
        serde_json::from_value(value.clone()).map_err(|_| "external_profile_invalid")?;
    draft.validate()?;
    Ok(draft)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod runtime_tests;
