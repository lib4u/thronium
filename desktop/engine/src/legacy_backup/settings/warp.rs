//! Saved Qt WARP identities are imported as a complete, explicit bundle.
use super::{alias, no_derived, no_notice, Converter};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

pub(crate) const FIELDS: &[&str] = &[
    "enable_warp",
    "warp_private_key",
    "warp_public_key",
    "warp_ifc_addrs",
    "warp_ep",
    "warp_reserved",
];
const INVALID: &str = "legacy_warp_value_unsupported";

fn report(values: &BTreeMap<String, Value>) -> Option<&'static str> {
    (values.get("enable_warp") == Some(&json!(true))).then_some("legacy_warp_enabled")
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice: no_notice,
    derived: no_derived,
    validate,
    report,
};

fn key(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.is_empty() || (s.len() == 44 && STANDARD.decode(s).is_ok_and(|bytes| bytes.len() == 32))
    })
}
fn endpoint(value: &Value) -> bool {
    let Some(raw) = value.as_str() else {
        return false;
    };
    if raw.is_empty() {
        return true;
    }
    if raw.len() > 512
        || !raw.is_ascii()
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    // Qt splits at the first colon, without IPv6 bracket parsing. Do not give
    // such old strings a new meaning using a more permissive URL parser.
    let (host, port) = raw
        .split_once(':')
        .map_or((raw, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|s| {
        s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || s.parse::<u16>().map_or(true, |p| p == 0)
    }) {
        return false;
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn list(value: &Value, addresses: bool) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    if addresses {
        items.len() <= 16
            && items.iter().all(|v| {
                let Some(raw) = v.as_str() else {
                    return false;
                };
                if raw.len() > 64 {
                    return false;
                }
                let Some((ip, mask)) = raw.split_once('/') else {
                    return false;
                };
                let Ok(ip) = ip.parse::<IpAddr>() else {
                    return false;
                };
                !mask.is_empty()
                    && mask.bytes().all(|b| b.is_ascii_digit())
                    && mask
                        .parse::<u8>()
                        .is_ok_and(|n| n <= if ip.is_ipv4() { 32 } else { 128 })
            })
    } else {
        (items.is_empty() || items.len() == 3)
            && items.iter().all(|v| {
                v.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 3
                        && s.bytes().all(|b| b.is_ascii_digit())
                        && s.parse::<u8>().is_ok()
                })
            })
    }
}
fn valid(field: &str, value: &Value) -> bool {
    match field {
        "enable_warp" => value.is_boolean(),
        "warp_private_key" | "warp_public_key" => key(value),
        "warp_ep" => endpoint(value),
        "warp_ifc_addrs" => list(value, true),
        "warp_reserved" => list(value, false),
        _ => false,
    }
}
pub(super) fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    let value = match field {
        "enable_warp" => super::boolean(text)?,
        "warp_ifc_addrs" | "warp_reserved" => {
            if text.len() > 8192 {
                return Err("legacy_settings_limit");
            }
            serde_json::from_str(text).map_err(|_| INVALID)?
        }
        _ => json!(text),
    };
    if valid(field, &value) {
        Ok(value)
    } else {
        Err(INVALID)
    }
}
pub(crate) fn validate(values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    let present: Vec<_> = FIELDS
        .iter()
        .filter_map(|&field| values.get(field).map(|v| (field, v)))
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    if present.iter().any(|(field, value)| !valid(field, value)) {
        return Err(INVALID);
    }
    // A lone explicit Off is a safe independent change. Credentials may never
    // be mixed with an unrelated identity already in the destination Library.
    if present.len() == 1 && values.get("enable_warp") == Some(&json!(false)) {
        return Ok(());
    }
    if present.len() != FIELDS.len() {
        return Err("legacy_warp_bundle_incomplete");
    }
    if values["enable_warp"] == true
        && (["warp_private_key", "warp_public_key", "warp_ep"]
            .iter()
            .any(|&k| values[k] == "")
            || values["warp_ifc_addrs"]
                .as_array()
                .is_none_or(Vec::is_empty))
    {
        return Err("legacy_warp_bundle_incomplete");
    }
    Ok(())
}
