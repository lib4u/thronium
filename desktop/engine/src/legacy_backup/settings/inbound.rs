//! Local inbound listener settings. Apply is refused while connected, so an
//! imported address or port never changes a running listener.
use super::{alias, catalog, no_derived, no_report, Converter};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const FIELDS: &[&str] = &[
    "inbound_address",
    "inbound_socks_port",
    "random_inbound_port",
    "inbound_auth",
    "inbound_user",
    "inbound_pass",
    "disable_mixed_inbound",
    "proxy_scheme",
    "reset_proxy_on_disable_sp",
    "custom_inbound",
];
/// Tags of Thronium's own listeners plus Qt's injected ones (generate.cpp
/// tags namespace); a custom inbound may not shadow either.
pub(crate) const RESERVED_TAGS: [&str; 7] = [
    "mixed-in",
    "thronium-tun",
    "dns-in",
    "tun-in",
    "hijack",
    "hijack-dns",
    "throne-bridge",
];
/// Qt stores `{"inbounds": [...]}`; the catalog field is the bare array. Each
/// entry must be a typed sing-box inbound with a unique, unreserved tag.
pub(crate) fn custom_inbound(text: &str) -> Result<Value, &'static str> {
    const INVALID: &str = "legacy_settings_value_invalid";
    if text.len() > 262144 {
        return Err("legacy_settings_limit");
    }
    let value = crate::strict_json::parse(text).map_err(|_| INVALID)?;
    let object = value.as_object().ok_or(INVALID)?;
    if object.keys().any(|key| key != "inbounds") {
        return Err(INVALID);
    }
    let inbounds = object
        .get("inbounds")
        .map_or(Some(&[][..]), |v| v.as_array().map(Vec::as_slice))
        .ok_or(INVALID)?;
    let mut tags = BTreeSet::new();
    for inbound in inbounds {
        if !inbound.is_object() || inbound["type"].as_str().is_none_or(str::is_empty) {
            return Err(INVALID);
        }
        if let Some(tag) = inbound.get("tag") {
            let tag = tag.as_str().filter(|t| !t.is_empty()).ok_or(INVALID)?;
            if RESERVED_TAGS.contains(&tag) || !tags.insert(tag) {
                return Err(INVALID);
            }
        }
    }
    catalog::checked(catalog::field("custom_inbound")?, json!(inbounds))
}
fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    if field == "custom_inbound" {
        return custom_inbound(text);
    }
    let value = catalog::by_kind(field, text)?;
    if field == "proxy_scheme" && !crate::settings::valid_proxy_scheme(text) {
        return Err("legacy_settings_value_invalid");
    }
    Ok(value)
}
fn notice(field: &str, _: &str, converted: &Value) -> Option<&'static str> {
    match field {
        "inbound_auth" if converted == true => Some("legacy_inbound_auth_enabled"),
        "custom_inbound" if converted.as_array().is_some_and(|a| !a.is_empty()) => {
            Some("legacy_inbound_custom_listeners")
        }
        "inbound_address"
            if converted.as_str().is_some_and(|text| {
                text.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| !ip.is_loopback())
            }) =>
        {
            Some("legacy_inbound_lan_listen")
        }
        _ => None,
    }
}
/// Enabled authentication needs both credentials from the same source. Values
/// the source lacks are checked against the current library at the final merge.
fn validate(values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    if values.get("inbound_auth") == Some(&json!(true))
        && ["inbound_user", "inbound_pass"]
            .iter()
            .any(|key| values.get(*key) == Some(&json!("")))
    {
        return Err("legacy_inbound_auth_incomplete");
    }
    Ok(())
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice,
    derived: no_derived,
    validate,
    report: no_report,
};
