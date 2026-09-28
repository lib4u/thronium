//! Core service settings: NTP, Clash/API listeners, rule-set mirror, route updates
//! and Xray logging. Qt sign-encodes listeners and intervals; the catalog splits them.
use super::{alias, catalog, no_report, Converter};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const FIELDS: &[&str] = &[
    "enable_ntp",
    "ntp_server_address",
    "ntp_server_port",
    "ntp_interval",
    "ntp_outbound",
    "core_box_clash_api",
    "core_box_clash_listen_addr",
    "core_box_clash_api_secret",
    "core_box_api_port",
    "core_box_api_secret",
    "core_dns_in_port",
    "ruleset_mirror",
    "route_auto_update",
    "xray_log_level",
    "xray_mux_concurrency",
];
const INVALID: &str = "legacy_settings_value_invalid";
/// `Mirrors` enum order from include/global/Const.hpp; the catalog stores the name.
const MIRRORS: [&str; 6] = ["github", "cloudflare", "gcore", "quantil", "fastly", "cdn"];

pub(crate) fn mirror(text: &str) -> Result<&'static str, &'static str> {
    let index = usize::try_from(super::integer(text)?).map_err(|_| INVALID)?;
    MIRRORS.get(index).copied().ok_or(INVALID)
}

/// A negative Qt listener port keeps the number but disables the listener.
fn listener(text: &str) -> Result<(bool, i64), &'static str> {
    let n = super::integer(text)?;
    if n == 0 || n.unsigned_abs() > 65535 {
        return Err(INVALID);
    }
    Ok((n > 0, n.abs()))
}
fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    let definition = catalog::field(field)?;
    let value = match field {
        // Qt passes 0 to the core, which then uses the protocol default port.
        "ntp_server_port" if super::integer(text)? == 0 => definition.default.clone(),
        "ntp_interval" if !text.is_empty() && !crate::settings::valid_duration(text) => {
            return Err(INVALID)
        }
        "core_box_clash_api" | "core_box_api_port" => json!(listener(text)?.1),
        "ruleset_mirror" => json!(mirror(text)?),
        "route_auto_update" => json!(super::interval(text)?),
        _ => return catalog::by_kind(field, text),
    };
    catalog::checked(definition, value)
}
fn notice(field: &str, source: &str, converted: &Value) -> Option<&'static str> {
    match field {
        "ntp_server_port" if super::integer(source) == Ok(0) => {
            Some("legacy_core_ntp_default_port")
        }
        "core_box_clash_api" if super::integer(source).is_ok_and(|n| n > 0) => {
            Some("legacy_core_clash_api_enabled")
        }
        "core_box_api_port" if super::integer(source).is_ok_and(|n| n > 0) => {
            Some("legacy_core_api_enabled")
        }
        "route_auto_update" if converted == 0 && super::integer(source).ok() != Some(0) => {
            Some("legacy_core_route_interval_disabled")
        }
        _ => None,
    }
}
fn derived(field: &str, source: &str, values: &mut BTreeMap<String, Value>) {
    let enabled = match field {
        "core_box_clash_api" => "core_box_clash_enabled",
        "core_box_api_port" => "core_box_api_enabled",
        _ => return,
    };
    if let Ok((on, _)) = listener(source) {
        values.insert(enabled.into(), json!(on));
    }
}
/// A Clash listener outside loopback needs a secret. This mirrors the settings
/// rule for the values this source supplies; the merge rechecks the whole library.
fn validate(values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    if values.get("core_box_clash_enabled") == Some(&json!(true))
        && values
            .get("core_box_clash_listen_addr")
            .and_then(Value::as_str)
            .is_some_and(|address| !["127.0.0.1", "::1"].contains(&address))
        && values.get("core_box_clash_api_secret") == Some(&json!(""))
    {
        return Err("legacy_core_clash_secret_required");
    }
    Ok(())
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice,
    derived,
    validate,
    report: no_report,
};
