//! Qt network/subscription settings: exact aliases and explicit semantic conversions.
use super::{alias, no_report, Converter};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) const NETWORK_FIELDS: &[&str] = &["net_use_proxy", "net_insecure", "user_agent"];
pub(crate) const SUBSCRIPTION_FIELDS: &[&str] = &[
    "sub_auto_update",
    "sub_clear",
    "sub_show_change_popup",
    "sub_send_hwid",
    "sub_custom_hwid_params",
    "allow_stopping_active_profile",
];
const INVALID: &str = "legacy_network_value_unsupported";

pub(super) const NETWORK: Converter = Converter {
    fields: NETWORK_FIELDS,
    source_key: alias,
    value,
    notice,
    derived,
    validate,
    report: no_report,
};
pub(super) const SUBSCRIPTIONS: Converter = Converter {
    fields: SUBSCRIPTION_FIELDS,
    source_key: alias,
    value,
    notice,
    derived,
    validate,
    report: no_report,
};
pub(super) fn is_field(field: &str) -> bool {
    NETWORK_FIELDS.contains(&field) || SUBSCRIPTION_FIELDS.contains(&field)
}
fn agent(text: &str) -> bool {
    text.len() <= 1024
        && !text.chars().any(char::is_control)
        && reqwest::header::HeaderValue::from_str(text).is_ok()
}
pub(super) fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    match field {
        "net_use_proxy"
        | "net_insecure"
        | "sub_show_change_popup"
        | "sub_send_hwid"
        | "allow_stopping_active_profile" => super::boolean(text),
        // Both Qt modes remove stale rows; recreation is a separate new setting.
        "sub_clear" => super::boolean(text).map(|_| json!(true)),
        "sub_auto_update" => super::interval(text)
            .map(|minutes| json!(minutes))
            .map_err(|code| {
                if code == "legacy_settings_limit" {
                    code
                } else {
                    INVALID
                }
            }),
        "user_agent" => {
            if !agent(text) {
                return Err(INVALID);
            }
            if text.is_empty() {
                // The old empty value chooses the old application's version.
                // Use this application's default, with an explicit review notice.
                Ok(crate::settings::fields()
                    .iter()
                    .find(|f| f.id == "user_agent")
                    .expect("user agent catalog field")
                    .default
                    .clone())
            } else {
                Ok(json!(text))
            }
        }
        "sub_custom_hwid_params" => {
            if text.len() > 8192 || text.contains('\0') {
                Err(INVALID)
            } else {
                Ok(json!(text))
            }
        }
        _ => Err(INVALID),
    }
}
pub(super) fn notice(field: &str, source: &str, converted: &Value) -> Option<&'static str> {
    match field {
        "user_agent" if source.is_empty() => Some("legacy_network_default_user_agent"),
        "sub_auto_update" if converted == 0 && source.parse::<i32>().ok() != Some(0) => {
            Some("legacy_subscription_interval_disabled")
        }
        "sub_clear" if matches!(source, "true" | "1") => Some("legacy_subscription_recreate"),
        "sub_clear" => Some("legacy_subscription_reconcile"),
        "net_insecure" if converted == true => Some("legacy_network_insecure_enabled"),
        "net_use_proxy" if converted == true => Some("legacy_network_proxy_enabled"),
        "sub_send_hwid" if converted == true => Some("legacy_subscription_hwid_enabled"),
        "allow_stopping_active_profile" if converted == true => {
            Some("legacy_subscription_stopping_enabled")
        }
        _ => None,
    }
}
pub(crate) fn validate(values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    if values
        .get("sub_update_mode")
        .is_some_and(|v| !matches!(v.as_str(), Some("reconcile" | "recreate")))
    {
        return Err(INVALID);
    }
    for (field, value) in values.iter().filter(|(k, _)| is_field(k)) {
        let valid = match field.as_str() {
            "user_agent" => value.as_str().is_some_and(agent),
            "sub_custom_hwid_params" => value
                .as_str()
                .is_some_and(|s| s.len() <= 8192 && !s.contains('\0')),
            "sub_auto_update" => value
                .as_i64()
                .is_some_and(|n| n == 0 || (30..=43200).contains(&n)),
            "sub_clear" => value == true,
            _ => value.is_boolean(),
        };
        if !valid {
            return Err(INVALID);
        }
    }
    Ok(())
}

/// One source bool maps to two destination fields, but counts once in review.
pub(super) fn derived(field: &str, source: &str, values: &mut BTreeMap<String, Value>) {
    if field == "sub_clear" {
        values.insert(
            "sub_update_mode".into(),
            json!(if matches!(source, "true" | "1") {
                "recreate"
            } else {
                "reconcile"
            }),
        );
    }
}
