//! Pure conversion of the four saved Qt geodata source settings.
use super::{alias, no_derived, no_report, no_validate, Converter};
use serde_json::{json, Value};

const FIELDS: &[&str] = &[
    "xray_geoip_url",
    "xray_geosite_url",
    "xray_geoip_url_history",
    "xray_geosite_url_history",
];
fn notice(field: &str, text: &str, _: &Value) -> Option<&'static str> {
    (text.is_empty() && matches!(field, "xray_geoip_url" | "xray_geosite_url"))
        .then_some("legacy_geodata_default_source")
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice,
    derived: no_derived,
    validate: no_validate,
    report: no_report,
};

pub(crate) fn is_history(key: &str) -> bool {
    matches!(key, "xray_geoip_url_history" | "xray_geosite_url_history")
}

fn source(text: &str) -> Result<Value, &'static str> {
    let value = super::url(text).map_err(|_| "legacy_geodata_url_unsupported")?;
    let url = reqwest::Url::parse(text).map_err(|_| "legacy_geodata_url_unsupported")?;
    if url.scheme() != "https" || url.fragment().is_some() {
        return Err("legacy_geodata_url_unsupported");
    }
    Ok(value)
}

/// Internal history settings are not general editable catalog fields. Both the
/// source converter and the final Library merge must enforce their exact shape.
pub(crate) fn validate_history(value: &Value) -> Result<(), &'static str> {
    let values = value.as_array().ok_or("legacy_settings_value_invalid")?;
    if values.len() > 5 {
        return Err("legacy_settings_limit");
    }
    for value in values {
        source(value.as_str().ok_or("legacy_settings_value_invalid")?)?;
    }
    Ok(())
}

pub(super) fn value(key: &str, text: &str) -> Result<Value, &'static str> {
    if is_history(key) {
        // Five URLs of at most8192 bytes plus JSON syntax and escaping.
        if text.len() > 5 * 8192 * 6 + 64 {
            return Err("legacy_settings_limit");
        }
        let value: Value =
            serde_json::from_str(text).map_err(|_| "legacy_settings_value_invalid")?;
        validate_history(&value)?;
        return Ok(value);
    }
    if text.is_empty() {
        // Qt's explicit empty current text uses the first provider's placeholder
        // when Download is pressed. Absent fields never reach this conversion.
        return Ok(json!(match key {
            "xray_geoip_url" =>
                "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geoip.dat",
            "xray_geosite_url" =>
                "https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geosite.dat",
            _ => return Err("legacy_settings_value_invalid"),
        }));
    }
    source(text)
}
