//! Qt host integration switches. The new host applies their effects after import.
use super::{alias, catalog, no_derived, no_report, no_validate, Converter};
use serde_json::Value;

const FIELDS: &[&str] = &[
    "disable_tray",
    "start_minimal",
    "remember_enable",
    "use_custom_icons",
    "follow_status_in_taskbar",
    "url_scheme_auto_register",
    "allow_beta_update",
];
fn notice(field: &str, _: &str, converted: &Value) -> Option<&'static str> {
    if converted != true {
        return None;
    }
    match field {
        "url_scheme_auto_register" => Some("legacy_system_url_scheme_enabled"),
        "disable_tray" => Some("legacy_system_tray_disabled"),
        // Qt icon files are a separate archive part and are not imported here.
        "use_custom_icons" => Some("legacy_system_custom_icons_deferred"),
        _ => None,
    }
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value: catalog::by_kind,
    notice,
    derived: no_derived,
    validate: no_validate,
    report: no_report,
};
