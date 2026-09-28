//! Global transport presets used by profiles that leave the matching field empty.
use super::{alias, catalog, no_derived, no_notice, no_report, no_validate, Converter};
use serde_json::Value;

const FIELDS: &[&str] = &[
    "fragment_implementation",
    "fragment_size",
    "fragment_sleep",
    "h2_idle_timeout",
    "h2_keep_alive_period",
    "h2_stream_receive_window",
    "h2_connection_receive_window",
    "h2_max_concurrent_streams",
    "quic_initial_packet_size",
    "quic_disable_path_mtu_discovery",
];
fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    let value = catalog::by_kind(field, text)?;
    if matches!(field, "h2_idle_timeout" | "h2_keep_alive_period")
        && !text.is_empty()
        && !crate::settings::valid_duration(text)
    {
        return Err("legacy_settings_value_invalid");
    }
    Ok(value)
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice: no_notice,
    derived: no_derived,
    validate: no_validate,
    report: no_report,
};
