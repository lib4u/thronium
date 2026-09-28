//! Qt scalar/list settings that share existing catalog owners and validation.
use super::{
    alias, boolean, bounded, integer, no_derived, no_report, no_validate, url, Converter, Group,
};
use serde_json::{json, Value};

pub(super) const APPEARANCE: &[&str] = &[
    "language",
    "show_config_security",
    "skip_delete_confirmation",
];
pub(super) const TESTING: &[&str] = &[
    "test_url",
    "url_test_timeout_ms",
    "test_concurrent",
    "speed_test_mode",
    "speed_test_timeout_ms",
    "simple_dl_url",
    "direct_test_url",
];
pub(super) const LOGGING: &[&str] = &[
    "log_auto_scroll",
    "log_level",
    "max_log_line",
    "log_file_level",
    "log_enable_include",
    "log_enable_exclude",
    "log_include_keyword",
    "log_include_regex",
    "log_exclude_keyword",
    "log_exclude_regex",
    "disable_traffic_stats",
    "enable_stats",
    "disable_traffic_aggregation",
    "traffic_stats_retention_days",
    "connection_sort",
    "connection_sort_asc",
    "show_system_dns",
];

/// Qt's language list (`mainwindow_view.cpp`); index 0 is the system locale.
const QT_LANGUAGES: [&str; 5] = ["", "en", "zh_CN", "fa_IR", "ru_RU"];

pub(super) fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    let value = match field {
        // Qt stores an index into its language list; 0 follows the system locale.
        "language" => usize::try_from(integer(text)?)
            .ok()
            .and_then(|index| QT_LANGUAGES.get(index))
            .and_then(|locale| crate::languages::from_locale(locale))
            .map(|code| json!(code))
            .ok_or("legacy_settings_language_unsupported")?,
        "test_url" | "simple_dl_url" => url(text)?,
        "direct_test_url" if !text.is_empty() => url(text)?,
        "speed_test_mode" => match integer(text)? {
            0 => json!("full"),
            1 => json!("download"),
            2 => json!("upload"),
            3 => json!("simple"),
            _ => return Err("legacy_settings_speed_mode_unsupported"),
        },
        "connection_sort" => match integer(text)? {
            0 => json!("created"),
            1 => json!("download"),
            2 => json!("upload"),
            3 => json!("process"),
            _ => return Err("legacy_settings_sort_unsupported"),
        },
        "traffic_stats_retention_days" => json!(integer(text)?.max(1)),
        "max_log_line" | "url_test_timeout_ms" | "test_concurrent" | "speed_test_timeout_ms" => {
            bounded(text, 0, i64::MAX)?
        }
        "log_include_keyword"
        | "log_include_regex"
        | "log_exclude_keyword"
        | "log_exclude_regex" => {
            // Qt serializes QStringList as a JSON array inside the SQLite TEXT value.
            serde_json::from_str(text).map_err(|_| "legacy_settings_value_invalid")?
        }
        "log_level" | "log_file_level" | "direct_test_url" => json!(text),
        _ => boolean(text)?,
    };
    let definition = crate::settings::fields()
        .iter()
        .find(|f| f.id == field)
        .ok_or("legacy_settings_value_invalid")?;
    crate::settings::validate_field(definition, &value).map_err(|_| {
        if field.ends_with("_regex") {
            "legacy_settings_regex_unsupported"
        } else {
            "legacy_settings_value_invalid"
        }
    })?;
    Ok(value)
}

fn notice_with(field: &str, text: &str, _: &Value) -> Option<&'static str> {
    notice(field, text)
}
pub(super) fn converter(group: &Group) -> Converter {
    Converter {
        fields: match group {
            Group::Appearance => APPEARANCE,
            Group::Testing => TESTING,
            _ => LOGGING,
        },
        source_key: alias,
        value,
        notice: notice_with,
        derived: no_derived,
        validate: no_validate,
        report: no_report,
    }
}
pub(super) fn notice(field: &str, text: &str) -> Option<&'static str> {
    match field {
        "connection_sort" if integer(text) == Ok(0) => Some("legacy_settings_sort_default"),
        "traffic_stats_retention_days" if integer(text).is_ok_and(|n| n < 1) => {
            Some("legacy_settings_retention_minimum")
        }
        "log_include_regex" | "log_exclude_regex" if text != "[]" => {
            Some("legacy_settings_regex_engine")
        }
        _ => None,
    }
}
