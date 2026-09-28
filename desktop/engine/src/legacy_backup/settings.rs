//! Bounded conversion of explicitly selected Qt settings without I/O or jobs.
//! Default/semantic changes have explicit notices; unknown source values stay deferred.
use super::{profiles::Issue, SourceArchive, SourceSetting, SourceValue};
mod basic;
mod catalog;
pub(super) mod core;
pub(crate) mod geodata;
mod hotkeys;
pub(crate) mod inbound;
mod intercept;
pub(crate) mod network;
mod presets;
mod system;
mod tun;
pub(crate) mod warp;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Group {
    Appearance,
    Testing,
    Logging,
    Geodata,
    Warp,
    Network,
    Subscriptions,
    Inbound,
    System,
    Presets,
    Intercept,
    Tun,
    Core,
    Hotkeys,
}
/// Values may contain private URLs: only imported_fields/report/count are public review data.
#[derive(Clone)]
pub struct SettingsPlan {
    pub group: Group,
    pub values: BTreeMap<String, Value>,
    pub imported_fields: Vec<String>,
    /// Rows outside this group. Do not sum this count across group plans.
    pub deferred_count: usize,
    pub report: Vec<Issue>,
}

/// One category's semantics. `convert` owns the pipeline: row lookup, duplicates,
/// structure, atomic failure and public review shape. A category owns only its
/// destination fields, their conversions and its own cross-field rules.
pub(crate) struct Converter {
    pub fields: &'static [&'static str],
    /// SQLite key holding a destination field. Renamed `SettingsRepo` members
    /// come from the alias table; a semantic rename names its source explicitly.
    pub source_key: fn(&str) -> &str,
    pub value: fn(&str, &str) -> Result<Value, &'static str>,
    /// Field-level review notice from the source text and the converted value.
    pub notice: fn(&str, &str, &Value) -> Option<&'static str>,
    /// One source row may also set a second destination field; it counts once in review.
    pub derived: fn(&str, &str, &mut BTreeMap<String, Value>),
    /// Cross-field rules of the category, checked on the plan and again at merge.
    pub validate: fn(&BTreeMap<String, Value>) -> Result<(), &'static str>,
    /// One unnamed notice about the whole selected category.
    pub report: fn(&BTreeMap<String, Value>) -> Option<&'static str>,
}
fn alias(field: &str) -> &str {
    super::source_settings::key(field)
}
fn no_notice(_: &str, _: &str, _: &Value) -> Option<&'static str> {
    None
}
fn no_derived(_: &str, _: &str, _: &mut BTreeMap<String, Value>) {}
fn no_validate(_: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    Ok(())
}
fn no_report(_: &BTreeMap<String, Value>) -> Option<&'static str> {
    None
}
pub(crate) fn converter(group: &Group) -> Converter {
    match group {
        Group::Appearance | Group::Testing | Group::Logging => basic::converter(group),
        Group::Geodata => geodata::CONVERTER,
        Group::Warp => warp::CONVERTER,
        Group::Network => network::NETWORK,
        Group::Subscriptions => network::SUBSCRIPTIONS,
        Group::Inbound => inbound::CONVERTER,
        Group::System => system::CONVERTER,
        Group::Presets => presets::CONVERTER,
        Group::Intercept => intercept::CONVERTER,
        Group::Tun => tun::CONVERTER,
        Group::Core => core::CONVERTER,
        Group::Hotkeys => hotkeys::CONVERTER,
    }
}
pub fn fields(group: &Group) -> &'static [&'static str] {
    converter(group).fields
}
/// Cross-field rules are rechecked against the plan that is about to be merged.
pub(crate) fn validate_plan(plan: &SettingsPlan) -> Result<(), &'static str> {
    (converter(&plan.group).validate)(&plan.values)
}
fn issue(code: &'static str, field: Option<&'static str>) -> Issue {
    Issue {
        code: code.into(),
        entity: Some("settings".into()),
        source_id: None,
        // Only a literal from fields(), never an arbitrary source key or value.
        name: field.map(str::to_owned),
    }
}
fn boolean(text: &str) -> Result<Value, &'static str> {
    match text {
        "true" | "1" => Ok(json!(true)),
        "false" | "0" => Ok(json!(false)),
        _ => Err("legacy_settings_value_invalid"),
    }
}
fn integer(text: &str) -> Result<i64, &'static str> {
    if text.is_empty() || text.len() > 32 {
        return Err("legacy_settings_value_invalid");
    }
    // QString::number() emits decimal. Valid plus/leading-zero forms retain
    // their numeric value; arbitrary whitespace/nondecimal text is not guessed.
    text.parse().map_err(|_| "legacy_settings_value_invalid")
}
fn bounded(text: &str, min: i64, max: i64) -> Result<Value, &'static str> {
    let n = integer(text)?;
    if !(min..=max).contains(&n) {
        return Err("legacy_settings_value_invalid");
    }
    Ok(json!(n))
}
/// Qt stores update intervals as signed minutes: negative or below 30 is disabled.
fn interval(text: &str) -> Result<i64, &'static str> {
    if text.len() > 32 {
        return Err("legacy_settings_value_invalid");
    }
    let minutes: i32 = text.parse().map_err(|_| "legacy_settings_value_invalid")?;
    if minutes > 43200 {
        return Err("legacy_settings_limit");
    }
    Ok(if minutes < 30 { 0 } else { i64::from(minutes) })
}
fn url(text: &str) -> Result<Value, &'static str> {
    if text.is_empty()
        || text.len() > 8192
        || text.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("legacy_settings_value_invalid");
    }
    let parsed = reqwest::Url::parse(text).map_err(|_| "legacy_settings_value_invalid")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("legacy_settings_value_invalid");
    }
    // Validate only: no normalization, HTTP→HTTPS upgrade, fetch or URL logging.
    Ok(json!(text))
}
fn value(
    converter: &Converter,
    field: &'static str,
    row: &SourceSetting,
) -> Result<Value, &'static str> {
    if row.columns.len() != 2
        || !matches!(row.columns.get("key"), Some(SourceValue::Text(v)) if v == (converter.source_key)(field))
        || !matches!(row.columns.get("value"), Some(SourceValue::Text(v)) if v == &row.value)
    {
        return Err("legacy_settings_structure");
    }
    (converter.value)(field, &row.value)
}

pub fn convert(source: &SourceArchive, group: &Group) -> Result<SettingsPlan, Vec<Issue>> {
    if !source.parts.settings {
        return Err(vec![issue("legacy_settings_part_missing", None)]);
    }
    let Some(db) = &source.database else {
        return Err(vec![issue("legacy_database_missing", None)]);
    };
    if db.settings.len() > super::MAX_ROWS_PER_TABLE {
        return Err(vec![issue("legacy_settings_limit", None)]);
    }
    let converter = converter(group);
    let mut values = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut duplicate_reported = BTreeSet::new();
    let mut errors = Vec::new();
    let mut report = Vec::new();
    let mut deferred_count = 0;
    for row in &db.settings {
        let Some(&field) = converter
            .fields
            .iter()
            .find(|&&known| (converter.source_key)(known) == row.key)
        else {
            deferred_count += 1;
            continue;
        };
        if !seen.insert(field) {
            if duplicate_reported.insert(field) {
                errors.push(issue("legacy_settings_duplicate", Some(field)));
            }
            continue;
        }
        match value(&converter, field, row) {
            Ok(v) => {
                if let Some(code) = (converter.notice)(field, &row.value, &v) {
                    report.push(issue(code, Some(field)));
                }
                values.insert(field.into(), v);
                (converter.derived)(field, &row.value, &mut values);
            }
            Err(code) => errors.push(issue(code, Some(field))),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    (converter.validate)(&values).map_err(|code| vec![issue(code, None)])?;
    if let Some(code) = (converter.report)(&values) {
        report.push(issue(code, None));
    }
    let imported_fields = converter
        .fields
        .iter()
        .filter(|&&field| values.contains_key(field))
        .map(|&field| field.into())
        .collect();
    Ok(SettingsPlan {
        group: *group,
        values,
        imported_fields,
        deferred_count,
        report: {
            if deferred_count != 0 {
                report.push(issue("legacy_settings_partial", None));
            }
            report
        },
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod geodata_tests;

#[cfg(test)]
mod warp_tests;

#[cfg(test)]
mod network_tests;

#[cfg(test)]
mod basic_tests;
#[cfg(test)]
mod hotkeys_tests;

#[cfg(test)]
mod runtime_tests;
