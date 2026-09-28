//! Explicit conversion of a Qt selector's last successful member list.
//! Profile import requires a separate choice to use this fixed snapshot.
//! No store, core, clock, regex evaluation or I/O. Caller converts every member,
//! then validates the remapped selector and its containing group's wrappers.
use super::{profiles::Issue, SourceDatabase, SourceProfile, SourceSetting};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, &'static str>;
const MAX_POOL: usize = crate::auto_selector::MAX_CANDIDATES;
const MAX_HISTORY: usize = 2000;
const MAX_TEXT: usize = 8192;
const MAX_TIMESTAMP: i64 = (1i64 << 53) - 1;
const DEFAULT_URL: &str = "http://cp.cloudflare.com/";

/// No Default: a caller must explicitly supply the reviewed choice.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    RequireChoice,
    LastBuilt,
}
/// Excluded archive settings are never inspected, even if malformed.
#[derive(Clone, Copy)]
pub enum SourceSettings<'a> {
    Excluded,
    Included(&'a [SourceSetting]),
}

/// Private conversion data, possibly containing private probe URLs. Neither
/// Serialize nor Debug is implemented; only report is suitable for public UI.
#[derive(Clone)]
pub struct SnapshotSpec {
    pub source_id: i64,
    pub name: String,
    pub containing_group_id: i64,
    pub tracked_group_id: Option<i64>,
    pub member_ids: Vec<i64>,
    pub pin_id: Option<i64>,
    pub runtime_options: Value,
    pub requires_warp: bool,
    pub report: Vec<Issue>,
}
impl SnapshotSpec {
    /// Preserve array order; UUID map ordering must never become pool ranking.
    /// This is only reference remapping. It does not validate converted members.
    pub fn to_config(&self, ids: &BTreeMap<i64, String>) -> Result<Value> {
        let mut seen = BTreeSet::new();
        let members = self
            .member_ids
            .iter()
            .map(|id| {
                let mapped = ids
                    .get(id)
                    .filter(|id| !id.is_empty() && id.len() <= 512)
                    .ok_or("legacy_selector_reference_missing")?;
                if !seen.insert(mapped) {
                    return Err("legacy_selector_reference_invalid");
                }
                Ok(mapped.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let mut config = self.runtime_options.clone();
        config["type"] = json!("auto-selector");
        config["members"] = json!(members);
        if let Some(pin) = self.pin_id {
            config["pinned_profile"] =
                json!(ids.get(&pin).ok_or("legacy_selector_reference_missing")?);
        }
        Ok(config)
    }
}

fn known(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("legacy_selector_structure")?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("legacy_selector_field_unsupported");
    }
    Ok(())
}
fn int(value: &Value) -> Result<i64> {
    value
        .as_i64()
        .filter(|n| i32::try_from(*n).is_ok())
        .ok_or("legacy_selector_structure")
}
fn integer(value: &Value, key: &str, default: i64) -> Result<i64> {
    value.get(key).map(int).unwrap_or(Ok(default))
}
fn boolean(value: &Value, key: &str, default: bool) -> Result<bool> {
    value.get(key).map_or(Ok(default), |v| {
        v.as_bool().ok_or("legacy_selector_structure")
    })
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).map_or(Ok(""), |v| {
        v.as_str()
            .filter(|s| s.len() <= MAX_TEXT && !s.chars().any(char::is_control))
            .ok_or("legacy_selector_structure")
    })
}
fn timestamp(value: &Value, key: &str) -> Result<()> {
    if value
        .get(key)
        .is_some_and(|v| v.as_i64().is_none_or(|n| !(0..=MAX_TIMESTAMP).contains(&n)))
    {
        return Err("legacy_selector_structure");
    }
    Ok(())
}
fn id_list(value: &Value, key: &str, limit: usize) -> Result<Vec<i64>> {
    let Some(value) = value.get(key) else {
        return Ok(vec![]);
    };
    let array = value.as_array().ok_or("legacy_selector_structure")?;
    if array.len() > limit {
        return Err("legacy_selector_snapshot_limit");
    }
    let mut seen = BTreeSet::new();
    array
        .iter()
        .map(|value| {
            let id = int(value)?;
            if id < 0 || !seen.insert(id) {
                return Err("legacy_selector_reference_invalid");
            }
            Ok(id)
        })
        .collect()
}
fn history(value: &Value) -> Result<()> {
    let Some(history) = value.get("history") else {
        return Ok(());
    };
    let entries = history.as_array().ok_or("legacy_selector_structure")?;
    if entries.len() > MAX_HISTORY {
        return Err("legacy_selector_history_limit");
    }
    for entry in entries {
        known(entry, &["id", "first", "last", "builds", "fails", "name"])?;
        if integer(entry, "id", -1)? < 0
            || integer(entry, "builds", 0)? < 0
            || integer(entry, "fails", 0)? < 0
        {
            return Err("legacy_selector_structure");
        }
        timestamp(entry, "first")?;
        timestamp(entry, "last")?;
        text(entry, "name")?;
    }
    Ok(())
}
fn setting<'a>(rows: &'a [SourceSetting], key: &str, default: &'a str) -> Result<&'a str> {
    let key = crate::legacy_backup::source_settings::key(key);
    let mut matches = rows.iter().filter(|row| row.key == key);
    let value = matches.next().map_or(default, |row| row.value.as_str());
    if matches.next().is_some() {
        return Err("legacy_selector_settings_invalid");
    }
    Ok(value)
}
fn url(value: &str) -> Result<()> {
    if value.len() > MAX_TEXT || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("legacy_selector_url_invalid");
    }
    let url = reqwest::Url::parse(value).map_err(|_| "legacy_selector_url_invalid")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("legacy_selector_url_invalid");
    }
    Ok(())
}
fn member_supported(member: &SourceProfile) -> bool {
    match member.kind.as_str() {
        "socks" | "http" | "shadowsocks" | "vmess" | "vless" | "trojan" | "xrayvless" => true,
        "custom" => {
            let subtype = member.outbound["subtype"].as_str();
            if !matches!(subtype, Some("outbound" | "xrayoutbound")) {
                return false;
            }
            let Some(raw) = member.outbound["config"].as_str() else {
                return false;
            };
            let Ok(value) = super::json::parse(raw) else {
                return false;
            };
            value.as_object().is_some_and(|m| !m.is_empty())
                && !value["type"].as_str().is_some_and(|kind| {
                    crate::chains::ENDPOINT_TYPES.contains(&kind)
                        || matches!(kind, "auto-selector" | "chain")
                })
        }
        // Even though current selectors can contain chains, Qt's planner could
        // not generate such a last_built list. Do not reinterpret malformed data.
        _ => false,
    }
}

/// Takes the actual last_built IDs, never pool, filters or today's clock/ranking.
/// Groups and referenced source kinds are checked here. Full converted config,
/// wrapper and destination-context validation remains the caller's responsibility.
/// `profiles` indexes the database's profiles by id once for every selector of
/// a conversion; rebuilding it per selector made large archives quadratic.
pub fn convert(
    source: &SourceProfile,
    db: &SourceDatabase,
    profiles: &BTreeMap<i64, &SourceProfile>,
    settings: SourceSettings<'_>,
    choice: Choice,
) -> Result<SnapshotSpec> {
    if choice != Choice::LastBuilt {
        return Err("legacy_selector_snapshot_choice_required");
    }
    let value = &source.outbound;
    if source.kind != "autoselector" || value["type"] != "autoselector" {
        return Err("legacy_selector_type_unsupported");
    }
    known(
        value,
        &[
            "type",
            "name",
            "gid",
            "name_filter",
            "country_filter",
            "exclude_unavailable",
            "pool_cap",
            "build_limit",
            "result_validity_mins",
            "test_url",
            "connectivity_url",
            "interval_sec",
            "bench_interval_sec",
            "watch_interval_sec",
            "active_size",
            "sampling",
            "tolerance_ms",
            "max_rtt_ms",
            "expected",
            "dial_retries",
            "interrupt_on_switch",
            "balance",
            "balance_mode",
            "balance_interval_sec",
            "pool",
            "pool_ranked_at",
            "pinned_id",
            "last_built",
            "last_built_at",
            "history",
        ],
    )?;
    if !(0..=i32::MAX as i64).contains(&source.id)
        || !(0..=i32::MAX as i64).contains(&source.group_id)
        || db.groups.iter().filter(|g| g.id == source.group_id).count() != 1
    {
        return Err("legacy_selector_group_missing");
    }
    let tracked = integer(value, "gid", -1)?;
    if tracked < -1 {
        return Err("legacy_selector_structure");
    }
    text(value, "name_filter")?;
    text(value, "country_filter")?;
    boolean(value, "exclude_unavailable", true)?;
    integer(value, "result_validity_mins", 1440)?;
    id_list(value, "pool", MAX_POOL)?;
    timestamp(value, "pool_ranked_at")?;
    timestamp(value, "last_built_at")?;
    history(value)?;
    let member_ids = id_list(value, "last_built", crate::auto_selector::MAX_MEMBERS)?;
    if member_ids.is_empty() {
        return Err("legacy_selector_snapshot_empty");
    }
    if profiles.len() != db.profiles.len() {
        return Err("legacy_selector_reference_invalid");
    }
    for id in &member_ids {
        let member = profiles
            .get(id)
            .ok_or("legacy_selector_reference_missing")?;
        if *id == source.id || !member_supported(member) {
            return Err("legacy_selector_member_unsupported");
        }
    }
    let pin = integer(value, "pinned_id", -1)?;
    if pin < -1 {
        return Err("legacy_selector_structure");
    }
    if pin >= 0 && !member_ids.contains(&pin) {
        return Err("legacy_selector_pin_outside_snapshot");
    }
    // Qt constructor defaults, followed by Normalize in its original order.
    let pool_cap = integer(value, "pool_cap", 1000)?.clamp(1, MAX_POOL as i64);
    let build_limit = integer(value, "build_limit", 300)?
        .clamp(1, 500)
        .min(pool_cap);
    let interval = integer(value, "interval_sec", 300)?.max(10);
    let bench = integer(value, "bench_interval_sec", 600)?.max(interval);
    let watch = integer(value, "watch_interval_sec", 15)?
        .max(5)
        .min(interval);
    let expected = integer(value, "expected", 3)?.max(1);
    let active = integer(value, "active_size", 8)?
        .max(1)
        .max(expected)
        .min(build_limit);
    let sampling = integer(value, "sampling", 10)?.clamp(2, 60);
    let tolerance = integer(value, "tolerance_ms", 300)?.max(0);
    // The pinned core declares uint16; Qt Normalize has no upper clamp.
    if tolerance > u16::MAX as i64 {
        return Err("legacy_selector_value_unsupported");
    }
    let max_rtt = integer(value, "max_rtt_ms", 0)?.max(0);
    let retries = integer(value, "dial_retries", 2)?.clamp(0, 5);
    let balance = boolean(value, "balance", false)?;
    let balance_mode = if text(value, "balance_mode")? == "connection" {
        "connection"
    } else {
        "rotate"
    };
    let balance_interval = integer(value, "balance_interval_sec", 30)?.max(5);
    let rows = match settings {
        SourceSettings::Excluded => &[][..],
        SourceSettings::Included(rows) => rows,
    };
    let requires_warp = match setting(rows, "enable_warp", "false")? {
        "false" | "0" => false,
        "true" | "1" => true,
        _ => return Err("legacy_selector_settings_invalid"),
    };
    let test_url = text(value, "test_url")?;
    let test_url = if test_url.is_empty() {
        setting(rows, "test_latency_url", DEFAULT_URL)?
    } else {
        test_url
    };
    url(test_url)?;
    let connectivity = text(value, "connectivity_url")?;
    let connectivity = if connectivity.is_empty() {
        setting(rows, "direct_test_url", "")?
    } else {
        connectivity
    };
    if !connectivity.is_empty() {
        url(connectivity)?;
    }
    let mut runtime_options = json!({
        "url":test_url, "interval":format!("{interval}s"), "bench_interval":format!("{bench}s"),
        "watch_interval":format!("{watch}s"), "active_size":active, "sampling":sampling,
        "tolerance":tolerance, "expected":expected.min(build_limit), "dial_retries":retries,
        "interrupt_exist_connections":boolean(value,"interrupt_on_switch",true)?,
    });
    if max_rtt > 0 {
        runtime_options["max_rtt"] = json!(format!("{max_rtt}ms"));
    }
    if !connectivity.is_empty() {
        runtime_options["connectivity_url"] = json!(connectivity);
    }
    if balance {
        runtime_options["balance"] = json!(true);
        runtime_options["balance_mode"] = json!(balance_mode);
        runtime_options["balance_interval"] = json!(format!("{balance_interval}s"));
    }
    let name = text(value, "name")?;
    let name = if !name.trim().is_empty() {
        name.to_owned()
    } else if let Some(name) = source.name.as_ref().filter(|s| !s.trim().is_empty()) {
        name.clone()
    } else {
        super::fallback_profile_name(source.id)
    };
    if name.len() > 512 || name.chars().any(char::is_control) {
        return Err("legacy_selector_structure");
    }
    let report = |code: &str| Issue {
        code: code.into(),
        entity: Some("profile".into()),
        source_id: Some(source.id),
        name: Some(name.chars().take(256).collect()),
    };
    let mut issues = vec![
        report("legacy_selector_fixed_snapshot"),
        report("legacy_selector_history_deferred"),
    ];
    if tracked < 0 || !db.groups.iter().any(|g| g.id == tracked) {
        issues.push(report("legacy_selector_source_group_missing"));
    }
    Ok(SnapshotSpec {
        source_id: source.id,
        containing_group_id: source.group_id,
        tracked_group_id: (tracked >= 0).then_some(tracked),
        name,
        member_ids,
        pin_id: (pin >= 0).then_some(pin),
        runtime_options,
        requires_warp,
        report: issues,
    })
}

#[cfg(test)]
mod tests;
