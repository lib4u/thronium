//! Pure conversion of the deliberately bounded profile/group part of Qt backups.
//! This is not a restore operation. The caller must honor archive.parts.profiles.
//! Raw custom full configurations retain their entire JSON, including DNS/routes.
//! Ordinary rows are ExportToJson, not Build: TLS/mux defaults are resolved below.
use super::{SourceDatabase, SourceGroup, SourceProfile, SourceRow, SourceValue};
use crate::{
    group_chains::GroupChain,
    store::{Group, Library, Profile, ProfileKind},
    subscriptions::{metadata::Metadata, Subscription},
    vless::Core,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
mod conversion;
mod outbound;
mod protocols;
use outbound::Defaults;
use protocols::{ordinary, xray_vless};
mod custom;
mod extended;
use conversion::{check_group_chains, convert_group, convert_profile, report_deferred};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub code: String,
    pub entity: Option<String>,
    pub source_id: Option<i64>,
    pub name: Option<String>,
}
/// Contains credentials; never serialize/debug this plan into a public response.
#[derive(Clone)]
pub struct ProfilePlan {
    /// Portable copies of files the review selected for custom profiles.
    pub resources: crate::routing::resources::Pack,
    pub requires_warp: bool,
    pub profiles: Vec<Profile>,
    pub groups: Vec<Group>,
    pub profile_ids: BTreeMap<i64, String>,
    pub group_ids: BTreeMap<i64, String>,
    pub vless_overrides: BTreeMap<String, Core>,
    pub vpn_bindings: BTreeMap<String, super::vpn::BindingSource>,
    pub selected: Option<String>,
    pub report: Vec<Issue>,
}
fn issue(code: &str, entity: Option<&str>, id: Option<i64>, name: Option<&str>) -> Issue {
    Issue {
        code: code.into(),
        entity: entity.map(str::to_owned),
        source_id: id,
        name: name.map(|s| s.chars().filter(|c| !c.is_control()).take(256).collect()),
    }
}
pub(super) fn pi(p: &SourceProfile, code: &str) -> Issue {
    issue(code, Some("profile"), Some(p.id), p.name.as_deref())
}
fn gi(g: &SourceGroup, code: &str) -> Issue {
    issue(code, Some("group"), Some(g.id), Some(&g.name))
}
fn text<'a>(row: &'a SourceRow, key: &str) -> Result<Option<&'a str>, &'static str> {
    match row.get(key) {
        None | Some(SourceValue::Null) => Ok(None),
        Some(SourceValue::Text(v)) => Ok(Some(v)),
        _ => Err("legacy_column_type"),
    }
}
fn integer(row: &SourceRow, key: &str, default: i64) -> Result<i64, &'static str> {
    match row.get(key) {
        None => Ok(default),
        Some(SourceValue::Integer(v)) => Ok(*v),
        _ => Err("legacy_column_type"),
    }
}
fn boolean(row: &SourceRow, key: &str) -> Result<bool, &'static str> {
    match integer(row, key, 0)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("legacy_column_type"),
    }
}
pub(super) fn object(value: &Value) -> Result<&Map<String, Value>, &'static str> {
    value.as_object().ok_or("legacy_profile_structure")
}
pub(super) fn keys(value: &Value, allowed: &[&str]) -> Result<(), &'static str> {
    if object(value)?
        .keys()
        .any(|key| !allowed.contains(&key.as_str()))
    {
        Err("legacy_profile_field_unsupported")
    } else {
        Ok(())
    }
}
fn optional_bool(value: &Value, key: &str) -> Result<Option<bool>, &'static str> {
    value
        .get(key)
        .map(|v| v.as_bool().ok_or("legacy_profile_structure"))
        .transpose()
}
fn optional_string<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, &'static str> {
    value
        .get(key)
        .map(|v| v.as_str().ok_or("legacy_profile_structure"))
        .transpose()
}
pub fn convert(db: &SourceDatabase) -> Result<ProfilePlan, Vec<Issue>> {
    convert_selected(db, true)
}

/// The reader preserves even excluded tables for inspection. Only selected
/// source settings may affect effective profile defaults or subscription data.
pub fn convert_selected(
    db: &SourceDatabase,
    use_source_settings: bool,
) -> Result<ProfilePlan, Vec<Issue>> {
    convert_selected_with_selectors(
        db,
        use_source_settings,
        super::autoselector::Choice::RequireChoice,
    )
}

/// A historical selector becomes a fixed last-built snapshot only after an
/// explicit caller choice. Automatic filtering/ranking/history is not migrated.
pub fn convert_selected_with_selectors(
    db: &SourceDatabase,
    use_source_settings: bool,
    selector_choice: super::autoselector::Choice,
) -> Result<ProfilePlan, Vec<Issue>> {
    let defaults = if use_source_settings {
        Defaults::new(db)?
    } else {
        Defaults {
            values: BTreeMap::new(),
        }
    };
    if db.profiles.iter().any(|p| {
        matches!(
            p.kind.as_str(),
            "openvpn" | "openvpn-client" | "openconnect"
        )
    }) {
        if let Some(value) = defaults.values.get("use_dns_object") {
            if !matches!(*value, "false" | "0") {
                return Err(vec![issue(
                    "legacy_vpn_dns_override_unsupported",
                    Some("database"),
                    None,
                    None,
                )]);
            }
        }
    }
    let mut plan = ProfilePlan {
        resources: Default::default(),
        requires_warp: false,
        profiles: Vec::new(),
        groups: Vec::new(),
        profile_ids: BTreeMap::new(),
        group_ids: BTreeMap::new(),
        vless_overrides: BTreeMap::new(),
        vpn_bindings: BTreeMap::new(),
        selected: None,
        report: Vec::new(),
    };
    let mut errors = Vec::new();
    if db.profiles.len() > 5000 || db.groups.len() > 5000 {
        return Err(vec![issue(
            "legacy_profile_limit",
            Some("database"),
            None,
            None,
        )]);
    }
    for group in &db.groups {
        if group.id < 0
            || plan
                .group_ids
                .insert(group.id, uuid::Uuid::new_v4().to_string())
                .is_some()
        {
            errors.push(gi(group, "legacy_group_id"));
        }
    }
    for profile in &db.profiles {
        if profile.id < 0
            || plan
                .profile_ids
                .insert(profile.id, uuid::Uuid::new_v4().to_string())
                .is_some()
        {
            errors.push(pi(profile, "legacy_profile_id"));
        }
        if !plan.group_ids.contains_key(&profile.group_id) {
            errors.push(pi(profile, "legacy_profile_group_missing"));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut group_order = BTreeMap::new();
    let mut positions = BTreeSet::new();
    for row in &db.group_order {
        match (
            integer(row, "group_id", -1),
            integer(row, "display_order", -1),
        ) {
            (Ok(id), Ok(order))
                if order >= 0
                    && plan.group_ids.contains_key(&id)
                    && !group_order.contains_key(&id)
                    && positions.insert(order) =>
            {
                group_order.insert(id, order);
            }
            _ => errors.push(issue("legacy_group_order", Some("database"), None, None)),
        }
    }
    let mut groups: Vec<_> = db.groups.iter().collect();
    groups.sort_by_key(|group| {
        (
            group_order.get(&group.id).copied().unwrap_or(i64::MAX),
            group.id,
        )
    });
    if !errors.is_empty() {
        return Err(errors);
    }
    // A profile that cannot be converted stays out together with everything
    // that depends on it: chains and pools using it, and groups whose front or
    // landing proxy it is (with their servers). Each pass converts from scratch
    // without the entries earlier passes excluded, until nothing else fails.
    let profiles_by_id = db.profiles_by_id();
    let mut skipped_profiles: BTreeMap<i64, String> = BTreeMap::new();
    let mut skipped_groups: BTreeMap<i64, String> = BTreeMap::new();
    loop {
        let mut pass = plan.clone();
        pass.profile_ids
            .retain(|id, _| !skipped_profiles.contains_key(id));
        pass.group_ids
            .retain(|id, _| !skipped_groups.contains_key(id));
        let mut excluded = false;
        let mut profile_order = Vec::new();
        for group in &groups {
            if skipped_groups.contains_key(&group.id) {
                continue;
            }
            match convert_group(
                db,
                group,
                &group_order,
                &defaults,
                &mut pass,
                &mut profile_order,
            ) {
                Ok(group) => pass.groups.push(group),
                Err("legacy_group_proxy_missing")
                    if ["front_proxy_id", "landing_proxy_id"].iter().any(|key| {
                        integer(&group.columns, key, -1)
                            .is_ok_and(|id| skipped_profiles.contains_key(&id))
                    }) =>
                {
                    skipped_groups.insert(group.id, "legacy_group_proxy_skipped".into());
                    excluded = true;
                }
                Err(code) => errors.push(gi(group, code)),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        for source in &db.profiles {
            if skipped_groups.contains_key(&source.group_id)
                && !skipped_profiles.contains_key(&source.id)
            {
                skipped_profiles.insert(source.id, "legacy_profile_group_skipped".into());
                excluded = true;
            }
        }
        for id in profile_order {
            if skipped_profiles.contains_key(&id) {
                continue;
            }
            let source = profiles_by_id[&id];
            match convert_profile(
                db,
                source,
                &profiles_by_id,
                &defaults,
                use_source_settings,
                selector_choice,
                &mut pass,
            ) {
                Ok(profile) => pass.profiles.push(profile),
                // A pending user choice is not a failure to leave out.
                Err(code @ "legacy_selector_snapshot_choice_required") => {
                    errors.push(pi(source, code))
                }
                Err(code) => {
                    skipped_profiles.insert(id, code.into());
                    excluded = true;
                }
            }
        }
        if !errors.is_empty() {
            // The pending choice blocks the review; name what would be left out too.
            errors.extend(
                skipped_profiles
                    .iter()
                    .map(|(id, code)| pi(profiles_by_id[id], code)),
            );
            return Err(errors);
        }
        if excluded {
            continue;
        }
        let (database, runtime): (Vec<_>, Vec<_>) = check_group_chains(db, &pass)
            .into_iter()
            .partition(|issue| issue.source_id.is_none());
        if !database.is_empty() {
            return Err(database);
        }
        if !runtime.is_empty() {
            for issue in runtime {
                skipped_profiles.insert(issue.source_id.unwrap(), issue.code);
            }
            continue;
        }
        for (id, code) in &skipped_groups {
            let group = groups.iter().find(|g| g.id == *id).unwrap();
            pass.report.push(gi(group, "legacy_group_skipped"));
            pass.report.push(gi(group, code));
        }
        for (id, code) in &skipped_profiles {
            let source = profiles_by_id[id];
            pass.report.push(pi(source, "legacy_profile_skipped"));
            pass.report.push(pi(source, code));
        }
        report_deferred(db, &defaults, use_source_settings, &mut pass);
        return Ok(pass);
    }
}

/// Columns of Qt's `groups` table (`GroupsRepo::createTables`).
const GROUP_COLUMNS: [&str; 19] = [
    "id",
    "archive",
    "skip_auto_update",
    "name",
    "url",
    "info",
    "sub_last_update",
    "front_proxy_id",
    "landing_proxy_id",
    "column_width_json",
    "profiles_json",
    "scroll_last_profile",
    "auto_clear_unavailable",
    "test_sort_by",
    "traffic_sort_by",
    "test_items_to_show",
    "type_sort_by",
    "created_at",
    "updated_at",
];
/// Columns of Qt's `profiles` table (`ProfilesRepo::createTables`).
const PROFILE_COLUMNS: [&str; 15] = [
    "id",
    "type",
    "name",
    "gid",
    "latency",
    "dl_speed",
    "ul_speed",
    "test_country",
    "ip_out",
    "outbound_json",
    "traffic_dl",
    "traffic_up",
    "created_at",
    "updated_at",
    "latency_at",
];

#[cfg(test)]
mod selector_tests;
#[cfg(test)]
mod tests;
