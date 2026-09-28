//! Independent, opt-in legacy settings categories. All values remain private.
use super::*;
use crate::legacy_backup::settings::{Group, SettingsPlan};

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsScopes {
    #[serde(default)]
    pub appearance: bool,
    #[serde(default)]
    pub testing: bool,
    #[serde(default)]
    pub logging: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub geodata: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub warp: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub network: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub subscriptions: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub inbound: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub system: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub presets: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub intercept: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tun: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub core: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub hotkeys: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl SettingsScopes {
    pub fn is_empty(&self) -> bool {
        !self.appearance
            && !self.testing
            && !self.logging
            && !self.geodata
            && !self.warp
            && !self.network
            && !self.subscriptions
            && !self.inbound
            && !self.system
            && !self.presets
            && !self.intercept
            && !self.tun
            && !self.core
            && !self.hotkeys
    }
    fn contains(self, group: Group) -> bool {
        match group {
            Group::Appearance => self.appearance,
            Group::Testing => self.testing,
            Group::Logging => self.logging,
            Group::Geodata => self.geodata,
            Group::Warp => self.warp,
            Group::Network => self.network,
            Group::Subscriptions => self.subscriptions,
            Group::Inbound => self.inbound,
            Group::System => self.system,
            Group::Presets => self.presets,
            Group::Intercept => self.intercept,
            Group::Tun => self.tun,
            Group::Core => self.core,
            Group::Hotkeys => self.hotkeys,
        }
    }
}
const GROUPS: [Group; 14] = [
    Group::Appearance,
    Group::Testing,
    Group::Logging,
    Group::Geodata,
    Group::Warp,
    Group::Network,
    Group::Subscriptions,
    Group::Inbound,
    Group::System,
    Group::Presets,
    Group::Intercept,
    Group::Tun,
    Group::Core,
    Group::Hotkeys,
];
fn key(group: Group) -> &'static str {
    match group {
        Group::Appearance => "appearance",
        Group::Testing => "testing",
        Group::Logging => "logging",
        Group::Geodata => "geodata",
        Group::Warp => "warp",
        Group::Network => "network",
        Group::Subscriptions => "subscriptions",
        Group::Inbound => "inbound",
        Group::System => "system",
        Group::Presets => "presets",
        Group::Intercept => "intercept",
        Group::Tun => "tun",
        Group::Core => "core",
        Group::Hotkeys => "hotkeys",
    }
}
#[derive(Clone)]
pub(in crate::backups) struct PreparedSettings {
    group: Group,
    plan: Option<SettingsPlan>,
    issues: Vec<Issue>,
}
pub(super) fn prepare(source: &legacy_backup::SourceArchive) -> Vec<PreparedSettings> {
    if !source.parts.settings {
        return vec![];
    }
    GROUPS
        .into_iter()
        .map(|group| {
            let (plan, issues) = match legacy_backup::settings::convert(source, &group) {
                Ok(plan) => {
                    let issues = plan.report.clone();
                    (Some(plan), issues)
                }
                Err(issues) => (None, issues),
            };
            PreparedSettings {
                group,
                plan,
                issues,
            }
        })
        .collect()
}
pub(super) fn review(
    prepared: &[PreparedSettings],
    scopes: SettingsScopes,
    review: &mut Value,
) -> bool {
    let mut usable = true;
    let mut groups = serde_json::Map::new();
    let mut imported = std::collections::BTreeSet::new();
    for group in GROUPS {
        let row = prepared.iter().find(|row| key(row.group) == key(group));
        let fields = row
            .and_then(|row| row.plan.as_ref())
            .map(|plan| plan.imported_fields.clone())
            .unwrap_or_default();
        groups.insert(
            key(group).into(),
            json!({"count":fields.len(),"fields":fields}),
        );
        if !scopes.contains(group) {
            continue;
        }
        let Some(row) = row else {
            issue(review, "legacy_settings_part_missing");
            usable = false;
            continue;
        };
        if row.plan.is_none() {
            usable = false;
        }
        imported.extend(fields);
        review["issues"]
            .as_array_mut()
            .unwrap()
            .extend(row.issues.iter().map(|issue| json!(issue)));
    }
    review["settingsGroups"] = json!(groups);
    review["settingsCount"] = json!(imported.len());
    review["settingsDeferred"] = json!(review["inventory"]["settings"]
        .as_u64()
        .unwrap_or(0)
        .saturating_sub(imported.len() as u64));
    if !scopes.is_empty() {
        review["issues"].as_array_mut().unwrap().retain(|issue| {
            !matches!(
                issue["code"].as_str(),
                Some("legacy_settings_deferred" | "legacy_settings_general_deferred")
            )
        });
    }
    usable
}
pub(super) fn plans(prepared: &[PreparedSettings], scopes: SettingsScopes) -> Vec<&SettingsPlan> {
    prepared
        .iter()
        .filter(|row| scopes.contains(row.group))
        .filter_map(|row| row.plan.as_ref())
        .collect()
}
pub(super) fn merge(next: &mut Library, plans: &[&SettingsPlan]) -> Result<(), String> {
    let mut prefs =
        serde_json::to_value(&next.preferences).map_err(|_| "legacy_settings_value_invalid")?;
    let mut seen = std::collections::BTreeSet::new();
    for plan in plans {
        legacy_backup::settings::validate_plan(plan)?;
        for (id, value) in &plan.values {
            if !seen.insert(id) {
                return Err("legacy_settings_duplicate".into());
            }
            if legacy_backup::settings::geodata::is_history(id) {
                legacy_backup::settings::geodata::validate_history(value)?;
                next.settings.insert(id.clone(), value.clone());
                continue;
            }
            let field = crate::settings::fields()
                .iter()
                .find(|field| field.id == *id)
                .ok_or("legacy_settings_value_invalid")?;
            if let Some(path) = &field.preference {
                *prefs
                    .pointer_mut(path)
                    .ok_or("legacy_settings_value_invalid")? = value.clone();
            } else {
                next.settings.insert(id.clone(), value.clone());
            }
        }
    }
    next.preferences =
        serde_json::from_value(prefs).map_err(|_| "legacy_settings_value_invalid")?;
    Ok(())
}

#[cfg(test)]
mod geodata_tests;

#[cfg(test)]
mod warp_tests;

#[cfg(test)]
mod network_tests;

/// Update only selected inherited fields, including groups added in this import.
/// Per-group overrides and last-update/attempt timestamps remain unchanged.
pub(super) fn apply_subscription_defaults(next: &mut Library, plans: &[&SettingsPlan]) {
    let agent_selected = plans.iter().any(|p| p.values.contains_key("user_agent"));
    let interval_selected = plans
        .iter()
        .any(|p| p.values.contains_key("sub_auto_update"));
    if !agent_selected && !interval_selected {
        return;
    }
    let agent = crate::settings::string(next, "user_agent");
    let interval = crate::settings::integer(next, "sub_auto_update") as u32;
    for group in &mut next.groups {
        if let Some(sub) = &mut group.subscription {
            if sub.settings.inherit_defaults == Some(true) {
                if agent_selected {
                    sub.settings.user_agent = agent.clone();
                }
                if interval_selected {
                    sub.settings.interval_minutes = interval;
                }
            }
        }
    }
}

#[cfg(test)]
mod basic_tests;

#[cfg(test)]
mod runtime_tests;
