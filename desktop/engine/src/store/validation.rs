//! Library validation, supported versions and repairs applied when loading.
use super::*;

pub(crate) fn supported_version(version: u64) -> bool {
    (1..=8).contains(&version)
}
/// A source group that no longer exists means "all groups". Returns whether
/// the dangling reference was cleared.
pub(crate) fn repair_auto_select_source(library: &mut Library) -> bool {
    let auto_select = &mut library.preferences.auto_select;
    let dangling = auto_select
        .source_group_id
        .as_ref()
        .is_some_and(|id| !library.groups.iter().any(|group| &group.id == id));
    if dangling {
        auto_select.source_group_id = None;
    }
    dangling
}
/// A name a profile or group can have: not blank and within the byte limit.
pub fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= MAX_NAME_BYTES
}
/// The JSON size of a configuration a profile can hold, for batch budgets.
pub fn config_size(config: &Value) -> Option<usize> {
    config
        .is_object()
        .then(|| config.to_string().len())
        .filter(|size| *size <= MAX_CONFIG_BYTES)
}
pub(crate) fn validate_library(l: &Library) -> Result<(), String> {
    if !supported_version(u64::from(l.version))
        || (l.version < 6 && !l.routing_resources.is_empty())
        || (l.version < 7
            && l.routing_resources
                .kinds()
                .any(crate::routing::resources::Kind::profile_only))
        || (l.version < 8
            && l.routing_resources
                .kinds()
                .any(crate::routing::resources::Kind::asset))
        || (l.version < 5 && !l.tray_icons.is_empty())
        || (l.version == 1 && !l.otp.is_empty())
        || (l.version < 3 && !l.vpn_otp_bindings.is_empty())
        || (l.version < 4 && l.profiles.iter().any(|p| p.vpn_policy.is_some()))
        || (l.version < 4
            && l.vpn_otp_bindings
                .values()
                .any(|b| b.mode == crate::vpn_otp_bindings::Mode::AutoStart))
    {
        return Err("library_version_unsupported".into());
    }
    crate::otp_engine::validate(&l.otp)?;
    crate::vpn_otp_bindings::validate(l)?;
    for profile in &l.profiles {
        crate::vpn_policy::validate_profile(profile)?;
    }
    l.preferences.ping.validate()?;
    l.preferences.tun.validate()?;
    crate::settings::validate(l)?;
    crate::references::validate_all(l)?;
    l.routing.validate()?;
    crate::routing::resources::validate(l)?;
    crate::group_chains::validate(l)?;
    if !crate::languages::supported(&l.preferences.language)
        || !matches!(l.preferences.theme.as_str(), "light" | "dark" | "system")
        || l.preferences.inbound_port == 0
    {
        return Err("invalid_preferences".into());
    }
    let groups: std::collections::HashSet<_> = l.groups.iter().map(|g| &g.id).collect();
    if l.preferences
        .auto_select
        .source_group_id
        .as_ref()
        .is_some_and(|id| !groups.contains(id))
    {
        return Err("auto_select_source_missing".into());
    }
    let profiles: std::collections::HashSet<_> = l.profiles.iter().map(|p| &p.id).collect();
    if groups.is_empty() || groups.len() != l.groups.len() || profiles.len() != l.profiles.len() {
        return Err("invalid_library_ids".into());
    }
    for p in &l.profiles {
        if p.kind == ProfileKind::ExternalCore {
            crate::external_core::parse(&p.config)?;
        }
        if !groups.contains(&p.group_id) || p.name.trim().is_empty() || !p.config.is_object() {
            return Err("invalid_profile".into());
        }
    }
    for group in &l.groups {
        if group.id.is_empty() || !valid_name(&group.name) {
            return Err("invalid_group".into());
        }
        if let Some(subscription) = &group.subscription {
            subscription.settings.validate()?;
        }
    }
    if l.selection_dangling() {
        return Err("invalid_selection".into());
    }
    Ok(())
}
