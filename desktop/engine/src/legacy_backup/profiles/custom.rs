//! Qt custom profiles: user JSON of one sing-box/Xray outbound or a complete
//! configuration, kept verbatim (custom.h Build). File paths inside stay as
//! written and are offered as selectable resources by the review; the merge
//! refuses a plan that still names an unreplaced path, including the lists an
//! Xray configuration names by `ext:`.
use super::{keys, object, pi, Issue, SourceProfile};
use crate::{routing::resources::profiles::visit_profile, store::ProfileKind};
use serde_json::Value;

type Result<T> = std::result::Result<T, &'static str>;

/// A remote rule set's `initial_path` seeds the first download from a local
/// file; the download itself makes the set complete, so the seed is dropped.
fn drop_initial_paths(config: &mut Value) -> bool {
    let mut dropped = false;
    for set in config
        .get_mut("route")
        .and_then(|route| route.get_mut("rule_set"))
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if set["type"] == "remote" && set["initial_path"].as_str().is_some_and(|s| !s.is_empty()) {
            set.as_object_mut().map(|set| set.remove("initial_path"));
            dropped = true;
        }
    }
    dropped
}

pub(super) fn convert(
    source: &SourceProfile,
    report: &mut Vec<Issue>,
) -> Result<(ProfileKind, Value)> {
    keys(&source.outbound, &["type", "name", "subtype", "config"])?;
    if source.outbound["type"] != "custom" {
        return Err("legacy_profile_discriminator");
    }
    let mut config: Value = crate::strict_json::parse(
        source.outbound["config"]
            .as_str()
            .ok_or("legacy_profile_structure")?,
    )
    .map_err(|_| "legacy_profile_json")?;
    object(&config)?;
    let kind = match source.outbound["subtype"].as_str() {
        Some("outbound") => ProfileKind::SingBoxOutbound,
        Some("fullconfig") => ProfileKind::SingBoxConfig,
        Some("xrayoutbound") => ProfileKind::XrayOutbound,
        Some("xrayfullconfig") => ProfileKind::XrayConfig,
        _ => return Err("legacy_profile_custom_subtype_unsupported"),
    };
    if matches!(kind, ProfileKind::SingBoxOutbound) && !config["type"].is_string()
        || matches!(kind, ProfileKind::XrayOutbound) && !config["protocol"].is_string()
    {
        return Err("legacy_profile_structure");
    }
    if matches!(kind, ProfileKind::SingBoxConfig | ProfileKind::XrayConfig) {
        for key in ["inbounds", "outbounds"] {
            if let Some(value) = config.get(key) {
                if !value.is_array() {
                    return Err("legacy_profile_structure");
                }
            }
        }
        if !config["outbounds"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
            && !config["endpoints"]
                .as_array()
                .is_some_and(|v| !v.is_empty())
        {
            return Err("legacy_profile_structure");
        }
    }
    if drop_initial_paths(&mut config) {
        report.push(pi(source, "legacy_profile_initial_path_omitted"));
    }
    visit_profile(&mut config.clone(), |path, _| {
        // Only the shape is checked here; the review decides what replaces it.
        match path.as_str() {
            Some(s) if s.len() <= 4096 && !s.chars().any(char::is_control) => Ok(()),
            _ => Err("legacy_profile_structure".into()),
        }
    })
    .map_err(|_| "legacy_profile_structure")?;
    Ok((kind, config))
}
