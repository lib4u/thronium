//! Add transient health hints to the final generated Core JSON only.
use super::{dynamic, member_tag};
use crate::{
    proto,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};

pub(crate) fn apply(
    request: &mut proto::LoadConfigReq,
    selected: &Profile,
    library: &Library,
) -> Result<(), String> {
    // A complete user configuration owns all its tags and warm values.
    if matches!(
        selected.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        return Ok(());
    }
    let roots = crate::vless::roots(library, selected)?;
    let mut owners = Vec::new();
    for id in roots {
        let profile = if id == selected.id {
            Some(selected)
        } else {
            library.profiles.iter().find(|p| p.id == id)
        };
        if let Some(profile) = profile.filter(|p| {
            p.kind == ProfileKind::AutoSelector && p.config["member_source"]["warm_start"] == true
        }) {
            let tag = if profile.id == selected.id {
                "proxy".into()
            } else {
                format!("thronium-route-{}", profile.id)
            };
            owners.push((tag, profile));
        }
    }
    if owners.is_empty() {
        return Ok(());
    }
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("selector_generated_fields")?,
    )
    .map_err(|_| "selector_generated_fields")?;
    let outbounds = core["outbounds"]
        .as_array_mut()
        .ok_or("selector_generated_fields")?;
    let mut changed = false;
    for (tag, profile) in owners {
        let Some(group) = outbounds.iter_mut().find(|p| {
            p["type"] == "auto-selector"
                && p["tag"]
                    .as_str()
                    .is_some_and(|actual| super::runtime::logical_tag(actual) == tag)
        }) else {
            continue;
        };
        if group.get("warm").is_some() {
            return Err("selector_generated_fields".into());
        }
        let prefix = member_tag(&tag, "");
        let ids: Vec<String> = group["outbounds"]
            .as_array()
            .ok_or("selector_generated_fields")?
            .iter()
            .map(|t| {
                t.as_str()
                    .and_then(|t| t.strip_prefix(&prefix))
                    .map(str::to_owned)
                    .ok_or("selector_generated_fields")
            })
            .collect::<Result<_, _>>()?;
        let seeds = dynamic::warm_candidates(profile, library, &ids)?;
        let entries: Vec<_> = ids
            .iter()
            .filter_map(|id| {
                seeds.get(id).map(
                    |seed| json!({"tag":member_tag(&tag,id),"rtt":seed["rtt"],"age":seed["age"]}),
                )
            })
            .collect();
        if !entries.is_empty() {
            group["warm"] = json!(entries);
            changed = true;
        }
    }
    if changed {
        request.core_config =
            Some(serde_json::to_string(&core).map_err(|_| "selector_generated_fields")?);
    }
    Ok(())
}
