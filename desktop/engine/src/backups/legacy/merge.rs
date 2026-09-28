//! Merge of independently reviewed sections into a candidate library. Pure:
//! the caller commits the result atomically or discards it with the preview.
use super::{dependencies, settings, VpnBindings};
use crate::{
    legacy_backup::{
        otp::OtpPlan,
        profiles::ProfilePlan,
        routes::RoutePlan,
        settings::{Group, SettingsPlan},
    },
    store::Library,
};
use serde_json::json;

pub(in crate::backups) fn merge(
    current: &Library,
    plan: Option<&ProfilePlan>,
    routes: Option<&RoutePlan>,
    otp: Option<&OtpPlan>,
    icons: Option<&crate::tray_icons::Pack>,
    settings: &[&SettingsPlan],
    binding_choice: VpnBindings,
) -> Result<Library, String> {
    if plan.is_none_or(|p| p.profiles.is_empty() && p.groups.is_empty())
        && routes.is_none_or(|p| p.presets.is_empty())
        && otp.is_none_or(|p| p.entries.is_empty())
        && icons.is_none_or(crate::tray_icons::Pack::is_empty)
        && settings.iter().all(|p| p.values.is_empty())
    {
        return Err(if settings.is_empty() {
            "legacy_import_no_profiles"
        } else {
            "legacy_settings_empty"
        }
        .into());
    }
    let requires_warp = plan.is_some_and(|p| p.requires_warp)
        || routes.is_some_and(|p| {
            p.presets.iter().any(|p| {
                p.legacy_constraints
                    .as_ref()
                    .is_some_and(|c| c.warp_enabled)
            })
        });
    if requires_warp
        && !settings.iter().any(|plan| {
            plan.group == Group::Warp && plan.values.get("enable_warp") == Some(&json!(true))
        })
    {
        return Err("legacy_import_requires_warp".into());
    }
    let mut next = current.clone();
    settings::merge(&mut next, settings)?;
    if let Some(icons) = icons.filter(|icons| !icons.is_empty()) {
        next.tray_icons.merge(icons);
        next.version = next.version.max(5);
    }
    if let Some(plan) = plan {
        if plan
            .vless_overrides
            .keys()
            .any(|id| current.preferences.vless_overrides.contains_key(id))
        {
            return Err("legacy_import_incompatible".into());
        }
        // A Qt path is never carried into the library: every profile input
        // must have been replaced by a selected portable copy.
        if crate::legacy_backup::profile_resources::unresolved(plan) {
            return Err("legacy_profile_resource_required".into());
        }
        next.routing_resources.merge(&plan.resources)?;
        next.profiles.extend(plan.profiles.iter().cloned());
        next.groups.extend(plan.groups.iter().cloned());
        next.preferences
            .vless_overrides
            .extend(plan.vless_overrides.clone());
    }
    if let Some(routes) = routes {
        next.routing_resources.merge(&routes.resources)?;
        dependencies::inbound_tags(&next, routes)?;
        let candidate = crate::routing::Routing {
            revision: 0,
            active: routes
                .presets
                .first()
                .ok_or("legacy_import_incompatible")?
                .id
                .clone(),
            profiles: routes.presets.clone(),
        };
        if plan.is_none() && !crate::routing::profile_references(&candidate).is_empty() {
            return Err("legacy_routes_require_profiles".into());
        }
        next.routing.profiles.extend(routes.presets.iter().cloned());
        next.routing.revision = next
            .routing
            .revision
            .checked_add(1)
            .ok_or("routing_revision_overflow")?;
    }
    dependencies::resource_version(&mut next);
    if let Some(otp) = otp {
        let mut imported = otp.entries.clone();
        // A Throne copy of an entry already in use keeps the counter spent here.
        crate::otp::keep_spent_counters(&next.otp, &mut imported);
        next.otp.extend(imported);
        if !otp.entries.is_empty() {
            next.version = next.version.max(2);
        }
    }
    if let Some(plan) = plan {
        if !plan.vpn_bindings.is_empty() {
            match binding_choice {
                VpnBindings::RequireChoice => {
                    return Err("legacy_vpn_bindings_choice_required".into())
                }
                VpnBindings::Manual => {
                    if plan
                        .vpn_bindings
                        .values()
                        .any(|binding| !binding.manual_allowed)
                    {
                        return Err("legacy_vpn_binding_required".into());
                    }
                }
                VpnBindings::AutoLive | VpnBindings::Automatic => {
                    let otp = otp.ok_or("legacy_vpn_bindings_require_otp")?;
                    for (profile_id, source) in &plan.vpn_bindings {
                        let otp_id = otp
                            .otp_ids
                            .get(&source.otp_source_id)
                            .ok_or("legacy_vpn_binding_missing")?;
                        let entry = otp
                            .entries
                            .iter()
                            .find(|e| &e.id == otp_id)
                            .ok_or("legacy_vpn_binding_missing")?;
                        let profile = plan
                            .profiles
                            .iter()
                            .find(|p| &p.id == profile_id)
                            .ok_or("legacy_vpn_binding_missing")?;
                        let mode = if binding_choice == VpnBindings::AutoLive {
                            crate::vpn_auth::otp::support(profile)
                                .map_err(|_| "legacy_vpn_binding_unsupported")?;
                            crate::vpn_otp_bindings::Mode::AutoLive
                        } else {
                            crate::vpn_auth::otp::recommended_mode(profile)
                                .map_err(|_| "legacy_vpn_binding_unsupported")?
                        };
                        if !crate::vpn_otp_bindings::durable_counters()
                            && entry.value.kind == crate::otp::Kind::Hotp
                        {
                            return Err("vpn_otp_platform_unsupported".into());
                        }
                        if next.vpn_otp_bindings.contains_key(profile_id) {
                            return Err("legacy_import_incompatible".into());
                        }
                        next.vpn_otp_bindings.insert(
                            profile_id.clone(),
                            crate::vpn_otp_bindings::Binding {
                                revision: source.revision.clone(),
                                otp_id: otp_id.clone(),
                                mode,
                            },
                        );
                        next.version =
                            next.version
                                .max(if mode == crate::vpn_otp_bindings::Mode::AutoStart {
                                    4
                                } else {
                                    3
                                });
                    }
                }
            }
        }
        if plan.profiles.iter().any(|p| p.vpn_policy.is_some()) {
            next.version = next.version.max(4);
        }
        if let Some(routes) = routes {
            let referenced = crate::routing::profile_references(&crate::routing::Routing {
                revision: 0,
                active: routes
                    .presets
                    .first()
                    .map(|p| p.id.clone())
                    .unwrap_or_default(),
                profiles: routes.presets.clone(),
            });
            let carried = dependencies::carried_endpoints(plan, routes);
            if plan.profiles.iter().any(|p| {
                p.vpn_policy.is_some() && referenced.contains(&p.id) && !carried.contains(&p.id)
            }) {
                return Err("legacy_vpn_graph_unsupported".into());
            }
        }
    }
    settings::apply_subscription_defaults(&mut next, settings);
    // UUID/reference collisions and resulting library/backup limits are checked
    // together. Active routing and selected profile are never copied from source.
    crate::backups::encode(&next)?;
    Ok(next)
}
