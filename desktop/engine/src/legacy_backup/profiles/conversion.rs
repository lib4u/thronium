//! Phases of converting Throne groups and profiles into a library plan.
use super::*;

pub(super) fn convert_group(
    db: &SourceDatabase,
    group: &SourceGroup,
    group_order: &BTreeMap<i64, i64>,
    defaults: &Defaults,
    plan: &mut ProfilePlan,
    profile_order: &mut Vec<i64>,
) -> Result<Group, &'static str> {
    if group.name.trim().is_empty() || group.name.len() > 512 {
        return Err("legacy_group_name");
    }
    let mut listed = BTreeSet::new();
    let list = match text(&group.columns, "profiles_json")? {
        None | Some("") => Vec::new(),
        Some(text) => crate::legacy_backup::json::parse(text)
            .map_err(|_| "legacy_group_profiles_json")?
            .as_array()
            .ok_or("legacy_group_profiles_json")?
            .iter()
            .map(|value| value.as_i64().ok_or("legacy_group_profiles_json"))
            .collect::<Result<Vec<_>, _>>()?,
    };
    for id in list {
        let source = db
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or("legacy_group_profile_missing")?;
        if source.group_id != group.id {
            return Err("legacy_group_profile_mismatch");
        }
        if listed.insert(id) {
            profile_order.push(id);
        } else {
            plan.report
                .push(gi(group, "legacy_profile_order_deduplicated"));
        }
    }
    let mut missing: Vec<_> = db
        .profiles
        .iter()
        .filter(|p| p.group_id == group.id && !listed.contains(&p.id))
        .map(|p| p.id)
        .collect();
    missing.sort();
    if !missing.is_empty() {
        plan.report
            .push(gi(group, "legacy_profile_order_completed"));
        profile_order.extend(missing);
    }
    if !group_order.contains_key(&group.id) {
        plan.report.push(gi(group, "legacy_group_order_completed"));
    }
    let reference = |key| -> Result<Option<String>, &'static str> {
        match integer(&group.columns, key, -1)? {
            -1 => Ok(None),
            id if id >= 0 => plan
                .profile_ids
                .get(&id)
                .cloned()
                .map(Some)
                .ok_or("legacy_group_proxy_missing"),
            _ => Err("legacy_group_proxy_missing"),
        }
    };
    let proxy_chain = GroupChain {
        front: reference("front_proxy_id")?,
        landing: reference("landing_proxy_id")?,
    };
    let url = text(&group.columns, "url")?.unwrap_or("");
    let info = text(&group.columns, "info")?.unwrap_or("");
    let archived = boolean(&group.columns, "archive")?;
    boolean(&group.columns, "skip_auto_update")?;
    let updated = integer(&group.columns, "sub_last_update", 0)?;
    if updated < 0 {
        return Err("legacy_subscription_timestamp");
    }
    let subscription = if url.is_empty() {
        None
    } else {
        let mut settings_json = json!({"url":url,"inheritDefaults":false,"intervalMinutes":0,"viaProxy":defaults.boolean("net_use_proxy")});
        match defaults.values.get("user_agent2").copied() {
            // An empty old value meant Throne's own client name, as in
            // Qt; the subscription then uses this application's default.
            Some("") => plan
                .report
                .push(gi(group, "legacy_network_default_user_agent")),
            Some(user_agent) => settings_json["userAgent"] = json!(user_agent),
            None => plan
                .report
                .push(gi(group, "legacy_subscription_user_agent_review")),
        }
        // HWID/device headers and insecure download policy remain global
        // in Thronium. This profile-only import cannot restore those.
        plan.report
            .push(gi(group, "legacy_subscription_transport_review"));
        let settings =
            serde_json::from_value(settings_json).map_err(|_| "legacy_subscription_settings")?;
        let subscription = Subscription {
            settings,
            metadata: Metadata {
                title: None,
                announcement: (!info.is_empty()).then(|| info.to_owned()),
                routing: None,
            },
            updated_at: (updated > 0).then_some(updated as u64),
            usage: None,
            managed_ids: Vec::new(),
            last_update: None,
        };
        subscription
            .settings
            .validate()
            .map_err(|_| "legacy_subscription_settings")?;
        plan.report
            .push(gi(group, "legacy_subscription_manual_review"));
        Some(subscription)
    };
    if archived {
        plan.report.push(gi(group, "legacy_group_archive_deferred"));
    }
    if !info.is_empty() && subscription.is_none() {
        plan.report.push(gi(group, "legacy_group_info_deferred"));
    }
    Ok(Group {
        id: plan.group_ids[&group.id].clone(),
        name: group.name.clone(),
        collapsed: false,
        auto_clear_unavailable: boolean(&group.columns, "auto_clear_unavailable")?,
        proxy_chain,
        subscription,
    })
}

pub(super) fn convert_profile(
    db: &SourceDatabase,
    source: &SourceProfile,
    profiles_by_id: &BTreeMap<i64, &SourceProfile>,
    defaults: &Defaults,
    use_source_settings: bool,
    selector_choice: crate::legacy_backup::autoselector::Choice,
    plan: &mut ProfilePlan,
) -> Result<Profile, &'static str> {
    object(&source.outbound)?;
    let mut vpn = None;
    let (kind, config) = match source.kind.as_str() {
        "openvpn" | "openvpn-client" | "openconnect" => {
            let converted = crate::legacy_backup::vpn::convert(source)?;
            vpn = Some((
                converted.policy,
                converted.otp_source_id,
                converted.manual_allowed,
            ));
            (ProfileKind::SingBoxOutbound, converted.config)
        }
        "chain" => {
            keys(&source.outbound, &["type", "name", "list"])?;
            if source.outbound["type"] != "chain" {
                return Err("legacy_profile_discriminator");
            }
            let list = source.outbound["list"]
                .as_array()
                .ok_or("legacy_chain_structure")?;
            if list.is_empty() || list.len() > crate::chains::MAX_HOPS {
                return Err("legacy_chain_structure");
            }
            let hops: Result<Vec<_>, _> = list
                .iter()
                .map(|id| {
                    id.as_i64()
                        .and_then(|id| plan.profile_ids.get(&id))
                        .cloned()
                        .ok_or("legacy_chain_reference_missing")
                })
                .collect();
            (ProfileKind::Chain, json!({"type":"chain","hops":hops?}))
        }
        "custom" => custom::convert(source, &mut plan.report)?,
        "xrayvless" => xray_vless(source, defaults)?,
        "autoselector" => {
            let spec = crate::legacy_backup::autoselector::convert(
                source,
                db,
                profiles_by_id,
                if use_source_settings {
                    crate::legacy_backup::autoselector::SourceSettings::Included(&db.settings)
                } else {
                    crate::legacy_backup::autoselector::SourceSettings::Excluded
                },
                selector_choice,
            )?;
            let config = spec.to_config(&plan.profile_ids)?;
            plan.requires_warp |= spec.requires_warp;
            plan.report.extend(spec.report);
            (ProfileKind::AutoSelector, config)
        }
        "extracore" => {
            let config = crate::legacy_backup::external_core::convert(
                source,
                if cfg!(any(target_os = "linux", target_os = "windows")) {
                    crate::legacy_backup::external_core::Platform::Supported
                } else {
                    crate::legacy_backup::external_core::Platform::Unsupported
                },
            )?;
            (ProfileKind::ExternalCore, config)
        }
        "wireguard" => (
            ProfileKind::SingBoxOutbound,
            crate::legacy_backup::wireguard::convert(source)?,
        ),
        "warp" => return Err("legacy_profile_wireguard_unsupported"),
        kind if super::extended::supports(kind) => {
            super::extended::convert(source, defaults, &mut plan.report)?
        }
        _ => ordinary(source, defaults)?,
    };
    let name_key = if matches!(
        source.kind.as_str(),
        "custom" | "chain" | "autoselector" | "extracore"
    ) {
        "name"
    } else {
        "tag"
    };
    let name = optional_string(&source.outbound, name_key)?
        .filter(|v| !v.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            source
                .name
                .as_ref()
                .filter(|v| !v.trim().is_empty())
                .cloned()
        })
        .unwrap_or_else(|| {
            plan.report
                .push(pi(source, "legacy_profile_name_generated"));
            crate::legacy_backup::fallback_profile_name(source.id)
        });
    // Qt's Tailscale `globalDNS` becomes the node's tunnel-DNS policy.
    let tailscale_dns = source.kind == "tailscale" && source.outbound["globalDNS"] == json!(true);
    let profile = Profile {
        vpn_policy: vpn
            .map(|v| v.0)
            .or(tailscale_dns.then_some(crate::vpn_policy::Policy {
                only_advertised_routes: false,
                use_tunnel_dns: true,
                block_outside_dns: false,
            })),
        id: plan.profile_ids[&source.id].clone(),
        name,
        group_id: plan.group_ids[&source.group_id].clone(),
        kind,
        config,
        favorite: false,
    };
    if let Some((_, otp_source_id, manual_allowed)) = vpn {
        plan.report.push(pi(source, "legacy_vpn_policy_preserved"));
        if let Some(otp_source_id) = otp_source_id {
            plan.vpn_bindings.insert(
                profile.id.clone(),
                crate::legacy_backup::vpn::BindingSource {
                    source_id: source.id,
                    otp_source_id,
                    manual_allowed,
                    revision: uuid::Uuid::new_v4().to_string(),
                },
            );
        }
    }
    if kind == ProfileKind::ExternalCore {
        for code in [
            "legacy_external_launch_review",
            "legacy_external_runtime_subset",
        ]
        .into_iter()
        .chain((profile.config["no_logs"] == false).then_some("legacy_external_output_enabled"))
        {
            plan.report.push(issue(
                code,
                Some("profile"),
                Some(source.id),
                Some(&profile.name),
            ));
        }
    }
    if crate::vless::is_vless(&profile) {
        plan.vless_overrides.insert(
            profile.id.clone(),
            if kind == ProfileKind::XrayOutbound {
                Core::Xray
            } else {
                Core::SingBox
            },
        );
    }
    Ok(profile)
}

/// Group proxies, chains and pools of the converted library, checked as the
/// runtime would build them.
pub(super) fn check_group_chains(db: &SourceDatabase, plan: &ProfilePlan) -> Vec<Issue> {
    let mut errors = Vec::new();
    let library = Library {
        version: if plan.profiles.iter().any(|p| p.vpn_policy.is_some()) {
            4
        } else {
            1
        },
        profiles: plan.profiles.clone(),
        groups: plan.groups.clone(),
        ..Library::default()
    };
    for source in &db.profiles {
        // Profiles an earlier pass excluded are not part of this library.
        let Some(profile) = plan
            .profile_ids
            .get(&source.id)
            .and_then(|id| plan.profiles.iter().find(|p| &p.id == id))
        else {
            continue;
        };
        if profile.vpn_policy.is_some()
            && plan
                .groups
                .iter()
                .any(|g| g.id == profile.group_id && g.proxy_chain.enabled())
        {
            errors.push(pi(source, "legacy_vpn_graph_unsupported"));
        }
        if profile.kind == ProfileKind::Chain {
            if let Err(code) = crate::chains::flatten(profile, &plan.profiles) {
                errors.push(pi(
                    source,
                    match code.as_str() {
                        "chain_cycle" => "legacy_chain_cycle",
                        "chain_too_long" => "legacy_chain_too_long",
                        "chain_profile_missing" => "legacy_chain_reference_missing",
                        _ => "legacy_chain_hop_unsupported",
                    },
                ));
            }
        } else if profile.kind == ProfileKind::AutoSelector {
            if crate::auto_selector::validate(profile, &plan.profiles).is_err() {
                errors.push(pi(source, "legacy_selector_member_unsupported"));
            }
        } else if crate::config::build(
            profile,
            crate::config::PLACEHOLDER_INBOUND_PORT,
            Some(crate::config::PLACEHOLDER_INBOUND_PORT + 1),
        )
        .is_err()
        {
            errors.push(pi(source, "legacy_profile_runtime_structure"));
        }
        if let Some(group) = plan
            .groups
            .iter()
            .find(|g| g.id == profile.group_id)
            .filter(|g| g.proxy_chain.enabled())
        {
            // Qt wraps every selected candidate in the selector's containing
            // group. A candidate's own group must not become another wrapper.
            let members = if profile.kind == ProfileKind::AutoSelector {
                crate::references::members(profile).unwrap_or_default()
            } else {
                vec![profile.id.as_str()]
            };
            for member in members {
                let mut length = 0;
                let mut valid = true;
                for part in group
                    .proxy_chain
                    .front
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(member))
                    .chain(group.proxy_chain.landing.iter().map(String::as_str))
                {
                    match plan
                        .profiles
                        .iter()
                        .find(|p| p.id == part)
                        .and_then(|p| crate::chains::flatten(p, &plan.profiles).ok())
                    {
                        // A connection refuses an external core inside a group
                        // chain (`external_chain_unsupported`), wherever it sits.
                        Some(hops) if hops.iter().any(|h| h.kind == ProfileKind::ExternalCore) => {
                            valid = false
                        }
                        Some(hops) => length += hops.len(),
                        None => valid = false,
                    }
                }
                if !valid || length > crate::chains::MAX_HOPS {
                    errors.push(pi(source, "legacy_group_chain_unsupported"));
                    break;
                }
            }
        }
    }
    if crate::group_chains::validate(&library).is_err() {
        errors.push(issue(
            "legacy_group_chain_unsupported",
            Some("database"),
            None,
            None,
        ));
    }
    errors
}

/// What the import reports as informational or left for later.
pub(super) fn report_deferred(
    db: &SourceDatabase,
    defaults: &Defaults,
    use_source_settings: bool,
    plan: &mut ProfilePlan,
) {
    if let Some(id) = defaults
        .values
        .get("remember_id")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|id| *id >= 0)
    {
        plan.selected = plan.profile_ids.get(&id).cloned();
        plan.report.push(issue(
            if plan.selected.is_some() {
                "legacy_selection_informational"
            } else {
                "legacy_selection_missing"
            },
            Some("profile"),
            Some(id),
            None,
        ));
    }
    plan.report.push(issue(
        "legacy_current_network_settings_retained",
        Some("database"),
        None,
        None,
    ));
    if use_source_settings && !db.settings.is_empty() {
        plan.report.push(issue(
            "legacy_settings_deferred",
            Some("database"),
            None,
            None,
        ));
    }
    if !db.routes.is_empty() || !db.rules.is_empty() {
        plan.report.push(issue(
            "legacy_routing_deferred",
            Some("database"),
            None,
            None,
        ));
    }
    if !db.otp.is_empty() {
        plan.report
            .push(issue("legacy_otp_deferred", Some("database"), None, None));
    }
    if !db.profiles.is_empty() {
        plan.report.push(issue(
            "legacy_profile_metrics_deferred",
            Some("database"),
            None,
            None,
        ));
    }
    if !db.groups.is_empty() {
        plan.report.push(issue(
            "legacy_group_layout_deferred",
            Some("database"),
            None,
            None,
        ));
    }
    if !db.other_tables.is_empty() {
        plan.report.push(issue(
            "legacy_other_tables_deferred",
            Some("database"),
            None,
            None,
        ));
    }
    // Columns of a newer Throne are not guessed at: they stay in the backup.
    if db.groups.iter().any(|g| {
        g.columns
            .keys()
            .any(|c| !GROUP_COLUMNS.contains(&c.as_str()))
    }) || db.profiles.iter().any(|p| {
        p.columns
            .keys()
            .any(|c| !PROFILE_COLUMNS.contains(&c.as_str()))
    }) {
        plan.report.push(issue(
            "legacy_unknown_columns_deferred",
            Some("database"),
            None,
            None,
        ));
    }
}
