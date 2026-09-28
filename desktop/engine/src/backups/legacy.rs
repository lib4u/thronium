//! Import with independently reviewed profiles, route/DNS presets, OTP and settings.
//! Active selection is preserved; settings change only in explicitly chosen categories.
use super::{summary, Pending, Preview};
use crate::{
    legacy_backup::{
        self,
        otp::OtpPlan,
        profiles::{Issue, ProfilePlan},
        routes::RoutePlan,
    },
    store::Library,
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Instant;
mod dependencies;
#[cfg(test)]
mod dependencies_tests;
mod merge;
pub(super) use merge::merge;
pub mod resources;
#[cfg(test)]
mod resources_tests;
mod settings;
pub use settings::SettingsScopes;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scopes {
    pub profiles: bool,
    pub routes: bool,
    #[serde(default)]
    pub otp: bool,
    #[serde(default)]
    pub icons: bool,
    #[serde(default, skip_serializing_if = "SettingsScopes::is_empty")]
    pub settings: SettingsScopes,
    #[serde(default)]
    pub auto_selectors: AutoSelectors,
    #[serde(default)]
    pub vpn_bindings: VpnBindings,
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoSelectors {
    #[default]
    RequireChoice,
    LastBuilt,
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnBindings {
    #[default]
    RequireChoice,
    AutoLive,
    Automatic,
    Manual,
}
impl Default for Scopes {
    fn default() -> Self {
        Self {
            profiles: true,
            routes: false,
            otp: false,
            icons: false,
            settings: SettingsScopes::default(),
            auto_selectors: AutoSelectors::RequireChoice,
            vpn_bindings: VpnBindings::RequireChoice,
        }
    }
}

#[derive(Clone)]
pub struct Prepared {
    pub(super) resources: legacy_backup::resources::Plan,
    pub(super) icons: Option<legacy_backup::icons::Plan>,
    pub(super) icon_issues: Vec<Issue>,
    pub(super) plan: Option<ProfilePlan>,
    pub(super) routes: Option<RoutePlan>,
    pub(super) route_issues: Vec<Issue>,
    pub(super) otp: Option<OtpPlan>,
    pub(super) otp_issues: Vec<Issue>,
    pub(super) settings: Vec<settings::PreparedSettings>,
    pub(super) scopes: Scopes,
    pub(super) review: Value,
    /// Traffic counted by the same copy, read from its `throne_stats.db`. It is
    /// taken over only when the user imports the servers it belongs to.
    pub(super) traffic: Option<legacy_backup::stats::Stats>,
}

/// Pure conversion runs before taking Engine's lock. No source configurations,
/// SQLite bytes or source settings values are included in public review data.
pub fn prepare(source: &legacy_backup::SourceArchive) -> Prepared {
    let selector_count = if source.parts.profiles {
        source.database.as_ref().map_or(0, |db| {
            db.profiles
                .iter()
                .filter(|p| p.kind == "autoselector")
                .count()
        })
    } else {
        0
    };
    let mut review = json!({
        "format":"throne-backup", "mode":"add-profiles",
        "createdAt":source.created_at.as_deref().filter(|date| date.len() <= 256 && !date.chars().any(char::is_control)),
        "inventory":source.inventory(), "issues":[], "canApply":false,
        "autoSelectorCount":selector_count, "selectorSnapshots":[],
    });
    let plan = if source.parts.profiles {
        match source
            .database
            .as_ref()
            // Prepare one private UUID map before review. The separate choice
            // below controls whether this prepared snapshot may be applied.
            .map(|db| {
                legacy_backup::profiles::convert_selected_with_selectors(
                    db,
                    source.parts.settings,
                    legacy_backup::autoselector::Choice::LastBuilt,
                )
            }) {
            Some(Ok(plan)) => {
                review["issues"] = json!(plan.report);
                review["selectorSnapshots"] = json!(plan.profiles.iter()
                    .filter(|p| p.kind == crate::store::ProfileKind::AutoSelector)
                    .map(|p| json!({
                        "name":p.name.chars().filter(|c| !c.is_control()).take(256).collect::<String>(),
                        "sourceId":plan.profile_ids.iter().find(|(_, id)| *id == &p.id).map(|(id, _)| *id),
                        "members":p.config["members"].as_array().map_or(0, |a| a.len()),
                        "pinned":p.config.get("pinned_profile").is_some()
                    })).collect::<Vec<_>>());
                Some(plan)
            }
            Some(Err(issues)) => {
                review["issues"] = json!(issues);
                None
            }
            None => {
                issue(&mut review, "legacy_import_no_profiles");
                None
            }
        }
    } else {
        None
    };
    let has_note = |review: &Value, code: &str| {
        review["issues"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| issue["code"] == code))
    };
    if source.inventory().unknown_files > 0 {
        issue(&mut review, "legacy_backup_unknown_files_deferred");
    }
    if source
        .database
        .as_ref()
        .is_some_and(|db| !db.other_tables.is_empty())
        && !has_note(&review, "legacy_other_tables_deferred")
    {
        issue(&mut review, "legacy_other_tables_deferred");
    }
    let (routes, mut route_issues) = if source.parts.routes {
        match legacy_backup::routes::convert(source, plan.as_ref()) {
            Ok(routes) => {
                let issues = routes.report.clone();
                (Some(routes), issues)
            }
            Err(issues) => (None, issues),
        }
    } else {
        (None, vec![])
    };
    let (otp, otp_issues) = if source.parts.otp {
        match legacy_backup::otp::convert(source) {
            Ok(otp) => {
                let issues = otp.report.clone();
                (Some(otp), issues)
            }
            Err(issues) => (None, issues),
        }
    } else {
        (None, vec![])
    };
    let (icons, icon_issues) = if source.parts.icons {
        match legacy_backup::icons::convert(source) {
            Ok(plan) => {
                let report = plan.report.clone();
                (Some(plan), report)
            }
            Err(issues) => (None, issues),
        }
    } else {
        (None, vec![])
    };
    let resources = legacy_backup::resources::Plan::discover(source, plan.as_ref());
    if resources.over_limit() {
        route_issues.push(Issue {
            code: "routing_resource_too_large".into(),
            entity: Some("resource".into()),
            source_id: None,
            name: None,
        });
    }
    Prepared {
        resources,
        icons,
        icon_issues,
        plan,
        routes,
        route_issues,
        otp,
        otp_issues,
        settings: settings::prepare(source),
        scopes: Scopes {
            profiles: source.parts.profiles,
            routes: false,
            otp: false,
            icons: false,
            settings: SettingsScopes::default(),
            auto_selectors: AutoSelectors::RequireChoice,
            vpn_bindings: VpnBindings::RequireChoice,
        },
        review,
        traffic: None,
    }
}

/// Notes about parts of the archive that stay in the source backup; they hold
/// whichever scopes are imported.
const ARCHIVE_NOTES: [&str; 5] = [
    "legacy_settings_deferred",
    "legacy_routing_deferred",
    "legacy_otp_deferred",
    "legacy_other_tables_deferred",
    "legacy_backup_unknown_files_deferred",
];
fn issue(review: &mut Value, code: &str) {
    review["issues"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code":code,"entity":"database","sourceId":null,"name":null}));
}

impl Engine {
    pub fn preview_legacy_import(&mut self, prepared: Prepared) -> Result<Preview, String> {
        let mut review = prepared.review.clone();
        review["canApply"] = json!(false);
        let scopes = prepared.scopes;
        review["resources"] = json!(prepared
            .resources
            .requirements()
            .into_iter()
            .filter(|r| if r.entity == "profile" {
                scopes.profiles
            } else {
                scopes.routes
            })
            .collect::<Vec<_>>());
        // Selected profile inputs replace their paths in a derived plan; the
        // pristine plan stays for later re-substitution.
        let plan = prepared
            .plan
            .as_ref()
            .map(|plan| prepared.resources.substitute(plan));
        review["scopes"] = json!(prepared.scopes);
        review["mode"] = json!(if prepared.scopes.routes
            || prepared.scopes.otp
            || prepared.scopes.icons
            || !prepared.scopes.settings.is_empty()
        {
            "add-selected"
        } else {
            "add-profiles"
        });
        review["routeCount"] = json!(prepared.routes.as_ref().map_or(0, |r| r.presets.len()));
        review["otpCount"] = json!(prepared.otp.as_ref().map_or(0, |p| p.entries.len()));
        review["iconCount"] = json!(prepared.icons.as_ref().map_or(0, |p| p.icons.len()));
        review["externalCoreCount"] = json!(prepared
            .plan
            .as_ref()
            .filter(|_| prepared.scopes.profiles)
            .map_or(0, |plan| plan
                .profiles
                .iter()
                .filter(|profile| profile.kind == crate::store::ProfileKind::ExternalCore)
                .count()));
        review["vpnBindingCount"] =
            json!(prepared.plan.as_ref().map_or(0, |p| p.vpn_bindings.len()));
        review["vpnBindingsPlanned"] = json!(0);
        review["vpnBindings"]=json!(prepared.plan.iter().flat_map(|plan|plan.vpn_bindings.iter().filter_map(|(profile_id,binding)| {
            let profile=plan.profiles.iter().find(|p|&p.id==profile_id)?;
            let clean=|s:&str|s.chars().filter(|c|!c.is_control()).take(256).collect::<String>();
            let mut row=json!({"sourceId":binding.source_id,"name":clean(&profile.name),"otpSourceId":binding.otp_source_id,"manualAllowed":binding.manual_allowed,"mode":crate::vpn_auth::otp::recommended_mode(profile).ok()?});
            if let Some(otp)=&prepared.otp {
                if let Some(entry)=otp.otp_ids.get(&binding.otp_source_id).and_then(|id|otp.entries.iter().find(|e|&e.id==id)) {
                    row["otpName"]=json!(clean(&entry.value.name));
                }
            }
            Some(row)
        })).collect::<Vec<_>>());
        review["requirements"] = json!([]);
        if !prepared.scopes.profiles {
            // Profile findings do not apply, but what stays in the source
            // backup is still reported.
            review["issues"]
                .as_array_mut()
                .unwrap()
                .retain(|issue| ARCHIVE_NOTES.iter().any(|code| issue["code"] == *code));
        }
        if prepared.scopes.routes {
            let issues = review["issues"].as_array_mut().unwrap();
            issues.retain(|issue| issue["code"] != "legacy_routing_deferred");
            for issue in issues.iter_mut() {
                if issue["code"] == "legacy_settings_deferred" {
                    issue["code"] = json!("legacy_settings_general_deferred");
                }
            }
            issues.extend(prepared.route_issues.iter().map(|i| json!(i)));
            if prepared.routes.is_none() && prepared.route_issues.is_empty() {
                issue(&mut review, "legacy_route_parts_required");
            }
            if let Some(routes) = &prepared.routes {
                let requirements = routes
                    .presets
                    .iter()
                    .flat_map(|preset| {
                        crate::routing::legacy_context::conflicts(&self.store.library, preset)
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                review["requirements"] = json!(requirements);
            }
        }
        if prepared.scopes.otp {
            let issues = review["issues"].as_array_mut().unwrap();
            issues.retain(|issue| issue["code"] != "legacy_otp_deferred");
            issues.extend(prepared.otp_issues.iter().map(|issue| json!(issue)));
            if prepared.otp.is_none() && prepared.otp_issues.is_empty() {
                issue(&mut review, "legacy_otp_parts_required");
            }
        }
        if prepared.scopes.icons {
            let issues = review["issues"].as_array_mut().unwrap();
            issues.retain(|issue| issue["code"] != "legacy_system_custom_icons_deferred");
            issues.extend(prepared.icon_issues.iter().map(|issue| json!(issue)));
            if prepared.icons.is_none() && prepared.icon_issues.is_empty() {
                issue(&mut review, "legacy_icons_part_missing");
            }
        }
        let settings_usable = settings::review(&prepared.settings, scopes.settings, &mut review);
        let profile_inputs_missing = scopes.profiles && prepared.resources.profiles_pending();
        if profile_inputs_missing {
            issue(&mut review, "legacy_profile_resource_required");
        }
        if scopes.icons && prepared.icons.is_some() {
            review["issues"]
                .as_array_mut()
                .unwrap()
                .retain(|issue| issue["code"] != "legacy_system_custom_icons_deferred");
        }
        // Traffic the same copy counted travels with its servers; nothing is
        // taken over when the user leaves the servers out.
        if scopes.profiles {
            if let Some(stats) = prepared.traffic.as_ref() {
                review["trafficBuckets"] = json!(stats.buckets());
            }
        }
        let selector_choice_missing = scopes.profiles
            && review["autoSelectorCount"].as_u64().unwrap_or(0) > 0
            && scopes.auto_selectors == AutoSelectors::RequireChoice;
        if selector_choice_missing {
            issue(&mut review, "legacy_selector_snapshot_choice_required");
        }
        let binding_choice_missing = scopes.profiles
            && review["vpnBindingCount"].as_u64().unwrap_or(0) > 0
            && scopes.vpn_bindings == VpnBindings::RequireChoice;
        if binding_choice_missing {
            issue(&mut review, "legacy_vpn_bindings_choice_required");
        }
        if !scopes.profiles
            && !scopes.routes
            && !scopes.otp
            && !scopes.icons
            && scopes.settings.is_empty()
        {
            issue(&mut review, "legacy_import_select_scope");
        }
        let usable = (scopes.profiles
            || scopes.routes
            || scopes.otp
            || scopes.icons
            || !scopes.settings.is_empty())
            && settings_usable
            && !profile_inputs_missing
            && !selector_choice_missing
            && !binding_choice_missing
            && (!scopes.profiles || prepared.plan.is_some())
            && (!scopes.routes || prepared.routes.is_some())
            && (!scopes.icons || prepared.icons.is_some())
            && (!scopes.otp || prepared.otp.is_some());
        let library = if usable {
            match merge(
                &self.store.library,
                plan.as_ref().filter(|_| scopes.profiles),
                prepared.routes.as_ref().filter(|_| scopes.routes),
                prepared.otp.as_ref().filter(|_| scopes.otp),
                prepared
                    .icons
                    .as_ref()
                    .filter(|_| scopes.icons)
                    .map(|p| &p.icons),
                &settings::plans(&prepared.settings, scopes.settings),
                scopes.vpn_bindings,
            ) {
                Ok(library) => {
                    if scopes.routes {
                        review["requirements"] = json!(prepared
                            .routes
                            .iter()
                            .flat_map(|routes| routes.presets.iter())
                            .flat_map(|preset| crate::routing::legacy_context::conflicts(
                                &library, preset
                            ))
                            .collect::<std::collections::BTreeSet<_>>());
                    }
                    if scopes.profiles && review["vpnBindingCount"].as_u64().unwrap_or(0) > 0 {
                        match scopes.vpn_bindings {
                            VpnBindings::AutoLive | VpnBindings::Automatic => {
                                review["vpnBindingsPlanned"] = review["vpnBindingCount"].clone();
                                review["issues"].as_array_mut().unwrap().retain(|issue| {
                                    issue["code"] != "legacy_otp_bindings_deferred"
                                });
                                issue(
                                    &mut review,
                                    if prepared
                                        .plan
                                        .iter()
                                        .flat_map(|plan| plan.vpn_bindings.keys())
                                        .any(|id| {
                                            library.vpn_otp_bindings.get(id).is_some_and(
                                                |binding| {
                                                    binding.mode
                                                        == crate::vpn_otp_bindings::Mode::AutoStart
                                                },
                                            )
                                        })
                                    {
                                        "legacy_vpn_bindings_auto_start"
                                    } else {
                                        "legacy_vpn_bindings_auto_live"
                                    },
                                );
                            }
                            VpnBindings::Manual => issue(&mut review, "legacy_vpn_bindings_manual"),
                            VpnBindings::RequireChoice => unreachable!("choice gates usable"),
                        }
                    }
                    review["canApply"] = json!(true);
                    library
                }
                Err(code) => {
                    issue(&mut review, &code);
                    self.store.library.clone()
                }
            }
        } else {
            self.store.library.clone()
        };
        let preview = Preview {
            token: uuid::Uuid::new_v4().to_string(),
            created_at: 0,
            incoming: summary(&library),
            current: summary(&self.store.library),
            legacy: Some(review),
        };
        self.restore = Some(Pending {
            preview: preview.clone(),
            library,
            original: json!(self.store.library),
            created: Instant::now(),
            legacy: Some(prepared),
        });
        Ok(preview)
    }

    pub fn legacy_backup_scopes(&mut self, token: &str, scopes: Scopes) -> Result<Preview, String> {
        let mut prepared = self
            .restore
            .as_ref()
            .filter(|p| p.preview.token == token)
            .and_then(|p| p.legacy.clone())
            .ok_or("backup_preview_expired")?;
        prepared.scopes = scopes;
        // Changing a scope is a fresh review: rebuild against the current library,
        // retain converted UUIDs, invalidate the former token and acknowledgement.
        self.preview_legacy_import(prepared)
    }
}
