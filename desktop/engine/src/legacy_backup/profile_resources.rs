//! Files a converted custom profile still names by its Qt path. Discovery
//! reads the converted plan only; a saved path is never opened. Selected copies
//! replace paths in a derived plan, so the pristine plan can be re-substituted
//! after every choice and unreplaced paths keep the profiles section blocked.
use super::{
    profiles::ProfilePlan,
    resources::{eligible_path, key, Requirement},
};
use crate::routing::resources::{
    profiles::{carries, visit_profile},
    Pack, Resource,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const ENTITY: &str = "profile";

pub(super) fn discover(plan: &ProfilePlan, required: &mut BTreeMap<String, Requirement>) {
    for profile in plan.profiles.iter().filter(|p| carries(p)) {
        let _ = visit_profile(&mut profile.config.clone(), |path, kind| {
            if let Some(path) = path.as_str().filter(|s| eligible_path(s)) {
                let id = key(ENTITY, path, kind);
                required.entry(id.clone()).or_insert_with(|| Requirement {
                    id,
                    path: path.into(),
                    kind,
                    entity: ENTITY.into(),
                    name: Some(
                        profile
                            .name
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(256)
                            .collect(),
                    ),
                    selected: false,
                    bytes: 0,
                });
            }
            Ok(())
        });
    }
}

/// The plan with every selected path replaced by a portable reference; the
/// pack holds exactly the copies those references name.
pub(super) fn substitute(plan: &ProfilePlan, selected: &BTreeMap<String, Resource>) -> ProfilePlan {
    let mut plan = plan.clone();
    let mut pack = Pack::default();
    for profile in plan.profiles.iter_mut().filter(|p| carries(p)) {
        let _ = visit_profile(&mut profile.config, |path, kind| {
            let resource = path
                .as_str()
                .and_then(|name| selected.get(&key(ENTITY, name, kind)));
            if let Some(resource) = resource {
                // select() already checked the complete pack's byte/count limits.
                if let Ok(reference) = pack.insert(resource.clone()) {
                    *path = Value::String(reference);
                }
            }
            Ok(())
        });
    }
    plan.resources = pack;
    plan
}

/// Whether any custom profile of the plan still names a file by its old path.
pub(crate) fn unresolved(plan: &ProfilePlan) -> bool {
    let mut found = false;
    for profile in plan.profiles.iter().filter(|p| carries(p)) {
        let _ = visit_profile(&mut profile.config.clone(), |path, _| {
            found |= path.as_str().is_some_and(eligible_path);
            Ok(())
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        legacy_backup::{autoselector::Choice, profiles::convert_selected_with_selectors},
        routing::resources::Kind,
    };
    use serde_json::json;
    use sha2::Digest;

    fn golden(name: &str) -> Result<ProfilePlan, Vec<crate::legacy_backup::profiles::Issue>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "src/legacy_backup/profile_resources/fixtures/{name}.thrbackup"
        ));
        let bytes = std::fs::read(path).unwrap();
        let manifest: Value =
            serde_json::from_str(include_str!("profile_resources/fixtures/manifest.json")).unwrap();
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&bytes)),
            manifest["archives"][name]["sha256"].as_str().unwrap()
        );
        let source = crate::legacy_backup::parse(&bytes).unwrap();
        assert!(source.parts.profiles);
        convert_selected_with_selectors(source.database.as_ref().unwrap(), true, Choice::LastBuilt)
    }

    #[test]
    fn actual_qt_custom_profiles_list_every_input_file_once_and_substitute_selected_copies() {
        let manifest: Value =
            serde_json::from_str(include_str!("profile_resources/fixtures/manifest.json")).unwrap();
        let plan = golden("profiles-resources").unwrap_or_else(|e| panic!("{}", json!(e)));
        assert!(plan
            .report
            .iter()
            .any(|i| i.code == "legacy_profile_initial_path_omitted"));
        let mut required = BTreeMap::new();
        discover(&plan, &mut required);
        let mut found: Vec<(String, String)> = required
            .values()
            .map(|r| (r.path.clone(), json!(r.kind).as_str().unwrap().to_owned()))
            .collect();
        found.sort();
        let mut expected: Vec<(String, String)> = manifest["paths"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, kind)| (path.clone(), kind.as_str().unwrap().to_owned()))
            .collect();
        expected.sort();
        assert_eq!(found, expected);
        assert!(required
            .values()
            .all(|r| r.entity == ENTITY && r.name.is_some()));
        assert!(unresolved(&plan));
        let pem =
            b"-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n".to_vec();
        let selected: BTreeMap<String, Resource> = required
            .values()
            .map(|r| {
                let bytes = match r.kind {
                    Kind::Hosts => b"127.0.0.1 resource.fixture.invalid\n".to_vec(),
                    Kind::RuleSetBinary => {
                        include_bytes!("../../../tests/fixtures/tray-controls/loopback.srs")
                            .to_vec()
                    }
                    Kind::Text => b"fixture.invalid ssh-ed25519 AAAA\n".to_vec(),
                    _ => pem.clone(),
                };
                (r.id.clone(), Resource::parse(r.kind, bytes).unwrap())
            })
            .collect();
        let substituted = substitute(&plan, &selected);
        assert!(!unresolved(&substituted));
        assert!(unresolved(&plan), "the pristine plan keeps its paths");
        assert_eq!(
            substituted.resources.kinds().count(),
            3,
            "one copy per distinct file: the certificate and key share bytes here"
        );
        let text = json!(substituted.profiles).to_string();
        assert!(!text.contains("/old/Throne"));
        assert!(!text.contains("initial_path"));
        // The profile that names a list of its own is imported and the list is
        // asked for, like any other file the review carries.
        let partial = golden("profiles-resources-blocked").unwrap();
        assert!(partial.profile_ids.contains_key(&3));
        assert!(partial
            .report
            .iter()
            .all(|i| i.code != "legacy_profile_resource_unsupported"));
        let mut required = BTreeMap::new();
        discover(&partial, &mut required);
        let assets: Vec<_> = required
            .values()
            .filter(|r| r.kind == crate::routing::resources::Kind::Geodata)
            .map(|r| r.path.as_str())
            .collect();
        assert_eq!(assets, ["private.dat"]);
        assert!(unresolved(&partial));
    }
}
