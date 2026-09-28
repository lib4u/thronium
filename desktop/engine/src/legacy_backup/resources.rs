//! Local resources are absent from Qt backups. Discover only known active
//! route/DNS fields and custom profile inputs; a saved path is never used to
//! read the user's filesystem.
use super::{profile_resources, profiles::ProfilePlan, SourceArchive, SourceDatabase, SourceValue};
use crate::routing::resources::{Kind, Pack, Resource};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Requirement {
    pub id: String,
    pub path: String,
    pub kind: Kind,
    /// `route` for preset/DNS documents, `profile` for custom profile inputs.
    pub entity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub selected: bool,
    pub bytes: usize,
}
#[derive(Clone, Default)]
pub struct Plan {
    source: Option<Arc<SourceArchive>>,
    required: BTreeMap<String, Requirement>,
    selected: BTreeMap<String, Resource>,
}
const ROUTE: &str = "route";
pub(super) fn key(entity: &str, path: &str, kind: Kind) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{entity}\0{kind:?}\0{path}"))
    )
}
pub(super) fn eligible_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.chars().any(char::is_control)
        && !path.starts_with("thronium-resource:")
}
fn documents(source: &mut SourceArchive, mut visit: impl FnMut(&mut Value, bool)) {
    let Some(db) = &mut source.database else {
        return;
    };
    if super::routes::setting(db, "use_dns_object", "false").is_ok_and(|s| s == "true" || s == "1")
    {
        for setting in &mut db.settings {
            if setting.key == "dns_object" {
                if let Ok(mut value) = super::json::parse(&setting.value) {
                    visit(&mut value, true);
                    setting.value = value.to_string();
                }
            }
        }
    }
    for route in &mut db.routes {
        if route.columns.get("is_raw") != Some(&SourceValue::Integer(1)) {
            continue;
        }
        if let Some(SourceValue::Text(text)) = route.columns.get_mut("raw_route") {
            if let Ok(mut value) = super::json::parse(text) {
                visit(&mut value, false);
                *text = value.to_string();
            }
        }
    }
}
fn paths(value: &mut Value, dns: bool, mut visit: impl FnMut(&mut Value, Kind)) {
    // Invalid documents keep their existing converter issue; discovery itself
    // never makes malformed source data eligible for import.
    let _ = crate::routing::resources::visit_document(value, dns, |value, kind| {
        visit(value, kind);
        Ok(())
    });
}
fn snapshot(source: &SourceArchive) -> SourceArchive {
    SourceArchive {
        container_version: source.container_version,
        content_version: source.content_version,
        metadata: Value::Null,
        created_at: None,
        parts: source.parts,
        files: BTreeMap::new(),
        database: source.database.as_ref().map(|db| SourceDatabase {
            routes: db.routes.clone(),
            rules: db.rules.clone(),
            settings: db.settings.clone(),
            ..Default::default()
        }),
    }
}
impl Plan {
    pub fn over_limit(&self) -> bool {
        self.required.len() > 64
    }
    pub fn discover(source: &SourceArchive, profiles: Option<&ProfilePlan>) -> Self {
        let mut required = BTreeMap::new();
        if let Some(plan) = profiles.filter(|_| source.parts.profiles) {
            profile_resources::discover(plan, &mut required);
        }
        let mut routes = None;
        if source.parts.routes && source.parts.settings {
            let mut source = snapshot(source);
            let before = required.len();
            documents(&mut source, |value, dns| {
                paths(value, dns, |path, kind| {
                    if let Some(path) = path.as_str().filter(|s| eligible_path(s)) {
                        let id = key(ROUTE, path, kind);
                        required.insert(
                            id.clone(),
                            Requirement {
                                id,
                                path: path.into(),
                                kind,
                                entity: ROUTE.into(),
                                name: None,
                                selected: false,
                                bytes: 0,
                            },
                        );
                    }
                })
            });
            if required.len() > before {
                routes = Some(Arc::new(source));
            }
        }
        Self {
            source: routes,
            required,
            selected: BTreeMap::new(),
        }
    }
    pub fn requirements(&self) -> Vec<Requirement> {
        self.required
            .values()
            .take(64)
            .map(|item| {
                let mut item = item.clone();
                if let Some(value) = self.selected.get(&item.id) {
                    item.selected = true;
                    item.bytes = value.len();
                }
                item
            })
            .collect()
    }
    /// Profile inputs the review still has to receive before profiles can apply.
    pub fn profiles_pending(&self) -> bool {
        self.required
            .values()
            .any(|r| r.entity == profile_resources::ENTITY && !self.selected.contains_key(&r.id))
    }
    pub fn kind(&self, id: &str) -> Result<Kind, String> {
        if self.required.len() > 64 {
            return Err("routing_resource_too_large".into());
        }
        self.required
            .get(id)
            .map(|r| r.kind)
            .ok_or_else(|| "routing_resource_missing".into())
    }
    pub fn select(&mut self, id: &str, resource: Resource) -> Result<(), String> {
        if self.kind(id)? != resource.kind() {
            return Err("routing_resource_invalid".into());
        }
        // Check the aggregate budget before changing the prepared choice.
        let mut proposed = self.selected.clone();
        proposed.insert(id.into(), resource);
        let mut pack = Pack::default();
        for value in proposed.values() {
            pack.insert(value.clone())?;
        }
        self.selected = proposed;
        Ok(())
    }
    /// The pristine profile plan with every selected profile input replaced.
    pub fn substitute(&self, plan: &ProfilePlan) -> ProfilePlan {
        profile_resources::substitute(plan, &self.selected)
    }
    pub fn convert(
        &self,
        profiles: Option<&ProfilePlan>,
    ) -> Option<Result<super::routes::RoutePlan, Vec<super::profiles::Issue>>> {
        let mut source = snapshot(self.source.as_ref()?);
        let mut pack = Pack::default();
        documents(&mut source, |value, dns| {
            paths(value, dns, |path, kind| {
                let Some(name) = path.as_str() else { return };
                if let Some(value) = self.selected.get(&key(ROUTE, name, kind)) {
                    // select() already checked the complete pack's byte/count limits.
                    if let Ok(reference) = pack.insert(value.clone()) {
                        *path = Value::String(reference);
                    }
                }
            })
        });
        Some(super::routes::convert(&source, profiles).map(|mut plan| {
            plan.resources = pack;
            plan
        }))
    }
}
