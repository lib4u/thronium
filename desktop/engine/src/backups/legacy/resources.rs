//! Selection work is prepared outside Engine's lock, then attached only to the
//! same unexpired review. No file selection or decode can commit a library.
use super::Prepared;
use crate::{
    backups::Preview,
    routing::resources::{Kind, Resource},
    Engine,
};

pub struct Selection {
    token: String,
    id: String,
    prepared: Prepared,
}
impl Selection {
    pub fn kind(&self) -> Result<Kind, String> {
        self.prepared.resources.kind(&self.id)
    }
    pub fn prepare(mut self, resource: Resource) -> Result<Self, String> {
        self.prepared.resources.select(&self.id, resource)?;
        let plan = self
            .prepared
            .plan
            .as_ref()
            .map(|plan| self.prepared.resources.substitute(plan));
        if let Some(result) = self.prepared.resources.convert(plan.as_ref()) {
            match result {
                Ok(mut routes) => {
                    if let Some(old) = &self.prepared.routes {
                        for (source, id) in &mut routes.route_ids {
                            if let Some(old_id) = old.route_ids.get(source) {
                                for route in &mut routes.presets {
                                    if route.id == *id {
                                        route.id = old_id.clone();
                                        if let Some(previous) =
                                            old.presets.iter().find(|r| r.id == *old_id)
                                        {
                                            for (rule, old_rule) in
                                                route.rules.iter_mut().zip(&previous.rules)
                                            {
                                                rule.id = old_rule.id.clone();
                                            }
                                        }
                                    }
                                }
                                if routes.selected.as_ref() == Some(id) {
                                    routes.selected = Some(old_id.clone());
                                }
                                *id = old_id.clone();
                            }
                        }
                    }
                    self.prepared.route_issues = routes.report.clone();
                    self.prepared.routes = Some(routes);
                }
                Err(issues) => {
                    self.prepared.routes = None;
                    self.prepared.route_issues = issues;
                }
            }
        }
        Ok(self)
    }
}
impl Engine {
    pub fn legacy_resource_selection(&self, token: &str, id: &str) -> Result<Selection, String> {
        let prepared = self
            .restore
            .as_ref()
            .filter(|p| {
                p.preview.token == token
                    && p.created.elapsed() <= std::time::Duration::from_secs(15 * 60)
            })
            .and_then(|p| p.legacy.clone())
            .ok_or("backup_preview_expired")?;
        prepared.resources.kind(id)?;
        Ok(Selection {
            token: token.into(),
            id: id.into(),
            prepared,
        })
    }
    pub fn finish_legacy_resource(&mut self, selection: Selection) -> Result<Preview, String> {
        if !self.restore.as_ref().is_some_and(|p| {
            p.preview.token == selection.token
                && p.created.elapsed() <= std::time::Duration::from_secs(15 * 60)
        }) {
            return Err("backup_preview_expired".into());
        }
        self.preview_legacy_import(selection.prepared)
    }
}
