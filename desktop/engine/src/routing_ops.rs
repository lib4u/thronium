//! The routing section: reading, saving, checking and applying it.
use super::*;

impl Engine {
    pub fn routing(&self) -> routing::Routing {
        self.store.library.routing.clone()
    }

    pub fn save_routing(&mut self, mut next: routing::Routing) -> Result<routing::Routing, String> {
        routing::source::retain_dns_edit(&self.store.library.routing, &mut next)?;
        next.validate()?;
        if next.revision != self.store.library.routing.revision {
            return Err("routing_changed".into());
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or("routing_revision_overflow")?;
        let mut library = self.store.library.clone();
        library.routing = next.clone();
        self.store.commit(library)?;
        Ok(next)
    }

    pub async fn check_routing(
        &mut self,
        mut candidate: routing::RoutingProfile,
    ) -> Result<(), String> {
        // Validate stored rules even when their mode/switch currently excludes them.
        candidate.mode = "rules".into();
        for rule in &mut candidate.rules {
            rule.enabled = true;
        }
        let r = routing::Routing {
            active: candidate.id.clone(),
            profiles: vec![candidate.clone()],
            revision: 0,
        };
        r.validate()?;
        // A direct placeholder validates routing even before the library has a selected profile.
        let profile = Profile {
            vpn_policy: None,
            id: String::new(),
            name: "Routing validation".into(),
            group_id: String::new(),
            kind: ProfileKind::SingBoxOutbound,
            favorite: false,
            config: json!({"type":"direct"}),
        };
        let mut library = self.store.library.clone();
        library.routing = r;
        self.check_with_library(&profile, &library).await
    }

    pub async fn apply_routing(&mut self) -> Result<(), String> {
        self.apply_routing_measured(None).await
    }

    pub async fn apply_routing_measured(
        &mut self,
        plan: Option<&auto_selector::ConnectionMeasurements>,
    ) -> Result<(), String> {
        let id = self.running.clone().ok_or("not_connected")?;
        let result = if let Some(plan) = plan {
            if plan.id != id {
                return Err("selector_measurements_stale".into());
            }
            self.connect_measured(plan).await
        } else {
            self.connect(&id).await
        };
        if result.is_err() && self.running.is_some() {
            // A failed Start can restore the old request. Network settings do
            // not change Routing.revision, so that restored revision alone
            // cannot prove the saved settings were applied.
            self.routing_revision = None;
        }
        result
    }
}
