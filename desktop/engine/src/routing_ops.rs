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

    /// The routing a subscription offers, as the read-only profile the Routing
    /// page lists. It is built from the subscription on every request, so it
    /// follows each update; `error` is what a connection would report.
    pub fn subscription_routing(&self, group_id: &str) -> Result<Value, String> {
        let group = self
            .store
            .library
            .groups
            .iter()
            .find(|g| g.id == group_id)
            .ok_or("group_not_found")?;
        let provider = group
            .subscription
            .as_ref()
            .ok_or("subscription_missing")?
            .metadata
            .routing
            .as_ref()
            .filter(|r| r.action != "off")
            .ok_or("subscription_routing_missing")?;
        let assets =
            geodata::Assets::new(&self.data_dir, Some(provider)).with_library(&self.store.library);
        let name = provider.config["Name"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&group.name);
        let id = format!("subscription:{group_id}");
        let (profile, error) =
            match subscriptions::provider_policy::profile(&id, name, provider, &assets) {
                Ok(profile) => (json!(profile), Value::Null),
                Err(error) => (
                    Value::Null,
                    json!(ipc::registered(&error).unwrap_or("subscription_routing_invalid")),
                ),
            };
        // Hosts records also pin the servers they name; a copy cannot say that.
        let pinned = provider.config["DnsHosts"]
            .as_object()
            .is_some_and(|hosts| !hosts.is_empty());
        Ok(json!({"groupId":group_id,"profile":profile,"error":error,"pinnedResolvers":pinned}))
    }

    /// Gives routing back to the subscription: the untouched Default profile
    /// becomes the active one. Changes made to Default are kept as a profile
    /// named `kept_name`, never discarded.
    pub fn use_subscription_routing(
        &mut self,
        revision: u64,
        kept_name: &str,
    ) -> Result<routing::Routing, String> {
        let mut next = self.store.library.routing.clone();
        if revision != next.revision {
            return Err("routing_changed".into());
        }
        let baseline = routing::RoutingProfile::default();
        match next.profiles.iter().position(|p| p.id == baseline.id) {
            Some(i) if !next.profiles[i].baseline() => {
                let mut kept = std::mem::replace(&mut next.profiles[i], baseline.clone());
                kept.id = uuid::Uuid::new_v4().to_string();
                kept.name = kept_name.trim().into();
                next.profiles.push(kept);
            }
            Some(_) => {}
            None => next.profiles.insert(0, baseline.clone()),
        }
        next.active = baseline.id;
        self.save_routing(next)
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
