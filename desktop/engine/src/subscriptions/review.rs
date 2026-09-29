//! Previewing, checking and applying a downloaded subscription.
use super::*;

impl Engine {
    pub fn subscription_downloaded(
        &mut self,
        request: Request,
        result: Download,
    ) -> Result<Value, String> {
        if request.stamp != self.subscription_stamp(&request.group_id)? {
            return Err("subscription_changed".into());
        }
        self.subscription_tickets
            .retain(|_, t| !t.expired() && t.group_id != request.group_id);
        if self.subscription_tickets.len() >= 8 {
            return Err("subscription_download_busy".into());
        }
        let token = uuid::Uuid::new_v4().to_string();
        // Happ `onadd` activates the policy when it first arrives; a later
        // explicit choice of the user is kept.
        let first_policy = self
            .store
            .library
            .groups
            .iter()
            .find(|g| g.id == request.group_id)
            .and_then(|g| g.subscription.as_ref())
            .is_some_and(|s| s.metadata.routing.is_none());
        let response = json!({"ticket":token, "body":result.body, "usage":result.usage,
            "providerRouting":result.metadata.routing.as_ref().map(|r| { let mut s = r.summary(); s["enabled"] = json!(request.settings.use_provider_routing || first_policy && r.action == "onadd"); s })});
        self.subscription_tickets.insert(
            token,
            Ticket {
                metadata: result.metadata,
                group_id: request.group_id,
                stamp: request.stamp,
                usage: result.usage,
                used: Instant::now(),
                plan: None,
                omitted: jobs::Omitted::default(),
                review: None,
            },
        );
        Ok(response)
    }
    pub fn preview_subscription(
        &mut self,
        token: &str,
        drafts: Vec<ProfileDraft>,
    ) -> Result<Vec<Change>, String> {
        if let Some(ticket) = self.subscription_tickets.get_mut(token) {
            ticket.plan = None;
        }
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.expired() {
            return Err("subscription_expired".into());
        }
        if ticket.stamp != self.subscription_stamp(&ticket.group_id)? {
            return Err("subscription_changed".into());
        }
        let plan = reconcile(self, &self.group(&ticket.group_id)?, drafts)?;
        let changes = plan.changes.clone();
        self.subscription_tickets.get_mut(token).unwrap().plan = Some(plan);
        Ok(changes)
    }
    pub fn subscription_check_index(&self, token: &str, id: &str) -> Result<usize, String> {
        self.subscription_tickets
            .get(token)
            .and_then(|t| t.plan.as_ref())
            .and_then(|p| p.profiles.iter().position(|p| p.id == id))
            .ok_or_else(|| "subscription_preview_required".into())
    }
    pub async fn check_subscription_profile(
        &mut self,
        token: &str,
        index: usize,
        use_routing: bool,
    ) -> Result<(), String> {
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.stamp != self.subscription_stamp(&ticket.group_id)? {
            return Err("subscription_changed".into());
        }
        let profile = ticket
            .plan
            .as_ref()
            .and_then(|p| p.profiles.get(index))
            .cloned()
            .ok_or("subscription_preview_required")?;
        let mut library = self.store.library.clone();
        let group = library
            .groups
            .iter_mut()
            .find(|g| g.id == ticket.group_id)
            .ok_or("group_not_found")?;
        let subscription = group.subscription.as_mut().ok_or("subscription_missing")?;
        subscription.metadata = ticket.metadata.clone();
        subscription.settings.use_provider_routing = use_routing;
        self.check_with_library(&profile, &library).await?;
        // Checking a large subscription one profile at a time keeps its review open.
        if let Some(ticket) = self.subscription_tickets.get_mut(token) {
            ticket.touch();
        }
        Ok(())
    }
    pub async fn prepare_subscription_apply(
        &mut self,
        token: &str,
        use_routing: Option<bool>,
    ) -> Result<(), String> {
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.stamp != self.subscription_stamp(&ticket.group_id)? {
            return Err("subscription_changed".into());
        }
        let mut library = self.store.library.clone();
        let group = library
            .groups
            .iter_mut()
            .find(|g| g.id == ticket.group_id)
            .ok_or("group_not_found")?;
        let subscription = group.subscription.as_mut().ok_or("subscription_missing")?;
        subscription.metadata = ticket.metadata.clone();
        if let Some(enabled) = use_routing {
            subscription.settings.use_provider_routing = enabled;
        }
        if !subscription.settings.use_provider_routing || subscription.metadata.routing.is_none() {
            return Ok(());
        }
        let plan = ticket
            .plan
            .as_ref()
            .ok_or("subscription_preview_required")?;
        // Prepare every needed asset and compile policy before publishing the new
        // metadata. The running request and immutable old assets remain available.
        for profile in &plan.profiles {
            crate::geodata::prepare_for(
                &self.geodata,
                profile,
                &library,
                &self.data_dir,
                self.settings_download_proxy()?.as_deref(),
            )
            .await?;
            Self::build_with_library(profile, &library, &self.data_dir)?;
        }
        Ok(())
    }
    pub fn discard_subscription(&mut self, token: &str) {
        self.subscription_tickets.remove(token);
    }
    pub fn apply_subscription(&mut self, token: &str) -> Result<Vec<Change>, String> {
        self.apply_subscription_routing(token, None)
    }
    pub fn apply_subscription_routing(
        &mut self,
        token: &str,
        use_routing: Option<bool>,
    ) -> Result<Vec<Change>, String> {
        let ticket = self
            .subscription_tickets
            .remove(token)
            .ok_or("subscription_expired")?;
        if ticket.expired() {
            return Err("subscription_expired".into());
        }
        if ticket.stamp != self.subscription_stamp(&ticket.group_id)? {
            return Err("subscription_changed".into());
        }
        let plan = ticket.plan.ok_or("subscription_preview_required")?;
        if plan.changes.iter().any(|c| {
            matches!(c.action.as_str(), "updated" | "removed")
                && self.subscription_change_restarts(&c.id)
        }) {
            return Err("stop_before_editing".into());
        }
        let deferred: HashSet<_> = plan
            .changes
            .iter()
            .filter(|c| self.selector_member_subscription_allowed(&c.id))
            .map(|c| c.id.clone())
            .collect();
        let mut next = self.store.library.clone();
        let at = next
            .profiles
            .iter()
            .position(|p| p.group_id == ticket.group_id)
            .unwrap_or(next.profiles.len());
        // A remote update cannot redirect a local OTP binding by retaining UUID.
        let previous_profiles: HashMap<_, _> = next
            .profiles
            .iter()
            .filter(|p| p.group_id == ticket.group_id)
            .map(|p| (p.id.clone(), (p.kind, p.config.clone())))
            .collect();
        next.profiles.retain(|p| p.group_id != ticket.group_id);
        next.profiles.splice(
            at.min(next.profiles.len())..at.min(next.profiles.len()),
            plan.profiles,
        );
        crate::vpn_otp_bindings::remove_deleted(&mut next);
        next.vpn_otp_bindings.retain(|id, _| {
            previous_profiles.get(id).is_none_or(|(kind, config)| {
                next.profiles
                    .iter()
                    .any(|p| p.id == *id && p.kind == *kind && p.config == *config)
            })
        });
        let subscription = next
            .groups
            .iter_mut()
            .find(|g| g.id == ticket.group_id)
            .unwrap()
            .subscription
            .as_mut()
            .ok_or("subscription_missing")?;
        subscription.managed_ids = plan.managed_ids;
        subscription.usage = ticket.usage;
        let routing_changed = subscription.metadata.routing != ticket.metadata.routing
            || use_routing
                .is_some_and(|enabled| enabled != subscription.settings.use_provider_routing);
        if let Some(enabled) = use_routing {
            subscription.settings.use_provider_routing = enabled;
        }
        subscription.metadata = ticket.metadata;
        subscription.updated_at = Some(now());
        subscription.last_update =
            Some(jobs::LastUpdate::of(&plan.changes, ticket.omitted).reviewed(ticket.review));
        if next.selected.is_none() || next.selection_dangling() {
            next.selected = next
                .profiles
                .iter()
                .find(|p| p.group_id == ticket.group_id)
                .or(next.profiles.first())
                .map(|p| p.id.clone());
        }
        let committed = self.store.commit(next);
        self.note_selector_subscription_commit(&ticket.group_id);
        committed?;
        if routing_changed
            && self
                .running
                .as_ref()
                .and_then(|id| self.profile(id).ok())
                .is_some_and(|p| p.group_id == ticket.group_id)
        {
            self.routing_revision = None;
        }
        if plan
            .changes
            .iter()
            .any(|c| c.action == "updated" && self.routing_uses(&c.id) && !deferred.contains(&c.id))
        {
            self.routing_revision = None;
        }
        Ok(plan.changes)
    }
}
