//! Creating, editing, ordering and deleting groups.
use super::*;

impl Engine {
    pub fn group(&self, id: &str) -> Result<Group, String> {
        self.store
            .library
            .groups
            .iter()
            .find(|g| g.id == id)
            .cloned()
            .ok_or("group_not_found".into())
    }
    pub fn save_group(&mut self, draft: GroupDraft) -> Result<String, String> {
        if !crate::store::valid_name(&draft.name)
            || draft.id.as_deref() == Some(crate::store::PERSONAL_GROUP)
        {
            return Err("invalid_group".into());
        }
        if let Some(settings) = &draft.subscription {
            settings.validate()?;
        }
        let id = draft
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let old = if draft.id.is_some() {
            Some(self.group(&id)?)
        } else {
            None
        };
        let proxy_chain = draft.proxy_chain.unwrap_or_else(|| {
            old.as_ref()
                .map(|g| g.proxy_chain.clone())
                .unwrap_or_default()
        });
        if old.as_ref().is_some_and(|g| g.proxy_chain != proxy_chain)
            && self.running_group_uses(&id)
        {
            return Err("stop_before_editing".into());
        }
        let subscription = draft.subscription.map(|mut settings| {
            if old.is_none() && settings.inherit_defaults.is_none() {
                settings.inherit_defaults = Some(true);
            }
            crate::settings::network::subscription_defaults(&mut settings, &self.store.library);
            let old = old.as_ref().and_then(|g| g.subscription.clone());
            let same_source = old.as_ref().is_some_and(|s| s.settings.url == settings.url);
            Subscription {
                metadata: old
                    .as_ref()
                    .filter(|_| same_source)
                    .map(|s| s.metadata.clone())
                    .unwrap_or_default(),
                settings,
                updated_at: old
                    .as_ref()
                    .filter(|_| same_source)
                    .and_then(|s| s.updated_at),
                usage: old
                    .as_ref()
                    .filter(|_| same_source)
                    .and_then(|s| s.usage.clone()),
                last_update: old
                    .as_ref()
                    .filter(|_| same_source)
                    .and_then(|s| s.last_update.clone()),
                managed_ids: old.map(|s| s.managed_ids).unwrap_or_default(),
            }
        });
        let group = Group {
            proxy_chain,
            collapsed: old.as_ref().is_some_and(|g| g.collapsed),
            auto_clear_unavailable: draft
                .auto_clear_unavailable
                .unwrap_or_else(|| old.as_ref().is_some_and(|g| g.auto_clear_unavailable)),
            id: id.clone(),
            name: draft.name.trim().into(),
            subscription,
        };
        let mut next = self.store.library.clone();
        if let Some(existing) = next.groups.iter_mut().find(|g| g.id == id) {
            *existing = group;
        } else {
            next.groups.push(group);
        }
        self.store.commit(next)?;
        Ok(id)
    }
    pub fn move_group(&mut self, id: &str, offset: i32) -> Result<(), String> {
        let mut next = self.store.library.clone();
        let i = next
            .groups
            .iter()
            .position(|g| g.id == id)
            .ok_or("group_not_found")?;
        let target = i as i64 + offset as i64;
        if !matches!(offset, -1 | 1) || target < 0 || target >= next.groups.len() as i64 {
            return Err("invalid_group_order".into());
        }
        next.groups.swap(i, target as usize);
        self.store.commit(next)
    }
    pub fn reorder_group(&mut self, id: &str, target_id: &str, after: bool) -> Result<(), String> {
        let mut next = self.store.library.clone();
        let source = next
            .groups
            .iter()
            .position(|g| g.id == id)
            .ok_or("group_not_found")?;
        let target = next
            .groups
            .iter()
            .position(|g| g.id == target_id)
            .ok_or("group_not_found")?;
        if source == target {
            return Ok(());
        }
        // Resolve the destination in the current library, including groups hidden
        // by UI filters. Commit once, without overwriting subscription metadata.
        let destination = target + usize::from(after) - usize::from(source < target);
        if destination == source {
            return Ok(());
        }
        let moved = next.groups.remove(source);
        next.groups.insert(destination, moved);
        self.store.commit(next)
    }
    pub fn collapse_group(&mut self, id: &str, collapsed: bool) -> Result<(), String> {
        let mut next = self.store.library.clone();
        let group = next
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or("group_not_found")?;
        group.collapsed = collapsed;
        self.store.commit(next)
    }
    pub fn delete_group(&mut self, id: &str, delete_profiles: bool) -> Result<(), String> {
        self.group(id)?;
        if self.store.library.profiles.iter().any(|p| {
            crate::auto_selector::source_group(p) == Some(id)
                && !(delete_profiles && p.group_id == id)
        }) {
            return Err("selector_source_in_use".into());
        }
        if id == crate::store::PERSONAL_GROUP
            || !self
                .store
                .library
                .groups
                .iter()
                .any(|g| g.id == crate::store::PERSONAL_GROUP)
        {
            return Err("protected_group".into());
        }
        if self.running_group_uses(id) {
            return Err("stop_before_editing".into());
        }
        let mut next = self.store.library.clone();
        if delete_profiles {
            let ids = next
                .profiles
                .iter()
                .filter(|p| p.group_id == id)
                .map(|p| p.id.clone())
                .collect();
            if crate::group_chains::referenced(&next, &ids, Some(id)) {
                return Err("profile_used_in_group_chain".into());
            }
            if crate::references::referenced_outside(&next.profiles, &ids) {
                return Err("profile_used_in_chain".into());
            }
            for p in next.profiles.iter().filter(|p| p.group_id == id) {
                if self.running_uses(&p.id) {
                    return Err("stop_before_editing".into());
                }
                if routing::uses_profile(&next.routing, &p.id) {
                    return Err("profile_used_in_routing".into());
                }
            }
            next.profiles.retain(|p| p.group_id != id);
            crate::vpn_otp_bindings::remove_deleted(&mut next);
        } else {
            for p in &mut next.profiles {
                if p.group_id == id {
                    p.group_id = crate::store::PERSONAL_GROUP.into();
                }
            }
        }
        next.groups.retain(|g| g.id != id);
        let reset_auto_select_source =
            next.preferences.auto_select.source_group_id.as_deref() == Some(id);
        if reset_auto_select_source {
            next.preferences.auto_select.source_group_id = None;
        }
        if next.selection_dangling() {
            next.selected = next.profiles.first().map(|p| p.id.clone());
        }
        self.store.commit(next)?;
        if reset_auto_select_source {
            self.logs.event("info", "auto_select_source_deleted", None);
        }
        Ok(())
    }
}
