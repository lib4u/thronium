//! Library operations validate the entire selection before one atomic store commit.
use crate::{routing, Engine};
use std::collections::HashSet;

impl Engine {
    /// Reorder only the current group slots. IDs, rather than view indices or
    /// captured Profile values, preserve concurrent edits and hidden groups.
    pub fn reorder_profile(
        &mut self,
        id: &str,
        target_id: &str,
        after: bool,
    ) -> Result<(), String> {
        let profiles = &self.store.library.profiles;
        let source = profiles
            .iter()
            .position(|p| p.id == id)
            .ok_or("profile_not_found")?;
        let target = profiles
            .iter()
            .position(|p| p.id == target_id)
            .ok_or("profile_not_found")?;
        if profiles[source].group_id != profiles[target].group_id {
            return Err("invalid_profile_order".into());
        }
        if source == target {
            return Ok(());
        }
        let slots: Vec<_> = profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| p.group_id == profiles[source].group_id)
            .map(|(index, _)| index)
            .collect();
        let source = slots.iter().position(|&index| index == source).unwrap();
        let target = slots.iter().position(|&index| index == target).unwrap();
        let destination = target + usize::from(after) - usize::from(source < target);
        if destination == source {
            return Ok(());
        }
        let mut next = self.store.library.clone();
        if source < destination {
            for position in source..destination {
                next.profiles.swap(slots[position], slots[position + 1]);
            }
        } else {
            for position in (destination..source).rev() {
                next.profiles.swap(slots[position], slots[position + 1]);
            }
        }
        self.store.commit(next)
    }

    pub(crate) fn selected_profiles(&self, ids: Vec<String>) -> Result<HashSet<String>, String> {
        if ids.is_empty() || ids.len() > 1000 {
            return Err("invalid_profile_selection".into());
        }
        let ids: HashSet<_> = ids.into_iter().collect();
        if ids
            .iter()
            .any(|id| !self.store.library.profiles.iter().any(|p| &p.id == id))
        {
            return Err("profile_not_found".into());
        }
        Ok(ids)
    }
    pub fn delete_profiles(&mut self, ids: Vec<String>) -> Result<usize, String> {
        let ids = self.selected_profiles(ids)?;
        if crate::group_chains::referenced(&self.store.library, &ids, None) {
            return Err("profile_used_in_group_chain".into());
        }
        if crate::references::referenced_outside(&self.store.library.profiles, &ids) {
            return Err("profile_used_in_chain".into());
        }
        if ids
            .iter()
            .any(|id| routing::uses_profile(&self.store.library.routing, id))
        {
            return Err("profile_used_in_routing".into());
        }
        if ids.iter().any(|id| self.running_uses(id)) {
            return Err("stop_before_editing".into());
        }
        let mut next = self.store.library.clone();
        next.profiles.retain(|p| !ids.contains(&p.id));
        crate::vpn_otp_bindings::remove_deleted(&mut next);
        next.release_managed(|id| ids.iter().any(|deleted| deleted == id), None);
        if next.selected.as_ref().is_some_and(|id| ids.contains(id)) {
            next.selected = next.profiles.first().map(|p| p.id.clone());
        }
        self.store.commit(next)?;
        Ok(ids.len())
    }
    pub fn move_profiles(&mut self, ids: Vec<String>, group_id: &str) -> Result<usize, String> {
        let ids = self.selected_profiles(ids)?;
        self.group(group_id)?;
        if ids.iter().any(|id| self.running_uses(id)) {
            return Err("stop_before_editing".into());
        }
        let mut next = self.store.library.clone();
        for p in &mut next.profiles {
            if ids.contains(&p.id) {
                p.group_id = group_id.into();
            }
        }
        next.release_managed(|id| ids.iter().any(|moved| moved == id), Some(group_id));
        self.store.commit(next)?;
        Ok(ids.len())
    }
}

#[cfg(test)]
mod order_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        store::ProfileKind,
        subscriptions::{GroupDraft, Settings},
        ProfileDraft,
    };
    use serde_json::json;
    fn setup() -> (tempfile::TempDir, Engine, Vec<String>, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), std::path::Path::new("missing")).unwrap();
        let group = e
            .save_group(GroupDraft {
                auto_clear_unavailable: None,
                proxy_chain: None,
                id: None,
                name: "Source".into(),
                subscription: Some(Settings {
                    name_rules: Default::default(),
                    inherit_defaults: Some(false),
                    allow_insecure: false,
                    timeout_seconds: 30,
                    url: "https://example.test/sub".into(),
                    headers: Default::default(),
                    user_agent: "test".into(),
                    via_proxy: false,
                    use_provider_routing: false,
                    interval_minutes: 0,
                }),
            })
            .unwrap();
        let ids = (0..3).map(|i| e.save_profile(ProfileDraft { vpn_policy: Default::default(), id: None, name: format!("Entry {i}"), group_id: group.clone(), kind: ProfileKind::SingBoxOutbound, config: json!({"type":"socks","server":"127.0.0.1","server_port":1080,"password":"secret","future":{"enabled":true}}) }).unwrap()).collect::<Vec<_>>();
        e.store
            .library
            .groups
            .iter_mut()
            .find(|g| g.id == group)
            .unwrap()
            .subscription
            .as_mut()
            .unwrap()
            .managed_ids = ids.clone();
        (dir, e, ids, group)
    }
    fn state(e: &Engine) -> serde_json::Value {
        serde_json::to_value(&e.store.library).unwrap()
    }
    #[test]
    fn move_preserves_configs_ids_favorites_selection_and_detaches_only_moved_members() {
        let (dir, mut e, ids, group) = setup();
        e.favorite(&ids[1]).unwrap();
        e.select(&ids[1]).unwrap();
        let old = e.profile(&ids[1]).unwrap();
        assert_eq!(
            e.move_profiles(
                vec![ids[0].clone(), ids[1].clone(), ids[1].clone()],
                "personal"
            )
            .unwrap(),
            2
        );
        assert_eq!(e.profile(&ids[1]).unwrap().config, old.config);
        assert!(e.profile(&ids[1]).unwrap().favorite);
        assert_eq!(e.store.library.selected.as_ref(), Some(&ids[1]));
        assert_eq!(
            e.group(&group).unwrap().subscription.unwrap().managed_ids,
            vec![ids[2].clone()]
        );
        let after = state(&e);
        drop(e);
        let reopened = Engine::open(dir.path(), std::path::Path::new("missing")).unwrap();
        assert_eq!(state(&reopened), after);
    }
    #[test]
    fn missing_or_connected_member_prevents_the_whole_operation() {
        let (_dir, mut e, ids, _) = setup();
        let original = state(&e);
        for selection in [
            vec![],
            vec![ids[0].clone(), "missing".into()],
            vec![ids[0].clone(); 1001],
        ] {
            assert!(e.move_profiles(selection.clone(), "personal").is_err());
            assert!(e.delete_profiles(selection).is_err());
            assert_eq!(state(&e), original);
        }
        assert!(e.move_profiles(ids.clone(), "missing-group").is_err());
        e.running = Some(ids[1].clone());
        assert_eq!(
            e.delete_profiles(ids.clone()).unwrap_err(),
            "stop_before_editing"
        );
        assert_eq!(
            e.move_profiles(ids, "personal").unwrap_err(),
            "stop_before_editing"
        );
        assert_eq!(state(&e), original);
    }
    #[test]
    fn deletion_is_deduplicated_and_updates_managed_ids_and_selection_together() {
        let (_dir, mut e, ids, group) = setup();
        assert_eq!(
            e.delete_profiles(vec![ids[0].clone(), ids[1].clone(), ids[0].clone()])
                .unwrap(),
            2
        );
        assert_eq!(e.store.library.profiles.len(), 1);
        assert_eq!(e.store.library.selected.as_ref(), Some(&ids[2]));
        assert_eq!(
            e.group(&group).unwrap().subscription.unwrap().managed_ids,
            vec![ids[2].clone()]
        );
        e.delete_profiles(vec![ids[2].clone()]).unwrap();
        assert!(e.store.library.selected.is_none());
    }
    #[test]
    fn routing_reference_blocks_the_entire_delete_but_allows_moving_with_same_ids() {
        let (_dir, mut e, ids, _) = setup();
        e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{}", ids[1]));
        let before = state(&e);
        assert_eq!(
            e.delete_profiles(vec![ids[0].clone(), ids[1].clone()])
                .unwrap_err(),
            "profile_used_in_routing"
        );
        assert_eq!(state(&e), before);
        e.move_profiles(ids.clone(), "personal").unwrap();
        assert!(routing::uses_profile(&e.store.library.routing, &ids[1]));
    }
    #[test]
    fn failed_disk_write_leaves_entire_batch_in_memory_and_on_disk() {
        let (dir, mut e, ids, _) = setup();
        e.store.commit(e.store.library.clone()).unwrap();
        let original = state(&e);
        let file = dir.path().join("library.json");
        let saved = dir.path().join("saved.json");
        std::fs::rename(&file, &saved).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(e.move_profiles(ids.clone(), "personal").is_err());
        assert_eq!(state(&e), original);
        assert!(e.delete_profiles(ids).is_err());
        assert_eq!(state(&e), original);
        std::fs::remove_dir(&file).unwrap();
        std::fs::rename(saved, file).unwrap();
        drop(e);
        assert_eq!(
            state(&Engine::open(dir.path(), std::path::Path::new("missing")).unwrap()),
            original
        );
    }
}
