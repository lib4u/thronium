//! Saving, importing and choosing profiles; checks of what a running connection uses.
use super::*;

impl Engine {
    pub fn profile(&self, id: &str) -> Result<Profile, String> {
        self.store
            .library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .or_else(|| {
                (id == crate::auto_selector::AUTO_SELECT_ID)
                    .then(|| self.auto_select_profile())
                    .flatten()
            })
            .ok_or("profile_not_found".into())
    }

    pub(crate) fn running_group_uses(&self, id: &str) -> bool {
        if let Some(active) = &self.active_connection {
            return active.groups.contains(id);
        }
        self.running
            .as_deref()
            .and_then(|id| self.profile(id).ok())
            .is_some_and(|p| {
                vless::roots(&self.store.library, &p).is_ok_and(|roots| {
                    self.store
                        .library
                        .profiles
                        .iter()
                        .any(|p| roots.contains(&p.id) && p.group_id == id)
                })
            })
    }
    pub(crate) fn running_uses(&self, id: &str) -> bool {
        if let Some(active) = &self.active_connection {
            return active.profiles.contains(id);
        }
        self.running
            .as_deref()
            .and_then(|id| self.profile(id).ok())
            .is_some_and(|p| {
                vless::relevant(&self.store.library, &p).is_ok_and(|ids| ids.contains(id))
            })
    }
    pub(crate) fn routing_uses(&self, id: &str) -> bool {
        let library = &self.store.library;
        let roots = library
            .profiles
            .iter()
            .filter(|p| routing::uses_profile(&library.routing, &p.id))
            .map(|p| p.id.clone())
            .collect();
        group_chains::dependencies(library, &roots).contains(id)
    }

    /// Checks a draft as it would be saved: the kept VPN policy of an existing
    /// profile applies, the policy must suit the protocol, and a VLESS core
    /// choice is checked with that core.
    pub async fn check_profile_draft(
        &mut self,
        draft: ProfileDraft,
        choice: Option<Option<vless::Core>>,
    ) -> Result<(), String> {
        let existing = draft
            .id
            .as_deref()
            .and_then(|id| self.store.library.profiles.iter().find(|p| p.id == id))
            .and_then(|p| p.vpn_policy);
        let profile = Profile {
            vpn_policy: draft.vpn_policy.resolve(existing),
            id: draft.id.unwrap_or_default(),
            name: draft.name,
            group_id: draft.group_id,
            kind: draft.kind,
            config: draft.config,
            favorite: false,
        };
        vpn_policy::validate_profile(&profile)?;
        match choice {
            Some(core) => self.check_vless_choice(profile, core).await,
            None => self.check(&profile).await,
        }
    }
    pub fn save_profile(&mut self, draft: ProfileDraft) -> Result<String, String> {
        self.save_profile_choice(draft, None)
    }
    pub fn save_profile_choice(
        &mut self,
        draft: ProfileDraft,
        choice: Option<Option<vless::Core>>,
    ) -> Result<String, String> {
        let mut next = self.store.library.clone();
        if !store::valid_name(&draft.name) || store::config_size(&draft.config).is_none() {
            return Err("invalid_profile".into());
        }
        let id = draft
            .id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if self.running_uses(&id) {
            return Err("stop_before_editing".into());
        }
        let favorite = if draft.id.is_some() {
            self.profile(&id)?.favorite
        } else {
            false
        };
        let policy = draft.vpn_policy.resolve(
            self.store
                .library
                .profiles
                .iter()
                .find(|p| p.id == id)
                .and_then(|p| p.vpn_policy),
        );
        let profile = Profile {
            vpn_policy: policy,
            id: id.clone(),
            name: draft.name.trim().into(),
            group_id: draft.group_id,
            kind: draft.kind,
            config: draft.config,
            favorite,
        };
        vpn_policy::validate_profile(&profile)?;
        if profile.vpn_policy.is_some() {
            next.version = next.version.max(4);
        }
        let mut core_changed = false;
        if let Some(core) = choice {
            if !vless::is_vless(&profile) {
                return Err("vless_core_profile_required".into());
            }
            match core {
                Some(c) => {
                    next.preferences.vless_overrides.insert(id.clone(), c);
                }
                None => {
                    next.preferences.vless_overrides.remove(&id);
                }
            }
            vless::compile(
                &profile,
                next.preferences.vless_core,
                &next.preferences.vless_overrides,
            )?;
            if draft.id.is_some()
                && self
                    .store
                    .library
                    .preferences
                    .vless_overrides
                    .get(&id)
                    .copied()
                    .unwrap_or(next.preferences.vless_core)
                    != core.unwrap_or(next.preferences.vless_core)
            {
                self.url_tests_resettable()?;
                core_changed = true;
            }
        }
        // Moving a profile out of its source group detaches it from that subscription.
        next.release_managed(|managed| managed == id, Some(&profile.group_id));
        if let Some(old) = next.profiles.iter_mut().find(|p| p.id == id) {
            *old = profile;
        } else {
            next.profiles.push(profile);
        }
        if next.selected.is_none() {
            next.selected = Some(id.clone());
        }
        let committed = self.store.commit(next);
        if Store::written(&committed) {
            if core_changed {
                self.reset_url_tests_after_commit();
            }
            if self.routing_uses(&id) {
                self.routing_revision = None;
            }
        }
        committed?;
        Ok(id)
    }

    /// Import a reviewed batch in one atomic write, without replacing existing IDs.
    pub fn import_profiles(&mut self, drafts: Vec<ProfileDraft>) -> Result<Vec<String>, String> {
        self.import_referenced_profiles(
            drafts
                .into_iter()
                .map(|draft| exports::ImportProfile {
                    draft,
                    reference: None,
                    vless_core: None,
                })
                .collect(),
        )
    }
    pub fn import_referenced_profiles(
        &mut self,
        drafts: Vec<exports::ImportProfile>,
    ) -> Result<Vec<String>, String> {
        let (next, ids) = self.prepare_import(drafts)?;
        self.store.commit(next)?;
        Ok(ids)
    }
    pub async fn check_import_profile(
        &mut self,
        drafts: Vec<exports::ImportProfile>,
        index: usize,
    ) -> Result<(), String> {
        let (next, ids) = self.prepare_import(drafts)?;
        let id = ids.get(index).ok_or("invalid_import_batch")?;
        let profile = next
            .profiles
            .iter()
            .find(|p| &p.id == id)
            .ok_or("invalid_import_batch")?;
        let profile = profile.clone();
        self.check_with_library(&profile, &next).await
    }
    pub(crate) fn prepare_import(
        &self,
        drafts: Vec<exports::ImportProfile>,
    ) -> Result<(store::Library, Vec<String>), String> {
        if drafts.is_empty() || drafts.len() > store::MAX_BATCH_PROFILES {
            return Err("invalid_import_batch".into());
        }
        let mut next = self.store.library.clone();
        let ids: Vec<String> = (0..drafts.len())
            .map(|_| uuid::Uuid::new_v4().to_string())
            .collect();
        let mut references = std::collections::HashMap::new();
        for (p, id) in drafts.iter().zip(&ids) {
            if let Some(core) = p.vless_core {
                next.preferences.vless_overrides.insert(id.clone(), core);
            }
            if let Some(reference) = &p.reference {
                if reference.is_empty()
                    || reference.len() > 64
                    || !reference
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || references.insert(reference.clone(), id.clone()).is_some()
                {
                    return Err("invalid_import_references".into());
                }
            }
        }
        let mut size = 0;
        for (input, id) in drafts.into_iter().zip(&ids) {
            let mut draft = input.draft;
            if let Some(key) = references::key(draft.kind) {
                let hops = draft.config[key].as_array().ok_or("invalid_chain")?;
                let resolved = hops
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .and_then(|r| references.get(r))
                            .cloned()
                            .ok_or_else(|| "invalid_import_references".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                draft.config[key] = json!(resolved);
                if draft.kind == ProfileKind::AutoSelector {
                    if let Some(pin) = draft
                        .config
                        .get("pinned_profile")
                        .and_then(Value::as_str)
                        .filter(|v| !v.is_empty())
                    {
                        draft.config["pinned_profile"] =
                            json!(references.get(pin).ok_or("invalid_import_references")?);
                    }
                }
            }
            size += store::config_size(&draft.config).ok_or("invalid_import_batch")?;
            if draft.id.is_some()
                || !store::valid_name(&draft.name)
                || size > store::MAX_CONFIG_BYTES
                || !next.groups.iter().any(|g| g.id == draft.group_id)
            {
                return Err("invalid_import_batch".into());
            }
            next.profiles.push(Profile {
                vpn_policy: draft.vpn_policy.resolve(None),
                id: id.clone(),
                name: draft.name.trim().into(),
                group_id: draft.group_id,
                kind: draft.kind,
                config: draft.config,
                favorite: false,
            });
        }
        if next.selected.is_none() {
            next.selected = ids.first().cloned();
        }
        if next.profiles.iter().any(|p| p.vpn_policy.is_some()) {
            next.version = next.version.max(4);
        }
        store::validate_library(&next)?;
        Ok((next, ids))
    }

    pub fn select(&mut self, id: &str) -> Result<(), String> {
        self.profile(id)?;
        let mut next = self.store.library.clone();
        next.selected = Some(id.into());
        self.store.commit(next)
    }

    pub fn favorite(&mut self, id: &str) -> Result<(), String> {
        let mut next = self.store.library.clone();
        let p = next
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or("profile_not_found")?;
        p.favorite = !p.favorite;
        self.store.commit(next)
    }

    pub fn delete(&mut self, id: &str) -> Result<(), String> {
        self.delete_profiles(vec![id.into()]).map(|_| ())
    }

    pub fn add_group(&mut self, name: &str) -> Result<(), String> {
        if !store::valid_name(name) {
            return Err("invalid_group".into());
        }
        let mut next = self.store.library.clone();
        next.groups.push(Group {
            proxy_chain: Default::default(),
            collapsed: false,
            auto_clear_unavailable: false,
            id: uuid::Uuid::new_v4().to_string(),
            name: name.trim().into(),
            subscription: None,
        });
        self.store.commit(next)
    }
}
