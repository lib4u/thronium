//! Pool members for the automatic selector: ordering, counting and the generated profile.
use super::*;

impl Engine {
    /// Eligible servers ordered for the pool: best latency first (as `latency`
    /// reports it), unmeasured members after in library order, a second endpoint
    /// on an already-taken fixed UDP port skipped, capped at the pool limit.
    pub(crate) fn auto_select_source(&self) -> Option<&str> {
        self.store
            .library
            .preferences
            .auto_select
            .source_group_id
            .as_deref()
            .filter(|id| {
                self.store
                    .library
                    .groups
                    .iter()
                    .any(|group| group.id == *id)
            })
    }
    pub(crate) fn auto_select_member_count(&self) -> usize {
        self.auto_select_members(|p| self.measurement(p).and_then(|m| m.latency_ms))
            .len()
    }
    pub(crate) fn auto_select_members(
        &self,
        latency: impl Fn(&Profile) -> Option<i32>,
    ) -> Vec<String> {
        let profiles = &self.store.library.profiles;
        let source = self.auto_select_source();
        let mut ranked: Vec<&Profile> = profiles
            .iter()
            .filter(|p| source.is_none_or(|id| p.group_id == id))
            .filter(|p| quick::hops(&self.store.library, p).is_some())
            .collect();
        ranked.sort_by_key(|p| latency(p).filter(|ms| *ms >= 0).unwrap_or(i32::MAX));
        let mut members = Vec::new();
        let mut fixed_ports = HashSet::new();
        for candidate in ranked {
            let ports: Vec<u64> = quick::hops(&self.store.library, candidate)
                .into_iter()
                .flatten()
                .filter(|hop| chains::is_endpoint(hop))
                .filter_map(|hop| hop.config["listen_port"].as_u64().filter(|p| *p > 0))
                .collect();
            if ports.iter().any(|port| fixed_ports.contains(port)) {
                continue;
            }
            fixed_ports.extend(ports);
            members.push(candidate.id.clone());
            if members.len() >= MAX_MEMBERS {
                break;
            }
        }
        members
    }
    /// The pool profile for an already-ordered member list, or `None` when the
    /// feature is off or fewer than two members remain. Defaults come first
    /// and the saved settings overlay them, so a config saved before a new
    /// default key existed still gets that key's effective value.
    pub(crate) fn auto_select_profile_from(&self, members: Vec<String>) -> Option<Profile> {
        let prefs = &self.store.library.preferences.auto_select;
        if !prefs.enabled || members.len() < AUTO_SELECT_MIN {
            return None;
        }
        let mut config = default_quick_config();
        let object = config.as_object_mut()?;
        if let Some(saved) = prefs.config.as_object() {
            for (key, value) in saved {
                object.insert(key.clone(), value.clone());
            }
        }
        object.insert("type".into(), json!("auto-selector"));
        object.insert("members".into(), json!(members));
        object.remove("member_source");
        object.remove("pinned_profile");
        object.remove("reuse_ttl");
        Some(Profile {
            vpn_policy: None,
            id: AUTO_SELECT_ID.into(),
            name: "auto-select".into(),
            group_id: "personal".into(),
            kind: ProfileKind::AutoSelector,
            config,
            favorite: false,
        })
    }
    /// The always-on quick auto-select pool, ordered by the last latency the
    /// library shows for each server. `None` when disabled or too few members.
    pub(crate) fn auto_select_profile(&self) -> Option<Profile> {
        if !self.store.library.preferences.auto_select.enabled {
            return None;
        }
        let members = self.auto_select_members(|p| self.measurement(p).and_then(|m| m.latency_ms));
        self.auto_select_profile_from(members)
    }
}
