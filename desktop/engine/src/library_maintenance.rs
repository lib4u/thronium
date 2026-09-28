//! Qt's library maintenance: replacing server names with the addresses they
//! resolve to and forgetting the traffic counted for a profile. Removing
//! unavailable, invalid or insecure servers is a selection the window makes and
//! `delete_profiles` carries out, with its usual references and running checks.
use crate::{profile_descriptor, store::Store, Engine};

impl Engine {
    /// The servers a maintenance action would take, chosen as Qt chooses them:
    /// the stored result of the last test and the security of the configuration.
    /// Invalid servers are found by asking the core about each one instead.
    pub fn maintenance_candidates(
        &self,
        kind: &str,
        ids: &[String],
    ) -> Result<Vec<String>, String> {
        let insecure = [
            crate::profile_descriptor::SECURITY_NONE,
            crate::profile_descriptor::SECURITY_WEAK,
        ];
        match kind {
            "unavailable" => Ok(self
                .store
                .library
                .profiles
                .iter()
                .filter(|p| ids.contains(&p.id))
                .filter(|p| {
                    self.measurement(p)
                        .is_some_and(|m| m.status == crate::probes::Status::Error)
                })
                .map(|p| p.id.clone())
                .collect()),
            // Qt spares a configuration whose security it cannot tell.
            "insecure" => Ok(self
                .store
                .library
                .profiles
                .iter()
                .filter(|p| ids.contains(&p.id))
                .filter(|p| {
                    insecure.contains(&crate::profile_descriptor::security_level(&p.config))
                })
                .map(|p| p.id.clone())
                .collect()),
            "named" => Ok(self
                .resolvable_hosts(ids)
                .into_iter()
                .map(|(id, _)| id)
                .collect()),
            _ => Err("invalid_profile_selection".into()),
        }
    }
    /// The server names of these profiles: what a resolve run asks the system
    /// about. A running profile is left out, as it is for any other edit.
    pub fn resolvable_hosts(&self, ids: &[String]) -> Vec<(String, String)> {
        self.store
            .library
            .profiles
            .iter()
            .filter(|p| ids.contains(&p.id) && !self.running_uses(&p.id))
            .filter_map(|p| {
                let host = profile_descriptor::describe(p).address.trim().to_owned();
                (!host.is_empty() && host.parse::<std::net::IpAddr>().is_err())
                    .then_some((p.id.clone(), host))
            })
            .collect()
    }
    /// Writes resolved addresses back in one commit; profiles changed in the
    /// meantime, or now running, keep their name.
    pub fn apply_resolved_hosts(&mut self, resolved: &[(String, String)]) -> Result<usize, String> {
        let mut next = self.store.library.clone();
        let mut changed = Vec::new();
        for (id, host) in resolved {
            if host.parse::<std::net::IpAddr>().is_err() || self.running_uses(id) {
                continue;
            }
            let Some(profile) = next.profiles.iter_mut().find(|p| p.id == *id) else {
                continue;
            };
            let mut config = profile.config.clone();
            if profile_descriptor::describe(profile).address == host
                || !profile_descriptor::set_host(&mut config, host)
                || crate::store::config_size(&config).is_none()
            {
                continue;
            }
            profile.config = config;
            changed.push(id.clone());
        }
        if changed.is_empty() {
            return Ok(0);
        }
        let committed = self.store.commit(next);
        if Store::written(&committed) && changed.iter().any(|id| self.routing_uses(id)) {
            self.routing_revision = None;
        }
        committed?;
        Ok(changed.len())
    }
    /// Qt's group `auto_clear_unavailable`: when a latency test the user asked
    /// for finishes, the servers of such a group that answered with an error are
    /// removed. Servers a chain, a route or the running connection needs stay,
    /// as they do for a manual delete.
    pub(crate) fn clear_unavailable(&mut self, failed: &[String]) {
        let library = &self.store.library;
        let clearing: Vec<String> = failed
            .iter()
            .filter(|id| {
                library.profiles.iter().any(|p| {
                    p.id == **id
                        && library
                            .groups
                            .iter()
                            .any(|g| g.id == p.group_id && g.auto_clear_unavailable)
                })
            })
            .filter(|id| {
                let one = std::collections::HashSet::from([(*id).clone()]);
                !self.running_uses(id)
                    && !self.routing_uses(id)
                    && !crate::group_chains::referenced(library, &one, None)
                    && !crate::references::referenced_outside(&library.profiles, &one)
            })
            .cloned()
            .collect();
        if clearing.is_empty() {
            return;
        }
        match self.delete_profiles(clearing) {
            Ok(count) => self
                .logs
                .event("info", "auto_clear_removed", Some(&count.to_string())),
            Err(_) => self.logs.event("warn", "auto_clear_failed", None),
        }
    }
    /// Qt's "Reset traffic" for the selected profiles.
    pub fn reset_profile_traffic(&mut self, ids: &[String]) -> Result<(), String> {
        self.history.reset_profiles(&self.data_dir, ids)
    }
}

#[cfg(test)]
mod tests;
