//! Exact duplicate removal requires a current, explicitly reviewed native preview.
use crate::{routing, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub reason: Option<&'static str>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cluster {
    pub group_id: String,
    pub keep: Vec<Entry>,
    pub remove: Vec<Entry>,
}
#[derive(Clone, Serialize)]
pub struct Preview {
    pub token: String,
    pub clusters: Vec<Cluster>,
    pub count: usize,
}
pub(crate) struct Pending {
    preview: Preview,
    library: Value,
    running: Option<String>,
    created: Instant,
}

impl Engine {
    pub fn preview_duplicates(&mut self, ids: Vec<String>) -> Result<Preview, String> {
        let selected = self.selected_profiles(ids)?;
        let mut groups: Vec<Vec<Entry>> = vec![];
        let mut keys = HashMap::new();
        let all = &self.store.library.profiles;
        for p in all.iter().filter(|p| selected.contains(&p.id)) {
            let core = crate::vless::is_vless(p).then(|| {
                self.store
                    .library
                    .preferences
                    .vless_overrides
                    .get(&p.id)
                    .copied()
                    .unwrap_or(self.store.library.preferences.vless_core)
            });
            let key = json!([p.group_id, p.kind, p.config, core, p.vpn_policy]).to_string();
            let index = *keys.entry(key).or_insert_with(|| {
                groups.push(vec![]);
                groups.len() - 1
            });
            let reason = if self.running_uses(&p.id) {
                Some("running")
            } else if routing::uses_profile(&self.store.library.routing, &p.id) {
                Some("routing")
            } else if crate::group_chains::referenced(
                &self.store.library,
                &HashSet::from([p.id.clone()]),
                None,
            ) || crate::references::referenced_outside(
                all,
                &HashSet::from([p.id.clone()]),
            ) {
                Some("chain")
            } else if self.store.library.vpn_otp_bindings.contains_key(&p.id) {
                Some("otp")
            } else if self.store.library.selected.as_deref() == Some(&p.id) {
                Some("selected")
            } else if p.favorite {
                Some("favorite")
            } else {
                None
            };
            groups[index].push(Entry {
                id: p.id.clone(),
                name: p.name.clone(),
                reason,
            });
        }
        let mut clusters = vec![];
        for mut entries in groups.into_iter().filter(|g| g.len() > 1) {
            if !entries.iter().any(|p| p.reason.is_some()) {
                entries[0].reason = Some("first");
            }
            let (keep, remove): (Vec<_>, Vec<_>) =
                entries.into_iter().partition(|p| p.reason.is_some());
            if remove.is_empty() {
                continue;
            }
            let group_id = self.profile(&keep[0].id)?.group_id;
            clusters.push(Cluster {
                group_id,
                keep,
                remove,
            });
        }
        let preview = Preview {
            token: uuid::Uuid::new_v4().to_string(),
            count: clusters.iter().map(|c| c.remove.len()).sum(),
            clusters,
        };
        self.duplicates = Some(Pending {
            preview: preview.clone(),
            library: json!(self.store.library),
            running: self.running.clone(),
            created: Instant::now(),
        });
        Ok(preview)
    }
    pub fn discard_duplicates(&mut self, token: &str) {
        if self
            .duplicates
            .as_ref()
            .is_some_and(|p| p.preview.token == token)
        {
            self.duplicates = None;
        }
    }
    pub fn remove_duplicates(&mut self, token: &str) -> Result<usize, String> {
        let pending = self
            .duplicates
            .as_ref()
            .filter(|p| p.preview.token == token)
            .ok_or("duplicates_preview_expired")?;
        if pending.created.elapsed() > Duration::from_secs(15 * 60)
            || pending.running != self.running
            || pending.library != json!(self.store.library)
        {
            return Err("duplicates_preview_stale".into());
        }
        let ids = pending
            .preview
            .clusters
            .iter()
            .flat_map(|c| c.remove.iter().map(|p| p.id.clone()))
            .collect::<Vec<_>>();
        let count = if ids.is_empty() {
            0
        } else {
            self.delete_profiles(ids)?
        };
        self.duplicates = None;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::ProfileKind, ProfileDraft};
    fn add(e: &mut Engine, name: &str, config: Value) -> String {
        e.save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: name.into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config,
        })
        .unwrap()
    }
    fn setup() -> (tempfile::TempDir, Engine, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), std::path::Path::new("missing")).unwrap();
        let ids = (0..4).map(|i| add(&mut e, &format!("Copy {i}"), json!({"type":"socks","server":"localhost","server_port":1080,"password":"synthetic-duplicate-secret","future":1}))).collect();
        (dir, e, ids)
    }
    #[test]
    fn exact_match_ignores_names_but_keeps_groups_kinds_credentials_and_unknown_fields_distinct() {
        let (_dir, mut e, ids) = setup();
        for field in ["password", "future"] {
            let mut c = e.profile(&ids[0]).unwrap().config;
            c[field] = json!("different");
            add(&mut e, field, c);
        }
        e.add_group("Separate").unwrap();
        let mut p = e.profile(&ids[3]).unwrap();
        p.group_id = e.store.library.groups[1].id.clone();
        e.store.library.profiles[3] = p;
        let all = e
            .store
            .library
            .profiles
            .iter()
            .map(|p| p.id.clone())
            .collect();
        let before = json!(e.store.library);
        let preview = e.preview_duplicates(all).unwrap();
        assert_eq!(preview.count, 2);
        assert_eq!(json!(e.store.library), before);
        assert!(!json!(preview)
            .to_string()
            .contains("synthetic-duplicate-secret"));
        e.remove_duplicates(&preview.token).unwrap();
        assert_eq!(e.store.library.profiles.len(), 4);
        assert!(e.profile(&ids[0]).is_ok());
        assert!(e.profile(&ids[3]).is_ok());
    }
    #[test]
    fn every_active_referenced_selected_or_favorite_copy_is_retained() {
        let (_dir, mut e, ids) = setup();
        e.running = Some(ids[1].clone());
        e.favorite(&ids[2]).unwrap();
        e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{}", ids[3]));
        let p = e.preview_duplicates(ids.clone()).unwrap();
        assert_eq!(p.count, 0);
        e.store.library.routing.profiles[0].route = json!({});
        e.running = None;
        let chain = e
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Chain".into(),
                group_id: "personal".into(),
                kind: ProfileKind::Chain,
                config: json!({"type":"chain","hops":[ids[1]]}),
            })
            .unwrap();
        let p = e.preview_duplicates(ids.clone()).unwrap();
        assert_eq!(p.count, 1);
        assert_eq!(p.clusters[0].remove[0].id, ids[3]);
        e.remove_duplicates(&p.token).unwrap();
        assert!(e.profile(&chain).is_ok());
        assert!(e.profile(&ids[1]).is_ok());
    }
    #[test]
    fn a_copy_bound_to_an_otp_entry_is_kept_even_when_it_is_not_the_first() {
        let (_dir, mut e, ids) = setup();
        e.store.library.vpn_otp_bindings.insert(
            ids[2].clone(),
            crate::vpn_otp_bindings::Binding {
                revision: "synthetic".into(),
                otp_id: "otp".into(),
                mode: crate::vpn_otp_bindings::Mode::AutoLive,
            },
        );
        e.store.library.selected = None;
        let p = e.preview_duplicates(ids.clone()).unwrap();
        assert_eq!(p.count, 3);
        let keep = &p.clusters[0].keep;
        assert_eq!(keep.len(), 1);
        assert_eq!(
            (keep[0].id.as_str(), keep[0].reason),
            (ids[2].as_str(), Some("otp"))
        );
        assert!(p.clusters[0].remove.iter().all(|r| r.id != ids[2]));
    }
    #[test]
    fn changed_library_connection_cancelled_superseded_and_expired_previews_cannot_delete() {
        let (_dir, mut e, ids) = setup();
        let first = e.preview_duplicates(ids.clone()).unwrap();
        let second = e.preview_duplicates(ids.clone()).unwrap();
        assert!(e.remove_duplicates(&first.token).is_err());
        e.discard_duplicates(&first.token);
        e.favorite(&ids[2]).unwrap();
        assert_eq!(
            e.remove_duplicates(&second.token).unwrap_err(),
            "duplicates_preview_stale"
        );
        let p = e.preview_duplicates(ids.clone()).unwrap();
        e.running = Some(ids[1].clone());
        assert!(e.remove_duplicates(&p.token).is_err());
        e.running = None;
        let p = e.preview_duplicates(ids.clone()).unwrap();
        e.duplicates.as_mut().unwrap().created -= Duration::from_secs(901);
        assert!(e.remove_duplicates(&p.token).is_err());
        let p = e.preview_duplicates(ids.clone()).unwrap();
        e.discard_duplicates(&p.token);
        assert!(e.remove_duplicates(&p.token).is_err());
        assert_eq!(e.store.library.profiles.len(), 4);
    }
    #[test]
    fn failed_atomic_write_preserves_every_profile_and_allows_retry() {
        let (dir, mut e, ids) = setup();
        let p = e.preview_duplicates(ids).unwrap();
        let before = json!(e.store.library);
        let path = dir.path().join("library.json");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(e.remove_duplicates(&p.token).is_err());
        assert_eq!(json!(e.store.library), before);
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(e.remove_duplicates(&p.token).unwrap(), 3);
        drop(e);
        let reopened = Engine::open(dir.path(), std::path::Path::new("missing")).unwrap();
        assert_eq!(reopened.store.library.profiles.len(), 1);
    }
}
