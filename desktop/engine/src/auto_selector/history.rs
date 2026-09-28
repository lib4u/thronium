//! Local membership history of successful explicit connections, not traffic usage.
use crate::{
    proto,
    store::{Library, ProfileKind},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const FILE: &str = "selector-history-v1.json";
const ERROR: &str = "selector_history_write_failed";
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_POOLS: usize = 64;
const MAX_ENTRIES: usize = 2000;
const MAX_NAME_BYTES: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    profile_id: String,
    name: String,
    first_used: u64,
    last_used: u64,
    builds: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pool {
    last_built_at: u64,
    last_built: Vec<String>,
    entries: Vec<Entry>,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Cache {
    pools: BTreeMap<String, Pool>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileData {
    version: u32,
    pools: BTreeMap<String, Pool>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn name(s: &str) -> String {
    let mut end = s.len().min(MAX_NAME_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].into()
}
fn owner(l: &Library, id: &str) -> bool {
    l.profiles
        .iter()
        .any(|p| p.id == id && p.kind == ProfileKind::AutoSelector)
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 512
}

impl Cache {
    fn bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&FileData {
            version: 1,
            pools: self.pools.clone(),
        })
        .map_err(|_| ERROR.into())
    }
    pub(crate) fn load(directory: &Path, library: &Library) -> Self {
        let read = || -> Option<Self> {
            let path = directory.join(FILE);
            let meta = std::fs::symlink_metadata(&path).ok()?;
            if !meta.is_file() || meta.len() > MAX_BYTES as u64 {
                return None;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            if bytes.len() > MAX_BYTES {
                return None;
            }
            let f: FileData = serde_json::from_slice(&bytes).ok()?;
            if f.version != 1 || f.pools.len() > MAX_POOLS {
                return None;
            }
            let upper = now().saturating_add(300);
            for (id, pool) in &f.pools {
                if !valid_id(id)
                    || pool.last_built_at == 0
                    || pool.last_built_at > upper
                    || pool.entries.is_empty()
                    || pool.entries.len() > MAX_ENTRIES
                    || pool.last_built.is_empty()
                    || pool.last_built.len() > super::MAX_MEMBERS
                {
                    return None;
                }
                let mut ids = HashSet::new();
                for e in &pool.entries {
                    if !valid_id(&e.profile_id)
                        || !ids.insert(e.profile_id.as_str())
                        || e.name.len() > MAX_NAME_BYTES
                        || e.first_used == 0
                        || e.first_used > e.last_used
                        || e.last_used > pool.last_built_at
                        || e.builds == 0
                    {
                        return None;
                    }
                }
                let mut built = HashSet::new();
                if pool
                    .last_built
                    .iter()
                    .any(|id| !ids.contains(id.as_str()) || !built.insert(id))
                {
                    return None;
                }
            }
            let mut result = Self { pools: f.pools };
            result.pools.retain(|id, _| owner(library, id));
            Some(result)
        };
        read().unwrap_or_default()
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        let bytes = self.bytes()?;
        if bytes.len() > MAX_BYTES {
            return Err(ERROR.into());
        }
        let mut tmp = tempfile::NamedTempFile::new_in(directory).map_err(|_| ERROR)?;
        tmp.write_all(&bytes)
            .and_then(|_| tmp.as_file().sync_all())
            .map_err(|_| ERROR)?;
        tmp.persist(directory.join(FILE)).map_err(|_| ERROR)?;
        Ok(())
    }
    fn record(
        &self,
        library: &Library,
        selected: &str,
        request: &proto::LoadConfigReq,
        at: u64,
    ) -> Result<Option<Self>, String> {
        let Some(selected) = library.profiles.iter().find(|p| p.id == selected) else {
            return Ok(None);
        };
        if matches!(
            selected.kind,
            ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
        ) {
            return Ok(None);
        }
        let core: Value = serde_json::from_str(request.core_config.as_deref().ok_or(ERROR)?)
            .map_err(|_| ERROR)?;
        let mut next = self.clone();
        next.pools.retain(|id, _| owner(library, id));
        let mut changed = false;
        let mut seen = HashSet::new();
        for super::runtime::CompiledPool {
            tag,
            group,
            owner,
            owner_id: id,
        } in super::runtime::compiled_pools(library, &selected.id, &core)
        {
            if owner.is_none() || !seen.insert(id) {
                continue;
            }
            let prefix = super::runtime::member_tag(tag, "");
            let ids: Vec<&str> = group["outbounds"]
                .as_array()
                .ok_or(ERROR)?
                .iter()
                .map(|v| {
                    v.as_str()
                        .and_then(|s| s.strip_prefix(&prefix))
                        .ok_or(ERROR)
                })
                .collect::<Result<_, _>>()?;
            if ids.is_empty()
                || ids.len() > super::MAX_MEMBERS
                || ids.iter().collect::<HashSet<_>>().len() != ids.len()
            {
                return Err(ERROR.into());
            }
            let pool = next.pools.entry(id.into()).or_default();
            let at = at.max(pool.last_built_at).max(1);
            let mut entries = Vec::new();
            for member in &ids {
                let p = library
                    .profiles
                    .iter()
                    .find(|p| p.id == *member)
                    .ok_or(ERROR)?;
                let old = pool.entries.iter().find(|e| e.profile_id == *member);
                entries.push(Entry {
                    profile_id: (*member).into(),
                    name: name(&p.name),
                    first_used: old.map_or(at, |e| e.first_used),
                    last_used: at,
                    builds: old.map_or(1, |e| e.builds.saturating_add(1)),
                });
            }
            entries.extend(
                pool.entries
                    .iter()
                    .filter(|e| !ids.contains(&e.profile_id.as_str()))
                    .cloned(),
            );
            entries.truncate(MAX_ENTRIES);
            *pool = Pool {
                last_built_at: at,
                last_built: ids.iter().map(|s| (*s).into()).collect(),
                entries,
            };
            changed = true;
        }
        if !changed {
            return Ok(None);
        }
        while next.pools.len() > MAX_POOLS || next.bytes()?.len() > MAX_BYTES {
            let oldest = next
                .pools
                .iter()
                .min_by_key(|(id, p)| (p.last_built_at, id.as_str()))
                .map(|(id, _)| id.clone())
                .ok_or(ERROR)?;
            next.pools.remove(&oldest);
        }
        Ok(Some(next))
    }
    fn view(&self, library: &Library) -> Value {
        let mut pools: Vec<_> = self
            .pools
            .iter()
            .filter(|(id, _)| owner(library, id))
            .collect();
        pools
            .sort_by(|(a, x), (b, y)| y.last_built_at.cmp(&x.last_built_at).then_with(|| a.cmp(b)));
        json!(pools.into_iter().map(|(id,pool)|json!({"profileId":id,"name":library.profiles.iter().find(|p|p.id==*id).map(|p|&p.name),"lastBuiltAt":pool.last_built_at,"lastBuilt":pool.last_built,"entries":pool.entries.iter().map(|e|{let current=library.profiles.iter().find(|p|p.id==e.profile_id);json!({"profileId":e.profile_id,"name":current.map_or(e.name.as_str(),|p|p.name.as_str()),"missing":current.is_none(),"firstUsed":e.first_used,"lastUsed":e.last_used,"builds":e.builds})}).collect::<Vec<_>>() })).collect::<Vec<_>>())
    }
}
impl Engine {
    pub fn selector_history(&self) -> Value {
        self.store
            .library
            .selector_history
            .view(&self.store.library)
    }
    pub fn clear_selector_history(&mut self, id: &str) -> Result<(), String> {
        if !owner(&self.store.library, id) {
            return Err("profile_not_found".into());
        }
        let mut next = self.store.library.selector_history.clone();
        if next.pools.remove(id).is_some() {
            self.store.save_selector_history(next)?;
        }
        Ok(())
    }
    pub(crate) fn remember_selector_start(&mut self) {
        let result = (|| {
            let Some(active) = &self.active_connection else {
                return Ok(());
            };
            if let Some(next) = self.store.library.selector_history.record(
                &self.store.library,
                &active.id,
                &active.request,
                now(),
            )? {
                self.store.save_selector_history(next)?;
            }
            Ok::<_, String>(())
        })();
        if result.is_err() {
            self.logs.event("warn", ERROR, None);
        }
    }
}
#[cfg(test)]
mod tests;
