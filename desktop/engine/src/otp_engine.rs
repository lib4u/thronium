//! OTP collection operations never start a core or change a VPN session.
//! Codes, secrets and exports are returned only by their explicit commands.
use crate::{
    otp::{Draft, Entry, MAX_CODES_PER_REQUEST, MAX_COLLECTION_BYTES, MAX_ENTRIES},
    Engine,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn validate(entries: &[Entry]) -> Result<(), String> {
    if entries.len() > MAX_ENTRIES {
        return Err("otp_limit".into());
    }
    let mut ids = BTreeSet::new();
    for entry in entries {
        if !ids.insert(entry.id.as_str()) {
            return Err("otp_invalid_entry".into());
        }
        entry.validate().map_err(str::to_owned)?;
    }
    if serde_json::to_vec(entries)
        .map_err(|_| "otp_invalid_entry")?
        .len()
        > MAX_COLLECTION_BYTES
    {
        return Err("otp_limit".into());
    }
    Ok(())
}
fn metadata(entry: &Entry) -> Value {
    let v = &entry.value;
    json!({"id":entry.id,"revision":entry.revision,"name":v.name,"issuer":v.issuer,
        "algorithm":v.algorithm,"type":v.kind,"digits":v.digits,"period":v.period,"counter":v.counter})
}
fn same_revision(entry: &Entry, revision: &str) -> Result<(), String> {
    if entry.revision != revision {
        Err("otp_changed".into())
    } else {
        Ok(())
    }
}
impl Engine {
    pub fn otp_list(&self) -> Value {
        json!(self
            .store
            .library
            .otp
            .iter()
            .map(metadata)
            .collect::<Vec<_>>())
    }
    /// Editing explicitly requests the secret. General snapshots and lists do not.
    pub fn otp_get(&self, id: &str) -> Result<Value, String> {
        let entry = self
            .store
            .library
            .otp
            .iter()
            .find(|e| e.id == id)
            .ok_or("otp_missing")?;
        serde_json::to_value(entry).map_err(|_| "otp_invalid_entry".into())
    }
    pub fn otp_save(&mut self, id: &str, revision: &str, draft: Draft) -> Result<Value, String> {
        let value = draft.normalized().map_err(str::to_owned)?;
        let old_entry = self
            .store
            .library
            .otp
            .iter()
            .find(|entry| entry.id == id)
            .cloned();
        let mut next = self.store.library.clone();
        let entry = if id.is_empty() {
            if !revision.is_empty() {
                return Err("otp_changed".into());
            }
            if next.otp.len() >= MAX_ENTRIES {
                return Err("otp_limit".into());
            }
            Entry {
                id: uuid::Uuid::new_v4().to_string(),
                revision: uuid::Uuid::new_v4().to_string(),
                value,
            }
        } else {
            let current = next.otp.iter().find(|e| e.id == id).ok_or("otp_missing")?;
            same_revision(current, revision)?;
            Entry {
                id: id.into(),
                revision: uuid::Uuid::new_v4().to_string(),
                value,
            }
        };
        let result = metadata(&entry);
        if id.is_empty() {
            next.otp.push(entry);
        } else {
            *next.otp.iter_mut().find(|e| e.id == id).unwrap() = entry;
        }
        // Older clients reject this library instead of silently discarding OTP.
        next.version = next.version.max(2);
        let commit_result = self.store.commit(next);
        // Explicit counter edits revoke an active session, even if another edit
        // restores the previous value before its next tick. Reservation bypasses this.
        if old_entry.as_ref().is_some_and(|old| {
            self.store
                .library
                .otp
                .iter()
                .find(|entry| entry.id == id)
                .is_some_and(|current| {
                    crate::otp::counter(&old.value.counter).ok()
                        != crate::otp::counter(&current.value.counter).ok()
                        && (old.value.kind == crate::otp::Kind::Hotp
                            || current.value.kind == crate::otp::Kind::Hotp)
                })
        }) {
            self.disable_vpn_otp_for_entry(id);
        }
        self.refresh_vpn_otp_bindings();
        commit_result.map_err(|code| {
            if code.starts_with("otp_") {
                code
            } else {
                "otp_save_failed".into()
            }
        })?;
        Ok(result)
    }
    pub fn otp_remove(&mut self, id: &str, revision: &str) -> Result<(), String> {
        let entry = self
            .store
            .library
            .otp
            .iter()
            .find(|e| e.id == id)
            .ok_or("otp_missing")?;
        same_revision(entry, revision)?;
        if self
            .store
            .library
            .vpn_otp_bindings
            .values()
            .any(|binding| binding.otp_id == id)
        {
            return Err("otp_in_use".into());
        }
        let mut next = self.store.library.clone();
        next.otp.retain(|e| e.id != id);
        let commit_result = self.store.commit(next);
        self.refresh_vpn_otp_bindings();
        commit_result.map_err(|_| "otp_save_failed".into())
    }
    pub fn otp_reorder(&mut self, previous: &[String], ids: &[String]) -> Result<(), String> {
        let current: Vec<_> = self
            .store
            .library
            .otp
            .iter()
            .map(|e| e.id.clone())
            .collect();
        if current != previous {
            return Err("otp_changed".into());
        }
        let wanted: BTreeSet<_> = ids.iter().collect();
        if ids.len() != current.len()
            || wanted.len() != ids.len()
            || wanted != current.iter().collect()
        {
            return Err("otp_invalid_order".into());
        }
        let mut next = self.store.library.clone();
        let mut entries: std::collections::BTreeMap<_, _> = next
            .otp
            .drain(..)
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        next.otp = ids.iter().map(|id| entries.remove(id).unwrap()).collect();
        let commit_result = self.store.commit(next);
        self.refresh_vpn_otp_bindings();
        commit_result.map_err(|_| "otp_save_failed".into())
    }
    pub fn otp_import(&mut self, text: &str) -> Result<Value, String> {
        let drafts = crate::otp::formats::import(text).map_err(str::to_owned)?;
        if drafts.is_empty() {
            return Err("otp_import_empty".into());
        }
        if self.store.library.otp.len().saturating_add(drafts.len()) > MAX_ENTRIES {
            return Err("otp_limit".into());
        }
        let mut next = self.store.library.clone();
        let count = drafts.len();
        for draft in drafts {
            next.otp.push(Entry {
                id: uuid::Uuid::new_v4().to_string(),
                revision: uuid::Uuid::new_v4().to_string(),
                value: draft.normalized().map_err(str::to_owned)?,
            });
        }
        next.version = next.version.max(2);
        let commit_result = self.store.commit(next);
        self.refresh_vpn_otp_bindings();
        commit_result.map_err(|code| {
            if code.starts_with("otp_") {
                code
            } else {
                "otp_save_failed".into()
            }
        })?;
        Ok(json!({"added":count}))
    }
    pub fn otp_codes(&self, ids: &[String]) -> Result<Value, String> {
        // A visible page requests its codes at once. No counter is advanced.
        if ids.len() > MAX_CODES_PER_REQUEST {
            return Err("otp_limit".into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "otp_clock_invalid")?
            .as_secs();
        let mut seen = BTreeSet::new();
        let mut result = Vec::new();
        for id in ids {
            if !seen.insert(id) {
                return Err("otp_invalid_entry".into());
            }
            let entry = self
                .store
                .library
                .otp
                .iter()
                .find(|e| &e.id == id)
                .ok_or("otp_missing")?;
            let code = entry.value.code_at(now).map_err(str::to_owned)?;
            result.push(
                json!({"id":entry.id,"code":code.code,"counter":entry.value.counter,"secondsRemaining":code.seconds_remaining}),
            );
        }
        Ok(json!(result))
    }
    pub fn otp_export(&self, ids: &[String], format: &str) -> Result<String, String> {
        if ids.is_empty() || ids.len() > MAX_ENTRIES {
            return Err("otp_limit".into());
        }
        let mut seen = BTreeSet::new();
        let values = ids
            .iter()
            .map(|id| {
                if !seen.insert(id) {
                    return Err("otp_invalid_entry".to_string());
                }
                self.store
                    .library
                    .otp
                    .iter()
                    .find(|e| &e.id == id)
                    .map(|e| e.value.clone())
                    .ok_or("otp_missing".into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        match format {
            "uri" if values.len() == 1 => {
                crate::otp::formats::export_uri(&values[0]).map_err(str::to_owned)
            }
            "json" => crate::otp::formats::export_json(&values).map_err(str::to_owned),
            "migration" => crate::otp::migration::export_migration(&values).map_err(str::to_owned),
            _ => Err("otp_export_format".into()),
        }
    }
}

#[cfg(test)]
mod tests;
