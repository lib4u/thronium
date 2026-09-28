//! Whole-library backups are explicit; restore is reviewed, atomic and reversible.
pub mod legacy;
#[cfg(test)]
mod legacy_tests;
#[cfg(test)]
mod legacy_vpn_tests;
use crate::{
    store::{self, Library},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::Read,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Backup {
    format: String,
    version: u32,
    created_at: u64,
    library: Library,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub icons: usize,
    pub otp: usize,
    pub profiles: usize,
    pub groups: usize,
    pub subscriptions: usize,
    pub routing_profiles: usize,
    pub language: String,
    pub autostart: bool,
    pub deep_links: bool,
    pub settings: usize,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub token: String,
    pub created_at: u64,
    pub incoming: Summary,
    pub current: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy: Option<Value>,
}
pub(crate) struct Pending {
    preview: Preview,
    library: Library,
    original: Value,
    created: Instant,
    legacy: Option<legacy::Prepared>,
}
fn summary(library: &Library) -> Summary {
    Summary {
        icons: library.tray_icons.len(),
        otp: library.otp.len(),
        profiles: library.profiles.len(),
        groups: library.groups.len(),
        subscriptions: library
            .groups
            .iter()
            .filter(|g| g.subscription.is_some())
            .count(),
        routing_profiles: library.routing.profiles.len(),
        language: library.preferences.language.clone(),
        autostart: crate::settings::boolean(library, "autostart"),
        deep_links: crate::settings::boolean(library, "url_scheme_auto_register"),
        settings: crate::settings::fields().len(),
    }
}
fn validate(library: &Library) -> Result<(), String> {
    if !store::supported_version(u64::from(library.version)) {
        return Err("backup_version_unsupported".into());
    }
    // The specific validation code tells what is wrong with the library.
    store::validate_library(library)?;
    let all: HashSet<_> = library.profiles.iter().map(|p| p.id.as_str()).collect();
    if crate::routing::profile_references(&library.routing)
        .iter()
        .any(|id| !all.contains(id.as_str()))
    {
        return Err("backup_invalid_library".into());
    }
    for group in &library.groups {
        if let Some(subscription) = &group.subscription {
            let mut seen = HashSet::new();
            if subscription.managed_ids.iter().any(|id| {
                !seen.insert(id)
                    || !library
                        .profiles
                        .iter()
                        .any(|p| &p.id == id && p.group_id == group.id)
            }) {
                return Err("backup_invalid_library".into());
            }
        }
    }
    Ok(())
}
fn encode(library: &Library) -> Result<String, String> {
    validate(library)?;
    let text = serde_json::to_string_pretty(&Backup {
        format: "thronium-backup".into(),
        version: 1,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        library: library.clone(),
    })
    .map_err(|_| "backup_failed")?;
    if text.len() > MAX_BYTES {
        return Err("backup_too_large".into());
    }
    Ok(text)
}
pub fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "backup_read_failed")?;
    if !file.metadata().map_err(|_| "backup_read_failed")?.is_file() {
        return Err("backup_read_failed".into());
    }
    let mut bytes = vec![];
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "backup_read_failed")?;
    if bytes.len() > MAX_BYTES {
        return Err("backup_too_large".into());
    }
    Ok(bytes)
}
pub fn read(path: &Path) -> Result<String, String> {
    String::from_utf8(read_bytes(path)?).map_err(|_| "backup_invalid".into())
}
/// A backup file chosen by the user, recognised by its content.
pub enum File {
    Throne(Box<legacy::Prepared>),
    Thronium(String),
}
/// Reads either format. Parsing a Throne archive is CPU-bound; callers run
/// this outside async threads and without the Engine lock.
pub fn read_file(bytes: Vec<u8>) -> Result<File, String> {
    read_files(bytes, None)
}
/// `traffic` are the bytes of the `throne_stats.db` that sits beside the copy
/// the user chose, when there is one. Nothing looks for it on its own.
pub fn read_files(bytes: Vec<u8>, traffic: Option<Vec<u8>>) -> Result<File, String> {
    let counted = |prepared: &mut legacy::Prepared| {
        if let Some(bytes) = traffic.as_deref() {
            // An unreadable statistics file costs only the old counters.
            prepared.traffic = crate::legacy_backup::stats::read(bytes)
                .ok()
                .filter(|stats| !stats.is_empty());
        }
    };
    if bytes.starts_with(crate::legacy_backup::MAGIC) {
        let source = crate::legacy_backup::parse(&bytes)?;
        let mut prepared = legacy::prepare(&source);
        counted(&mut prepared);
        return Ok(File::Throne(Box::new(prepared)));
    }
    // Qt keeps its library in a plain SQLite file, so a chosen `throne.db` is
    // read exactly like the database inside an archive.
    if bytes.starts_with(b"SQLite format 3\0") {
        let source = crate::legacy_backup::read_database(&bytes)?;
        let mut prepared = legacy::prepare(&source);
        counted(&mut prepared);
        return Ok(File::Throne(Box::new(prepared)));
    }
    String::from_utf8(bytes)
        .map(File::Thronium)
        .map_err(|_| "backup_invalid".into())
}
impl Engine {
    pub fn preview_backup_file(&mut self, file: File) -> Result<Preview, String> {
        match file {
            File::Throne(prepared) => self.preview_legacy_import(*prepared),
            File::Thronium(text) => self.preview_backup(&text),
        }
    }
    pub fn export_backup(&self) -> Result<String, String> {
        encode(&self.store.library)
    }
    pub fn backup_status(&self) -> Value {
        json!({"canUndo":self.data_dir.join("backup-before-restore.json").is_file(),"current":summary(&self.store.library)})
    }
    pub fn preview_backup(&mut self, text: &str) -> Result<Preview, String> {
        if text.len() > MAX_BYTES {
            return Err("backup_too_large".into());
        }
        let mut header: Value = serde_json::from_str(text).map_err(|_| "backup_invalid")?;
        if header["format"] != "thronium-backup" {
            return Err("backup_invalid".into());
        }
        if header["version"] != 1 {
            return Err("backup_version_unsupported".into());
        }
        if header["library"]["version"]
            .as_u64()
            .is_some_and(|version| !store::supported_version(version))
        {
            return Err("backup_version_unsupported".into());
        }
        crate::vpn_policy::validate_wire(text.as_bytes(), true).map_err(|_| "backup_invalid")?;
        crate::vpn_otp_bindings::validate_wire(text.as_bytes(), true)
            .map_err(|_| "backup_invalid")?;
        crate::vless::migrate(&mut header["library"]);
        let mut backup: Backup = serde_json::from_value(header).map_err(|_| "backup_invalid")?;
        // A backup whose auto-select source group is gone restores with all groups.
        store::repair_auto_select_source(&mut backup.library);
        validate(&backup.library)?;
        let preview = Preview {
            token: uuid::Uuid::new_v4().to_string(),
            created_at: backup.created_at,
            incoming: summary(&backup.library),
            current: summary(&self.store.library),
            legacy: None,
        };
        self.restore = Some(Pending {
            preview: preview.clone(),
            library: backup.library,
            original: json!(self.store.library),
            created: Instant::now(),
            legacy: None,
        });
        Ok(preview)
    }
    /// The rollback copy is one of the files this installation owns, so it is
    /// sealed with the same key as the library.
    pub(crate) fn sealed_locally(&self, text: &str) -> Result<Vec<u8>, String> {
        match self.store.secrets.as_ref() {
            Ok(key) => crate::secrets::seal(key, text.as_bytes()),
            Err(_) => Ok(text.as_bytes().to_vec()),
        }
    }
    fn opened_locally(&self, bytes: Vec<u8>) -> Result<String, String> {
        let bytes = if crate::secrets::sealed(&bytes) {
            let key = self
                .store
                .secrets
                .as_ref()
                .map_err(|_| "secrets_unavailable")?;
            crate::secrets::unseal(key, &bytes)?
        } else {
            bytes
        };
        String::from_utf8(bytes).map_err(|_| "backup_invalid".into())
    }
    pub fn preview_previous_backup(&mut self) -> Result<Preview, String> {
        let text = self.opened_locally(read_bytes(
            &self.data_dir.join("backup-before-restore.json"),
        )?)?;
        self.preview_backup(&text)
    }
    pub fn refresh_backup_preview(&mut self, token: &str) -> Result<Preview, String> {
        if let Some(prepared) = self
            .restore
            .as_ref()
            .filter(|p| p.preview.token == token)
            .and_then(|p| p.legacy.clone())
        {
            return self.preview_legacy_import(prepared);
        }
        let library = self
            .restore
            .as_ref()
            .filter(|p| p.preview.token == token)
            .ok_or("backup_preview_expired")?
            .library
            .clone();
        // Recheck against the current library while retaining the original backup timestamp.
        let timestamp = self.restore.as_ref().unwrap().preview.created_at;
        let text = encode(&library)?;
        let mut preview = self.preview_backup(&text)?;
        preview.created_at = timestamp;
        self.restore.as_mut().unwrap().preview.created_at = timestamp;
        Ok(preview)
    }
    pub fn discard_backup_preview(&mut self, token: &str) {
        if self
            .restore
            .as_ref()
            .is_some_and(|p| p.preview.token == token)
        {
            self.restore = None;
        }
    }
    pub fn restore_backup(&mut self, token: &str) -> Result<(), String> {
        if self.running.is_some() {
            return Err("backup_disconnect_first".into());
        }
        if self.subscription_jobs.busy()
            || self.url_tests_snapshot().is_some_and(|b| {
                b.entries.iter().any(|e| {
                    matches!(
                        e.status,
                        crate::probes::Status::Queued | crate::probes::Status::Testing
                    )
                })
            })
        {
            return Err("backup_background_busy".into());
        }
        let pending = self
            .restore
            .as_ref()
            .filter(|p| p.preview.token == token)
            .ok_or("backup_preview_expired")?;
        if pending
            .preview
            .legacy
            .as_ref()
            .is_some_and(|review| review["canApply"] != true)
        {
            return Err("legacy_import_blocked".into());
        }
        if pending.created.elapsed() > Duration::from_secs(15 * 60)
            || pending.original != json!(self.store.library)
        {
            return Err("backup_preview_stale".into());
        }
        let mut next = pending.library.clone();
        // Read before the commit, while the prepared import is still borrowed.
        let traffic = pending
            .legacy
            .as_ref()
            .filter(|prepared| prepared.scopes.profiles)
            .and_then(|prepared| {
                let stats = prepared.traffic.as_ref()?;
                let mapping = prepared
                    .plan
                    .as_ref()
                    .map(|plan| plan.profile_ids.clone())
                    .unwrap_or_default();
                Some(crate::legacy_backup::stats::entries(stats, &mapping))
            });
        crate::otp::keep_spent_counters(&self.store.library.otp, &mut next.otp);
        let previous = encode(&self.store.library)?;
        // The recovery point is staged beside the current one and replaces it
        // only once the restore is written: a failed restore keeps the undo of
        // the previous one.
        let recovery = self.data_dir.join("backup-before-restore.json");
        let staged = self.data_dir.join("backup-before-restore.json.next");
        if recovery.exists() && !recovery.is_file() {
            return Err("backup_recovery_write_failed".into());
        }
        crate::exports::save_bytes_limited(&staged, &self.sealed_locally(&previous)?, MAX_BYTES)
            .map_err(|_| "backup_recovery_write_failed")?;
        let result = self.store.commit(next);
        self.refresh_vpn_otp_bindings();
        if !crate::store::Store::written(&result) {
            let _ = std::fs::remove_file(&staged);
            return result.map_err(|_| "backup_restore_failed".into());
        }
        if std::fs::rename(&staged, &recovery).is_err() {
            self.logs
                .event("warn", "backup_recovery_write_failed", None);
        }
        if let Some((entries, names)) = traffic {
            match self.history.import(&self.data_dir, entries, names) {
                Ok(count) if count > 0 => self.logs.event("info", "traffic_history_imported", None),
                Err(_) => self.logs.event("warn", "history_write_failed", None),
                _ => {}
            }
        }
        self.reload_settings();
        self.restore = None;
        self.duplicates = None;
        self.subscription_tickets.clear();
        self.subscription_jobs = Default::default();
        self.probes = Default::default();
        self.traffic = Default::default();
        self.traffic_available = false;
        self.since = None;
        self.error = None;
        self.routing_revision = None;
        self.logs.event("info", "library_restored", None);
        result
    }
}
#[cfg(test)]
mod tests;
