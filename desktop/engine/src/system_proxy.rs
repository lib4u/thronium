//! Own only settings we applied. Keep a recovery journal outside library backups.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode {
    #[default]
    Local,
    SystemProxy,
    Tun,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub available: bool,
    pub active: bool,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetainedProxy {
    Owned,
    Lost,
}

// Mode is last: publish the new proxy only after every endpoint is configured.
const KEYS: &[(&str, &str)] = &[
    ("http", "host"),
    ("http", "port"),
    ("http", "enabled"),
    ("http", "use-authentication"),
    ("https", "host"),
    ("https", "port"),
    ("ftp", "host"),
    ("ftp", "port"),
    ("socks", "host"),
    ("socks", "port"),
    ("", "use-same-proxy"),
    ("", "mode"),
];
#[derive(Clone, Copy, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum BackendKind {
    #[default]
    Gnome,
    Kde,
    WinInet,
}
impl BackendKind {
    fn len(self) -> usize {
        match self {
            Self::Gnome => KEYS.len(),
            Self::Kde => 6,
            // The address and the flags that decide it is used.
            Self::WinInet => 2,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Value {
    effective: String,
    user: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    #[serde(default)]
    backend: BackendKind,
    port: u16,
    /// Windows writes one address, shaped by the person's own scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
    before: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}
impl Journal {
    fn desired(&self) -> Vec<String> {
        if self.backend == BackendKind::WinInet {
            // PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY: the address below is used,
            // the person's PAC file and autodetection are left in place but
            // not consulted, exactly as Qt's configurator does.
            const MANUAL: u32 = 1 | 2;
            let scheme = self.scheme.as_deref().unwrap_or("{ip}:{port}");
            return vec![
                scheme
                    .replace("{ip}", "127.0.0.1")
                    .replace("{port}", &self.port.to_string()),
                MANUAL.to_string(),
            ];
        }
        if self.backend == BackendKind::Kde {
            let http = format!("http://127.0.0.1 {}", self.port);
            return vec![
                http.clone(),
                http.clone(),
                http,
                format!("socks://127.0.0.1 {}", self.port),
                "false".into(),
                "1".into(),
            ];
        }
        KEYS.iter()
            .map(|(_, key)| match *key {
                "host" => "'127.0.0.1'".into(),
                "port" => self.port.to_string(),
                "enabled" => "true".into(),
                "mode" => "'manual'".into(),
                _ => "false".into(),
            })
            .collect()
    }
}
trait Backend: Send {
    fn kind(&self) -> BackendKind {
        BackendKind::Gnome
    }
    fn read(&self) -> Result<Vec<Value>, String>;
    fn writable(&self) -> Result<(), String>;
    fn write(&self, index: usize, value: Option<&str>) -> Result<(), String>;
    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}
// flock is owned by an open file description, which fork can share before
// O_CLOEXEC takes effect. Release our ownership even if that child is alive.
struct ProxyLock {
    file: File,
    creator_pid: u32,
}
impl Drop for ProxyLock {
    fn drop(&mut self) {
        // A fork child may only close its inherited descriptor, not unlock the
        // still-live parent's ownership. No logging or allocation in this path.
        if self.creator_pid == std::process::id() {
            let _ = FileExt::unlock(&self.file);
        }
    }
}
struct Lease {
    _file: ProxyLock,
    journal: Journal,
}
#[derive(Default)]
pub struct Manager {
    directory: Option<PathBuf>,
    scheme: Option<String>,
    backend: Option<Box<dyn Backend>>,
    lease: Option<Lease>,
    active: bool,
    error: Option<String>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    guardian_required: bool,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    guardian: Option<guardian::Guardian>,
}
impl Manager {
    pub fn platform() -> Self {
        let mut this = Self::platform_unrecovered();
        this.recover_on_open();
        this
    }
    /// Only executables with the early guardian entry point may enable this.
    pub fn platform_guarded() -> Self {
        // Linux and Windows own a guardian; elsewhere this is the plain manager.
        #[cfg_attr(
            not(any(target_os = "linux", target_os = "windows")),
            allow(unused_mut)
        )]
        let mut this = Self::platform();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            this.guardian_required = true;
        }
        this
    }
    fn platform_unrecovered() -> Self {
        #[cfg(target_os = "linux")]
        {
            let config = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")));
            if let Some(config) = config {
                if let Some(backend) = kde::platform(&config) {
                    let mut this = Self::default();
                    this.directory = Some(config.join("thronium-system-proxy-kde"));
                    this.backend = Some(Box::new(backend));
                    return this;
                }
                if gnome::available() {
                    let mut this = Self::default();
                    this.directory = Some(config.join("thronium-system-proxy"));
                    this.backend = Some(Box::new(gnome::Gnome));
                    return this;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let local = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute());
            if let Some(local) = local {
                let mut this = Self::default();
                this.directory = Some(local.join("Thronium").join("system-proxy"));
                this.backend = Some(Box::<wininet::WinInet>::default());
                return this;
            }
        }
        Self::default()
    }
    #[cfg(test)]
    fn open(directory: PathBuf, backend: Box<dyn Backend>) -> Self {
        let mut this = Self::default();
        this.directory = Some(directory);
        this.backend = Some(backend);
        this.recover_on_open();
        this
    }
    /// Windows shapes the address it publishes with the person's own scheme
    /// (`proxy_scheme`), as Qt does; other platforms set fields, not a string.
    pub fn set_scheme(&mut self, scheme: String) {
        self.scheme = (!scheme.is_empty()).then_some(scheme);
    }
    pub fn preflight(&self) -> Result<(), String> {
        self.backend
            .as_ref()
            .ok_or("system_proxy_unavailable")?
            .writable()?;
        if self.lease.is_none() {
            let _ = self.lock()?;
        }
        Ok(())
    }
    pub fn status(&self) -> Status {
        Status {
            available: self.backend.is_some(),
            active: self.active,
            error: self.error.clone(),
        }
    }
    pub fn enable(&mut self, port: u16) -> Result<(), String> {
        if port == 0 {
            return Err("system_proxy_incompatible".into());
        }
        self.preflight()?;
        if self.lease.is_some() {
            self.restore()?;
        }
        if self.path().exists() {
            self.recover()?;
        }
        let file = self.lock()?;
        let before = self.backend.as_ref().unwrap().read()?;
        let backend = self.backend.as_ref().unwrap().kind();
        if before.len() != backend.len() {
            return Err("system_proxy_apply_failed".into());
        }
        let journal = Journal {
            version: 1,
            backend,
            port,
            scheme: self.scheme.clone(),
            before,
            token: Some(uuid::Uuid::new_v4().simple().to_string()),
        };
        let mut temp = tempfile::NamedTempFile::new_in(self.directory.as_ref().unwrap())
            .map_err(|_| "system_proxy_journal_failed")?;
        temp.write_all(&serde_json::to_vec(&journal).map_err(|_| "system_proxy_journal_failed")?)
            .and_then(|_| temp.as_file().sync_all())
            .map_err(|_| "system_proxy_journal_failed")?;
        temp.persist(self.path())
            .map_err(|_| "system_proxy_journal_failed")?;
        self.lease = Some(Lease {
            _file: file,
            journal,
        });
        if let Err(error) = self.start_guardian() {
            // No OS write has happened yet. Do not rewrite the user's values
            // while handling a failed handshake.
            self.release()?;
            self.error = Some(error.clone());
            return Err(error);
        }
        let result = self.apply().and_then(|()| self.guardian_alive());
        if result.is_err() {
            // A partial write is recoverable because both previous and intended values are recorded first.
            if self.restore().is_err() {
                return Err("system_proxy_recovery_failed".into());
            }
            if self.error.as_deref() == Some("system_proxy_changed") {
                return Err("system_proxy_changed".into());
            }
            let error = if result.err().as_deref() == Some("system_proxy_guardian_failed") {
                "system_proxy_guardian_failed"
            } else {
                "system_proxy_apply_failed"
            };
            self.error = Some(error.into());
            return Err(error.into());
        }
        self.active = true;
        self.error = None;
        Ok(())
    }
    fn apply(&self) -> Result<(), String> {
        let backend = self.backend.as_ref().unwrap();
        let desired = self.lease.as_ref().unwrap().journal.desired();
        for (index, value) in desired.iter().enumerate() {
            backend.write(index, Some(value))?;
        }
        backend.flush()?;
        if backend
            .read()?
            .iter()
            .map(|v| &v.effective)
            .ne(desired.iter())
        {
            return Err("system_proxy_apply_failed".into());
        }
        Ok(())
    }
    fn release(&mut self) -> Result<(), String> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if let Some(mut guardian) = self.guardian.take() {
            guardian.disarm();
        }
        match std::fs::remove_file(self.path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("system_proxy_journal_failed".into()),
        }
        self.lease = None;
        self.active = false;
        Ok(())
    }
    pub fn restore(&mut self) -> Result<(), String> {
        if self.lease.is_none() {
            return Ok(());
        }
        let result = self.restore_inner();
        if result.is_err() {
            self.error = Some("system_proxy_recovery_failed".into());
        }
        result
    }
    fn restore_inner(&mut self) -> Result<(), String> {
        let journal = &self.lease.as_ref().unwrap().journal;
        let backend = self.backend.as_ref().unwrap();
        let current = backend.read()?;
        let desired = journal.desired();
        if current.len() != journal.backend.len() {
            return Err("system_proxy_recovery_failed".into());
        }
        if current
            .iter()
            .zip(&journal.before)
            .zip(&desired)
            .any(|((now, old), ours)| now.effective != *ours && now.effective != old.effective)
        {
            // Another program/user changed the proxy. Relinquish the entire setting set.
            self.release()?;
            self.error = Some("system_proxy_changed".into());
            return Ok(());
        }
        backend.writable()?;
        for (index, before) in journal.before.iter().enumerate().rev() {
            backend.write(index, before.user.as_deref())?;
        }
        backend.flush()?;
        if backend.read()? != journal.before {
            return Err("system_proxy_recovery_failed".into());
        }
        self.release()?;
        self.error = None;
        Ok(())
    }
    pub fn observe(&mut self) {
        if !self.active {
            return;
        }
        if self.check_guardian().is_err() {
            return;
        }
        let Some(lease) = &self.lease else {
            return;
        };
        if let Ok(values) = self.backend.as_ref().unwrap().read() {
            if values
                .iter()
                .map(|v| &v.effective)
                .ne(lease.journal.desired().iter())
                && self.release().is_ok()
            {
                self.error = Some("system_proxy_changed".into());
            }
        }
    }

    /// Verify an existing lease without acquiring one or writing OS settings.
    /// Unlike the best-effort observer, errors never count as proof of ownership.
    pub(crate) fn check_retained(&mut self, port: u16) -> Result<RetainedProxy, String> {
        self.check_guardian()?;
        if !self.active || self.lease.is_none() {
            self.error = Some("system_proxy_changed".into());
            return Ok(RetainedProxy::Lost);
        }
        let lease = self.lease.as_ref().unwrap();
        if port == 0 || port != lease.journal.port {
            self.error = Some("system_proxy_incompatible".into());
            return Err("system_proxy_incompatible".into());
        }
        let result = (|| {
            let values = self
                .backend
                .as_ref()
                .ok_or("system_proxy_unavailable")?
                .read()?;
            if values.len() != lease.journal.backend.len() {
                return Err("system_proxy_recovery_failed".into());
            }
            if values
                .iter()
                .map(|value| &value.effective)
                .ne(lease.journal.desired().iter())
            {
                return Ok(false);
            }
            Ok(true)
        })();
        match result {
            Ok(true) => {
                self.error = None;
                Ok(RetainedProxy::Owned)
            }
            Ok(false) => match self.release() {
                Ok(()) => {
                    self.error = Some("system_proxy_changed".into());
                    Ok(RetainedProxy::Lost)
                }
                Err(error) => {
                    self.error = Some("system_proxy_recovery_failed".into());
                    Err(error)
                }
            },
            Err(error) => {
                self.error = Some("system_proxy_recovery_failed".into());
                Err(error)
            }
        }
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        let _ = self.restore();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if let Some(mut guardian) = self.guardian.take() {
            // Failed restoration keeps the journal. Unlock before EOF lets the
            // independent child make one bounded final recovery attempt.
            self.lease = None;
            guardian.recover_after_drop();
        }
    }
}

#[cfg(target_os = "linux")]
mod guardian;
#[cfg(target_os = "windows")]
#[path = "system_proxy/guardian_windows.rs"]
mod guardian;

/// The guardian's work once its owner is gone: restore from the journal only
/// when that journal is still the one this guardian was armed for.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn recover_owned(manager: &mut Manager, token: &str) -> Result<(), String> {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_secs(2);
    let lock = loop {
        match manager.lock() {
            Ok(lock) => break lock,
            Err(error) if error == "system_proxy_busy" => {
                if Instant::now() >= end {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    let Some(journal) = manager.read_journal()? else {
        return Ok(());
    };
    if journal.token.as_deref() != Some(token) {
        return Ok(());
    }
    manager.lease = Some(Lease {
        _file: lock,
        journal,
    });
    let result = manager.restore();
    // A failure preserves the journal; do not retry unboundedly in Manager::drop.
    manager.lease = None;
    result
}

#[cfg(target_os = "windows")]
mod wininet;

/// Call before GTK, single-instance setup, or any other application services.
pub fn run_guardian_if_requested() -> Option<i32> {
    if std::env::args_os().nth(1).as_deref()
        != Some(std::ffi::OsStr::new("--thronium-proxy-guardian"))
    {
        return None;
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        Some(if guardian::run().is_ok() { 0 } else { 2 })
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Some(2)
    }
}

#[cfg(target_os = "linux")]
mod kde;

#[cfg(target_os = "linux")]
mod gnome;

mod journal;
#[cfg(test)]
pub(crate) mod tests;
