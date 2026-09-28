//! The on-disk journal of the proxy values Thronium replaced, its lock and crash recovery.
use super::*;

impl Manager {
    pub(crate) fn recover_on_open(&mut self) {
        if self.directory.is_some() && self.path().symlink_metadata().is_ok() {
            if let Err(error) = self.recover() {
                // An active owner in another library holds the global lock.
                if error != "system_proxy_busy" {
                    self.error = Some(error);
                }
            }
        }
    }
    pub(crate) fn path(&self) -> PathBuf {
        self.directory
            .as_ref()
            .expect("proxy directory")
            .join("recovery.json")
    }
    pub(super) fn lock(&self) -> Result<ProxyLock, String> {
        let directory = self.directory.as_ref().ok_or("system_proxy_unavailable")?;
        std::fs::create_dir_all(directory).map_err(|_| "system_proxy_journal_failed")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta =
                std::fs::symlink_metadata(directory).map_err(|_| "system_proxy_journal_failed")?;
            if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
                return Err("system_proxy_journal_failed".into());
            }
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "system_proxy_journal_failed")?;
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        crate::nofollow::open_link_itself(&mut options);
        let file = options
            .open(directory.join("owner.lock"))
            .map_err(|_| "system_proxy_journal_failed")?;
        #[cfg(windows)]
        if !crate::nofollow::single_plain_file(&file) {
            return Err("system_proxy_journal_failed".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta = file.metadata().map_err(|_| "system_proxy_journal_failed")?;
            if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
                return Err("system_proxy_journal_failed".into());
            }
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "system_proxy_journal_failed")?;
        }
        file.try_lock_exclusive().map_err(|_| "system_proxy_busy")?;
        Ok(ProxyLock {
            file,
            creator_pid: std::process::id(),
        })
    }
    pub(crate) fn recover(&mut self) -> Result<(), String> {
        let file = self.lock()?;
        let Some(journal) = self.read_journal()? else {
            return Ok(());
        };
        self.lease = Some(Lease {
            _file: file,
            journal,
        });
        self.restore()
    }
    pub(super) fn read_journal(&self) -> Result<Option<Journal>, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let directory = self.directory.as_ref().ok_or("system_proxy_unavailable")?;
            let meta =
                std::fs::symlink_metadata(directory).map_err(|_| "system_proxy_recovery_failed")?;
            if !meta.is_dir()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                return Err("system_proxy_recovery_failed".into());
            }
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        crate::nofollow::open_link_itself(&mut options);
        let file = match options.open(self.path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("system_proxy_recovery_failed".into()),
        };
        let meta = file
            .metadata()
            .map_err(|_| "system_proxy_recovery_failed")?;
        if !meta.is_file() || meta.len() > 65536 {
            return Err("system_proxy_recovery_failed".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
                || meta.nlink() != 1
            {
                return Err("system_proxy_recovery_failed".into());
            }
        }
        #[cfg(windows)]
        if !crate::nofollow::single_plain_file(&file) {
            return Err("system_proxy_recovery_failed".into());
        }
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "system_proxy_recovery_failed")?;
        if bytes.len() > 65536 {
            return Err("system_proxy_recovery_failed".into());
        }
        let journal: Journal =
            serde_json::from_slice(&bytes).map_err(|_| "system_proxy_recovery_failed")?;
        if journal.version != 1
            || journal.port == 0
            || journal.before.len() != journal.backend.len()
            || self.backend.as_ref().map(|b| b.kind()) != Some(journal.backend)
            || journal.token.as_ref().is_some_and(|t| {
                t.len() != 32
                    || !t
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("system_proxy_recovery_failed".into());
        }
        Ok(Some(journal))
    }
    pub fn retry_recovery(&mut self) -> Result<(), String> {
        if self.lease.is_some() {
            return self.restore();
        }
        if self.backend.is_some() && self.path().exists() {
            return self.recover();
        }
        self.error = None;
        Ok(())
    }
    pub(crate) fn start_guardian(&mut self) -> Result<(), String> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if self.guardian_required {
            self.guardian = Some(guardian::Guardian::spawn(
                self.lease
                    .as_ref()
                    .unwrap()
                    .journal
                    .token
                    .as_deref()
                    .unwrap(),
            )?);
        }
        Ok(())
    }
    pub(crate) fn guardian_alive(&mut self) -> Result<(), String> {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if self.guardian_required && !self.guardian.as_mut().is_some_and(|g| g.alive()) {
            return Err("system_proxy_guardian_failed".into());
        }
        Ok(())
    }
    pub(crate) fn check_guardian(&mut self) -> Result<(), String> {
        if self.active && self.guardian_alive().is_err() {
            self.restore()?;
            if self.error.as_deref() == Some("system_proxy_changed") {
                return Err("system_proxy_changed".into());
            }
            self.error = Some("system_proxy_guardian_failed".into());
            return Err("system_proxy_guardian_failed".into());
        }
        Ok(())
    }
}
