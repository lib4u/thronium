//! Immutable content and a small atomic reference compatible with Assets::prepare.
use super::{index::Index, Kind, Selection, LIMIT};
use crate::geodata::{default_url, digest, write, Assets};
use serde::Serialize;
use serde_json::json;
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

impl Selection {
    pub(super) fn checked(mut self) -> Result<Self, String> {
        self.url = self.url.trim().to_owned();
        if self.url.is_empty() {
            self.url = default_url(self.kind.sites()).into();
        }
        if self.url.len() > 8192 || self.url.chars().any(char::is_control) {
            return Err("geodata_url_invalid".into());
        }
        let url = reqwest::Url::parse(&self.url).map_err(|_| "geodata_url_invalid")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("geodata_url_invalid".into());
        }
        Ok(self)
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub kind: Kind,
    pub url: String,
    pub state: &'static str,
    pub hash: Option<String>,
    pub bytes: Option<usize>,
    pub categories: Option<usize>,
    pub entries: Option<usize>,
    pub updated_at: Option<u64>,
}
pub(super) struct Files {
    pub selection: Selection,
    assets: Assets,
}
pub(super) struct Staged {
    pub files: Files,
    pub index: Index,
    pub hash: String,
    pub bytes: usize,
}
fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "geodata_missing")?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err("geodata_invalid".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    crate::nofollow::open_link_itself(&mut options);
    let mut bytes = Vec::new();
    options
        .open(path)
        .map_err(|_| "geodata_missing")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "geodata_invalid")?;
    if bytes.len() > limit {
        return Err("geodata_invalid".into());
    }
    Ok(bytes)
}
impl Files {
    pub fn new(root: &Path, selection: Selection) -> Result<Self, String> {
        let selection = selection.checked()?;
        let mut assets = Assets::new(root, None);
        assets.config[if selection.kind.sites() {
            "Geositeurl"
        } else {
            "Geoipurl"
        }] = json!(selection.url);
        Ok(Self { selection, assets })
    }
    pub fn belongs_to(&self, root: &Path) -> bool {
        self.assets.directory == root.join("xray-assets")
    }
    pub fn manifest(&self) -> PathBuf {
        self.assets.manifest(self.selection.kind.sites())
    }
    pub fn matches(&self, assets: &Assets) -> bool {
        self.manifest() == assets.manifest(self.selection.kind.sites())
    }
    pub fn status(&self) -> Result<Status, String> {
        let mut status = Status {
            kind: self.selection.kind,
            url: self.selection.url.clone(),
            state: "missing",
            hash: None,
            bytes: None,
            categories: None,
            entries: None,
            updated_at: None,
        };
        let reference = self.manifest();
        match std::fs::symlink_metadata(&reference) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(status),
            Err(_) => return Err("geodata_missing".into()),
            Ok(_) => {}
        }
        let loaded = (|| {
            let hash =
                String::from_utf8(bounded(&reference, 64)?).map_err(|_| "geodata_invalid")?;
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("geodata_invalid".to_owned());
            }
            let bytes = bounded(&self.assets.directory.join(format!("{hash}.dat")), LIMIT)?;
            if digest(&bytes) != hash {
                return Err("geodata_invalid".into());
            }
            let index = Index::parse(&bytes, self.selection.kind)?;
            Ok((hash, bytes.len(), index))
        })();
        match loaded {
            Ok((hash, bytes, index)) => {
                status.state = "ready";
                status.hash = Some(hash);
                status.bytes = Some(bytes);
                status.categories = Some(index.count());
                status.entries = Some(index.entries);
                status.updated_at = std::fs::metadata(reference)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
            }
            Err(_) => status.state = "invalid",
        }
        Ok(status)
    }
    pub fn stage(self, bytes: &[u8], cancelled: impl Fn() -> bool) -> Result<Staged, String> {
        if cancelled() {
            return Err("geodata_cancelled".into());
        }
        let index = Index::parse(bytes, self.selection.kind)?;
        if cancelled() {
            return Err("geodata_cancelled".into());
        }
        std::fs::create_dir_all(&self.assets.directory).map_err(|_| "geodata_write_failed")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta =
                std::fs::metadata(&self.assets.directory).map_err(|_| "geodata_write_failed")?;
            if meta.uid() != unsafe { libc::geteuid() } {
                return Err("geodata_write_failed".into());
            }
            std::fs::set_permissions(
                &self.assets.directory,
                std::fs::Permissions::from_mode(0o700),
            )
            .map_err(|_| "geodata_write_failed")?;
        }
        let hash = digest(bytes);
        let path = self.assets.directory.join(format!("{hash}.dat"));
        if !bounded(&path, LIMIT).is_ok_and(|old| digest(&old) == hash) {
            write(&path, bytes)?;
        }
        sync_directory(&self.assets.directory)?;
        if cancelled() {
            return Err("geodata_cancelled".into());
        }
        Ok(Staged {
            files: self,
            index,
            hash,
            bytes: bytes.len(),
        })
    }
}
impl Staged {
    // Called only after validating current saved references while holding the Engine lock.
    pub fn commit(self) -> Result<Status, String> {
        let path = self.files.manifest();
        write(&path, self.hash.as_bytes())?;
        sync_directory(&self.files.assets.directory)?;
        Ok(Status {
            kind: self.files.selection.kind,
            url: self.files.selection.url,
            state: "ready",
            hash: Some(self.hash),
            bytes: Some(self.bytes),
            categories: Some(self.index.count()),
            entries: Some(self.index.entries),
            updated_at: std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
        })
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    // Windows has no directory handle to flush: a rename there is already
    // ordered against the file data it publishes.
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "geodata_write_failed")?;
    Ok(())
}
