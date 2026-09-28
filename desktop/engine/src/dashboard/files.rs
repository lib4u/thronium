//! Versioned dashboard assets. Extraction never modifies the currently served tree.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_ARCHIVE: usize = 32 * 1024 * 1024;
const MAX_UNPACKED: u64 = 64 * 1024 * 1024;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const OWNER: &[u8] = b"thronium-dashboard-v1\n";
const BOOTSTRAP_HTML: &str = include_str!("bootstrap.html");
/// Page texts for every interface language, then the page logic.
const BOOTSTRAP_JS: &str = concat!(include_str!("messages.js"), include_str!("bootstrap.js"));
const PLACEHOLDER: &str = "<!doctype html><html><meta charset=\"utf-8\"><title>Thronium</title><body data-thronium-page=\"placeholder\"><p id=\"dashboard-status\"></p><script src=\"/thronium-dashboard.js\"></script></body></html>";

fn io_error<T>(result: std::io::Result<T>) -> Result<T, String> {
    result.map_err(|_| "dashboard_files_unavailable".into())
}
fn invalid() -> String {
    "dashboard_invalid_archive".into()
}
fn version(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone)]
pub struct Assets {
    root: PathBuf,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub archive_sha256: String,
    pub installation_id: String,
    pub installed_at: u64,
    pub file_count: usize,
    pub unpacked_bytes: u64,
}

fn private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("dashboard_files_unavailable".into()),
        }
        let meta = io_error(fs::symlink_metadata(path))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("dashboard_files_unavailable".into());
        }
        Ok(())
    }
    // Windows: the same private list as the library, and never a junction.
    #[cfg(windows)]
    {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err("dashboard_files_unavailable".into()),
        }
        if !io_error(fs::symlink_metadata(path))?.is_dir() {
            return Err("dashboard_files_unavailable".into());
        }
        crate::ownership::restrict_directory(path).map_err(|_| "dashboard_files_unavailable".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("dashboard_platform_unsupported".into())
    }
}
fn check_directory(path: &Path) -> Result<(), String> {
    let meta = io_error(fs::symlink_metadata(path))?;
    if !meta.is_dir() {
        return Err("dashboard_files_unavailable".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("dashboard_files_unavailable".into());
        }
    }
    Ok(())
}
fn regular(path: &Path) -> Result<fs::Metadata, String> {
    let meta = io_error(fs::symlink_metadata(path))?;
    if !meta.is_file() {
        return Err("dashboard_files_unavailable".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 || meta.mode() & 0o077 != 0
        {
            return Err("dashboard_files_unavailable".into());
        }
    }
    Ok(meta)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    crate::nofollow::open_link_itself(&mut options);
    let mut file = io_error(options.open(path))?;
    io_error(file.write_all(bytes))?;
    io_error(file.sync_all())
}
fn read_small(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    if regular(path)?.len() > limit as u64 {
        return Err("dashboard_files_unavailable".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    crate::nofollow::open_link_itself(&mut options);
    let file = io_error(options.open(path))?;
    #[cfg(windows)]
    if !crate::nofollow::single_plain_file(&file) {
        return Err("dashboard_files_unavailable".into());
    }
    let mut bytes = Vec::new();
    io_error(file.take(limit as u64 + 1).read_to_end(&mut bytes))?;
    if bytes.len() > limit {
        return Err("dashboard_files_unavailable".into());
    }
    Ok(bytes)
}
fn sync_directory(path: &Path) -> Result<(), String> {
    // Windows cannot flush a directory; a replaced name there is already final.
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(not(windows))]
    io_error(io_error(File::open(path))?.sync_all())
}

impl Assets {
    pub fn new(data: &Path) -> Self {
        Self {
            root: data.join("web-dashboard"),
        }
    }
    /// What the Core serves: the `current` link on Unix, the version the
    /// `current` pointer file names on Windows.
    pub fn serving_path(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.current()
                .ok()
                .flatten()
                .unwrap_or_else(|| self.versions().join("seed"))
        }
        #[cfg(not(windows))]
        self.root.join("current")
    }
    /// Whether a running Core serves these files: on Windows it keeps the
    /// version it started with even after another is installed.
    pub fn serves(&self, path: &Path) -> bool {
        #[cfg(windows)]
        {
            path.parent() == Some(self.versions().as_path())
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == "seed" || version(name))
        }
        #[cfg(not(windows))]
        {
            path == self.serving_path()
        }
    }
    fn versions(&self) -> PathBuf {
        self.root.join("versions")
    }

    fn prepare_root(&self) -> Result<(), String> {
        private_directory(&self.root)?;
        let marker = self.root.join("owner");
        if !marker
            .try_exists()
            .map_err(|_| "dashboard_files_unavailable")?
        {
            if io_error(fs::read_dir(&self.root))?.next().is_some() {
                return Err("dashboard_files_unavailable".into());
            }
            write_new(&marker, OWNER)?;
        }
        if read_small(&marker, 128)? != OWNER {
            return Err("dashboard_files_unavailable".into());
        }
        private_directory(&self.versions())
    }
    fn lock(&self) -> Result<File, String> {
        let path = self.root.join("install.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        crate::nofollow::open_link_itself(&mut options);
        let file = io_error(options.open(&path))?;
        regular(&path)?;
        file.try_lock_exclusive().map_err(|_| "dashboard_busy")?;
        Ok(file)
    }
    #[cfg(windows)]
    fn current(&self) -> Result<Option<PathBuf>, String> {
        let pointer = self.root.join("current");
        match fs::symlink_metadata(&pointer) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("dashboard_files_unavailable".into()),
            Ok(_) => {}
        }
        let bytes = read_small(&pointer, 128)?;
        let name = std::str::from_utf8(&bytes).map_err(|_| "dashboard_files_unavailable")?;
        if name != "seed" && !version(name) {
            return Err("dashboard_files_unavailable".into());
        }
        let path = self.versions().join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("dashboard_files_unavailable".into()),
            Ok(_) => check_directory(&path).map(|()| Some(path)),
        }
    }
    #[cfg(not(windows))]
    fn current(&self) -> Result<Option<PathBuf>, String> {
        let link = self.root.join("current");
        let meta = match fs::symlink_metadata(&link) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("dashboard_files_unavailable".into()),
        };
        if !meta.file_type().is_symlink() {
            return Err("dashboard_files_unavailable".into());
        }
        let target = io_error(fs::read_link(link))?;
        let name = target
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("dashboard_files_unavailable")?;
        if target.parent() != Some(Path::new("versions")) || (name != "seed" && !version(name)) {
            return Err("dashboard_files_unavailable".into());
        }
        let path = self.root.join(target);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("dashboard_files_unavailable".into()),
            Ok(_) => check_directory(&path)?,
        }
        Ok(Some(path))
    }
    fn point_to(&self, name: &str) -> Result<(), String> {
        #[cfg(unix)]
        {
            let temp = self.root.join(format!("current-{}", uuid::Uuid::new_v4()));
            io_error(std::os::unix::fs::symlink(
                Path::new("versions").join(name),
                &temp,
            ))?;
            let result = io_error(fs::rename(&temp, self.serving_path()));
            if result.is_err() {
                let _ = fs::remove_file(&temp);
            }
            result?;
            sync_directory(&self.root)
        }
        // Windows: a pointer file replaced whole, since links need privileges.
        #[cfg(windows)]
        {
            let temp = self.root.join(format!("current-{}", uuid::Uuid::new_v4()));
            write_new(&temp, name.as_bytes())?;
            let result = io_error(fs::rename(&temp, self.root.join("current")));
            if result.is_err() {
                let _ = fs::remove_file(&temp);
            }
            result
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = name;
            Err("dashboard_platform_unsupported".into())
        }
    }
    /// A local nonempty tree suppresses the Core's automatic external download.
    pub fn ensure(&self) -> Result<(), String> {
        self.prepare_root()?;
        if self.current()?.is_some() {
            return Ok(());
        }
        let _lock = self.lock()?;
        if self.current()?.is_some() {
            return Ok(());
        }
        let seed = self.versions().join("seed");
        private_directory(&seed)?;
        for (name, content) in [
            ("index.html", PLACEHOLDER),
            ("thronium.html", BOOTSTRAP_HTML),
            ("thronium-bootstrap.js", BOOTSTRAP_JS),
        ] {
            let file = seed.join(name);
            if file
                .try_exists()
                .map_err(|_| "dashboard_files_unavailable")?
            {
                if read_small(&file, 16 * 1024)? != content.as_bytes() {
                    return Err("dashboard_files_unavailable".into());
                }
            } else {
                write_new(&file, content.as_bytes())?;
            }
        }
        sync_directory(&seed)?;
        sync_directory(&self.versions())?;
        self.point_to("seed")
    }
    pub fn inspect(&self) -> Result<Option<Receipt>, String> {
        if !self
            .root
            .try_exists()
            .map_err(|_| "dashboard_files_unavailable")?
        {
            return Ok(None);
        }
        check_directory(&self.root)?;
        check_directory(&self.versions())?;
        if read_small(&self.root.join("owner"), 128)? != OWNER {
            return Err("dashboard_files_unavailable".into());
        }
        let Some(current) = self.current()? else {
            return Ok(None);
        };
        if current.file_name().is_some_and(|name| name == "seed") {
            return Ok(None);
        }
        if regular(&current.join("index.html"))?.len() == 0 {
            return Err("dashboard_files_unavailable".into());
        }
        let bytes = read_small(&current.join("receipt.json"), 4096)?;
        let receipt: Receipt =
            serde_json::from_slice(&bytes).map_err(|_| "dashboard_files_unavailable")?;
        if !version(&receipt.archive_sha256)
            || !version(&receipt.installation_id)
            || current.file_name().and_then(|s| s.to_str())
                != Some(receipt.installation_id.as_str())
            || receipt.file_count == 0
            || receipt.file_count > MAX_ENTRIES
            || receipt.unpacked_bytes > MAX_UNPACKED
        {
            return Err("dashboard_files_unavailable".into());
        }
        Ok(Some(receipt))
    }
    pub fn install(&self, bytes: &[u8], cancelled: impl Fn() -> bool) -> Result<Receipt, String> {
        if cancelled() {
            return Err("dashboard_cancelled".into());
        }
        if bytes.is_empty() || bytes.len() > MAX_ARCHIVE {
            return Err(invalid());
        }
        self.ensure()?;
        let _lock = self.lock()?;
        let digest = Sha256::digest(bytes);
        let hash = format!("{digest:x}");
        let installation_id = format!(
            "{:x}",
            Sha256::new()
                .chain_update(digest)
                .chain_update(BOOTSTRAP_HTML)
                .chain_update([0])
                .chain_update(BOOTSTRAP_JS)
                .chain_update(uuid::Uuid::new_v4().as_bytes())
                .finalize()
        );
        let destination = self.versions().join(&installation_id);
        // Validate every archive before switching, including a repeated version.
        let mut builder = tempfile::Builder::new();
        builder.prefix("extract-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let stage = builder
            .tempdir_in(self.versions())
            .map_err(|_| "dashboard_files_unavailable")?;
        let (file_count, unpacked_bytes) = extract(bytes, stage.path(), &cancelled)?;
        write_new(
            &stage.path().join("thronium.html"),
            BOOTSTRAP_HTML.as_bytes(),
        )?;
        write_new(
            &stage.path().join("thronium-bootstrap.js"),
            BOOTSTRAP_JS.as_bytes(),
        )?;
        let receipt = Receipt {
            archive_sha256: hash.clone(),
            installation_id: installation_id.clone(),
            installed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            file_count,
            unpacked_bytes,
        };
        write_new(
            &stage.path().join("receipt.json"),
            &serde_json::to_vec(&receipt).map_err(|_| "dashboard_files_unavailable")?,
        )?;
        sync_directory(stage.path())?;
        if destination
            .try_exists()
            .map_err(|_| "dashboard_files_unavailable")?
        {
            return Err("dashboard_files_unavailable".into());
        }
        io_error(fs::rename(stage.path(), &destination))?;
        sync_directory(&self.versions())?;
        if cancelled() {
            // Never served: the unused version must not stay on disk.
            let _ = fs::remove_dir_all(&destination);
            let _ = sync_directory(&self.versions());
            return Err("dashboard_cancelled".into());
        }
        let previous = self.current()?;
        self.point_to(&installation_id)?;
        self.prune(&destination, previous.as_deref());
        self.inspect()?.ok_or("dashboard_files_unavailable".into())
    }
    fn prune(&self, current: &Path, previous: Option<&Path>) {
        let Ok(entries) = fs::read_dir(self.versions()) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !version(name)
                || path == current
                || previous == Some(path.as_path())
                || check_directory(&path).is_err()
            {
                continue;
            }
            let Ok(bytes) = read_small(&path.join("receipt.json"), 4096) else {
                continue;
            };
            let Ok(receipt) = serde_json::from_slice::<Receipt>(&bytes) else {
                continue;
            };
            if receipt.installation_id == name {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

mod archive;
#[cfg(all(test, unix))]
mod tests;
#[cfg(all(test, windows))]
mod windows_tests;
use archive::extract;
