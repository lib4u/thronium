use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

/// flock belongs to the open file description. O_CLOEXEC only closes the child
/// descriptor at exec; a concurrent fork can otherwise retain our lock after
/// this process closes its last descriptor. Release ownership explicitly.
pub(super) struct LibraryLock {
    file: File,
    creator_pid: u32,
}

impl LibraryLock {
    pub(super) fn acquire(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.try_lock_exclusive()
            .map_err(|_| "library_in_use".to_string())?;
        Ok(Self {
            file,
            creator_pid: std::process::id(),
        })
    }
}

impl Drop for LibraryLock {
    fn drop(&mut self) {
        // A fork child dropping its inherited object must only close its copy,
        // never unlock the parent's still-active Store. No logs or allocation.
        if self.creator_pid == std::process::id() {
            let _ = FileExt::unlock(&self.file);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
