//! Replacement durability and deterministic, per-Store test faults.
use std::path::Path;
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    BeforeRename,
    AfterRename,
    DirectorySync,
}
#[derive(Default)]
pub(super) struct Durability {
    pub uncertain: bool,
    #[cfg(test)]
    pub fault: Option<Fault>,
}
impl Durability {
    #[cfg(test)]
    pub fn fail(&mut self, point: Fault) -> Result<(), String> {
        if self.fault == Some(point) {
            self.fault = None;
            Err("store_injected_failure".into())
        } else {
            Ok(())
        }
    }
}
/// Publishes the written replacement, so that after this call the new file is
/// the one on disk even if the machine loses power.
///
/// Linux renames and then syncs the directory that holds the name. Windows has
/// no directory to sync: the replacement itself is asked to write through, and
/// that is what lets a spent HOTP counter survive a power cut there.
pub(super) fn replace(file: tempfile::NamedTempFile, path: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "windows"))]
    {
        file.persist(path).map_err(|_| "store_write_failed")?;
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        // The handle must be closed before the file can be moved over another.
        let (handle, temporary) = file.keep().map_err(|_| "store_write_failed")?;
        drop(handle);
        let result = with_retries(
            || write_through(&temporary, path),
            |round| std::thread::sleep(std::time::Duration::from_millis(20 << round)),
        )
        .map_err(|_| "store_write_failed".to_string());
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

/// Antivirus scanners and indexers hold a just-written file for a moment; a
/// replace that meets them is tried again a few times (about 0.3 s in all),
/// any other refusal at once.
#[cfg(any(target_os = "windows", test))]
fn with_retries(
    mut attempt: impl FnMut() -> Result<(), u32>,
    mut pause: impl FnMut(u32),
) -> Result<(), u32> {
    const ACCESS_DENIED: u32 = 5;
    const SHARING_VIOLATION: u32 = 32;
    let mut round = 0;
    loop {
        match attempt() {
            Err(ACCESS_DENIED | SHARING_VIOLATION) if round < 4 => pause(round),
            other => return other,
        }
        round += 1;
    }
}

/// The Windows error code on failure.
#[cfg(target_os = "windows")]
fn write_through(from: &Path, to: &Path) -> Result<(), u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
    let ok = unsafe {
        MoveFileExW(
            wide(from).as_ptr(),
            wide(to).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())?;
    // Windows published the name write-through in `replace`; a directory there
    // cannot be flushed, and nothing is left to confirm.
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The same contract on every platform: after the call the destination
    /// holds the new bytes and the temporary name is gone.
    #[test]
    fn a_replacement_publishes_the_new_bytes_and_leaves_no_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("library.json");
        std::fs::write(&path, b"old").unwrap();
        let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        file.write_all(b"new").unwrap();
        file.as_file().sync_all().unwrap();
        replace(file, &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let left: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["library.json"]);
    }
}

#[cfg(test)]
mod retry_tests {
    use super::with_retries;
    #[test]
    fn only_a_briefly_held_file_is_tried_again_and_only_a_few_times() {
        let mut calls = 0;
        let mut pauses = Vec::new();
        let held_twice = with_retries(
            || {
                calls += 1;
                if calls <= 2 {
                    Err(32)
                } else {
                    Ok(())
                }
            },
            |round| pauses.push(round),
        );
        assert_eq!((held_twice, calls, pauses), (Ok(()), 3, vec![0, 1]));
        let mut calls = 0;
        assert_eq!(
            with_retries(
                || {
                    calls += 1;
                    Err(5)
                },
                |_| {}
            ),
            Err(5)
        );
        assert_eq!(calls, 5);
        let mut calls = 0;
        // A missing directory or a full disk is not waited out.
        assert_eq!(
            with_retries(
                || {
                    calls += 1;
                    Err(3)
                },
                |_| {}
            ),
            Err(3)
        );
        assert_eq!(calls, 1);
    }
}
