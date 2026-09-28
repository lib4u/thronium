//! Windows counterparts of `O_NOFOLLOW` and the `nlink == 1` check.
//!
//! With `FILE_FLAG_OPEN_REPARSE_POINT` a symbolic link or junction is opened as
//! itself, so the `is_file()` check every caller already makes rejects it,
//! just as `O_NOFOLLOW` makes the open fail on Unix.
use std::fs::{File, OpenOptions};

pub(crate) fn open_link_itself(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

/// One name for the data and no reparse point: what `nlink() == 1` and a
/// no-follow open prove on Unix.
pub(crate) fn single_plain_file(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let read = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    read != 0
        && info.nNumberOfLinks == 1
        && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn links_are_opened_as_themselves_and_a_second_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        std::fs::write(&path, b"data").unwrap();
        let open = |p: &std::path::Path| {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            super::open_link_itself(&mut options);
            options.open(p)
        };
        assert!(super::single_plain_file(&open(&path).unwrap()));
        std::fs::hard_link(&path, dir.path().join("second")).unwrap();
        assert!(!super::single_plain_file(&open(&path).unwrap()));
    }
}
