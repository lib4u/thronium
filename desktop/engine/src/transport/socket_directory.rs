//! Filesystem sockets need short absolute paths, independent of the Core's cwd.
//! Keep the caller's temp location when usable; only an unrepresentable socket
//! path falls back to the platform's short temp directory.
use std::{io, path::Path};

pub(super) const SOCKET_NAME: &str = "core.sock";

pub(super) fn create(preferred: &Path) -> io::Result<tempfile::TempDir> {
    let directory = private(preferred)?;
    if usable(directory.path()) {
        return Ok(directory);
    }
    // Drop only our empty, newly created directory before taking the fallback.
    directory.close()?;
    let fallback = private(Path::new("/tmp"))?;
    if !usable(fallback.path()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "core_socket_path",
        ));
    }
    Ok(fallback)
}

fn private(root: &Path) -> io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    // Resolving the root also handles relative TMPDIR and long symlink aliases.
    let root = root.canonicalize()?;
    let directory = tempfile::Builder::new()
        .prefix("thronium-")
        .tempdir_in(root)?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn usable(directory: &Path) -> bool {
    let path = directory.join(SOCKET_NAME);
    // The Core receives this path as a UTF-8 environment value. Do not silently
    // change a non-UTF-8 path with to_string_lossy(). The OS supplies its limit.
    path.to_str().is_some() && std::os::unix::net::SocketAddr::from_pathname(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt, net::UnixListener};

    fn bind_and_close(root: &Path, fallback: bool) {
        let directory = create(root).unwrap();
        let path = directory.path().join(SOCKET_NAME);
        assert!(path.is_absolute());
        assert_eq!(!path.starts_with(root.canonicalize().unwrap()), fallback);
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let listener = UnixListener::bind(&path).expect("real OS socket must fit");
        drop(listener);
        directory.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn short_temp_root_keeps_its_private_socket_and_cleans_up() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        bind_and_close(root.path(), false);
        assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
    }

    #[test]
    fn long_and_non_utf8_roots_fall_back_without_leaking_a_directory() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        for name in [
            std::ffi::OsString::from("long".repeat(45)),
            std::ffi::OsString::from_vec(vec![0xff]),
        ] {
            let preferred = root.path().join(name);
            std::fs::create_dir(&preferred).unwrap();
            bind_and_close(&preferred, true);
            assert!(std::fs::read_dir(&preferred).unwrap().next().is_none());
        }
    }

    #[test]
    fn invalid_temp_root_is_an_error_instead_of_an_unrelated_fallback() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        assert_eq!(
            create(&root.path().join("missing")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
