use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
use zip::{write::SimpleFileOptions, ZipWriter};

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in files {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn install(assets: &Assets, html: &[u8]) -> Receipt {
    assets
        .install(
            &archive(&[
                ("site/index.html", html),
                ("site/assets/main.js", b"void 0;"),
            ]),
            || false,
        )
        .unwrap()
}
fn target(assets: &Assets) -> PathBuf {
    fs::read_link(assets.serving_path()).unwrap()
}

#[test]
fn inspection_of_missing_installation_does_not_create_files() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assert!(assets.inspect().unwrap().is_none());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}
#[test]
fn seed_is_private_and_nonempty_without_core_auto_update_marker() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assets.ensure().unwrap();
    assets.ensure().unwrap();
    assert_eq!(target(&assets), Path::new("versions/seed"));
    assert!(assets.inspect().unwrap().is_none());
    assert!(!assets.serving_path().join(".etag").exists());
    assert_eq!(
        fs::read_to_string(assets.serving_path().join("index.html")).unwrap(),
        PLACEHOLDER
    );
    assert_eq!(fs::metadata(&assets.root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(assets.serving_path().join("index.html"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}
#[test]
fn wrapped_archive_is_served_with_bootstrap_and_an_immutable_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    let first = install(&assets, b"first");
    let previous = target(&assets);
    assert_eq!(first.file_count, 2);
    assert_eq!(first.unpacked_bytes, 12);
    assert!(version(&first.archive_sha256));
    let next = install(&assets, b"second");
    assert_ne!(first.archive_sha256, next.archive_sha256);
    assert_ne!(target(&assets), previous);
    assert_eq!(
        fs::read(assets.root.join(&previous).join("index.html")).unwrap(),
        b"first"
    );
    assert_eq!(
        fs::read(assets.serving_path().join("index.html")).unwrap(),
        b"second"
    );
    assert_eq!(
        fs::read_to_string(assets.serving_path().join("thronium-bootstrap.js")).unwrap(),
        BOOTSTRAP_JS
    );
    assert_eq!(
        assets.inspect().unwrap().unwrap().archive_sha256,
        next.archive_sha256
    );
    assert!(!assets.serving_path().join(".etag").exists());
    let repeated = install(&assets, b"second");
    assert_eq!(repeated.archive_sha256, next.archive_sha256);
    assert_ne!(repeated.installation_id, next.installation_id);
    assert!(repeated.installed_at >= next.installed_at);
    assert!(!assets.root.join(previous).exists());
    assert!(!fs::read_dir(assets.versions()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("extract-")));
}
#[test]
fn malformed_and_reserved_archives_leave_the_prior_pointer_and_files_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    install(&assets, b"working");
    let previous = target(&assets);
    for bytes in [
        b"not ZIP".to_vec(),
        archive(&[]),
        archive(&[("missing-index.txt", b"x")]),
        archive(&[("index.html", b"")]),
        archive(&[("index.html", b"x"), (".etag", b"force-download")]),
        archive(&[
            ("index.html", b"x"),
            ("thronium.html", b"untrusted-bootstrap"),
        ]),
        archive(&[("index.html", b"x"), ("receipt.json", b"{}")]),
    ] {
        assert!(assets.install(&bytes, || false).is_err());
        assert_eq!(target(&assets), previous);
        assert_eq!(
            fs::read(assets.serving_path().join("index.html")).unwrap(),
            b"working"
        );
    }
}
#[test]
fn archive_paths_cannot_escape_staging_or_install_links() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    install(&assets, b"working");
    let previous = target(&assets);
    for path in [
        "../escape",
        "/absolute",
        "C:/drive",
        "dir\\backslash",
        "dir/../escape",
        "dir//empty",
        "dir/./dot",
    ] {
        let bytes = archive(&[("index.html", b"x"), (path, b"forbidden")]);
        assert!(assets.install(&bytes, || false).is_err(), "{path}");
        assert_eq!(target(&assets), previous);
    }
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("index.html", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"x").unwrap();
    writer
        .add_symlink("asset", "../outside", SimpleFileOptions::default())
        .unwrap();
    assert!(assets
        .install(&writer.finish().unwrap().into_inner(), || false)
        .is_err());
    assert!(!directory.path().join("escape").exists());
}
#[test]
fn archive_size_and_declared_unpacked_file_limits_are_checked_before_extraction() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assets.ensure().unwrap();
    assert_eq!(
        assets
            .install(&vec![0; MAX_ARCHIVE + 1], || false)
            .err()
            .as_deref(),
        Some("dashboard_invalid_archive")
    );
    let mut bytes = archive(&[("index.html", b"x")]);
    let central = bytes.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
    bytes[central + 24..central + 28].copy_from_slice(&((MAX_FILE + 1) as u32).to_le_bytes());
    assert!(assets.install(&bytes, || false).is_err());
    assert_eq!(target(&assets), Path::new("versions/seed"));
}
#[test]
fn cancellation_before_or_during_extraction_keeps_the_working_version() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    install(&assets, b"working");
    let previous = target(&assets);
    let bytes = archive(&[("index.html", b"next"), ("asset.js", b"next")]);
    assert_eq!(
        assets.install(&bytes, || true).err().as_deref(),
        Some("dashboard_cancelled")
    );
    let calls = Cell::new(0);
    assert_eq!(
        assets
            .install(&bytes, || {
                calls.set(calls.get() + 1);
                calls.get() > 2
            })
            .err()
            .as_deref(),
        Some("dashboard_cancelled")
    );
    assert_eq!(target(&assets), previous);
    assert!(!fs::read_dir(assets.versions()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("extract-")));
}
#[test]
fn cancellation_after_the_version_is_written_removes_it() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    install(&assets, b"working");
    let previous = target(&assets);
    let versions = || fs::read_dir(assets.versions()).unwrap().count();
    let before = versions();
    let bytes = archive(&[("index.html", b"next")]);
    // The last cancellation check follows the rename into versions/.
    let probe = tempfile::tempdir().unwrap();
    let counting = Assets::new(probe.path());
    let total = Cell::new(0);
    counting
        .install(&bytes, || {
            total.set(total.get() + 1);
            false
        })
        .unwrap();
    let calls = Cell::new(0);
    assert_eq!(
        assets
            .install(&bytes, || {
                calls.set(calls.get() + 1);
                calls.get() == total.get()
            })
            .err()
            .as_deref(),
        Some("dashboard_cancelled")
    );
    assert_eq!(target(&assets), previous);
    assert_eq!(versions(), before);
}
#[test]
fn foreign_directory_and_escaping_pointer_are_never_adopted() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    private_directory(&assets.root).unwrap();
    fs::write(assets.root.join("foreign"), b"keep").unwrap();
    assert!(assets.ensure().is_err());
    assert_eq!(fs::read(assets.root.join("foreign")).unwrap(), b"keep");
    fs::remove_file(assets.root.join("foreign")).unwrap();
    assets.ensure().unwrap();
    fs::remove_file(assets.serving_path()).unwrap();
    symlink("../../outside", assets.serving_path()).unwrap();
    assert!(assets.ensure().is_err());
    assert!(assets.inspect().is_err());
    assert!(!directory.path().join("outside").exists());
}
#[test]
fn concurrent_install_and_insecure_owned_directory_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assets.ensure().unwrap();
    let lock = assets.lock().unwrap();
    assert_eq!(
        assets
            .install(&archive(&[("index.html", b"x")]), || false)
            .err()
            .as_deref(),
        Some("dashboard_busy")
    );
    drop(lock);
    fs::set_permissions(&assets.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(assets.inspect().is_err());
    assert!(assets.ensure().is_err());
}

#[test]
fn same_archive_repairs_removed_assets_and_prunes_only_old_owned_versions() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path());
    let first = install(&assets, b"working");
    let first_path = assets.current().unwrap().unwrap();
    fs::remove_file(first_path.join("index.html")).unwrap();
    assert!(assets.inspect().is_err());
    let repaired = install(&assets, b"working");
    assert_eq!(first.archive_sha256, repaired.archive_sha256);
    assert_ne!(first.installation_id, repaired.installation_id);
    assert_eq!(
        fs::read(assets.serving_path().join("index.html")).unwrap(),
        b"working"
    );
    // A non-manager directory is left alone even when older versions are pruned.
    let foreign = assets.versions().join("user-kept");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("note"), b"keep").unwrap();
    install(&assets, b"newest");
    assert!(!first_path.exists());
    assert_eq!(fs::read(foreign.join("note")).unwrap(), b"keep");
}

#[test]
fn missing_owned_version_is_reseeded_without_following_a_foreign_pointer() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path());
    install(&assets, b"working");
    fs::remove_dir_all(assets.current().unwrap().unwrap()).unwrap();
    assert!(assets.inspect().unwrap().is_none());
    assets.ensure().unwrap();
    assert_eq!(target(&assets), Path::new("versions/seed"));
    assert_eq!(
        fs::read_to_string(assets.serving_path().join("index.html")).unwrap(),
        PLACEHOLDER
    );
}
