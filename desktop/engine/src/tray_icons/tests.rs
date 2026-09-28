use super::*;
use crate::{
    backups::legacy::{self, Scopes},
    legacy_backup::{Parts, SourceArchive},
    Engine,
};
use serde_json::json;

fn png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let pixels = image::RgbaImage::from_pixel(width, height, image::Rgba(color));
    let mut data = Cursor::new(Vec::new());
    pixels.write_to(&mut data, image::ImageFormat::Png).unwrap();
    data.into_inner()
}
fn source(files: &[(&str, Vec<u8>)]) -> SourceArchive {
    SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            icons: true,
            ..Default::default()
        },
        database: None,
        files: files
            .iter()
            .map(|(name, bytes)| (name.to_string(), Some(bytes.clone())))
            .collect(),
    }
}
fn choose(e: &mut Engine, s: &SourceArchive) -> crate::backups::Preview {
    let preview = e.preview_legacy_import(legacy::prepare(s)).unwrap();
    assert!(!preview.legacy.as_ref().unwrap()["canApply"]
        .as_bool()
        .unwrap());
    e.legacy_backup_scopes(
        &preview.token,
        Scopes {
            profiles: false,
            icons: true,
            ..Default::default()
        },
    )
    .unwrap()
}
#[test]
fn bounded_png_decoding_serialization_and_shared_library_clones() {
    let bytes = png(2, 3, [40, 90, 180, 128]);
    let icon = Icon::from_png(&bytes).unwrap();
    assert_eq!((icon.width(), icon.height()), (2, 3));
    assert_eq!(icon.rgba(), [40, 90, 180, 128].repeat(6));
    assert!(Arc::ptr_eq(&icon.0, &icon.clone().0));
    let decoded: Icon = serde_json::from_value(json!(icon)).unwrap();
    assert!(icon == decoded);
    assert_eq!(
        STANDARD.decode(json!(icon).as_str().unwrap()).unwrap(),
        bytes
    );
    for bytes in [
        vec![],
        b"\x89PNG\r\n\x1a\ncorrupt".to_vec(),
        png(513, 1, [0; 4]),
        png(1, 513, [0; 4]),
        vec![0; MAX_PNG_BYTES + 1],
    ] {
        assert!(Icon::from_png(&bytes).is_err());
        assert!(serde_json::from_value::<Icon>(json!(STANDARD.encode(bytes))).is_err());
    }
    assert!(serde_json::from_value::<Pack>(json!({"../Off":json!(icon)})).is_err());
}
#[test]
fn only_named_status_pngs_are_imported_and_no_archive_path_is_extracted() {
    let s = source(&[
        ("icons/Off.png", png(1, 1, [1, 2, 3, 255])),
        ("icons/../../escape", vec![1]),
        ("icons/other.png", vec![1]),
    ]);
    let plan = crate::legacy_backup::icons::convert(&s).unwrap_or_else(|_| panic!("valid PNG"));
    assert_eq!(plan.icons.len(), 1);
    assert_eq!(plan.report.len(), 1);
    assert_eq!(plan.report[0].code, "legacy_icons_unused");
    for status in [
        Status::Off,
        Status::Throne,
        Status::Proxy,
        Status::Tun,
        Status::Dns,
        Status::ProxyDns,
    ] {
        assert_eq!(
            Status::from_archive_path(&format!("icons/{}.png", status.name())),
            Some(status)
        );
    }
}
#[test]
fn actual_qt_icon_archives_preserve_pixels_and_reject_whole_invalid_scope() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/legacy_backup/icons/fixtures");
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    for name in ["valid", "corrupt", "missing-part"] {
        let source = crate::legacy_backup::read(&root.join(format!("{name}.thrbackup"))).unwrap();
        let plan = crate::legacy_backup::icons::convert(&source);
        if name != "valid" {
            assert!(plan.is_err());
            continue;
        }
        let plan = plan.unwrap_or_else(|_| panic!("valid Qt archive"));
        assert_eq!(plan.icons.len(), 6);
        for (name, color) in expected["colors"].as_object().unwrap() {
            let status = Status::from_archive_path(&format!("icons/{name}.png")).unwrap();
            let icon = plan.icons.get(status).unwrap();
            let pixel: Vec<u8> = serde_json::from_value(color.clone()).unwrap();
            assert_eq!(icon.rgba(), pixel.repeat(32 * 32));
        }
    }
}
#[test]
fn icons_have_independent_scopes_atomic_replace_backup_and_undo() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let mut baseline = e.store.library.clone();
    baseline.version = 5;
    baseline.tray_icons.insert(
        Status::Off,
        Icon::from_png(&png(1, 1, [255, 0, 0, 255])).unwrap(),
    );
    baseline.tray_icons.insert(
        Status::Tun,
        Icon::from_png(&png(1, 1, [1, 2, 3, 255])).unwrap(),
    );
    e.store.commit(baseline.clone()).unwrap();
    let s = source(&[
        ("icons/Off.png", png(1, 1, [0, 255, 0, 255])),
        ("icons/Proxy.png", png(1, 1, [0, 0, 255, 255])),
    ]);
    let preview = choose(&mut e, &s);
    assert_eq!(preview.legacy.as_ref().unwrap()["iconCount"], 2);
    assert_eq!(preview.current.icons, 2);
    assert_eq!(preview.incoming.icons, 3);
    assert!(!json!(preview).to_string().contains("iVBOR"));
    assert_eq!(json!(e.store.library), json!(baseline));
    e.restore_backup(&preview.token).unwrap();
    assert_eq!(
        e.store.library.tray_icons.get(Status::Off).unwrap().rgba(),
        [0, 255, 0, 255]
    );
    assert!(e.store.library.tray_icons.get(Status::Tun) == baseline.tray_icons.get(Status::Tun));
    assert_eq!(e.store.library.settings, baseline.settings);
    assert!(!dir.path().join("icons").exists());
    let exported = e.export_backup().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut target = Engine::open(other.path(), &other.path().join("absent-core")).unwrap();
    let p = target.preview_backup(&exported).unwrap();
    target.restore_backup(&p.token).unwrap();
    assert!(target.store.library.tray_icons == e.store.library.tray_icons);
    drop(target);
    let target = Engine::open(other.path(), &other.path().join("absent-core")).unwrap();
    assert!(target.store.library.tray_icons == e.store.library.tray_icons);
    let undo = e.preview_previous_backup().unwrap();
    e.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(e.store.library), json!(baseline));
}
#[test]
fn invalid_or_unselected_icons_never_change_library_and_failed_commit_is_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
    let before = json!(e.store.library);
    let bad = source(&[
        ("icons/Off.png", png(1, 1, [0; 4])),
        ("icons/Tun.png", b"invalid PNG".to_vec()),
    ]);
    let p = choose(&mut e, &bad);
    assert_eq!(p.legacy.as_ref().unwrap()["canApply"], false);
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "legacy_import_blocked"
    );
    assert_eq!(json!(e.store.library), before);
    let mut missing = source(&[("icons/Off.png", png(1, 1, [0; 4]))]);
    missing.parts.icons = false;
    let p = choose(&mut e, &missing);
    assert_eq!(p.legacy.as_ref().unwrap()["canApply"], false);
    let good = source(&[("icons/Off.png", png(1, 1, [0; 4]))]);
    let p = choose(&mut e, &good);
    e.store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_restore_failed"
    );
    assert_eq!(json!(e.store.library), before);
    e.restore_backup(&p.token).unwrap();
    assert_eq!(e.store.library.version, 5);
    assert_eq!(e.store.library.tray_icons.len(), 1);
    let undo = e.preview_previous_backup().unwrap();
    e.restore_backup(&undo.token).unwrap();
    assert!(e.store.library.tray_icons.is_empty());
    assert_eq!(
        e.store.library.version, 5,
        "reader boundary remains monotonic like VPN policies"
    );
}
