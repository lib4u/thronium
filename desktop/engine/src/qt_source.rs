//! Verbatim Qt Throne blocks, frozen next to their recorded origin.
//!
//! Tests assert against the original application's own code, but never read its
//! tree: `desktop/engine/qt-source` holds each block and the manifest says which
//! file, marker and line it came from. Refresh with
//! `desktop/scripts/freeze_qt_snapshot.py` against a checkout that carries Qt.
use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/qt-source/manifest.json"
));

const BLOCKS: &[(&str, &str)] = &[
    (
        "settings-repo-init-maps.cpp",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/settings-repo-init-maps.cpp"
        )),
    ),
    (
        "generate-warp-profile.cpp",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/generate-warp-profile.cpp"
        )),
    ),
    (
        "group-updater-refresh.cpp",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/group-updater-refresh.cpp"
        )),
    ),
    (
        "mainwindow-setup-minutes.cpp",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/mainwindow-setup-minutes.cpp"
        )),
    ),
];

const VERBATIM: &[(&str, &[u8])] = &[
    (
        "src/global/OTP.cpp",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/global-otp.cpp"
        )),
    ),
    (
        "include/global/OTP.hpp",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/qt-source/global-otp.hpp"
        )),
    ),
];

/// A whole Qt file kept byte for byte, addressed by its path in that application.
pub(crate) fn verbatim(path: &str) -> Option<&'static [u8]> {
    VERBATIM
        .iter()
        .find_map(|&(name, body)| (name == path).then_some(body))
}

/// The frozen block, refused unless it still hashes to what the manifest recorded.
pub(crate) fn frozen(name: &str) -> &'static str {
    let body = BLOCKS
        .iter()
        .find_map(|&(file, body)| (file == name).then_some(body))
        .unwrap_or_else(|| panic!("{name} is not frozen"));
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let entry = manifest["extracts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["file"] == name)
        .unwrap_or_else(|| panic!("{name} has no manifest entry"));
    assert_eq!(
        format!("{:x}", Sha256::digest(body)),
        entry["sha256"].as_str().unwrap(),
        "{name} no longer matches the recorded Qt block"
    );
    body
}

#[test]
fn every_frozen_block_matches_its_recorded_origin() {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let extracts = manifest["extracts"].as_array().unwrap();
    assert_eq!(extracts.len(), BLOCKS.len() + VERBATIM.len());
    for entry in extracts {
        let name = entry["file"].as_str().unwrap();
        let path = entry["path"].as_str().unwrap();
        assert!(entry["sourceSha256"].as_str().unwrap().len() == 64);
        if entry["verbatim"] == serde_json::json!(true) {
            let body = verbatim(path).unwrap_or_else(|| panic!("{path} is not frozen"));
            assert_eq!(
                format!("{:x}", Sha256::digest(body)),
                entry["sha256"].as_str().unwrap(),
                "{path} no longer matches the recorded Qt file"
            );
        } else {
            assert!(!frozen(name).is_empty());
            assert!(path.starts_with("src/"));
        }
    }
}
