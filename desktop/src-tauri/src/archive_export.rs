//! Save locally generated archives without extracting or interpreting their entries.
use crate::localization::{text as localized, TextKey};
use base64::Engine as _;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use thronium_engine::exports::MAX_ARCHIVE_BYTES as MAX_BYTES;
const MAX_ENCODED: usize = MAX_BYTES.div_ceil(3) * 4;

fn file_name(format: &str) -> Result<&'static str, String> {
    match format {
        "wireguard-archive" => Ok("thronium-wireguard.zip"),
        "qr-archive" => Ok("thronium-qr.zip"),
        _ => Err("invalid_export_format".into()),
    }
}

fn decode(data: &str) -> Result<Vec<u8>, String> {
    if data.len() > MAX_ENCODED {
        return Err("archive_too_large".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| "archive_invalid_data")?;
    if bytes.len() > MAX_BYTES {
        return Err("archive_too_large".into());
    }
    // Local-file signature excludes the empty-archive EOCD signature. The
    // frontend validates every conversion and entry before producing this ZIP.
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err("archive_invalid_data".into());
    }
    Ok(bytes)
}

pub async fn deliver(
    app: &AppHandle,
    data: &str,
    format: &str,
    language: crate::localization::Language,
) -> Result<Value, String> {
    let name = file_name(format)?;
    // Check before allocating an owned copy or entering the decoder.
    if data.len() > MAX_ENCODED {
        return Err("archive_too_large".into());
    }
    let data = data.to_owned();
    let bytes = tokio::task::spawn_blocking(move || decode(&data))
        .await
        .map_err(|_| "export_failed")??;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut dialog = app
        .dialog()
        .file()
        .set_title(localized(language, TextKey::SaveArchiveD337443))
        .set_file_name(name)
        .add_filter("ZIP", &["zip"]);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.save_file(move |path| {
        let _ = sender.send(path);
    });
    let Some(file) = receiver.await.map_err(|_| "export_failed")? else {
        return Ok(json!({"status":"cancelled"}));
    };
    let path = file.into_path().map_err(|_| "export_write_failed")?;
    tokio::task::spawn_blocking(move || {
        thronium_engine::exports::save_bytes_limited(&path, &bytes, MAX_BYTES)
    })
    .await
    .map_err(|_| "export_write_failed")??;
    Ok(json!({"status":"saved"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
    #[test]
    fn names_are_fixed_and_invalid_format_cannot_supply_a_path() {
        assert_eq!(
            file_name("wireguard-archive").unwrap(),
            "thronium-wireguard.zip"
        );
        assert_eq!(file_name("qr-archive").unwrap(), "thronium-qr.zip");
        for format in ["", "wireguard", "../../../private.zip", "qr-archive\n"] {
            assert_eq!(file_name(format).unwrap_err(), "invalid_export_format");
        }
    }
    #[test]
    fn invalid_base64_empty_archives_and_other_signatures_are_rejected_without_echoing_data() {
        for text in [
            "".to_owned(),
            "sensitive malformed fixture".into(),
            encoded(b""),
            encoded(b"PK\x05\x06empty"),
            encoded(b"PK"),
            encoded(b"PNG fixture"),
        ] {
            assert_eq!(decode(&text).unwrap_err(), "archive_invalid_data");
        }
        let body = b"PK\x03\x04locally-produced-binary\0fixture";
        assert_eq!(decode(&encoded(body)).unwrap(), body);
    }
    #[test]
    fn both_encoded_and_decoded_caps_are_checked_without_truncation() {
        assert_eq!(
            decode(&"a".repeat(MAX_ENCODED + 1)).unwrap_err(),
            "archive_too_large"
        );
        let mut bytes = vec![0; MAX_BYTES];
        bytes[..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(decode(&encoded(&bytes)).unwrap(), bytes);
        // MAX_BYTES has remainder one modulo three. Adding one byte retains
        // the same base64 length, so the second bound must also be enforced.
        bytes.push(0);
        assert_eq!(encoded(&bytes).len(), MAX_ENCODED);
        assert_eq!(decode(&encoded(&bytes)).unwrap_err(), "archive_too_large");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn archive_write_is_atomic_private_and_keeps_previous_file_when_limit_fails() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.zip");
        std::fs::write(&path, b"previous archive").unwrap();
        let bytes = b"PK\x03\x04fixture";
        let error = thronium_engine::exports::save_bytes_limited(&path, bytes, 3).unwrap_err();
        assert_eq!(error, "export_too_large");
        assert_eq!(std::fs::read(&path).unwrap(), b"previous archive");
        thronium_engine::exports::save_bytes_limited(&path, bytes, MAX_BYTES).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
