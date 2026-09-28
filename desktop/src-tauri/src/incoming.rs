//! Links and files the system hands to the application: `throne://` links from
//! the URL handler, and configuration files opened with Thronium, passed on the
//! command line or forwarded by a second launch. Like Qt's `Deeplink_Submit` and
//! `LaunchFiles_Submit`, they reach the running window whether or not the URL
//! handler is registered; every one ends in a dialog the user confirms.
use crate::tray;
use serde_json::{json, Value};
use std::{
    ffi::{OsStr, OsString},
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, Emitter, Manager};
use thronium_engine::exports::MAX_QR_IMAGE_BYTES;
use thronium_engine::store::MAX_CONFIG_BYTES;

/// Requests waiting for the window; a burst beyond this is dropped.
const MAX_WAITING: usize = 8;
/// Files taken from one launch; Qt imports them as one batch.
const MAX_FILES: usize = 32;
const MAX_LINK_BYTES: usize = 262144;

#[derive(Default)]
pub struct State {
    waiting: Mutex<Vec<Incoming>>,
}
#[derive(Debug, PartialEq)]
enum Incoming {
    Link(String),
    Files(Vec<PathBuf>),
}

pub fn receive(app: &AppHandle, args: impl IntoIterator<Item = OsString>, cwd: &Path) {
    let mut requests = Vec::new();
    let mut files = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some(link) if link.len() > MAX_LINK_BYTES => {}
            // Stored links are normalized so the same link under either scheme
            // waits once.
            Some(link) if link.starts_with("throne://") || link.starts_with("thronium://") => {
                requests.push(Incoming::Link(link.replacen("thronium://", "throne://", 1)))
            }
            _ => {
                if let Some(path) = file(&arg, cwd).filter(|_| files.len() < MAX_FILES) {
                    files.push(path);
                }
            }
        }
    }
    if !files.is_empty() {
        requests.push(Incoming::Files(files));
    }
    if requests.is_empty() {
        return;
    }
    {
        let state = app.state::<State>();
        let mut waiting = state.waiting.lock().unwrap();
        for request in requests {
            if waiting.len() < MAX_WAITING && !waiting.contains(&request) {
                waiting.push(request);
            }
        }
    }
    tray::show(app);
    let _ = app.emit("settings-link-ready", ());
}

/// The oldest waiting request. Files are read now, so a file changed while the
/// window was busy is imported as it is when the dialog opens.
pub async fn take(app: &AppHandle) -> Result<Value, String> {
    let next = {
        let state = app.state::<State>();
        let mut waiting = state.waiting.lock().unwrap();
        (!waiting.is_empty()).then(|| waiting.remove(0))
    };
    Ok(match next {
        None => Value::Null,
        Some(Incoming::Link(text)) => json!({"kind": "link", "text": text}),
        Some(Incoming::Files(paths)) => tokio::task::spawn_blocking(move || documents(&paths))
            .await
            .map_err(|_| "operation_failed")?,
    })
}

/// A launch argument naming an existing file: a path, relative to the
/// launching directory, or a `file://` URL from a desktop entry's `%U`.
fn file(arg: &OsStr, cwd: &Path) -> Option<PathBuf> {
    let text = arg.to_string_lossy();
    if text.is_empty() || text.starts_with('-') {
        return None;
    }
    let path = if text.starts_with("file://") {
        tauri::Url::parse(&text).ok()?.to_file_path().ok()?
    } else if text.contains("://") {
        return None;
    } else {
        PathBuf::from(arg)
    };
    let path = cwd.join(path);
    path.is_file().then_some(path)
}

fn documents(paths: &[PathBuf]) -> Value {
    let mut documents = Vec::new();
    let mut problems = Vec::new();
    let mut total = 0;
    for path in paths {
        let filename = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        match read(path) {
            // The import dialog reviews the files together, within one import.
            Ok(text) if total + text.len() > MAX_CONFIG_BYTES => {
                problems.push(json!({"filename": filename, "code": "import_too_large"}))
            }
            Ok(text) => {
                total += text.len();
                documents.push(json!({"filename": filename, "text": text}));
            }
            Err(code) => problems.push(json!({"filename": filename, "code": code})),
        }
    }
    json!({"kind": "files", "documents": documents, "problems": problems})
}

/// Import text of one file: the codes a QR image holds, or the file's text.
fn read(path: &Path) -> Result<String, &'static str> {
    let mut file = std::fs::File::open(path).map_err(|_| "unreadable")?;
    let size = file.metadata().map_err(|_| "unreadable")?.len();
    let mut bytes = Vec::new();
    (&mut file)
        .take(12)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable")?;
    let image = image(&bytes);
    let (limit, too_large) = if image {
        (MAX_QR_IMAGE_BYTES, "qr_image_too_large")
    } else {
        (MAX_CONFIG_BYTES, "import_too_large")
    };
    if size > limit as u64 {
        return Err(too_large);
    }
    file.take(limit as u64 + 1 - bytes.len() as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable")?;
    if bytes.len() > limit {
        return Err(too_large);
    }
    if image {
        return crate::qr_import::from_bytes(&bytes)
            .map(|texts| texts.join("\n"))
            .map_err(|code| match code.as_str() {
                "qr_not_found" => "qr_not_found",
                "qr_image_too_large" => "qr_image_too_large",
                _ => "qr_image_invalid",
            });
    }
    text(&bytes)
}

/// The image formats the QR reader accepts, by signature.
fn image(head: &[u8]) -> bool {
    head.starts_with(&[0x89, b'P'])
        || head.starts_with(&[0xff, 0xd8])
        || head.starts_with(b"GIF")
        || head.starts_with(b"BM")
        || head.get(8..12) == Some(b"WEBP")
}

/// Text as the import dialog reads a chosen file: UTF-8, or UTF-16 with a byte
/// order mark, without binary control characters.
fn text(bytes: &[u8]) -> Result<String, &'static str> {
    fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, &'static str> {
        let (pairs, rest) = bytes.as_chunks::<2>();
        if !rest.is_empty() {
            return Err("unreadable");
        }
        String::from_utf16(&pairs.iter().map(|pair| unit(*pair)).collect::<Vec<_>>())
            .map_err(|_| "unreadable")
    }
    let text = match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(rest, u16::from_le_bytes)?,
        [0xfe, 0xff, rest @ ..] => utf16(rest, u16::from_be_bytes)?,
        _ => {
            let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
            text.strip_prefix('\u{feff}').unwrap_or(text).to_owned()
        }
    };
    if text.trim().is_empty()
        || text
            .chars()
            .any(|c| matches!(c, '\u{0}'..='\u{8}' | '\u{e}'..='\u{1f}'))
    {
        return Err("unreadable");
    }
    Ok(text)
}

#[cfg(test)]
mod tests;
