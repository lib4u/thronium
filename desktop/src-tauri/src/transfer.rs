use crate::localization::{text as localized, TextKey};
use tauri::{AppHandle, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

async fn pick_file(
    app: &AppHandle,
    language: crate::localization::Language,
    title: TextKey,
    filter: Option<(&str, &[&str])>,
) -> Result<Option<std::path::PathBuf>, String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut dialog = app.dialog().file().set_title(localized(language, title));
    if let Some((name, extensions)) = filter {
        dialog = dialog.add_filter(name, extensions);
    }
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.pick_file(move |path| {
        let _ = sender.send(path);
    });
    receiver
        .await
        .map_err(|_| "external_path_invalid")?
        .map(|file| file.into_path().map_err(|_| "external_path_invalid".into()))
        .transpose()
}

pub async fn legacy_policy_resource(
    app: &AppHandle,
    language: crate::localization::Language,
    kind: thronium_engine::routing::resources::Kind,
) -> Result<Option<thronium_engine::routing::resources::Resource>, String> {
    use thronium_engine::routing::resources::{self, Kind};
    let filter: Option<(&str, &[&str])> = match kind {
        Kind::Hosts | Kind::Text => None,
        Kind::RuleSetSource => Some(("JSON", &["json"])),
        Kind::RuleSetBinary => Some(("SRS", &["srs"])),
        Kind::Pem => Some(("PEM", &["pem", "crt", "cer", "key"])),
        Kind::Geodata => Some(("DAT", &["dat"])),
    };
    let Some(path) = pick_file(app, language, TextKey::ChoosePolicyResource, filter).await? else {
        return Ok(None);
    };
    tokio::task::spawn_blocking(move || resources::read(&path, kind).map(Some))
        .await
        .map_err(|_| "routing_resource_read_failed")?
}

pub async fn choose_external_core(
    app: &AppHandle,
    language: crate::localization::Language,
) -> Result<Option<String>, String> {
    let Some(path) = pick_file(app, language, TextKey::ChooseCoreExecutable087bad5, None).await?
    else {
        return Ok(None);
    };
    tokio::task::spawn_blocking(move || {
        let path = path.canonicalize().map_err(|_| "external_path_invalid")?;
        if !path.is_file() {
            return Err("external_path_invalid".into());
        }
        let path = path.to_str().ok_or("external_path_invalid")?;
        if path.len() > 4096 || path.chars().any(char::is_control) {
            return Err("external_path_invalid".into());
        }
        Ok(Some(path.to_owned()))
    })
    .await
    .map_err(|_| "external_path_invalid")?
}

pub async fn backup_file(
    app: &AppHandle,
    text: Option<String>,
    language: crate::localization::Language,
) -> Result<Option<(Vec<u8>, Option<Vec<u8>>)>, String> {
    let saving = text.is_some();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut dialog = app.dialog().file().set_title(match saving {
        true => localized(language, TextKey::SaveBackup8af1a7f),
        false => localized(language, TextKey::OpenBackup53325a0),
    });
    dialog = if saving {
        dialog.add_filter(localized(language, TextKey::BackupFilter), &["json"])
    } else {
        let dialog = dialog.add_filter(
            localized(language, TextKey::BackupOpenFilter),
            &["json", "thrbackup", "db"],
        );
        // An installed Qt Throne's library is one choice away: its `throne.db`.
        match crate::qt_throne::library_directory() {
            Some(directory) => dialog.set_directory(directory),
            None => dialog,
        }
    };
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    if saving {
        dialog
            .set_file_name("thronium-backup.json")
            .save_file(move |path| {
                let _ = sender.send(path);
            });
    } else {
        dialog.pick_file(move |path| {
            let _ = sender.send(path);
        });
    }
    let Some(file) = receiver.await.map_err(|_| "backup_read_failed")? else {
        return Ok(None);
    };
    let path = file.into_path().map_err(|_| "backup_read_failed")?;
    tokio::task::spawn_blocking(move || {
        if let Some(text) = text {
            thronium_engine::exports::save_text_limited(
                &path,
                &text,
                thronium_engine::backups::MAX_BYTES,
            )
            .map_err(|_| "backup_write_failed")?;
            return Ok(Some((Vec::new(), None)));
        }
        let bytes = thronium_engine::backups::read_bytes(&path)?;
        // A Throne library keeps the traffic it counted in a file of its own
        // beside it. Only the copy the user chose is looked at.
        let traffic = path
            .parent()
            .map(|directory| directory.join("throne_stats.db"))
            .filter(|beside| *beside != path)
            .and_then(|beside| thronium_engine::backups::read_bytes(&beside).ok());
        Ok(Some((bytes, traffic)))
    })
    .await
    .map_err(|_| "backup_read_failed")?
}

pub fn read_clipboard(app: &AppHandle) -> Result<String, String> {
    let text = app
        .clipboard()
        .read_text()
        .map_err(|_| "clipboard_read_failed")?;
    if text.len() > thronium_engine::exports::MAX_BYTES {
        return Err("export_too_large".into());
    }
    Ok(text)
}

pub async fn deliver(
    app: &AppHandle,
    text: String,
    destination: &str,
    file_name: &str,
    language: crate::localization::Language,
) -> Result<serde_json::Value, String> {
    // One bound for every delivered text, whichever command produced it.
    if text.len() > thronium_engine::exports::MAX_BYTES {
        return Err("export_too_large".into());
    }
    match destination {
        "preview" => Ok(serde_json::json!({"text":text})),
        "clipboard" => {
            app.clipboard()
                .write_text(text)
                .map_err(|_| "clipboard_write_failed")?;
            Ok(serde_json::json!({"status":"copied"}))
        }
        "file" => {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let mut dialog = app
                .dialog()
                .file()
                .set_title(localized(language, TextKey::SaveExport0873fc1))
                .set_file_name(file_name);
            if file_name.ends_with(".json") {
                dialog = dialog.add_filter("JSON", &["json"]);
            } else if file_name.ends_with(".conf") {
                dialog = dialog.add_filter("WireGuard / AmneziaWG", &["conf"]);
            } else {
                dialog =
                    dialog.add_filter(localized(language, TextKey::TextFilter), &["txt", "log"]);
            }
            if let Some(window) = app.get_webview_window("main") {
                dialog = dialog.set_parent(&window);
            }
            dialog.save_file(move |path| {
                let _ = sender.send(path);
            });
            let Some(file) = receiver.await.map_err(|_| "export_failed")? else {
                return Ok(serde_json::json!({"status":"cancelled"}));
            };
            let path = file.into_path().map_err(|_| "export_write_failed")?;
            tokio::task::spawn_blocking(move || thronium_engine::exports::save_text(&path, &text))
                .await
                .map_err(|_| "export_write_failed")??;
            Ok(serde_json::json!({"status":"saved"}))
        }
        _ => Err("invalid_export_destination".into()),
    }
}
