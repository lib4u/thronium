use crate::{system_settings, transfer, Shared};
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::State;
use thronium_engine::Engine;
pub(super) async fn unlocked(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: AppHandle,
) -> Result<Value, String> {
    if name == "chooseLegacyResource" {
        let (selection, language) = {
            let guard = state.engine.lock().await;
            let engine = guard.as_ref().map_err(|e| e.clone())?;
            (
                engine.legacy_resource_selection(
                    payload["token"].as_str().unwrap_or(""),
                    payload["id"].as_str().unwrap_or(""),
                )?,
                crate::localization::Language::of(&guard),
            )
        };
        let Some(resource) =
            transfer::legacy_policy_resource(&app, language, selection.kind()?).await?
        else {
            return Ok(json!({"status":"cancelled"}));
        };
        let selection = tauri::async_runtime::spawn_blocking(move || selection.prepare(resource))
            .await
            .map_err(|_| "routing_resource_invalid")??;
        let preview = state
            .engine
            .lock()
            .await
            .as_mut()
            .map_err(|e| e.clone())?
            .finish_legacy_resource(selection)?;
        return Ok(json!({"status":"ready", "preview":preview}));
    }
    if name == "exportBackup" || name == "readBackup" {
        let (text, language) = {
            let guard = state.engine.lock().await;
            let engine = guard.as_ref().map_err(|e| e.clone())?;
            (
                if name == "exportBackup" {
                    Some(engine.export_backup()?)
                } else {
                    None
                },
                crate::localization::Language::of(&guard),
            )
        };
        let Some((bytes, traffic)) = transfer::backup_file(&app, text, language).await? else {
            return Ok(json!({"status":"cancelled"}));
        };
        if name == "exportBackup" {
            return Ok(json!({"status":"saved"}));
        }
        let file = tauri::async_runtime::spawn_blocking(move || {
            thronium_engine::backups::read_files(bytes, traffic)
        })
        .await
        .map_err(|_| "legacy_backup_read_failed")??;
        let preview = state
            .engine
            .lock()
            .await
            .as_mut()
            .map_err(|e| e.clone())?
            .preview_backup_file(file)?;
        return Ok(json!({"status":"ready","preview":preview}));
    }
    Err("unknown_command".into())
}

pub(super) async fn locked(
    name: &str,
    payload: Value,
    engine: &mut Engine,
    app: &AppHandle,
) -> Result<Value, String> {
    match name {
        "backupStatus" => Ok(engine.backup_status()),
        "previewPreviousBackup" => serde_json::to_value(engine.preview_previous_backup()?)
            .map_err(|_| "backup_invalid".into()),
        "refreshBackupPreview" => serde_json::to_value(
            engine.refresh_backup_preview(payload["token"].as_str().unwrap_or(""))?,
        )
        .map_err(|_| "backup_invalid".into()),
        "legacyBackupScopes" => serde_json::to_value(
            engine.legacy_backup_scopes(
                payload["token"].as_str().unwrap_or(""),
                serde_json::from_value(payload["scopes"].clone())
                    .map_err(|_| "legacy_import_blocked")?,
            )?,
        )
        .map_err(|_| "backup_invalid".into()),
        "discardBackupPreview" => {
            engine.discard_backup_preview(payload["token"].as_str().unwrap_or(""));
            Ok(Value::Null)
        }
        "restoreBackup" => {
            let old = engine.store.library.clone();
            engine.restore_backup(payload["token"].as_str().unwrap_or(""))?;
            let next = thronium_engine::settings::section(&engine.store.library, "system");
            if let Err(error) = system_settings::apply(
                app,
                &thronium_engine::settings::section(&old, "system"),
                &next,
                false,
            ) {
                engine
                    .store
                    .commit(old)
                    .map_err(|_| "settings_rollback_failed")?;
                engine.reload_settings();
                return Err(error);
            }
            Ok(engine.backup_status())
        }
        _ => Err("unknown_command".into()),
    }
}
