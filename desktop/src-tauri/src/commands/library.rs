use crate::{archive_export, qr_export, qr_import, transfer, Shared};
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::State;
use thronium_engine::Engine;
use thronium_engine::ProfileDraft;
pub(super) async fn unlocked(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: AppHandle,
) -> Result<Value, String> {
    if name == "resolveProfileAddresses" {
        return crate::library_maintenance::resolve(&app, &payload).await;
    }
    if name == "readClipboard" {
        return transfer::read_clipboard(&app).map(Value::String);
    }
    if name == "decodeQrImage" {
        return qr_import::image(payload["data"].as_str().ok_or("qr_image_invalid")?.into())
            .await
            .map(|texts| json!(texts));
    }
    if name == "readQrClipboard" {
        return qr_import::clipboard(app).await.map(|texts| json!(texts));
    }
    if name == "scanScreenQr" {
        return qr_import::screen(app).await.map(|texts| json!(texts));
    }
    if name == "writeClipboard" {
        let text = payload["text"].as_str().ok_or("clipboard_write_failed")?;
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return transfer::deliver(&app, text.into(), "clipboard", "", language).await;
    }
    if name == "exportQr" {
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return qr_export::deliver(
            &app,
            payload["text"].as_str().ok_or("export_failed")?,
            payload["destination"].as_str().unwrap_or(""),
            language,
        )
        .await;
    }
    if name == "exportArchive" {
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return archive_export::deliver(
            &app,
            payload["data"].as_str().ok_or("archive_invalid_data")?,
            payload["format"].as_str().unwrap_or(""),
            language,
        )
        .await;
    }
    if name == "exportSharedText" {
        let text = payload["text"].as_str().ok_or("export_failed")?;
        let file_name = thronium_engine::exports::shared_text_file_name(
            payload["format"].as_str().unwrap_or(""),
        )?;
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return transfer::deliver(
            &app,
            text.into(),
            payload["destination"].as_str().unwrap_or(""),
            file_name,
            language,
        )
        .await;
    }
    if name == "exportConfiguration" {
        let (text, language) = {
            let guard = state.engine.lock().await;
            let engine = guard.as_ref().map_err(|e| e.clone())?;
            (
                engine.configuration_export(
                    payload.get("sourceProfileId").and_then(Value::as_str),
                    &payload["config"],
                )?,
                crate::localization::Language::of(&guard),
            )
        };
        return transfer::deliver(
            &app,
            text,
            payload["destination"].as_str().unwrap_or(""),
            "thronium-config.json",
            language,
        )
        .await;
    }
    if name == "exportProfiles" {
        let (text, language) = {
            let guard = state.engine.lock().await;
            let engine = guard.as_ref().map_err(|e| e.clone())?;
            let ids = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_profile_selection")?;
            let format = serde_json::from_value(payload["format"].clone())
                .map_err(|_| "invalid_export_format")?;
            (
                engine.export_profiles(ids, format)?,
                crate::localization::Language::of(&guard),
            )
        };
        return transfer::deliver(
            &app,
            text,
            payload["destination"].as_str().unwrap_or(""),
            "thronium-profiles.json",
            language,
        )
        .await;
    }
    Err("unknown_command".into())
}

pub(super) async fn locked(
    name: &str,
    payload: Value,
    engine: &mut Engine,
) -> Result<Value, String> {
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    match name {
        "deleteProfiles" | "moveProfiles" => {
            let ids = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_profile_selection")?;
            let count = if name == "deleteProfiles" {
                engine.delete_profiles(ids)?
            } else {
                engine.move_profiles(ids, payload["groupId"].as_str().unwrap_or(""))?
            };
            Ok(json!({"count":count}))
        }
        "maintenanceCandidates" => {
            let ids: Vec<String> = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_profile_selection")?;
            let kind = payload["kind"].as_str().unwrap_or_default();
            Ok(json!({"ids": engine.maintenance_candidates(kind, &ids)?}))
        }
        "resetProfileTraffic" => {
            let ids: Vec<String> = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_profile_selection")?;
            engine.reset_profile_traffic(&ids)?;
            Ok(Value::Null)
        }
        "group" => serde_json::to_value(engine.group(id)?)
            .map_err(|_| "invalid_command_response".to_owned()),
        "collapseGroup" => {
            let collapsed = payload["collapsed"].as_bool().ok_or("invalid_group")?;
            engine.collapse_group(id, collapsed)?;
            Ok(Value::Null)
        }
        "saveGroup" => {
            let draft = serde_json::from_value(payload).map_err(|_| "invalid_group")?;
            Ok(json!({"id":engine.save_group(draft)?}))
        }
        "moveGroup" => {
            let offset = payload["offset"]
                .as_i64()
                .filter(|o| matches!(o, -1 | 1))
                .ok_or("invalid_group_order")?;
            engine.move_group(id, offset as i32)?;
            Ok(Value::Null)
        }
        "reorderGroup" => {
            let target = payload["targetId"].as_str().ok_or("invalid_group_order")?;
            let after = payload["after"].as_bool().ok_or("invalid_group_order")?;
            engine.reorder_group(id, target, after)?;
            Ok(Value::Null)
        }
        "reorderProfile" => {
            let target = payload["targetId"]
                .as_str()
                .ok_or("invalid_profile_order")?;
            let after = payload["after"].as_bool().ok_or("invalid_profile_order")?;
            engine.reorder_profile(id, target, after)?;
            Ok(Value::Null)
        }
        "deleteGroup" => {
            engine.delete_group(id, payload["deleteProfiles"].as_bool().unwrap_or(false))?;
            Ok(Value::Null)
        }
        "profile" => {
            serde_json::to_value(engine.editable_profile(id)?).map_err(|_| "invalid_profile".into())
        }
        "saveProfile" => {
            let choice = vless_choice(&payload)?;
            let request = serde_json::from_value(payload).map_err(|_| "invalid_profile")?;
            Ok(json!({"id":engine.save_profile_edit(request, choice)?}))
        }
        "saveProfileConfiguration" => {
            let expected = payload["expectedRevision"]
                .as_str()
                .ok_or("profile_configuration_changed")?;
            Ok(
                json!({"id":engine.save_profile_configuration(id, expected, payload["config"].clone())?}),
            )
        }
        "saveProfileCore" => {
            let expected = payload["expectedRevision"]
                .as_str()
                .ok_or("profile_configuration_changed")?;
            let core = serde_json::from_value(payload["core"].clone())
                .map_err(|_| "invalid_preferences")?;
            serde_json::to_value(engine.save_profile_core(id, expected, core)?)
                .map_err(|_| "invalid_profile".into())
        }
        "previewDuplicates" => {
            let ids = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_profile_selection")?;
            serde_json::to_value(engine.preview_duplicates(ids)?)
                .map_err(|_| "invalid_profile_selection".into())
        }
        "removeDuplicates" => {
            Ok(json!({"count":engine.remove_duplicates(payload["token"].as_str().unwrap_or(""))?}))
        }
        "discardDuplicates" => {
            engine.discard_duplicates(payload["token"].as_str().unwrap_or(""));
            Ok(Value::Null)
        }
        "importProfiles" => {
            let drafts: Vec<thronium_engine::exports::ImportProfile> =
                serde_json::from_value(payload["profiles"].clone())
                    .map_err(|_| "invalid_import_batch")?;
            Ok(json!({"ids": engine.import_referenced_profiles(drafts)?}))
        }
        "checkImportProfile" => {
            let drafts = serde_json::from_value(payload["profiles"].clone())
                .map_err(|_| "invalid_import_batch")?;
            let index = payload["index"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("invalid_import_batch")?;
            engine.check_import_profile(drafts, index).await?;
            Ok(Value::Null)
        }
        "checkProfile" => {
            let choice = vless_choice(&payload)?;
            let draft: ProfileDraft =
                serde_json::from_value(payload).map_err(|_| "invalid_profile")?;
            engine.check_profile_draft(draft, choice).await?;
            Ok(Value::Null)
        }
        "select" => {
            engine.select(id)?;
            Ok(Value::Null)
        }
        "favorite" => {
            engine.favorite(id)?;
            Ok(Value::Null)
        }
        "delete" => {
            engine.delete(id)?;
            Ok(Value::Null)
        }
        "generateWgKeys" => engine.generate_wg_keys().await,
        "addGroup" => {
            engine.add_group(payload["name"].as_str().unwrap_or(""))?;
            Ok(Value::Null)
        }
        _ => Err("unknown_command".into()),
    }
}

fn vless_choice(payload: &Value) -> Result<Option<Option<thronium_engine::vless::Core>>, String> {
    payload
        .get("vlessCore")
        .map(|v| {
            if v == "default" || v.is_null() {
                Ok(None)
            } else {
                serde_json::from_value(v.clone())
                    .map(Some)
                    .map_err(|_| "invalid_preferences".into())
            }
        })
        .transpose()
}
