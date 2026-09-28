use crate::{
    dashboard, storage, system_settings, transfer, warp_registration, window_behavior, Shared,
};
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::State;
use thronium_engine::store::Preferences;
use thronium_engine::Engine;
pub(super) async fn unlocked(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: AppHandle,
) -> Result<Value, String> {
    if name == "storageLocation" {
        if payload.as_object().is_none_or(|o| !o.is_empty()) {
            return Err("storage_invalid_arguments".into());
        }
        return Ok(storage::info(&app));
    }
    if matches!(
        name.as_str(),
        "dashboardStatus" | "installDashboard" | "cancelDashboardInstallation" | "openDashboard"
    ) {
        return dashboard::run(&app, &name, &payload).await;
    }
    if name == "takeSettingsLink" {
        return crate::incoming::take(&app).await;
    }
    if name == "windowBehavior" {
        return Ok(json!({"trayAvailable": window_behavior::available(&app)}));
    }
    if name == "windowSnapLayouts" {
        crate::window_chrome::snap_layouts(&app);
        return Ok(Value::Null);
    }
    if name == "windowSystemMenu" {
        crate::window_chrome::system_menu(&app);
        return Ok(Value::Null);
    }
    if name == "quitApp" {
        app.exit(0);
        return Ok(Value::Null);
    }
    if name == "chooseExternalCorePath" {
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return transfer::choose_external_core(&app, language)
            .await
            .map(|path| json!(path));
    }
    if matches!(
        name.as_str(),
        "registerWarp" | "cancelWarpRegistration" | "openWarpTerms"
    ) {
        return warp_registration::run(&app, &name, &payload).await;
    }
    if name == "checkUpstreamRelease" {
        let check = state
            .engine
            .lock()
            .await
            .as_ref()
            .map_err(|e| e.clone())?
            .release_check()?;
        return check.execute().await;
    }
    Err("unknown_command".into())
}

pub(super) async fn locked(
    name: &str,
    payload: Value,
    engine: &mut Engine,
    app: &AppHandle,
) -> Result<Value, String> {
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    match name {
        "settings" => Ok(engine.settings()),
        "saveSettings" => {
            system_settings::save(
                app,
                engine,
                payload["section"].as_str().unwrap_or(""),
                payload["previous"].clone(),
                payload["values"].clone(),
            )
            .await
        }
        "preferences" => {
            let preferences: Preferences =
                serde_json::from_value(payload).map_err(|_| "invalid_preferences")?;
            engine.preferences(preferences)?;
            Ok(Value::Null)
        }
        "saveAutoSelectSettings" => {
            let update = thronium_engine::auto_selector::AutoSelectSettingsUpdate {
                failover: payload
                    .get("failover")
                    .map(|value| value.as_bool().ok_or("invalid_auto_select_settings"))
                    .transpose()?,
                source_group_id: payload
                    .get("sourceGroupId")
                    .map(|value| {
                        if value.is_null() {
                            Ok(None)
                        } else {
                            value
                                .as_str()
                                .map(|id| Some(id.to_owned()))
                                .ok_or("invalid_auto_select_settings")
                        }
                    })
                    .transpose()?,
                previous_options: payload
                    .get("previousOptions")
                    .map(|value| {
                        serde_json::from_value(value.clone())
                            .map_err(|_| "invalid_auto_select_settings")
                    })
                    .transpose()?,
            };
            engine.save_auto_select_settings(
                &payload["previous"],
                payload["config"].clone(),
                update,
            )?;
            Ok(Value::Null)
        }
        "saveWindowSettings" => {
            let mut preferences = engine.store.library.preferences.clone();
            preferences.close_behavior = serde_json::from_value(payload["closeBehavior"].clone())
                .map_err(|_| "invalid_preferences")?;
            engine.preferences(preferences)?;
            Ok(Value::Null)
        }
        "setVlessCore" => {
            engine.vless_core(
                id,
                serde_json::from_value(payload["core"].clone())
                    .map_err(|_| "invalid_preferences")?,
            )?;
            Ok(Value::Null)
        }
        "connectionSettings" => {
            let mode = serde_json::from_value(payload["mode"].clone())
                .map_err(|_| "invalid_preferences")?;
            let port: u16 = serde_json::from_value(payload["port"].clone())
                .map_err(|_| "invalid_preferences")?;
            let mut preferences = engine.store.library.preferences.clone();
            preferences.connection_mode = mode;
            preferences.inbound_port = port;
            if let Some(settings) = payload.get("tun") {
                preferences.tun =
                    serde_json::from_value(settings.clone()).map_err(|_| "invalid_tun_settings")?;
            }
            if let Some(core) = payload.get("vlessCore") {
                preferences.vless_core =
                    serde_json::from_value(core.clone()).map_err(|_| "invalid_preferences")?;
            }
            engine.preferences(preferences)?;
            Ok(Value::Null)
        }
        "savePingSettings" => {
            let settings = serde_json::from_value(payload).map_err(|_| "probe_invalid_options")?;
            engine.save_ping_settings(settings)?;
            Ok(Value::Null)
        }
        _ => Err("unknown_command".into()),
    }
}
