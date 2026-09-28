use crate::{connection_preflight, vpn_browser, Shared};
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
    if name == "openVpnChallengeUrl" {
        let request = serde_json::from_value(payload).map_err(|_| "vpn_auth_invalid_response")?;
        let url = state
            .engine
            .lock()
            .await
            .as_mut()
            .map_err(|_| "vpn_auth_stale")?
            .vpn_challenge_url(request)
            .await?;
        // The browser launcher must not hold the engine lock while it runs.
        return tauri::async_runtime::spawn_blocking(move || vpn_browser::open(&url))
            .await
            .map_err(|_| "vpn_browser_open_failed")?
            .map(|_| Value::Null);
    }
    if name == "cancelConnectionPreparation" {
        return Ok(json!(connection_preflight::cancel(
            &app,
            Some(payload["id"].as_str().unwrap_or(""))
        )));
    }
    if name == "disconnect" {
        connection_preflight::disconnect(&app).await?;
        return Ok(Value::Null);
    }
    if name == "applyRouting" {
        connection_preflight::apply_routing(&app).await?;
        return Ok(Value::Null);
    }
    if name == "connect" {
        connection_preflight::connect(&app, payload["id"].as_str().unwrap_or("")).await?;
        return Ok(Value::Null);
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
        "snapshot" => {
            let mut value = serde_json::to_value(engine.poll().await)
                .map_err(|_| "invalid_command_response".to_owned())?;
            value["connectionPreparation"] = connection_preflight::snapshot(app);
            value["selectorSubscriptionUpdate"] = engine.selector_subscription_update();
            Ok(value)
        }
        "vpnChallenge" => {
            let request =
                serde_json::from_value(payload).map_err(|_| "vpn_auth_invalid_response")?;
            serde_json::to_value(engine.vpn_challenge(request).await?)
                .map_err(|_| "vpn_auth_unsupported".into())
        }
        "vpnChallengeUrl" => {
            let request =
                serde_json::from_value(payload).map_err(|_| "vpn_auth_invalid_response")?;
            Ok(Value::String(engine.vpn_challenge_url(request).await?))
        }
        "vpnCredentials" => {
            let request = serde_json::from_value(payload).map_err(|_| "vpn_credentials_invalid")?;
            serde_json::to_value(engine.vpn_credentials(request).await?)
                .map_err(|_| "vpn_credentials_unavailable".into())
        }
        "restartVpnCredentials" => {
            let request = serde_json::from_value(payload).map_err(|_| "vpn_credentials_invalid")?;
            engine.restart_vpn_credentials(request).await?;
            Ok(Value::Null)
        }
        "cancelVpnCredentials" => {
            let request = serde_json::from_value(payload).map_err(|_| "vpn_credentials_invalid")?;
            engine.cancel_vpn_credentials(request)?;
            Ok(Value::Null)
        }
        "submitVpnChallenge" => {
            let request =
                serde_json::from_value(payload).map_err(|_| "vpn_auth_invalid_response")?;
            engine.submit_vpn_challenge(request).await?;
            Ok(Value::Null)
        }
        "cancelVpnChallenge" => {
            let request =
                serde_json::from_value(payload).map_err(|_| "vpn_auth_invalid_response")?;
            engine.cancel_vpn_challenge(request).await?;
            Ok(Value::Null)
        }
        "connectionConfiguration" => {
            engine
                .connection_configuration(id, payload["active"].as_bool().unwrap_or(false))
                .await
        }
        "restoreSystemProxy" => {
            engine.retry_system_proxy_cleanup().await?;
            Ok(Value::Null)
        }
        _ => Err("unknown_command".into()),
    }
}
