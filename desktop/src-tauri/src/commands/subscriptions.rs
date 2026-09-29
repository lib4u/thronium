use crate::Shared;
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::State;
use thronium_engine::Engine;
pub(super) async fn unlocked(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    _app: AppHandle,
) -> Result<Value, String> {
    if name == "cancelSubscription" {
        state
            .downloads
            .cancel(payload["requestId"].as_str().unwrap_or(""))
            .await;
        return Ok(Value::Null);
    }
    if matches!(
        name.as_str(),
        "cancelSubscriptionUpdates" | "releaseSubscriptionWorker"
    ) {
        let ids = {
            let mut guard = state.engine.lock().await;
            let engine = guard.as_mut().map_err(|e| e.clone())?;
            if name == "cancelSubscriptionUpdates" {
                engine.cancel_subscription_jobs()?
            } else {
                engine.release_subscription_worker(payload["owner"].as_str().unwrap_or(""))?
            }
        };
        for id in ids {
            state.downloads.cancel(&id).await;
            state.validator.cancel(&id).await;
        }
        return Ok(Value::Null);
    }
    if name == "checkSubscriptionJob" {
        let id = payload["id"].as_str().unwrap_or("");
        let owner = payload["owner"].as_str().unwrap_or("");
        let request = {
            let mut guard = state.engine.lock().await;
            guard
                .as_mut()
                .map_err(|e| e.clone())?
                .subscription_job_check_request(id, owner)?
        };
        // The job shows whether routing lists are prepared or the Core checks.
        let engine = &state.engine;
        let stage = move |status| async move {
            if let Ok(engine) = engine.lock().await.as_mut() {
                let _ = engine.subscription_job_stage(id, owner, status);
            }
        };
        // One validation may download lists and start the Core for longer than
        // the job lease; renew it while the check is really running.
        let check = state.validator.check(id, request, stage);
        tokio::pin!(check);
        let mut renew = tokio::time::interval(std::time::Duration::from_secs(30));
        renew.tick().await;
        let result = loop {
            tokio::select! {
                result = &mut check => break result,
                _ = renew.tick() => {
                    if let Ok(engine) = state.engine.lock().await.as_mut() {
                        let _ = engine.renew_subscription_job(id, owner);
                    }
                }
            }
        };
        let verdict = result?;
        return state
            .engine
            .lock()
            .await
            .as_mut()
            .map_err(|e| e.clone())?
            .subscription_job_checked(id, owner, verdict)
            .map(|_| Value::Null);
    }
    if name == "fetchSubscription" || name == "fetchSubscriptionJob" {
        let job = name == "fetchSubscriptionJob";
        let id = payload["id"].as_str().unwrap_or("");
        let owner = payload["owner"].as_str().unwrap_or("");
        let request_id = if job {
            id
        } else {
            payload["requestId"].as_str().unwrap_or("")
        };
        let request = {
            let mut guard = state.engine.lock().await;
            let engine = guard.as_mut().map_err(|e| e.clone())?;
            if job {
                engine.subscription_job_request(id, owner)?
            } else {
                engine.begin_manual_subscription(id, request_id)?
            }
        };
        let result = state
            .downloads
            .fetch(request_id, &request.settings, request.proxy.as_deref())
            .await;
        // Downloading does not hold the engine lock: stop, snapshots and cancellation remain available.
        let mut guard = state.engine.lock().await;
        let engine = guard.as_mut().map_err(|e| e.clone())?;
        if job {
            return engine.subscription_job_downloaded(id, owner, request, result?);
        }
        engine.end_manual_subscription(id, request_id);
        return engine.subscription_downloaded(request, result?);
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
        "startSubscriptionUpdates" => Ok(
            json!({"queued":if id.is_empty() { engine.enqueue_subscription_updates()? } else { engine.enqueue_subscription_update(id)? }}),
        ),
        "claimSubscriptionJob" => {
            engine.claim_subscription_job(payload["owner"].as_str().unwrap_or(""))
        }
        "prepareSubscriptionJob" => {
            let drafts = serde_json::from_value(payload["profiles"].clone())
                .map_err(|_| "subscription_invalid_profiles")?;
            let omitted = serde_json::from_value(payload["omitted"].clone()).unwrap_or_default();
            Ok(
                json!({"checks":engine.prepare_subscription_job(id,payload["owner"].as_str().unwrap_or(""),drafts,omitted)?}),
            )
        }
        "applySubscriptionJob" => {
            engine
                .apply_subscription_job_with_stop(id, payload["owner"].as_str().unwrap_or(""))
                .await?;
            Ok(Value::Null)
        }
        "failSubscriptionJob" => {
            engine.fail_subscription_job(
                id,
                payload["owner"].as_str().unwrap_or(""),
                payload["error"].as_str().unwrap_or(""),
            )?;
            Ok(Value::Null)
        }
        "clearSubscriptionJobs" => {
            engine.clear_subscription_jobs();
            Ok(Value::Null)
        }
        "checkSubscriptionProfile" => {
            engine
                .check_subscription_profile(
                    payload["ticket"].as_str().unwrap_or(""),
                    if let Some(id) = payload["profileId"].as_str() {
                        engine.subscription_check_index(
                            payload["ticket"].as_str().unwrap_or(""),
                            id,
                        )?
                    } else {
                        payload["index"]
                            .as_u64()
                            .ok_or("subscription_invalid_profiles")?
                            as usize
                    },
                    payload["useProviderRouting"].as_bool().unwrap_or(false),
                )
                .await?;
            Ok(Value::Null)
        }
        "previewSubscription" => {
            let drafts = serde_json::from_value(payload["profiles"].clone())
                .map_err(|_| "subscription_invalid_profiles")?;
            serde_json::to_value(
                engine.preview_subscription(payload["ticket"].as_str().unwrap_or(""), drafts)?,
            )
            .map_err(|_| "invalid_command_response".to_owned())
        }
        "applySubscription" => {
            let token = payload["ticket"].as_str().unwrap_or("");
            let enabled = payload["useProviderRouting"].as_bool();
            engine.prepare_subscription_apply(token, enabled).await?;
            serde_json::to_value(engine.apply_subscription_with_stop(token, enabled).await?)
                .map_err(|_| "invalid_command_response".to_owned())
        }
        "discardSubscription" => {
            engine.discard_subscription(payload["ticket"].as_str().unwrap_or(""));
            Ok(Value::Null)
        }
        _ => Err("unknown_command".into()),
    }
}
