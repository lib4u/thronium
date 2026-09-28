use crate::{probe_runner, settings_tests, transfer, ResourceMetrics, Shared};
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::Manager;
use tauri::State;
use thronium_engine::Engine;

/// Longest wait for Engine before a process-metrics sample is skipped as busy.
const METRICS_ENGINE_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

pub(super) async fn unlocked(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: AppHandle,
) -> Result<Value, String> {
    if name == "processMetrics" {
        // The snapshot poll and background ticks hold Engine for short core
        // calls every second; wait out those, but never a connection transition.
        // Copy only the identity of our child, then release Engine before
        // reading /proc.
        let core = {
            let guard = tokio::time::timeout(METRICS_ENGINE_WAIT, state.engine.lock())
                .await
                .map_err(|_| "process_metrics_busy")?;
            guard
                .as_ref()
                .map_err(|_| "process_metrics_unavailable")?
                .owned_core_process()
        };
        let sampler = app.state::<ResourceMetrics>().0.clone();
        let reset = payload["reset"].as_bool().unwrap_or(false);
        return tauri::async_runtime::spawn_blocking(move || {
            let mut guard = sampler.lock().map_err(|_| "process_metrics_unavailable")?;
            serde_json::to_value(guard.sample(core, reset))
                .map_err(|_| "process_metrics_unavailable")
        })
        .await
        .map_err(|_| "process_metrics_unavailable")?
        .map_err(String::from);
    }
    if name == "getLogs" {
        let filter = serde_json::from_value(payload).map_err(|_| "invalid_log_filter")?;
        return serde_json::to_value(state.logs.view(filter)?)
            .map_err(|_| "log_read_failed".into());
    }
    if name == "clearLogs" {
        state.logs.clear();
        return Ok(Value::Null);
    }
    if name == "exportLogs" {
        let text = payload["text"].as_str().ok_or("export_failed")?;
        let language = crate::localization::Language::of(&*state.engine.lock().await);
        return transfer::deliver(&app, text.into(), "file", "thronium.log", language).await;
    }
    if matches!(
        name.as_str(),
        "startUrlTests" | "startPing" | "startIpTests" | "startSpeedTests"
    ) {
        let run = {
            let mut guard = state.engine.lock().await;
            let engine = guard.as_mut().map_err(|e| e.clone())?;
            if name == "startUrlTests" {
                let options =
                    serde_json::from_value(payload).map_err(|_| "probe_invalid_options")?;
                engine.start_url_tests(options)?
            } else {
                let ids = serde_json::from_value(payload["ids"].clone())
                    .map_err(|_| "probe_invalid_options")?;
                match name.as_str() {
                    "startIpTests" => engine.start_ip_tests(ids)?,
                    "startSpeedTests" => engine.start_speed_tests(ids)?,
                    _ => engine.start_ping(ids)?,
                }
            }
        };
        let id = run.id.clone();
        probe_runner::start(&app, run);
        return Ok(json!({"id":id}));
    }
    if matches!(
        name.as_str(),
        "testSpeed" | "testIp" | "testInternet" | "cancelSettingsTest"
    ) {
        return settings_tests::run(&app, &name, &payload).await;
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
        "trafficHistory" => Ok(engine.traffic_history()),
        "trafficStats" => engine.traffic_stats(
            payload["days"].as_u64().unwrap_or_default() as u32,
            payload["utcOffsetMinutes"].as_i64().unwrap_or_default(),
        ),
        "clearTrafficHistory" => {
            engine.clear_traffic_history()?;
            Ok(Value::Null)
        }
        "getMeasurementJournal" => Ok(engine.measurement_journal()),
        "clearMeasurementJournal" => {
            engine.clear_measurement_journal()?;
            Ok(Value::Null)
        }
        "getSwitchHistory" => Ok(engine.switch_history()),
        "clearSwitchHistory" => {
            engine.clear_switch_history()?;
            Ok(Value::Null)
        }
        "cancelUrlTests" => {
            engine.cancel_url_tests();
            Ok(Value::Null)
        }
        "clearUrlTests" => {
            engine.clear_url_tests()?;
            Ok(Value::Null)
        }
        "cancelUrlTestBatch" => Ok(json!(engine.cancel_url_test_batch(id))),
        "closeConnections" => {
            let ids: Vec<String> = serde_json::from_value(payload["ids"].clone())
                .map_err(|_| "invalid_connections")?;
            Ok(json!({"closed": engine.close_connections(ids).await?}))
        }
        _ => Err("unknown_command".into()),
    }
}
