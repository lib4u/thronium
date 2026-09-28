//! The native owner of catalog downloads. Only the independent HTTP future is
//! cancellable; the Engine remains the sole owner of core/RPC transactions.
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::{AppHandle, Manager};
use thronium_engine::{geodata_assets::Jobs, routing_downloads::Preparation, Engine};
use tokio::sync::{watch, Mutex};

#[derive(Default)]
pub struct State(Mutex<Jobs>);
impl State {
    pub async fn cancel_all(&self) {
        self.0.lock().await.cancel_all();
    }
    async fn execute(
        &self,
        engine: &Mutex<Result<Engine, String>>,
        quitting: &AtomicBool,
        name: &str,
        payload: Value,
    ) -> Result<Value, String> {
        if name == "cancelRoutingDownload" {
            self.0.lock().await.cancel(
                payload["requestId"]
                    .as_str()
                    .ok_or("geodata_invalid_request")?,
            )?;
            return Ok(Value::Null);
        }
        if quitting.load(Ordering::SeqCst) {
            return Err("app_quitting".into());
        }
        // Older callers may omit the id. UI callers always send one for cancellation.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = match payload.get("requestId") {
            Some(value) => value.as_str().ok_or("geodata_invalid_request")?.to_owned(),
            None => format!("native-routing-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        };
        let mut cancelled = self.0.lock().await.begin(&id)?;
        let result = async {
            let mut guard = tokio::select! {
                biased;
                _ = cancelled.wait_for(|value| *value) => return Err("geodata_cancelled".into()),
                guard = engine.lock() => guard,
            };
            // Serialize cancellation with the synchronous local/cache path too.
            let jobs = self.0.lock().await;
            current(&cancelled, quitting)?;
            let current_engine = guard.as_mut().map_err(|e| e.clone())?;
            let preparation = match name {
                "loadGeodata" => current_engine.prepare_geodata_load(payload)?,
                "fetchRoutingSource" => {
                    Preparation::Download(current_engine.prepare_routing_source(
                        payload["url"].as_str().ok_or("geodata_url_invalid")?,
                    )?)
                }
                "refreshRoutingSource" => {
                    Preparation::Download(current_engine.prepare_routing_update(
                        payload["id"].as_str().ok_or("routing_profile_missing")?,
                    )?)
                }
                _ => return Err("unknown_command".into()),
            };
            let download = match preparation {
                Preparation::Ready(value) => return Ok(value),
                Preparation::Download(download) => download,
            };
            drop(jobs);
            drop(guard);
            let prepared = download.execute(cancelled.clone()).await?;
            let mut guard = tokio::select! {
                biased;
                _ = cancelled.wait_for(|value| *value) => return Err("geodata_cancelled".into()),
                guard = engine.lock() => guard,
            };
            // Linearization point: accepted cancellation wins before commit. The
            // tiny job lock is never held across an Engine wait or external I/O.
            let _jobs = self.0.lock().await;
            current(&cancelled, quitting)?;
            guard
                .as_mut()
                .map_err(|e| e.clone())?
                .commit_routing_download(prepared)
        }
        .await;
        self.0.lock().await.finish(&id);
        result
    }
}
fn current(cancelled: &watch::Receiver<bool>, quitting: &AtomicBool) -> Result<(), String> {
    if quitting.load(Ordering::SeqCst) {
        Err("app_quitting".into())
    } else if *cancelled.borrow() {
        Err("geodata_cancelled".into())
    } else {
        Ok(())
    }
}
pub async fn run(app: &AppHandle, name: &str, payload: Value) -> Result<Value, String> {
    let shared = app.state::<crate::Shared>();
    app.state::<State>()
        .execute(&shared.engine, &shared.quitting, name, payload)
        .await
}

pub fn start_background(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut schedule = thronium_engine::routing::source::Schedule::default();
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(15));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let shared = app.state::<crate::Shared>();
            // One sequential worker; manual downloads remain independently cancellable.
            for _ in 0..100 {
                if shared.quitting.load(Ordering::SeqCst) {
                    break;
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let id = {
                    let guard = shared.engine.lock().await;
                    guard
                        .as_ref()
                        .ok()
                        .and_then(|engine| engine.next_routing_update(&mut schedule, now))
                };
                let Some(id) = id else { break };
                if let Err(error) =
                    run(&app, "refreshRoutingSource", serde_json::json!({"id":id})).await
                {
                    let code = thronium_engine::ipc::BoundaryError::legacy(&error).code;
                    shared
                        .logs
                        .event("warn", "routing_update_error", Some(code));
                    schedule.failed(&id);
                }
            }
        }
    });
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
