use serde_json::Value;
use tauri::{AppHandle, Manager};
use thronium_engine::settings::warp::{CancelRequest, Jobs, StartRequest, TERMS_URL};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct State(Mutex<Jobs>);
impl State {
    /// Application exit: the running request stops and a late Start is refused.
    pub async fn cancel_all(&self) {
        self.0.lock().await.cancel_all();
    }
}

pub async fn run(app: &AppHandle, name: &str, payload: &Value) -> Result<Value, String> {
    if name == "openWarpTerms" {
        return tauri::async_runtime::spawn_blocking(|| crate::vpn_browser::open(TERMS_URL))
            .await
            .map_err(|_| "warp_terms_open_failed")?
            .map(|()| Value::Null)
            .map_err(|_| "warp_terms_open_failed".into());
    }
    let state = app.state::<State>();
    if name == "cancelWarpRegistration" {
        let request: CancelRequest =
            serde_json::from_value(payload.clone()).map_err(|_| "warp_invalid_request")?;
        state.0.lock().await.cancel(&request.request_id)?;
        return Ok(Value::Null);
    }
    let request: StartRequest =
        serde_json::from_value(payload.clone()).map_err(|_| "warp_invalid_request")?;
    let mut cancelled = {
        // Checked under the registry lock that exit cancellation also takes.
        let mut jobs = state.0.lock().await;
        if app
            .state::<crate::Shared>()
            .quitting
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("app_quitting".into());
        }
        jobs.begin(&request)?
    };
    let result = async {
        let shared = app.state::<crate::Shared>();
        let mut guard = tokio::select! {
            biased;
            _ = cancelled.wait_for(|value| *value) => return Err("warp_cancelled".into()),
            guard = shared.engine.lock() => guard,
        };
        if *cancelled.borrow() {
            return Err("warp_cancelled".into());
        }
        // The existing key-generation RPC must finish before cancellation can
        // discard its result, so the shared Core stream stays synchronized.
        let registration = guard
            .as_mut()
            .map_err(|e| e.clone())?
            .prepare_warp_registration()
            .await?;
        drop(guard);
        let config = registration.execute(&mut cancelled).await?;
        if *cancelled.borrow() {
            return Err("warp_cancelled".into());
        }
        serde_json::to_value(config).map_err(|_| "warp_invalid_response".into())
    }
    .await;
    state.0.lock().await.finish(&request.request_id);
    result
}
