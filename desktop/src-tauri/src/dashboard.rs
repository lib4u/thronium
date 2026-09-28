use serde_json::Value;
use tauri::{AppHandle, Manager};
use thronium_engine::dashboard::download::{Jobs, Request};
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
    let shared = app.state::<crate::Shared>();
    if matches!(name, "dashboardStatus" | "openDashboard") {
        if payload.as_object().is_none_or(|o| !o.is_empty()) {
            return Err("dashboard_invalid_request".into());
        }
        let mut guard = shared.engine.lock().await;
        let engine = guard.as_mut().map_err(|e| e.clone())?;
        if name == "dashboardStatus" {
            return serde_json::to_value(engine.dashboard_status()?)
                .map_err(|_| "dashboard_files_unavailable".into());
        }
        let url = engine.dashboard_open_url()?;
        drop(guard);
        return tauri::async_runtime::spawn_blocking(move || crate::vpn_browser::open(&url))
            .await
            .map_err(|_| "dashboard_open_failed")?
            .map(|()| Value::Null)
            .map_err(|_| "dashboard_open_failed".into());
    }
    let request: Request =
        serde_json::from_value(payload.clone()).map_err(|_| "dashboard_invalid_request")?;
    let state = app.state::<State>();
    if name == "cancelDashboardInstallation" {
        state.0.lock().await.cancel(&request.request_id)?;
        return Ok(Value::Null);
    }
    let mut cancelled = {
        // Checked under the registry lock that exit cancellation also takes.
        let mut jobs = state.0.lock().await;
        if shared.quitting.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("app_quitting".into());
        }
        jobs.begin(&request.request_id)?
    };
    let result=async {
        let mut guard=tokio::select!{biased;_ = cancelled.wait_for(|v|*v)=>return Err("dashboard_cancelled".into()),guard=shared.engine.lock()=>guard};
        if *cancelled.borrow(){return Err("dashboard_cancelled".into());}
        let download=guard.as_mut().map_err(|e|e.clone())?.prepare_dashboard_download()?;drop(guard);
        // A committed installation is reported as completed even if Cancel
        // arrives just after the atomic asset switch. Never claim it was undone.
        let receipt=download.execute(cancelled).await?;
        serde_json::to_value(receipt).map_err(|_|"dashboard_files_unavailable".into())
    }.await;
    state.0.lock().await.finish(&request.request_id);
    result
}
