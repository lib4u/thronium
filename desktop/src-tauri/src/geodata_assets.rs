use serde::Deserialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};
use thronium_engine::geodata_assets::{Jobs, Selection};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct State(Mutex<Jobs>);
impl State {
    /// Application exit: the running request stops and a late Start is refused.
    pub async fn cancel_all(&self) {
        self.0.lock().await.cancel_all();
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cancel {
    request_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    request_id: String,
    selection: Selection,
}

pub async fn run(app: &AppHandle, name: &str, payload: &Value) -> Result<Value, String> {
    let shared = app.state::<crate::Shared>();
    if name == "xrayGeodataSources" {
        if payload.as_object().is_none_or(|p| !p.is_empty()) {
            return Err("geodata_invalid_request".into());
        }
        return Ok(shared
            .engine
            .lock()
            .await
            .as_ref()
            .map_err(Clone::clone)?
            .xray_geodata_sources());
    }
    if name == "xrayGeodataStatus" {
        let selection: Selection =
            serde_json::from_value(payload.clone()).map_err(|_| "geodata_invalid_request")?;
        let guard = shared.engine.lock().await;
        let inspection = guard
            .as_ref()
            .map_err(Clone::clone)?
            .inspect_xray_geodata(selection)?;
        drop(guard);
        let status = tauri::async_runtime::spawn_blocking(move || inspection.execute())
            .await
            .map_err(|_| "geodata_invalid")??;
        return serde_json::to_value(status).map_err(|_| "geodata_invalid".into());
    }
    let state = app.state::<State>();
    if name == "cancelXrayGeodataDownload" {
        let request: Cancel =
            serde_json::from_value(payload.clone()).map_err(|_| "geodata_invalid_request")?;
        state.0.lock().await.cancel(&request.request_id)?;
        return Ok(Value::Null);
    }
    let request: Request =
        serde_json::from_value(payload.clone()).map_err(|_| "geodata_invalid_request")?;
    let mut cancelled = {
        // Checked under the registry lock that exit cancellation also takes.
        let mut jobs = state.0.lock().await;
        if shared.quitting.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("app_quitting".into());
        }
        jobs.begin(&request.request_id)?
    };
    let result = async {
        let mut guard = tokio::select! {biased;_ = cancelled.wait_for(|v|*v)=>return Err("geodata_cancelled".into()),guard=shared.engine.lock()=>guard};
        if *cancelled.borrow() {return Err("geodata_cancelled".into());}
        let download = guard.as_mut().map_err(|e|e.clone())?.prepare_xray_geodata_download(request.selection)?;
        drop(guard);
        let prepared = download.execute(cancelled.clone()).await?;
        let guard = tokio::select! {biased;_ = cancelled.wait_for(|v|*v)=>return Err("geodata_cancelled".into()),guard=shared.engine.lock()=>guard};
        if *cancelled.borrow() {return Err("geodata_cancelled".into());}
        // The immutable data was validated and synced away from this lock.
        // Current library dependencies are checked immediately before switching its tiny reference.
        let status = guard.as_ref().map_err(Clone::clone)?.commit_xray_geodata(prepared)?;
        serde_json::to_value(status).map_err(|_| "geodata_invalid".into())
    }.await;
    state.0.lock().await.finish(&request.request_id);
    result
}
