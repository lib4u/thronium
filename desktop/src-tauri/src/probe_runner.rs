use super::Shared;
use std::time::Duration;
use tauri::Manager;
use thronium_engine::probes::{Outcome, Probe};
use tokio::sync::watch;

pub async fn execute(
    app: &tauri::AppHandle,
    probe: Probe,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<Outcome, String> {
    if *cancelled.borrow() {
        return Err("probe_cancelled".into());
    }
    if probe.is_disposable_vpn() || probe.owns_execution() {
        return probe.execute_detailed(cancelled).await;
    }
    let shared = app.state::<Shared>();
    let job = shared
        .engine
        .lock()
        .await
        .as_mut()
        .map_err(|e| e.clone())?
        .start_managed_probe(&probe)
        .await?;
    let Some(job) = job else {
        return probe.execute_detailed(cancelled).await;
    };
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(probe.timeout_ms() as u64 + 2000);
    let result = loop {
        if *cancelled.borrow() {
            break Err("probe_cancelled".into());
        }
        let result = shared
            .engine
            .lock()
            .await
            .as_mut()
            .map_err(|e| e.clone())?
            .query_managed_probe(&job)
            .await;
        match result {
            Ok(Some(ms)) => break Ok(ms),
            Err(error) => break Err(error),
            Ok(None) => {}
        }
        tokio::select! {
            biased;
            _ = cancelled.changed() => break Err("probe_cancelled".into()),
            _ = tokio::time::sleep_until(deadline) => break Err("probe_timeout".into()),
            _ = tokio::time::sleep(Duration::from_millis(40)) => {}
        }
    };
    if result.is_err() {
        if let Ok(engine) = shared.engine.lock().await.as_mut() {
            engine.cancel_managed_probe(&job).await;
        }
    }
    result.map(Outcome::Latency)
}

/// Queue ownership is carried by Run.id; every caller awaits or retains its workers.
pub fn start(
    app: &tauri::AppHandle,
    run: thronium_engine::probes::Run,
) -> Vec<tauri::async_runtime::JoinHandle<()>> {
    (0..run.concurrency)
        .map(|_| {
            let app = app.clone();
            let mut run = run.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let shared = app.state::<Shared>();
                    if shared.quitting.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let probe = shared
                        .engine
                        .lock()
                        .await
                        .as_mut()
                        .ok()
                        .and_then(|e| e.next_url_test(&run.id));
                    let Some(probe) = probe else {
                        break;
                    };
                    let id = probe.id.clone();
                    let result = execute(&app, probe, &mut run.cancelled).await;
                    if let Ok(engine) = shared.engine.lock().await.as_mut() {
                        engine.finish_url_test_detailed(&run.id, &id, result);
                    };
                }
            })
        })
        .collect()
}
