//! Shared by window, tray and startup. Measurement workers never hold Engine.
use crate::{probe_runner, Shared};
use serde_json::{json, Value};
use std::sync::{atomic::Ordering, Arc, Mutex};
use tauri::Manager;
use thronium_engine::{
    auto_selector::{ConnectionMeasurements, RebuildTicket},
    probes::Status,
};
use tokio::sync::watch;

#[derive(Default)]
pub struct State(Arc<Mutex<Registry>>);
#[derive(Default)]
struct Registry {
    next: u64,
    active: Option<Job>,
}
struct Job {
    id: String,
    cancel: watch::Sender<bool>,
    status: Option<Value>,
    committing: bool,
}
struct Owner {
    state: Arc<Mutex<Registry>>,
    id: String,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let mut registry = self.state.lock().unwrap();
        if registry.active.as_ref().is_some_and(|j| j.id == self.id) {
            if let Some(job) = registry.active.take() {
                let _ = job.cancel.send(true);
            }
        }
    }
}
pub fn snapshot(app: &tauri::AppHandle) -> Value {
    app.state::<State>()
        .0
        .lock()
        .unwrap()
        .active
        .as_ref()
        .and_then(|j| j.status.clone())
        .unwrap_or(Value::Null)
}
pub fn cancel(app: &tauri::AppHandle, id: Option<&str>) -> bool {
    let state = app.state::<State>();
    let registry = state.0.lock().unwrap();
    if let Some(job) = registry
        .active
        .as_ref()
        .filter(|j| !j.committing && id.is_none_or(|id| j.id == id))
    {
        let _ = job.cancel.send(true);
        return true;
    }
    false
}
fn update(owner: &Owner, value: Option<Value>, committing: bool) {
    if let Some(job) = owner
        .state
        .lock()
        .unwrap()
        .active
        .as_mut()
        .filter(|j| j.id == owner.id)
    {
        job.status = value;
        job.committing = committing;
    }
}
/// Marks the job as committing unless it was cancelled. The check and the mark
/// hold the registry lock that `cancel` takes, so a Cancel either stops the job
/// before its transaction starts or is refused because it started.
fn begin_commit(
    app: &tauri::AppHandle,
    owner: &Owner,
    cancelled: &watch::Receiver<bool>,
) -> Result<(), String> {
    let mut registry = owner.state.lock().unwrap();
    current(app, cancelled)?;
    if let Some(job) = registry.active.as_mut().filter(|j| j.id == owner.id) {
        job.status = None;
        job.committing = true;
    }
    Ok(())
}
fn current(app: &tauri::AppHandle, cancelled: &watch::Receiver<bool>) -> Result<(), String> {
    if app.state::<Shared>().quitting.load(Ordering::SeqCst) {
        return Err("app_quitting".into());
    }
    if *cancelled.borrow() {
        return Err("selector_measurements_cancelled".into());
    }
    Ok(())
}

/// The window and the tray stop the same way: a connection still being
/// prepared is cancelled, then the running one is disconnected.
pub async fn disconnect(app: &tauri::AppHandle) -> Result<(), String> {
    cancel(app, None);
    app.state::<Shared>()
        .engine
        .lock()
        .await
        .as_mut()
        .map_err(|e| e.clone())?
        .disconnect()
        .await
}
pub async fn connect(app: &tauri::AppHandle, id: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    crate::qt_throne::warn_once(app).await;
    transition(app, id, false, None).await
}
pub async fn apply_routing(app: &tauri::AppHandle) -> Result<(), String> {
    let id = app
        .state::<Shared>()
        .engine
        .lock()
        .await
        .as_mut()
        .map_err(|e| e.clone())?
        .snapshot()
        .running
        .ok_or("not_connected")?;
    transition(app, &id, true, None).await
}
async fn transition(
    app: &tauri::AppHandle,
    id: &str,
    routing: bool,
    rebuild: Option<&RebuildTicket>,
) -> Result<(), String> {
    let (owner, mut cancelled) = {
        let state = app.state::<State>();
        let mut registry = state.0.lock().unwrap();
        if registry.active.is_some() {
            return Err("connection_preparing".into());
        }
        registry.next = registry.next.wrapping_add(1);
        let token = format!("connect-{}", registry.next);
        let (sender, receiver) = watch::channel(false);
        registry.active = Some(Job {
            id: token.clone(),
            cancel: sender,
            status: None,
            committing: false,
        });
        (
            Owner {
                state: state.0.clone(),
                id: token,
            },
            receiver,
        )
    };
    let shared = app.state::<Shared>();
    let (mut plan, name) = {
        let mut guard = shared.engine.lock().await;
        current(app, &cancelled)?;
        let engine = guard.as_mut().map_err(|e| e.clone())?;
        let plan = if let Some(ticket) = rebuild {
            Some(engine.prepare_selector_rebuild(ticket)?)
        } else {
            engine.connection_measurements(id)?
        };
        (plan, engine.profile(id)?.name)
    };
    if let Some(plan) = &mut plan {
        loop {
            let batch = measure(app, &owner, plan, &name, &mut cancelled).await?;
            let mut guard = shared.engine.lock().await;
            current(app, &cancelled)?;
            let engine = guard.as_mut().map_err(|e| e.clone())?;
            if !engine.complete_connection_measurements(plan, batch.as_deref())? {
                break;
            }
        }
    }
    // Assets are downloaded before the transaction commits, so that wait stays
    // cancellable and does not hold the Engine lock.
    let mut deferred = crate::geodata_deferral::Deferred::new(&shared).cancellable(
        cancelled.clone(),
        |downloading| {
            // A download is cancellable again; the next attempt marks the commit.
            if downloading {
                update(&owner, None, false)
            }
        },
    );
    loop {
        let mut guard = deferred.lock().await?;
        // Once the checked connection transaction starts, its existing rollback owns it.
        begin_commit(app, &owner, &cancelled)?;
        let engine = guard.as_mut().map_err(|e| e.clone())?;
        let result = if routing {
            if let Some(plan) = &plan {
                if !engine.connection_measurements_current(plan) {
                    return Err("selector_measurements_stale".into());
                }
            }
            engine.apply_routing_measured(plan.as_ref()).await
        } else if let Some(ticket) = rebuild {
            engine
                .connect_rebuilt(ticket, plan.as_ref().ok_or("selector_measurements_stale")?)
                .await
        } else if let Some(plan) = &plan {
            engine.connect_measured(plan).await
        } else {
            engine.connect(id).await
        };
        if let Some(result) = deferred.finish(guard, result).await {
            // A cancelled download reports the preparation's own cancellation.
            return result.or_else(|error| {
                current(app, &cancelled)?;
                Err(error)
            });
        }
    }
}

async fn measure(
    app: &tauri::AppHandle,
    owner: &Owner,
    plan: &ConnectionMeasurements,
    name: &str,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<Option<String>, String> {
    let shared = app.state::<Shared>();
    let mut last_batch = None;
    let total: usize = plan.pools.iter().map(|p| p.ids.len()).sum();
    let fresh: usize = plan.pools.iter().map(|p| p.fresh_count).sum();
    let mut completed = 0;
    let progress = |done: usize| {
        update(
            owner,
            Some(json!({"id":owner.id,"profileId":plan.id,
        "name":name,"total":total,"done":done,"fresh":fresh,"reusing":plan.reuses_selection()})),
            false,
        )
    };
    progress(0);
    for pool in &plan.pools {
        for ids in pool.ids.chunks(1000) {
            let run = {
                let mut guard = shared.engine.lock().await;
                current(app, cancelled)?;
                let engine = guard.as_mut().map_err(|e| e.clone())?;
                if !engine.connection_measurements_current(plan) {
                    return Err("selector_measurements_stale".into());
                }
                engine.start_preflight_tests(pool, ids)?
            };
            let batch_id = run.id.clone();
            let workers = probe_runner::start(app, run);
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(
                    30_000 + ids.len() as u64 * (2 * pool.timeout_ms as u64 + 9000),
                );
            let result: Result<(), String> = async {
                loop {
                    current(app, cancelled)?;
                    let batch = {
                        let mut guard = shared.engine.lock().await;
                        current(app, cancelled)?;
                        let engine = guard.as_mut().map_err(|e| e.clone())?;
                        if !engine.connection_measurements_current(plan) { return Err("selector_measurements_stale".into()); }
                        engine.snapshot().url_tests.ok_or("selector_measurements_interrupted")?
                    };
                    if batch.id != batch_id || batch.entries.len() != ids.len()
                        || batch.entries.iter().zip(ids).any(|(e,id)| &e.profile_id != id)
                        || batch.entries.iter().any(|e| !matches!(e.status, Status::Queued | Status::Testing | Status::Ok | Status::Error)
                            && !(batch.source == thronium_engine::probes::Source::AutoSelect && e.status == Status::Unsupported)) {
                        return Err("selector_measurements_interrupted".into());
                    }
                    let done = batch.entries.iter().filter(|e| matches!(e.status, Status::Ok | Status::Error | Status::Unsupported)).count();
                    progress(completed + done);
                    if done == ids.len() { return Ok(()); }
                    tokio::select! { biased;
                        _ = cancelled.changed() => return Err("selector_measurements_cancelled".into()),
                        _ = tokio::time::sleep_until(deadline) => return Err("selector_measurements_timeout".into()),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(120)) => {}
                    }
                }
            }.await;
            if result.is_err() {
                if let Ok(engine) = shared.engine.lock().await.as_mut() {
                    engine.cancel_url_test_batch(&batch_id);
                }
            }
            // Reap this batch before releasing the connection slot or starting another batch.
            let mut workers_ok = true;
            for worker in workers {
                workers_ok &= worker.await.is_ok();
            }
            result?;
            if !workers_ok {
                return Err("selector_measurements_interrupted".into());
            }
            completed += ids.len();
            last_batch = Some(batch_id);
        }
    }
    current(app, cancelled)?;
    Ok(last_batch)
}

/// The worker runs while the window is hidden. It never holds Engine over the
/// automatic measurement sweep, so disconnect and normal recovery remain live.
pub fn watch(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(5));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let shared = app.state::<Shared>();
            if shared.quitting.load(Ordering::SeqCst)
                || app.state::<State>().0.lock().unwrap().active.is_some()
            {
                continue;
            }
            let ticket = {
                let mut guard = shared.engine.lock().await;
                if shared.quitting.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(engine) = guard.as_mut() else { continue };
                engine.selector_rebuild_tick().await
            };
            let Some(ticket) = ticket else { continue };
            let result = transition(&app, &ticket.id, false, Some(&ticket)).await;
            let cancelled = result
                .as_ref()
                .is_err_and(|e| e == "selector_measurements_cancelled");
            if let Ok(engine) = shared.engine.lock().await.as_mut() {
                engine.finish_selector_rebuild(&ticket, cancelled);
            }
            if result.is_err_and(|e| {
                !matches!(
                    e.as_str(),
                    "probe_busy"
                        | "connection_preparing"
                        | "selector_measurements_stale"
                        | "selector_measurements_cancelled"
                        | "app_quitting"
                )
            }) {
                shared
                    .logs
                    .event("warn", "selector_rebuild_kept_previous", None);
            }
        }
    });
}
