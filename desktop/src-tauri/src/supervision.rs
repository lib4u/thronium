//! Background work that must run whether or not a window or tray exists:
//! core recovery, VPN and TUN observation, due subscriptions and periodic
//! probes. The workers keep running while a failed shutdown may cancel Quit,
//! but start nothing during shutdown.
use crate::{probe_runner, Shared};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::{AppHandle, Manager};

pub fn start(app: &AppHandle) {
    every(app, Duration::from_secs(1), |_, engine| {
        Box::pin(async move {
            engine.recovery_tick().await;
            engine.vpn_tick().await;
            // Without a tray these were noticed only while the window polled.
            engine.observe_tun().await;
            engine.observe_external().await;
        })
    });
    every(app, Duration::from_secs(15), |app, engine| {
        Box::pin(async move {
            engine.queue_due_subscriptions();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            if let Some(run) = engine.periodic_probe_tick(now) {
                probe_runner::start(app, run);
            }
        })
    });
}

type Tick = for<'a> fn(
    &'a AppHandle,
    &'a mut thronium_engine::Engine,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

fn every(app: &AppHandle, period: Duration, tick: Tick) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut ticks = tokio::time::interval(period);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let shared = app.state::<Shared>();
            if shared.quitting.load(Ordering::SeqCst) {
                continue;
            }
            let mut guard = shared.engine.lock().await;
            if shared.quitting.load(Ordering::SeqCst) {
                continue;
            }
            if let Ok(engine) = guard.as_mut() {
                tick(&app, engine).await;
            }
        }
    });
}
