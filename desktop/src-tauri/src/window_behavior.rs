//! Keep a reachable window when a desktop has no tray host, or loses it.
use crate::{Ordering, Shared};
use std::sync::atomic::AtomicBool;
use tauri::{AppHandle, Manager};
use thronium_engine::store::CloseBehavior;

#[derive(Default)]
pub struct State {
    disabled: AtomicBool,
    available: AtomicBool,
    hidden: AtomicBool,
    closing: AtomicBool,
}

/// Whether a tray host shows our indicator, as last observed by `watch`.
/// Callers on the main thread and in async tasks read this instead of
/// waiting on D-Bus themselves.
pub fn available(app: &AppHandle) -> bool {
    let state = app.state::<State>();
    !state.disabled.load(Ordering::SeqCst) && state.available.load(Ordering::SeqCst)
}

pub fn shown(app: &AppHandle) {
    app.state::<State>().hidden.store(false, Ordering::SeqCst);
}

/// Asks the session bus; blocking for up to 500 ms, so only `watch` calls it
/// on a blocking thread.
fn host_available(app: &AppHandle) -> bool {
    if app.state::<State>().disabled.load(Ordering::SeqCst) {
        return false;
    }
    if app.tray_by_id("thronium").is_none() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        use gtk::gio::{self, prelude::*};
        // GNOME may export our DBusMenu without displaying an indicator.
        // A registered StatusNotifierHost is required before hiding the window.
        gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)
            .ok()
            .and_then(|bus| {
                bus.call_sync(
                    Some("org.kde.StatusNotifierWatcher"),
                    "/StatusNotifierWatcher",
                    "org.freedesktop.DBus.Properties",
                    "Get",
                    Some(
                        &(
                            "org.kde.StatusNotifierWatcher",
                            "IsStatusNotifierHostRegistered",
                        )
                            .to_variant(),
                    ),
                    None,
                    gio::DBusCallFlags::NO_AUTO_START,
                    500,
                    gio::Cancellable::NONE,
                )
                .ok()
            })
            .and_then(|v| v.get::<(gtk::glib::Variant,)>())
            .and_then(|v| v.0.get::<bool>())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

fn background(app: &AppHandle, can_hide: bool) {
    if let Some(window) = app.get_webview_window("main") {
        if can_hide && window.hide().is_ok() {
            app.state::<State>().hidden.store(true, Ordering::SeqCst);
        } else {
            // Keep the window in the task switcher when there is no indicator.
            let _ = window.show();
            let _ = window.minimize();
            shown(app);
        }
    }
}

pub fn close(app: &AppHandle) {
    if app.state::<Shared>().quitting.load(Ordering::SeqCst)
        || app.state::<State>().closing.swap(true, Ordering::SeqCst)
    {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let keep_running = app
            .state::<Shared>()
            .engine
            .lock()
            .await
            .as_ref()
            .is_ok_and(|e| e.store.library.preferences.close_behavior == CloseBehavior::Background);
        let can_hide = keep_running && available(&app);
        let handle = app.clone();
        let result = app.run_on_main_thread(move || {
            if !handle.state::<Shared>().quitting.load(Ordering::SeqCst) {
                if keep_running {
                    background(&handle, can_hide);
                } else {
                    handle.exit(0);
                }
            }
            handle
                .state::<State>()
                .closing
                .store(false, Ordering::SeqCst);
        });
        if result.is_err() {
            app.state::<State>().closing.store(false, Ordering::SeqCst);
        }
    });
}

pub fn watch(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            if app.state::<Shared>().quitting.load(Ordering::SeqCst) {
                // A failed proxy restore can cancel an exit. Keep monitoring.
                continue;
            }
            let handle = app.clone();
            let available = tauri::async_runtime::spawn_blocking(move || host_available(&handle))
                .await
                .unwrap_or(false);
            app.state::<State>()
                .available
                .store(available, Ordering::SeqCst);
            if !available && app.state::<State>().hidden.load(Ordering::SeqCst) {
                let handle = app.clone();
                let _ = app.run_on_main_thread(move || {
                    if !handle.state::<Shared>().quitting.load(Ordering::SeqCst)
                        && handle.state::<State>().hidden.swap(false, Ordering::SeqCst)
                    {
                        background(&handle, false);
                    }
                });
            }
        }
    });
}

pub fn tray_enabled(app: &AppHandle, enabled: bool) {
    app.state::<State>()
        .disabled
        .store(!enabled, Ordering::SeqCst);
    if !enabled {
        crate::tray::show(app);
    }
}
pub fn toggle(app: &AppHandle) {
    if app
        .get_webview_window("main")
        .is_some_and(|w| w.is_visible().unwrap_or(false))
    {
        background(app, available(app));
    } else {
        crate::tray::show(app);
    }
}
