//! Reopening focuses the existing process and hands it the links and files the
//! second launch received.
use crate::{tray, Ordering, Shared};
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use tauri::{plugin::TauriPlugin, AppHandle, Manager, Wry};

#[cfg(any(target_os = "windows", test))]
mod handoff;
#[cfg(target_os = "windows")]
mod windows;

static FOCUS_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(not(target_os = "windows"))]
pub fn plugin(identifier: &str, location: &thronium_engine::launch::Location) -> TauriPlugin<Wry> {
    let builder = tauri_plugin_single_instance::Builder::new().callback(|app, args, cwd| {
        received(app, args.into_iter().map(Into::into), Path::new(&cwd));
    });
    #[cfg(target_os = "linux")]
    let builder = builder.dbus_id(location.instance_id(identifier));
    #[cfg(not(target_os = "linux"))]
    let _ = (identifier, location);
    builder.build()
}

#[cfg(target_os = "windows")]
pub fn plugin(identifier: &str, location: &thronium_engine::launch::Location) -> TauriPlugin<Wry> {
    windows::plugin(location.instance_id(identifier))
}

/// A later launch of the same library: `args` starts with its executable.
fn received(app: &AppHandle, args: impl IntoIterator<Item = OsString>, cwd: &Path) {
    if app
        .try_state::<Shared>()
        .is_some_and(|s| s.quitting.load(Ordering::SeqCst))
    {
        return;
    }
    if app.try_state::<crate::incoming::State>().is_some() {
        crate::storage::receive_launch(app, args, cwd);
    }
    if app.get_webview_window("main").is_some() {
        tray::show(app);
    } else {
        FOCUS_PENDING.store(true, Ordering::SeqCst);
    }
}

pub fn ready(app: &AppHandle) {
    if FOCUS_PENDING.swap(false, Ordering::SeqCst) {
        tray::show(app);
    }
}
