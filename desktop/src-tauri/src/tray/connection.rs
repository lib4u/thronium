//! Connecting, disconnecting and switching profiles from the tray menu.
use super::{show, Tray};
use crate::localization::{text as localized, TextKey};
use crate::{Ordering, Shared};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

pub(super) fn change(app: &AppHandle, id: &str) {
    let target = if id.starts_with("tray-profile-") {
        let target = app.state::<Tray>().targets.lock().unwrap().get(id).cloned();
        // Events from a menu removed by a refresh have no valid target.
        let Some(target) = target else {
            return;
        };
        Some(target)
    } else {
        None
    };
    if app.state::<Tray>().busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let connect = id != "tray-disconnect";
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = async {
            let shared = app.state::<Shared>();
            let mut guard = shared.engine.lock().await;
            if shared.quitting.load(Ordering::SeqCst) {
                return Ok(());
            }
            let engine = guard.as_mut().map_err(|_| ())?;
            let snapshot = engine.snapshot();
            // A queued/double-clicked menu event must not restart an active connection.
            let chosen = if let Some(id) = target {
                (snapshot.running.as_ref() != Some(&id)).then_some(id)
            } else if connect && snapshot.running.is_none() {
                snapshot.selected
            } else {
                None
            };
            drop(guard);
            if let Some(id) = chosen {
                crate::connection_preflight::connect(&app, &id)
                    .await
                    .map_err(|_| ())?;
            } else if !connect {
                crate::connection_preflight::disconnect(&app)
                    .await
                    .map_err(|_| ())?;
            }
            Ok::<(), ()>(())
        }
        .await;
        app.state::<Tray>().busy.store(false, Ordering::SeqCst);
        // CheckMenuItem toggles itself even after a no-op or failure.
        app.state::<Tray>().refresh.store(true, Ordering::SeqCst);
        if result.is_err() && !app.state::<Shared>().quitting.load(Ordering::SeqCst) {
            let shared = app.state::<Shared>();
            shared.logs.event("error", "tray_connection_failed", None);
            let language = crate::localization::Language::of(&*shared.engine.lock().await);
            show(&app);
            app.dialog()
                .message(localized(
                    language,
                    TextKey::CouldNotChangeTheConnectionCheckTheProfilDc86529,
                ))
                .title("Thronium")
                .show(|_| {});
        }
    });
}
