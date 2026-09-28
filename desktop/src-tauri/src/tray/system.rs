//! Qt's tray toggles and restarts: start at login, connecting to the last
//! server, LAN access, the connection mode, restarting the connection and the
//! program. They save through the same checks as the Settings page. A change the
//! running connection cannot take stops it and connects the same profile again,
//! as Qt restarts the proxy.
use super::{show, Tray};
use crate::localization::{text as localized, Language, TextKey};
use crate::{Ordering, Shared};
use serde_json::Value;
use tauri::{
    menu::{CheckMenuItem, MenuItem, Submenu},
    AppHandle, Manager, Wry,
};
use tauri_plugin_dialog::DialogExt;
use thronium_engine::{settings, store::Library};

const MODES: [(&str, TextKey); 3] = [
    ("local", TextKey::TrayModeLocal),
    ("system-proxy", TextKey::TrayModeSystemProxy),
    ("tun", TextKey::TrayModeTun),
];

#[derive(Default, PartialEq, Eq)]
pub(super) struct View {
    autostart: bool,
    remember: bool,
    lan: bool,
    mode: String,
    proxy_available: bool,
    tun_supported: bool,
}
impl View {
    pub(super) fn new(library: &Library, snapshot: &thronium_engine::Snapshot) -> Self {
        Self {
            autostart: settings::boolean(library, "autostart"),
            remember: settings::boolean(library, "remember_enable"),
            lan: lan(&settings::string(library, "inbound_address")),
            mode: mode(library),
            proxy_available: snapshot.system_proxy.available,
            tun_supported: snapshot.tun_supported,
        }
    }
    /// A mode this desktop cannot provide stays visible but cannot be chosen.
    fn offers(&self, mode: &str) -> bool {
        self.mode == mode
            || match mode {
                "system-proxy" => self.proxy_available,
                "tun" => self.tun_supported,
                _ => true,
            }
    }
}
fn mode(library: &Library) -> String {
    settings::value(library, "connection_mode")
        .as_str()
        .unwrap_or_default()
        .to_owned()
}
/// Qt's "Allow LAN" is an inbound listening on every address.
fn lan(address: &str) -> bool {
    matches!(address, "::" | "0.0.0.0")
}

pub(super) struct Items {
    pub(super) autostart: CheckMenuItem<Wry>,
    pub(super) remember: CheckMenuItem<Wry>,
    pub(super) lan: CheckMenuItem<Wry>,
    pub(super) mode: Submenu<Wry>,
    modes: Vec<CheckMenuItem<Wry>>,
    pub(super) restart_connection: MenuItem<Wry>,
    pub(super) restart: MenuItem<Wry>,
}
fn mode_items(
    app: &AppHandle,
    view: &View,
    language: Language,
    prefix: &str,
    enabled: bool,
) -> tauri::Result<Vec<CheckMenuItem<Wry>>> {
    MODES
        .iter()
        .map(|(mode, key)| {
            CheckMenuItem::with_id(
                app,
                format!("{prefix}{mode}"),
                localized(language, *key),
                enabled && view.offers(mode),
                view.mode == *mode,
                None::<&str>,
            )
        })
        .collect()
}
pub(super) fn items(app: &AppHandle, language: Language) -> tauri::Result<Items> {
    let text = |key| localized(language, key);
    let check =
        |id: &str, key| CheckMenuItem::with_id(app, id, text(key), false, false, None::<&str>);
    let modes = mode_items(app, &View::default(), language, "tray-mode-", false)?;
    let mode = Submenu::with_id(app, "tray-mode", text(TextKey::TrayConnectionMode), true)?;
    for item in &modes {
        mode.append(item)?;
    }
    Ok(Items {
        autostart: check("tray-autostart", TextKey::TrayStartAtLogin)?,
        remember: check("tray-remember", TextKey::TrayRememberLastServer)?,
        lan: check("tray-lan", TextKey::TrayAllowLan)?,
        mode,
        modes,
        restart_connection: MenuItem::with_id(
            app,
            "tray-restart-connection",
            text(TextKey::TrayRestartConnection),
            false,
            None::<&str>,
        )?,
        restart: MenuItem::with_id(
            app,
            "tray-restart",
            text(TextKey::TrayRestartThronium),
            true,
            None::<&str>,
        )?,
    })
}
pub(super) fn update(items: &Items, view: &View, language: Language, idle: bool, running: bool) {
    let text = |key| localized(language, key);
    for (item, checked, key) in [
        (&items.autostart, view.autostart, TextKey::TrayStartAtLogin),
        (
            &items.remember,
            view.remember,
            TextKey::TrayRememberLastServer,
        ),
        (&items.lan, view.lan, TextKey::TrayAllowLan),
    ] {
        let _ = item.set_text(text(key));
        let _ = item.set_checked(checked);
        let _ = item.set_enabled(idle);
    }
    let _ = items.mode.set_text(text(TextKey::TrayConnectionMode));
    for (item, (mode, key)) in items.modes.iter().zip(MODES) {
        let _ = item.set_text(text(key));
        let _ = item.set_checked(view.mode == mode);
        let _ = item.set_enabled(idle && view.offers(mode));
    }
    let _ = items
        .restart_connection
        .set_text(text(TextKey::TrayRestartConnection));
    let _ = items.restart_connection.set_enabled(idle && running);
    let _ = items.restart.set_text(text(TextKey::TrayRestartThronium));
}

enum Change {
    Toggle(&'static str),
    Lan,
    Mode(&'static str),
    Reconnect,
}
enum Failure {
    Save,
    Reconnect,
}

/// Handles the actions of this part of the menu; `false` for any other item.
pub(super) fn action(app: &AppHandle, id: &str) -> bool {
    let change = match id {
        "tray-autostart" => Change::Toggle("autostart"),
        "tray-remember" => Change::Toggle("remember_enable"),
        "tray-lan" => Change::Lan,
        "tray-restart-connection" => Change::Reconnect,
        "tray-restart" => {
            if !app.state::<Tray>().busy.load(Ordering::SeqCst) {
                crate::restart(app);
            }
            return true;
        }
        id => match id
            .strip_prefix("tray-mode-")
            .map(|mode| mode.trim_start_matches("popup-"))
        {
            Some(mode) => match MODES.iter().find(|(known, _)| *known == mode) {
                Some((mode, _)) => Change::Mode(mode),
                None => return true,
            },
            None => return false,
        },
    };
    if app.state::<Tray>().busy.swap(true, Ordering::SeqCst) {
        return true;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let result = change_setting(&app, change).await;
        app.state::<Tray>().busy.store(false, Ordering::SeqCst);
        // Check items toggle themselves, also after a refused change.
        app.state::<Tray>().refresh.store(true, Ordering::SeqCst);
        let shared = app.state::<Shared>();
        let Err(failure) = result else {
            return;
        };
        if shared.quitting.load(Ordering::SeqCst) {
            return;
        }
        shared.logs.event(
            "error",
            match failure {
                Failure::Save => "tray_setting_failed",
                Failure::Reconnect => "tray_reconnect_failed",
            },
            None,
        );
        let language = Language::of(&*shared.engine.lock().await);
        show(&app);
        app.dialog()
            .message(localized(
                language,
                match failure {
                    Failure::Save => TextKey::TraySettingFailed,
                    Failure::Reconnect => TextKey::TraySettingReconnectFailed,
                },
            ))
            .title("Thronium")
            .show(|_| {});
    });
    true
}

async fn change_setting(app: &AppHandle, change: Change) -> Result<(), Failure> {
    let shared = app.state::<Shared>();
    let (section, key, value, running) = {
        let mut guard = shared.engine.lock().await;
        if shared.quitting.load(Ordering::SeqCst) {
            return Ok(());
        }
        let engine = guard.as_mut().map_err(|_| Failure::Save)?;
        let running = engine.snapshot().running;
        let library = &engine.store.library;
        match change {
            Change::Reconnect => {
                drop(guard);
                if running.is_none() {
                    return Ok(());
                }
                return crate::connection_preflight::apply_routing(app)
                    .await
                    .map_err(|_| Failure::Reconnect);
            }
            Change::Toggle(key) => (
                "system",
                key,
                Value::Bool(!settings::boolean(library, key)),
                running,
            ),
            Change::Lan => (
                "inbound",
                "inbound_address",
                Value::from(if lan(&settings::string(library, "inbound_address")) {
                    "127.0.0.1"
                } else {
                    "::"
                }),
                running,
            ),
            Change::Mode(next) if mode(library) == next => return Ok(()),
            Change::Mode(next) => ("inbound", "connection_mode", Value::from(next), running),
        }
    };
    // System settings apply to a running connection; inbound settings are
    // refused while one runs, so it is stopped and the same profile restored.
    let reconnect = running.filter(|_| section == "inbound");
    if reconnect.is_some() {
        crate::connection_preflight::disconnect(app)
            .await
            .map_err(|_| Failure::Save)?;
    }
    let mut deferred = crate::geodata_deferral::Deferred::new(&shared);
    let saved = loop {
        let Ok(mut guard) = deferred.lock().await else {
            return Ok(());
        };
        let result = match guard.as_mut() {
            Ok(engine) => {
                let previous = settings::section(&engine.store.library, section);
                let mut values = previous.clone();
                values[key] = value.clone();
                crate::system_settings::save(app, engine, section, previous, values)
                    .await
                    .map(|_| ())
            }
            Err(error) => Err(error.clone()),
        };
        if let Some(result) = deferred.finish(guard, result).await {
            break result;
        }
    };
    if let Some(id) = reconnect {
        crate::connection_preflight::connect(app, &id)
            .await
            .map_err(|_| match saved {
                Ok(()) => Failure::Reconnect,
                Err(_) => Failure::Save,
            })?;
    }
    saved.map_err(|_| Failure::Save)
}
