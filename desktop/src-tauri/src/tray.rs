//! Native tray actions share the engine and normal asynchronous shutdown path.
use crate::localization::{text as localized, TextKey};
use crate::{Ordering, Shared};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64},
    Mutex,
};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use thronium_engine::tray_icons::{Icon, Status};
mod connection;
mod profiles;
mod routing;
mod system;

struct Tray {
    #[cfg(target_os = "linux")]
    menu: Menu<tauri::Wry>,
    status: MenuItem<tauri::Wry>,
    show: MenuItem<tauri::Wry>,
    otp: MenuItem<tauri::Wry>,
    connect: MenuItem<tauri::Wry>,
    disconnect: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
    servers: Submenu<tauri::Wry>,
    routing: Submenu<tauri::Wry>,
    system: system::Items,
    targets: Mutex<HashMap<String, String>>,
    route_targets: Mutex<HashMap<String, routing::Target>>,
    generation: AtomicU64,
    busy: AtomicBool,
    refresh: AtomicBool,
}
#[derive(PartialEq, Eq)]
struct View {
    follow_title: bool,
    custom_icons: bool,
    icon_directory: std::path::PathBuf,
    prefer_icon_directory: bool,
    imported_icon: Option<Icon>,
    icon_status: Status,
    language: crate::localization::Language,
    running: bool,
    reconnecting: bool,
    phase: String,
    selected: bool,
    available: bool,
    busy: bool,
    name: String,
    profiles: profiles::View,
    routing: routing::View,
    system: system::View,
}
pub(crate) fn show(app: &AppHandle) {
    crate::window_behavior::shown(app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        #[cfg(target_os = "linux")]
        {
            // Tao queues deiconify, but can discard focus while its minimized flag
            // still reflects the old window state. GTK present performs both.
            let _ = app.run_on_main_thread(move || {
                use gtk::prelude::*;
                if let Ok(window) = window.gtk_window() {
                    // An external launch has no fresh GTK input event. A stale user
                    // timestamp can make Mutter ignore activation after another app
                    // took focus. Ask the X server for the current timestamp on X11;
                    // Wayland keeps GTK's normal activation behavior.
                    let time = window
                        .window()
                        .and_then(|surface| surface.downcast::<gdkx11::X11Window>().ok())
                        .map(|surface| gdkx11::functions::x11_get_server_time(&surface))
                        .unwrap_or_else(gtk::current_event_time);
                    window.present_with_time(time);
                }
            });
        }
    }
}
fn custom_icon(path: &std::path::Path) -> Option<tauri::image::Image<'static>> {
    use std::io::Read;
    let mut bytes = vec![];
    std::fs::File::open(path)
        .ok()?
        .take(2097153)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 2097152 {
        return None;
    }
    Some(icon_image(&Icon::from_png(&bytes).ok()?))
}
fn icon_image(icon: &Icon) -> tauri::image::Image<'static> {
    tauri::image::Image::new_owned(icon.rgba().to_vec(), icon.width(), icon.height())
}
fn update(app: &AppHandle, view: &View, previous: Option<&View>) -> tauri::Result<()> {
    let tray = app.state::<Tray>();
    let text = |key| localized(view.language, key);
    let status = if view.busy {
        text(TextKey::Working8ba5b78).to_string()
    } else if view.reconnecting {
        text(TextKey::ReconnectingAef685e).into()
    } else if view.running && view.phase == "auth-pending" {
        text(TextKey::VpnAuthenticationRequiredC911203).into()
    } else if view.running && view.phase == "connecting" {
        text(TextKey::ConnectingToVpnE25b29b).into()
    } else if view.running && view.phase == "error" {
        text(TextKey::VpnTunnelUnavailable718c206).into()
    } else if view.running && view.phase == "unknown" {
        text(TextKey::VpnStateUnavailable1927156).into()
    } else if view.running {
        format!("{}: {}", text(TextKey::Connected8582d18), view.name)
    } else if !view.available {
        text(TextKey::CoreUnavailable9f988f6).into()
    } else {
        text(TextKey::Disconnected47d3ebf).into()
    };
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(&if view.follow_title {
            format!("Thronium · {status}")
        } else {
            "Thronium".into()
        });
    }
    let connect = if !view.running && view.selected {
        format!("{}: {}", text(TextKey::ConnectA27ba0c), view.name)
    } else {
        text(TextKey::ConnectA27ba0c).into()
    };
    let _ = tray.status.set_text(&status);
    let _ = tray.show.set_text(text(TextKey::OpenThronium5ce46db));
    let _ = tray.otp.set_text(text(TextKey::OtpCodes83b6c30));
    let _ = tray.connect.set_text(connect);
    let _ = tray
        .connect
        .set_enabled(view.available && view.selected && !view.running && !view.busy);
    let _ = tray.disconnect.set_text(text(TextKey::Disconnect2d5128c));
    let _ = tray.disconnect.set_enabled(view.running && !view.busy);
    let _ = tray.quit.set_text(text(TextKey::Quit9f9f8cf));
    system::update(
        &tray.system,
        &view.system,
        view.language,
        view.available && !view.busy,
        view.running,
    );
    if previous.is_none_or(|p| {
        p.profiles != view.profiles
            || p.language != view.language
            || p.busy != view.busy
            || p.available != view.available
    }) {
        profiles::update(
            app,
            &tray,
            &view.profiles,
            view.language,
            view.available && !view.busy,
        )?;
    }
    if previous.is_none_or(|p| {
        p.routing != view.routing
            || p.language != view.language
            || p.busy != view.busy
            || p.available != view.available
    }) {
        routing::update(
            app,
            &tray,
            &view.routing,
            view.language,
            !view.busy,
            view.available,
        )?;
    }
    #[cfg(target_os = "linux")]
    if previous.is_none_or(|p| p.language != view.language) {
        // muda 0.19 creates submenu text in a nested GTK AccelLabel. Its
        // set_text updates MenuItem.label, which DBusMenu does not display.
        // Reinsert these items in place so GTK recreates the visible labels.
        for submenu in [&tray.servers, &tray.routing, &tray.system.mode] {
            if let Some(index) = tray
                .menu
                .items()?
                .iter()
                .position(|item| item.id() == submenu.id())
            {
                tray.menu.remove(submenu)?;
                tray.menu.insert(submenu, index)?;
            }
        }
    }
    let custom = if view.custom_icons {
        let imported = || view.imported_icon.as_ref().map(icon_image);
        let directory = || {
            custom_icon(
                &view
                    .icon_directory
                    .join(format!("{}.png", view.icon_status.name())),
            )
        };
        if view.prefer_icon_directory {
            directory().or_else(imported)
        } else {
            imported().or_else(directory)
        }
    } else {
        None
    };
    let image = custom.as_ref().or_else(|| app.default_window_icon());
    if let Some(window) = app.get_webview_window("main") {
        if let Some(image) = if view.follow_title {
            image
        } else {
            app.default_window_icon()
        } {
            let _ = window.set_icon(image.clone());
        }
    }
    if let Some(icon) = app.tray_by_id("thronium") {
        if let Some(image) = image {
            let _ = icon.set_icon(Some(image.clone()));
        }
        let _ = icon.set_tooltip(Some(tooltip(&status)));
    }
    Ok(())
}
/// Windows keeps at most 127 UTF-16 units of a tray tip and cuts the rest
/// mid-word; a long profile name ends in an ellipsis instead.
fn tooltip(status: &str) -> String {
    let full = format!("Thronium · {status}");
    if full.encode_utf16().count() <= 127 {
        return full;
    }
    let mut cut = String::new();
    let mut units = 0;
    for c in full.chars() {
        if units + c.len_utf16() > 126 {
            break;
        }
        units += c.len_utf16();
        cut.push(c);
    }
    cut.push('…');
    cut
}
fn action(app: &AppHandle, id: &str) {
    if app.state::<Shared>().quitting.load(Ordering::SeqCst) {
        return;
    }
    if system::action(app, id) {
        return;
    }
    match id {
        "tray-show" => show(app),
        "tray-otp" => {
            // DBusMenu contains only this action, never account names or codes.
            // Opening the read-only popup does not use the connection workflow.
            show(app);
            let _ = app.emit_to("main", "otp-quick-open", ());
        }
        "tray-quit" => app.exit(0),
        id if id.starts_with("tray-route-catalog-") => routing::open_catalog(app, id),
        id if id.starts_with("tray-route-action-") => routing::action(app, id),
        id if id == "tray-connect"
            || id == "tray-disconnect"
            || id.starts_with("tray-profile-") =>
        {
            connection::change(app, id)
        }
        _ => {}
    }
}
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    // The first refresh applies the saved language; until then the default one.
    let language = crate::localization::Language::default_preference();
    let item = |id, text, enabled| MenuItem::with_id(app, id, text, enabled, None::<&str>);
    let menu = Menu::new(app)?;
    let tray = Tray {
        #[cfg(target_os = "linux")]
        menu: menu.clone(),
        status: item("tray-status", "Thronium", false)?,
        show: item(
            "tray-show",
            localized(language, TextKey::OpenThronium5ce46db),
            true,
        )?,
        otp: item(
            "tray-otp",
            localized(language, TextKey::OtpCodes83b6c30),
            true,
        )?,
        connect: item(
            "tray-connect",
            localized(language, TextKey::ConnectA27ba0c),
            false,
        )?,
        disconnect: item(
            "tray-disconnect",
            localized(language, TextKey::Disconnect2d5128c),
            false,
        )?,
        quit: item("tray-quit", localized(language, TextKey::Quit9f9f8cf), true)?,
        servers: Submenu::with_id(
            app,
            "tray-servers",
            localized(language, TextKey::ConnectToServer87401c4),
            false,
        )?,
        routing: Submenu::with_id(
            app,
            "tray-routing",
            localized(language, TextKey::Routing3247b97),
            true,
        )?,
        system: system::items(app, language)?,
        targets: Mutex::new(HashMap::new()),
        route_targets: Mutex::new(HashMap::new()),
        generation: AtomicU64::new(0),
        busy: AtomicBool::new(false),
        refresh: AtomicBool::new(false),
    };
    // Qt's order: the window, the startup and LAN toggles, the connection,
    // then restarts and quitting.
    menu.append_items(&[
        &tray.status,
        &PredefinedMenuItem::separator(app)?,
        &tray.show,
        &PredefinedMenuItem::separator(app)?,
        &tray.system.autostart,
        &tray.system.remember,
        &tray.system.lan,
        &PredefinedMenuItem::separator(app)?,
        &tray.otp,
        &tray.connect,
        &tray.servers,
        &tray.disconnect,
        &tray.routing,
        &tray.system.mode,
        &PredefinedMenuItem::separator(app)?,
        &tray.system.restart_connection,
        &tray.system.restart,
        &tray.quit,
    ])?;
    let mut builder = TrayIconBuilder::with_id("thronium")
        .temp_dir_path(
            app.path()
                .app_cache_dir()?
                .join("tray")
                .join(std::process::id().to_string()),
        )
        .menu(&menu)
        .tooltip("Thronium")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| action(app, event.id.as_ref()))
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    app.manage(tray);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut previous = None;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let view = {
                let shared = app.state::<Shared>();
                if shared.quitting.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(mut guard) = shared.engine.try_lock() else {
                    continue;
                };
                let busy = app.state::<Tray>().busy.load(Ordering::SeqCst);
                if let Ok(engine) = guard.as_mut() {
                    let snapshot = engine.snapshot();
                    let language =
                        crate::localization::Language::from_code(&snapshot.preferences.language);
                    let current = snapshot.running.as_ref().or(snapshot.selected.as_ref());
                    // The built-in auto-select pool is not a stored profile.
                    let name = if current
                        .is_some_and(|id| id == thronium_engine::auto_selector::AUTO_SELECT_ID)
                    {
                        localized(language, TextKey::AutoSelect).to_owned()
                    } else {
                        current
                            .and_then(|id| {
                                engine.store.library.profiles.iter().find(|p| &p.id == id)
                            })
                            .map(|p| p.name.as_str())
                            .unwrap_or_default()
                            .to_owned()
                    }
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(64)
                    .collect::<String>()
                    .replace('&', "&&");
                    let icon_status = Status::for_connection(
                        snapshot.running.is_some(),
                        &snapshot.preferences.connection_mode,
                    );
                    View {
                        icon_status,
                        imported_icon: engine.store.library.tray_icons.get(icon_status).cloned(),
                        prefer_icon_directory: !thronium_engine::settings::string(
                            &engine.store.library,
                            "custom_icon_directory",
                        )
                        .is_empty(),
                        custom_icons: thronium_engine::settings::boolean(
                            &engine.store.library,
                            "use_custom_icons",
                        ),
                        icon_directory: {
                            let directory = thronium_engine::settings::string(
                                &engine.store.library,
                                "custom_icon_directory",
                            );
                            if directory.is_empty() {
                                crate::storage::directory(&app)
                                    .unwrap_or_default()
                                    .join("icons")
                            } else {
                                directory.into()
                            }
                        },
                        follow_title: thronium_engine::settings::boolean(
                            &engine.store.library,
                            "follow_status_in_taskbar",
                        ),
                        language,
                        running: snapshot.running.is_some(),
                        reconnecting: snapshot.phase == "reconnecting",
                        phase: snapshot.phase.clone(),
                        selected: snapshot.selected.is_some(),
                        available: snapshot.core_available,
                        busy,
                        name,
                        profiles: profiles::View::new(
                            &engine.store.library,
                            snapshot.running.as_deref(),
                        ),
                        routing: routing::View::new(
                            &engine.store.library.routing,
                            &snapshot.routing,
                            snapshot.running.as_deref(),
                            snapshot.selected.as_deref(),
                        )
                        .with_intercept(
                            &thronium_engine::settings::section(&engine.store.library, "intercept"),
                        ),
                        system: system::View::new(&engine.store.library, &snapshot),
                    }
                } else {
                    View {
                        follow_title: false,
                        custom_icons: false,
                        icon_directory: Default::default(),
                        icon_status: Status::Off,
                        imported_icon: None,
                        prefer_icon_directory: false,
                        language: crate::localization::Language::default_preference(),
                        running: false,
                        reconnecting: false,
                        phase: String::new(),
                        selected: false,
                        available: false,
                        busy,
                        name: String::new(),
                        profiles: profiles::View::default(),
                        routing: routing::View::default(),
                        system: system::View::default(),
                    }
                }
            };
            let force = app.state::<Tray>().refresh.swap(false, Ordering::SeqCst);
            if force || previous.as_ref() != Some(&view) {
                if update(&app, &view, if force { None } else { previous.as_ref() }).is_ok() {
                    previous = Some(view);
                } else {
                    app.state::<Tray>().refresh.store(true, Ordering::SeqCst);
                }
            }
        }
    });
    Ok(())
}
#[cfg(test)]
mod tooltip_tests {
    #[test]
    fn a_tray_tip_fits_windows_limit_without_splitting_a_character() {
        assert_eq!(super::tooltip("Connected"), "Thronium · Connected");
        for status in ["x".repeat(300), "日本".repeat(100), "🦊".repeat(100)] {
            let tip = super::tooltip(&status);
            assert!(tip.encode_utf16().count() <= 127, "{tip}");
            assert!(tip.ends_with('…'));
        }
    }
}
