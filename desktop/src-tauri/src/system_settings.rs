//! OS integrations. Settings are rolled back if registration or persistence fails.
use crate::{tray, Shared};
use serde_json::Value;
use std::str::FromStr;
use tauri::{AppHandle, Emitter, Manager};
#[cfg(target_os = "macos")]
use tauri_plugin_autostart::ManagerExt;
// Windows keeps its own handler in the registry; the plugin serves the rest.
#[cfg(not(target_os = "windows"))]
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};
const KEYS: [&str; 5] = [
    "hotkey_mainwindow",
    "hotkey_group",
    "hotkey_route",
    "hotkey_system_proxy_menu",
    "hotkey_toggle_system_proxy",
];
fn enabled(v: &Value, key: &str) -> bool {
    v[key] == true
}
fn shortcuts(v: &Value) -> Result<Vec<(&'static str, Shortcut)>, String> {
    let mut out = vec![];
    for key in KEYS {
        let text = v[key].as_str().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        let shortcut = Shortcut::from_str(text).map_err(|_| format!("settings_invalid:{key}"))?;
        if out
            .iter()
            .any(|(_, s): &(_, Shortcut)| s.id() == shortcut.id())
        {
            return Err(format!("settings_invalid:{key}"));
        }
        out.push((key, shortcut));
    }
    Ok(out)
}
/// Registers the hotkeys of `v`. A settings change is all or nothing; at
/// startup every available hotkey is registered and the first failure is
/// reported, so one key taken by another program does not disable the rest.
fn register(app: &AppHandle, v: &Value, startup: bool) -> Result<(), String> {
    let mut first = Ok(());
    for (key, shortcut) in shortcuts(v)? {
        let registered = app
            .global_shortcut()
            .on_shortcut(shortcut, move |app, _, event| {
                if event.state != ShortcutState::Pressed {
                    return;
                }
                let app = app.clone();
                if key == "hotkey_mainwindow" {
                    crate::window_behavior::toggle(&app);
                } else if key == "hotkey_toggle_system_proxy" {
                    tauri::async_runtime::spawn(async move {
                        let shared = app.state::<Shared>();
                        let mut guard = shared.engine.lock().await;
                        if let Ok(engine) = guard.as_mut() {
                            let result = engine.toggle_system_proxy().await;
                            if result.is_err() {
                                shared
                                    .logs
                                    .event("error", "system_proxy_shortcut_failed", None);
                                tray::show(&app);
                            }
                        }
                    });
                } else {
                    // Qt opens the group manager, the routing settings and the
                    // connection modes; the window owns the mode chooser, the
                    // tray menu has the modes themselves.
                    tray::show(&app);
                    let _ = app.emit("settings-navigation", key);
                }
            })
            .map_err(|_| format!("settings_shortcut_unavailable:{key}"));
        match registered {
            Err(error) if !startup => return Err(error),
            Err(error) if first.is_ok() => first = Err(error),
            _ => {}
        }
    }
    first
}
fn autostart(app: &AppHandle, enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let directory = app
            .path()
            .config_dir()
            .map_err(|_| "settings_autostart_failed")?
            .join("autostart");
        let path = directory.join(format!("{}.desktop", app.config().identifier));
        if !enabled {
            return match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err("settings_autostart_failed".into()),
            };
        }
        let executable = app
            .env()
            .appimage
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::current_exe().ok())
            .ok_or("settings_autostart_failed")?;
        let args = crate::storage::arguments(app).map_err(|_| "settings_autostart_failed")?;
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let command = thronium_engine::launch::desktop_exec(&executable, &args, false)
            .map_err(|_| "settings_autostart_failed")?;
        let file = gtk::glib::KeyFile::new();
        file.set_string("Desktop Entry", "Type", "Application");
        file.set_string("Desktop Entry", "Name", "Thronium");
        file.set_string("Desktop Entry", "Exec", &command);
        file.set_boolean("Desktop Entry", "Terminal", false);
        std::fs::create_dir_all(&directory).map_err(|_| "settings_autostart_failed")?;
        use std::io::Write;
        let mut temp =
            tempfile::NamedTempFile::new_in(directory).map_err(|_| "settings_autostart_failed")?;
        temp.write_all(file.to_data().as_bytes())
            .map_err(|_| "settings_autostart_failed")?;
        temp.persist(path)
            .map_err(|_| "settings_autostart_failed")?;
        Ok(())
    }
    // Windows starts the value of this key, parsed by CommandLineToArgvW: the
    // launcher must carry the chosen library itself, and a path with spaces
    // must survive it. Switching it off in Task Manager is read back at start
    // (`follow_task_manager`).
    #[cfg(target_os = "windows")]
    {
        use windows_startup::{NAME, RUN, STARTUP_APPROVED};
        if !enabled {
            return crate::windows_registry::remove_value(RUN, NAME)
                .map_err(|_| "settings_autostart_failed".into());
        }
        let executable = std::env::current_exe().map_err(|_| "settings_autostart_failed")?;
        let args = crate::storage::arguments(app).map_err(|_| "settings_autostart_failed")?;
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let command = thronium_engine::launch::windows_command_line(&executable, &args, false)
            .map_err(|_| "settings_autostart_failed")?;
        crate::windows_registry::set_string(RUN, NAME, &command)
            .map_err(|_| "settings_autostart_failed")?;
        // Switching it on here is the person's newer word than an old "off"
        // in Task Manager, which would otherwise keep the entry from running.
        crate::windows_registry::remove_value(STARTUP_APPROVED, NAME)
            .map_err(|_| "settings_autostart_failed".into())
    }
    #[cfg(target_os = "macos")]
    {
        crate::storage::arguments(app).map_err(|_| "settings_autostart_failed")?;
        let manager = app.autolaunch();
        if enabled {
            manager.enable()
        } else {
            manager.disable()
        }
        .map_err(|_| "settings_autostart_failed".into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (app, enabled);
        Err("settings_autostart_failed".into())
    }
}
/// Where Windows keeps autostart and what Task Manager records about it.
#[cfg(target_os = "windows")]
mod windows_startup {
    pub const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    pub const STARTUP_APPROVED: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    pub const NAME: &str = "Thronium";
}

/// Task Manager stores its switch as the first byte of a binary value: even
/// (2, 6) is on, odd (3, 7) is off. No value means it was never switched.
#[cfg(any(target_os = "windows", test))]
fn switched_off(approved: Option<&[u8]>) -> bool {
    approved
        .and_then(|value| value.first())
        .is_some_and(|flag| flag & 1 == 1)
}

/// The setting follows an entry the person switched off in Task Manager, so
/// Settings never claims an autostart Windows will not perform.
#[cfg(target_os = "windows")]
async fn follow_task_manager(
    engine: &mut thronium_engine::Engine,
    logs: &thronium_engine::logs::Logs,
    system: Value,
) -> Value {
    use windows_startup::{NAME, STARTUP_APPROVED};
    let approved = crate::windows_registry::binary(STARTUP_APPROVED, NAME);
    if !enabled(&system, "autostart") || !switched_off(approved.as_deref()) {
        return system;
    }
    let mut next = system.clone();
    next["autostart"] = Value::Bool(false);
    match engine.save_settings("system", system.clone(), next).await {
        Ok(saved) => {
            logs.event("info", "autostart_switched_off_in_windows", None);
            saved
        }
        Err(_) => system,
    }
}

/// Configuration files offered "Open with" Thronium, as Qt listed them; the
/// default application for these types stays whatever the person chose.
#[cfg(target_os = "windows")]
const OPEN_WITH: [&str; 5] = [".json", ".conf", ".yaml", ".yml", ".txt"];
#[cfg(target_os = "windows")]
const PROG_ID: &str = "Thronium.Config";

/// Whether a registered command starts this very executable.
#[cfg(target_os = "windows")]
fn ours(command_key: &str) -> bool {
    starts_here(crate::windows_registry::string(command_key, ""))
}

#[cfg(target_os = "windows")]
fn starts_here(command: Option<String>) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.to_str().map(str::to_owned))
        .zip(command)
        .is_some_and(|(exe, command)| starts(&command, &exe))
}

/// A command line starts `exe` when it names it, quoted or not; Qt Throne or
/// another copy of Thronium lives at another path.
#[cfg(any(target_os = "windows", test))]
fn starts(command: &str, exe: &str) -> bool {
    let command = command.trim_start();
    let named = command
        .strip_prefix('"')
        .and_then(|rest| rest.split_once('"'))
        .map(|(path, _)| path)
        .unwrap_or_else(|| command.split(' ').next().unwrap_or_default());
    named.eq_ignore_ascii_case(exe)
}

/// What the uninstaller asks of this installation for the person removing
/// it: autostart, link handlers and "Open with" that start this executable
/// go, entries of Qt Throne or another copy stay, and a system proxy an
/// unclean exit left behind is restored from its journal. With the data
/// also goes the library key and that journal's folder.
#[cfg(target_os = "windows")]
pub(crate) fn forget_installation(with_data: bool) -> bool {
    use windows_startup::{NAME, RUN, STARTUP_APPROVED};
    let mut clean = true;
    if starts_here(crate::windows_registry::string(RUN, NAME)) {
        clean &= crate::windows_registry::remove_value(RUN, NAME).is_ok();
        clean &= crate::windows_registry::remove_value(STARTUP_APPROVED, NAME).is_ok();
    }
    for scheme in ["throne", "thronium"] {
        if ours(&format!(r"Software\Classes\{scheme}\shell\open\command")) {
            clean &= crate::windows_registry::remove_tree(&format!(r"Software\Classes\{scheme}"))
                .is_ok();
        }
    }
    clean &= unregister_open_with().is_ok();
    // Opening the manager restores an orphaned journal; a running Thronium
    // holds its lock, and then its own exit restores the proxy.
    drop(thronium_engine::system_proxy::Manager::platform());
    if with_data {
        clean &= thronium_engine::secrets::keyring::forget_windows_key();
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from) {
            let folder = local.join("Thronium");
            clean &= !folder.exists() || std::fs::remove_dir_all(folder).is_ok();
        }
    }
    clean
}

#[cfg(target_os = "windows")]
fn register_open_with(app: &AppHandle) -> Result<(), String> {
    let arguments = crate::storage::arguments(app).map_err(|_| "settings_deeplink_failed")?;
    let executable = std::env::current_exe().map_err(|_| "settings_deeplink_failed")?;
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    let command = thronium_engine::launch::windows_command_line(&executable, &arguments, true)
        .map_err(|_| "settings_deeplink_failed")?;
    let root = format!(r"Software\Classes\{PROG_ID}");
    crate::windows_registry::set_string(&root, "", "Thronium")
        .and_then(|()| {
            crate::windows_registry::set_string(
                &format!(r"{root}\shell\open\command"),
                "",
                &command,
            )
        })
        .map_err(|_| "settings_deeplink_failed")?;
    for extension in OPEN_WITH {
        crate::windows_registry::set_string(
            &format!(r"Software\Classes\{extension}\OpenWithProgids"),
            PROG_ID,
            "",
        )
        .map_err(|_| "settings_deeplink_failed")?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn unregister_open_with() -> Result<(), String> {
    let root = format!(r"Software\Classes\{PROG_ID}");
    if !ours(&format!(r"{root}\shell\open\command")) {
        return Ok(());
    }
    for extension in OPEN_WITH {
        crate::windows_registry::remove_value(
            &format!(r"Software\Classes\{extension}\OpenWithProgids"),
            PROG_ID,
        )
        .map_err(|_| "settings_deeplink_failed")?;
    }
    crate::windows_registry::remove_tree(&root).map_err(|_| "settings_deeplink_failed".into())
}

#[cfg(target_os = "linux")]
fn remove_handler(app: &AppHandle) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|_| "settings_deeplink_failed")?;
    let name = executable
        .file_name()
        .ok_or("settings_deeplink_failed")?
        .to_string_lossy();
    let directory = app
        .path()
        .data_dir()
        .map_err(|_| "settings_deeplink_failed")?
        .join("applications");
    let file = directory.join(format!("{name}-handler.desktop"));
    match std::fs::remove_file(file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("settings_deeplink_failed".into()),
    }
    let status = std::process::Command::new("update-desktop-database")
        .arg(directory)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| "settings_deeplink_failed")?;
    if status.success() {
        Ok(())
    } else {
        Err("settings_deeplink_failed".into())
    }
}
/// Configuration files Qt's URL handler entry lists (`UrlScheme_Apply`).
#[cfg(target_os = "linux")]
const FILE_TYPES: [&str; 3] = ["application/json", "application/yaml", "text/yaml"];
/// Gives the scheme back: on Windows only when this application still owns the
/// handler, so a Qt Throne registration written by someone else survives.
#[cfg(not(target_os = "macos"))]
fn unregister_link(app: &AppHandle, scheme: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let _ = app;
        if !ours(&format!(r"Software\Classes\{scheme}\shell\open\command")) {
            return Ok(());
        }
        crate::windows_registry::remove_tree(&format!(r"Software\Classes\{scheme}"))
            .map_err(|_| "settings_deeplink_failed".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        if app.deep_link().is_registered(scheme).unwrap_or(false) {
            app.deep_link()
                .unregister(scheme)
                .map_err(|_| "settings_deeplink_failed".to_owned())?;
        }
        Ok(())
    }
}
#[cfg(not(target_os = "macos"))]
fn register_link(app: &AppHandle, scheme: &str) -> Result<(), String> {
    // Asked for first: a handler is only worth writing for a library this
    // launcher can name again.
    let arguments = crate::storage::arguments(app).map_err(|_| "settings_deeplink_failed")?;
    // Windows keeps the handler in the user's own class store: the command it
    // starts carries the chosen library and the link as its last argument, so a
    // portable or custom library opens links as the system one does.
    #[cfg(target_os = "windows")]
    {
        let root = format!(r"Software\Classes\{scheme}");
        let command_key = format!(r"{root}\shell\open\command");
        // Qt Throne's own throne:// handler is not taken over silently: it
        // stays, thronium:// links open here, and the log says so.
        if crate::windows_registry::string(&command_key, "").is_some() && !ours(&command_key) {
            app.state::<crate::Shared>()
                .logs
                .event("info", "deeplink_foreign_handler_kept", None);
            return Ok(());
        }
        let executable = std::env::current_exe().map_err(|_| "settings_deeplink_failed")?;
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let command = thronium_engine::launch::windows_command_line(&executable, &arguments, true)
            .map_err(|_| "settings_deeplink_failed")?;
        crate::windows_registry::set_string(&root, "", &format!("URL:{scheme} Protocol"))
            .and_then(|()| crate::windows_registry::set_string(&root, "URL Protocol", ""))
            .and_then(|()| {
                crate::windows_registry::set_string(
                    &format!(r"{root}\shell\open\command"),
                    "",
                    &command,
                )
            })
            .map_err(|_| "settings_deeplink_failed")?;
    }
    #[cfg(target_os = "macos")]
    app.deep_link()
        .register(scheme)
        .map_err(|_| "settings_deeplink_failed")?;
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::current_exe().map_err(|_| "settings_deeplink_failed")?;
        let name = executable
            .file_name()
            .ok_or("settings_deeplink_failed")?
            .to_string_lossy();
        let directory = app
            .path()
            .data_dir()
            .map_err(|_| "settings_deeplink_failed")?
            .join("applications");
        let path = directory.join(format!("{name}-handler.desktop"));
        let launcher = app
            .env()
            .appimage
            .map(std::path::PathBuf::from)
            .unwrap_or(executable);
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let command = thronium_engine::launch::desktop_exec(&launcher, &arguments, true)
            .map_err(|_| "settings_deeplink_failed")?;
        app.deep_link()
            .register(scheme)
            .map_err(|_| "settings_deeplink_failed")?;
        let file = gtk::glib::KeyFile::new();
        file.load_from_file(
            &path,
            gtk::glib::KeyFileFlags::KEEP_COMMENTS | gtk::glib::KeyFileFlags::KEEP_TRANSLATIONS,
        )
        .map_err(|_| "settings_deeplink_failed")?;
        file.set_string("Desktop Entry", "Exec", &command);
        // Qt's handler also offers the application in "Open with" for
        // configuration files; only the scheme is made the default handler.
        let mut types: Vec<String> = file
            .string("Desktop Entry", "MimeType")
            .map(|list| {
                list.split(';')
                    .filter(|t| !t.is_empty())
                    .map(Into::into)
                    .collect()
            })
            .unwrap_or_default();
        for kind in FILE_TYPES {
            if !types.iter().any(|t| t == kind) {
                types.push(kind.into());
            }
        }
        file.set_string(
            "Desktop Entry",
            "MimeType",
            &format!("{};", types.join(";")),
        );
        use std::io::Write;
        let mut temp =
            tempfile::NamedTempFile::new_in(&directory).map_err(|_| "settings_deeplink_failed")?;
        temp.write_all(file.to_data().as_bytes())
            .map_err(|_| "settings_deeplink_failed")?;
        temp.persist(path).map_err(|_| "settings_deeplink_failed")?;
        // The file types resolve through the desktop database cache; a system
        // without the tool still has the scheme, which is the default handler.
        let _ = std::process::Command::new("update-desktop-database")
            .arg(&directory)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    Ok(())
}
/// Saves a settings section; a System change that the desktop refuses (a taken
/// hotkey, autostart, the URL handler) restores the saved library.
pub async fn save(
    app: &AppHandle,
    engine: &mut thronium_engine::Engine,
    section: &str,
    previous: Value,
    values: Value,
) -> Result<Value, String> {
    let old = engine.store.library.clone();
    let result = engine.save_settings(section, previous, values).await?;
    if section == "system" {
        if let Err(error) = apply(
            app,
            &thronium_engine::settings::section(&old, "system"),
            &result,
            false,
        ) {
            engine
                .store
                .commit(old)
                .map_err(|_| "settings_rollback_failed")?;
            engine.reload_settings();
            return Err(error);
        }
    }
    Ok(result)
}
pub fn apply(app: &AppHandle, old: &Value, next: &Value, startup: bool) -> Result<(), String> {
    shortcuts(next)?;
    let shortcuts_changed = startup || KEYS.iter().any(|k| old[*k] != next[*k]);
    // At startup a hotkey failure is reported after the tray, deep links and
    // autostart are applied; a settings change is rolled back as a whole.
    let mut startup_error = Ok(());
    if shortcuts_changed {
        app.global_shortcut()
            .unregister_all()
            .map_err(|_| "settings_shortcut_unavailable")?;
        if let Err(error) = register(app, next, startup) {
            if startup {
                startup_error = Err(error);
            } else {
                let _ = app.global_shortcut().unregister_all();
                let _ = register(app, old, false);
                return Err(error);
            }
        }
    }
    let result = (|| {
        if old["autostart"] != next["autostart"] || (startup && enabled(next, "autostart")) {
            autostart(app, enabled(next, "autostart"))?;
        }
        if old["url_scheme_auto_register"] != next["url_scheme_auto_register"]
            || (startup && enabled(next, "url_scheme_auto_register"))
        {
            #[cfg(target_os = "macos")]
            {
                return Err("settings_deeplink_bundled_only".into());
            }
            #[cfg(not(target_os = "macos"))]
            {
                for scheme in ["throne", "thronium"] {
                    if enabled(next, "url_scheme_auto_register") {
                        register_link(app, scheme)
                    } else {
                        unregister_link(app, scheme)
                    }?;
                }
                #[cfg(target_os = "linux")]
                if !enabled(next, "url_scheme_auto_register") {
                    remove_handler(app)?;
                }
                #[cfg(target_os = "windows")]
                if enabled(next, "url_scheme_auto_register") {
                    register_open_with(app)?;
                } else {
                    unregister_open_with()?;
                }
            }
        }
        if let Some(icon) = app.tray_by_id("thronium") {
            icon.set_visible(!enabled(next, "disable_tray"))
                .map_err(|_| "settings_tray_failed")?;
        }
        crate::window_behavior::tray_enabled(app, !enabled(next, "disable_tray"));
        Ok(())
    })();
    if result.is_err() {
        if old["url_scheme_auto_register"] != next["url_scheme_auto_register"] {
            #[cfg(not(target_os = "macos"))]
            for scheme in ["throne", "thronium"] {
                if enabled(old, "url_scheme_auto_register") {
                    let _ = register_link(app, scheme);
                } else {
                    let _ = unregister_link(app, scheme);
                }
            }
        }
        if let Some(icon) = app.tray_by_id("thronium") {
            let _ = icon.set_visible(!enabled(old, "disable_tray"));
        }
        crate::window_behavior::tray_enabled(app, !enabled(old, "disable_tray"));
        if shortcuts_changed {
            let _ = app.global_shortcut().unregister_all();
            let _ = register(app, old, startup);
        }
        if old["autostart"] != next["autostart"] {
            if enabled(old, "autostart") {
                let _ = autostart(app, true);
            } else {
                let _ = autostart(app, false);
            }
        }
    }
    result.and(startup_error)
}
pub fn ready(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shared = app.state::<Shared>();
        let mut guard = shared.engine.lock().await;
        let Ok(engine) = guard.as_mut() else {
            return;
        };
        let s = thronium_engine::settings::section(&engine.store.library, "system");
        #[cfg(target_os = "windows")]
        let s = follow_task_manager(engine, &shared.logs, s).await;
        if apply(&app, &s, &s, true).is_err() {
            shared
                .logs
                .event("warn", "system_integrations_restore_failed", None);
        }
        if enabled(&s, "start_minimal") {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.minimize();
            }
        }
        let remembered = enabled(&s, "remember_enable")
            .then(|| engine.store.library.selected.clone())
            .flatten();
        drop(guard);
        if let Some(id) = remembered {
            if crate::connection_preflight::connect(&app, &id)
                .await
                .is_err()
            {
                tray::show(&app);
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            crate::storage::receive_launch(&app, std::env::args_os(), &cwd);
        }
    });
}

#[cfg(test)]
mod uninstall_tests {
    #[test]
    fn a_command_starts_the_executable_it_names_first() {
        let exe = r"C:\Program Files\Thronium\Thronium.exe";
        assert!(super::starts(&format!(r#""{exe}" --portable "%1""#), exe));
        assert!(super::starts(
            r#""c:\program files\thronium\thronium.exe" "%1""#,
            exe
        ));
        assert!(!super::starts(r#""C:\Throne\Throne.exe" "%1""#, exe));
        assert!(!super::starts(
            &format!(r#""C:\Other\Thronium.exe" --data-dir "{exe}""#),
            exe
        ));
        assert!(super::starts(
            r"C:\Thronium\Thronium.exe %1",
            r"C:\Thronium\Thronium.exe"
        ));
    }
}

#[cfg(test)]
mod startup_tests {
    #[test]
    fn task_manager_switch_is_the_parity_of_the_first_byte() {
        for (value, off) in [
            (None, false),
            (Some(&[][..]), false),
            (Some(&[2, 0, 0, 0][..]), false),
            (Some(&[6][..]), false),
            (Some(&[3, 0, 0, 0, 0x10, 0x20, 0, 0, 0, 0, 0, 0][..]), true),
            (Some(&[7][..]), true),
        ] {
            assert_eq!(super::switched_off(value), off, "{value:?}");
        }
    }
}
