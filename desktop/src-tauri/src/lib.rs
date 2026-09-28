mod commands;
mod connection_preflight;
mod dashboard;
mod geodata_assets;
mod geodata_deferral;
mod localization;
mod probe_runner;
mod routing_downloads;
mod storage;
mod supervision;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Manager;
use thronium_engine::Engine;
use tokio::sync::Mutex;
mod archive_export;
mod incoming;
mod instance;
mod library_maintenance;
mod notifications;
mod process_metrics;
mod qr_export;
mod qr_import;
mod qt_throne;
#[cfg(target_os = "windows")]
mod session_end;
mod settings_tests;
mod system_settings;
mod transfer;
mod tray;
mod vpn_browser;
mod warp_registration;
mod window_behavior;
mod window_chrome;
mod window_geometry;
#[cfg(target_os = "windows")]
mod windows_registry;

struct Shared {
    engine: Mutex<Result<Engine, String>>,
    logs: thronium_engine::logs::Logs,
    quitting: AtomicBool,
    exit_ready: AtomicBool,
    /// Start a new process once this one has shut down.
    restart: AtomicBool,
    downloads: thronium_engine::subscriptions::Downloads,
    validator: thronium_engine::subscriptions::jobs::Validator,
}

#[derive(Default)]
struct ResourceMetrics(std::sync::Arc<std::sync::Mutex<process_metrics::Sampler>>);

pub fn run() {
    if let Some(code) = thronium_engine::system_proxy::run_guardian_if_requested() {
        std::process::exit(code);
    }
    // The uninstaller's request, before any window or single-instance check.
    #[cfg(target_os = "windows")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--thronium-uninstall")) {
        let with_data =
            std::env::args_os().nth(2).as_deref() == Some(std::ffi::OsStr::new("--with-data"));
        std::process::exit(if system_settings::forget_installation(with_data) {
            0
        } else {
            1
        });
    }
    let mut context = tauri::generate_context!();
    let storage = storage::State::resolve(&context.config().identifier);
    let launch_arguments = storage.launch_arguments().unwrap_or_default();
    let manual_window = if storage.manual_window() {
        context
            .config_mut()
            .app
            .windows
            .iter_mut()
            .find(|w| w.label == "main")
            .map(|window| {
                window.create = false;
                window.clone()
            })
    } else {
        None
    };
    let mut builder = tauri::Builder::default();
    if let Ok(location) = &storage.location {
        builder = builder.plugin(instance::plugin(&context.config().identifier, location));
    }
    builder
        .manage(storage)
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .args(launch_arguments)
                .build(),
        )
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            let opened = (|| {
                let data_dir = storage::directory(app.handle())?;
                let executable =
                    std::env::current_exe().map_err(|_| "executable_directory_missing")?;
                let core = executable
                    .parent()
                    .ok_or("executable_directory_missing")?
                    .join(if cfg!(windows) {
                        "ThroniumCore.exe"
                    } else {
                        "ThroniumCore"
                    });
                // A portable or chosen-folder library travels between
                // computers; a key of this one would lock it out there.
                let seal = app
                    .state::<storage::State>()
                    .location
                    .as_ref()
                    .is_ok_and(|location| location.mode == thronium_engine::launch::Mode::System);
                let mut engine = Engine::open_with(&data_dir, &core, seal)?;
                engine.verify_core_pair();
                engine.initialize_guarded_system_proxy();
                Ok(engine)
            })();
            app.manage(Shared {
                logs: opened.as_ref().map(|e| e.logs.clone()).unwrap_or_default(),
                engine: Mutex::new(opened),
                quitting: AtomicBool::new(false),
                exit_ready: AtomicBool::new(false),
                restart: AtomicBool::new(false),
                downloads: thronium_engine::subscriptions::Downloads::default(),
                validator: thronium_engine::subscriptions::jobs::Validator::default(),
            });
            if let Some(config) = &manual_window {
                let mut window = tauri::WebviewWindowBuilder::from_config(app, config)?;
                if let Some(path) = app.state::<storage::State>().webview_directory() {
                    window = window.data_directory(path);
                }
                window.build()?;
            }
            app.manage(window_behavior::State::default());
            app.manage(settings_tests::State::default());
            app.manage(warp_registration::State::default());
            app.manage(dashboard::State::default());
            app.manage(geodata_assets::State::default());
            app.manage(routing_downloads::State::default());
            routing_downloads::start_background(app.handle().clone());
            app.manage(connection_preflight::State::default());
            app.manage(ResourceMetrics::default());
            app.manage(incoming::State::default());
            if tray::install(app.handle()).is_err() {
                app.state::<Shared>()
                    .logs
                    .event("warn", "tray_unavailable", None);
            }
            notifications::install(app.handle());
            window_geometry::restore(app.handle());
            #[cfg(target_os = "windows")]
            session_end::watch(app.handle());
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    incoming::receive(
                        &handle,
                        event.urls().into_iter().map(|u| u.to_string().into()),
                        &std::env::current_dir().unwrap_or_default(),
                    )
                });
            }
            window_behavior::watch(app.handle());
            connection_preflight::watch(app.handle());
            supervision::start(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                window_geometry::changed(window.app_handle(), event);
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    // Preserve the webview until shutdown succeeds. In particular,
                    // a failed OS proxy restore must leave a usable window.
                    api.prevent_close();
                    window_behavior::close(window.app_handle());
                }
            }
        })
        .invoke_handler(tauri::generate_handler![commands::app_command])
        .build(context)
        .expect("could not initialize Thronium")
        .run(|app, event| {
            if let tauri::RunEvent::Ready = event {
                instance::ready(app);
                system_settings::ready(app);
            }
            if let tauri::RunEvent::Exit = event {
                // Plugins have released the single-instance name by now, so the
                // new process does not hand its launch to this one.
                if app.state::<Shared>().restart.load(Ordering::SeqCst) {
                    relaunch(app);
                }
            }
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                let shared = app.state::<Shared>();
                if !shared.exit_ready.load(Ordering::SeqCst) {
                    api.prevent_exit();
                }
                if !shared.quitting.swap(true, Ordering::SeqCst) {
                    connection_preflight::cancel(app, None);
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let shared = app.state::<Shared>();
                        if release(&app).await.is_err() {
                            shared.quitting.store(false, Ordering::SeqCst);
                            shared.restart.store(false, Ordering::SeqCst);
                            tray::show(&app);
                            return;
                        }
                        shared.exit_ready.store(true, Ordering::SeqCst);
                        app.exit(0);
                    });
                }
            }
        });
}

/// The checked shutdown behind every exit: running jobs stop, then the engine
/// restores the system proxy, cleans up pending VPN state and stops the core.
/// On failure the engine keeps working and the caller keeps the app open.
pub(crate) async fn release(app: &tauri::AppHandle) -> Result<(), String> {
    app.state::<routing_downloads::State>().cancel_all().await;
    app.state::<settings_tests::State>().cancel_all().await;
    app.state::<geodata_assets::State>().cancel_all().await;
    app.state::<dashboard::State>().cancel_all().await;
    app.state::<warp_registration::State>().cancel_all().await;
    let shared = app.state::<Shared>();
    let mut engine = shared.engine.lock().await;
    if let Ok(engine) = engine.as_mut() {
        engine.cancel_url_tests();
        engine.shutdown_checked().await?;
    }
    if shared.restart.load(Ordering::SeqCst) {
        // Release the library lock now: the new process opens it as soon as it
        // starts.
        *engine = Err("app_quitting".into());
    }
    Ok(())
}

/// Qt's "Restart Program": the normal checked shutdown, then the same launcher
/// with the same storage selection, without the links or files of this launch.
pub(crate) fn restart(app: &tauri::AppHandle) {
    app.state::<Shared>().restart.store(true, Ordering::SeqCst);
    app.exit(0);
}
fn relaunch(app: &tauri::AppHandle) {
    // An AppImage must be started again through its own file, not the binary
    // unpacked inside it; every other platform relaunches the executable.
    #[cfg(target_os = "linux")]
    let launcher = app
        .env()
        .appimage
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok());
    #[cfg(not(target_os = "linux"))]
    let launcher = std::env::current_exe().ok();
    if let Some(launcher) = launcher {
        let arguments = storage::arguments(app).unwrap_or_default();
        let _ = std::process::Command::new(launcher).args(arguments).spawn();
    }
}
