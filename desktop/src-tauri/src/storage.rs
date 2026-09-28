//! One selected library location for native state, window storage and OS launchers.
use std::path::PathBuf;
use tauri::{AppHandle, Manager};
use thronium_engine::launch::{self, Location, Mode};

pub struct State {
    pub location: Result<Location, String>,
    error_webview: Option<tempfile::TempDir>,
}
impl State {
    pub fn resolve(identifier: &str) -> Self {
        let location = (|| {
            let executable = std::env::current_exe().map_err(|_| "storage_unavailable")?;
            let cwd = std::env::current_dir().map_err(|_| "storage_unavailable")?;
            #[cfg(target_os = "linux")]
            let appimage = tauri::Env::default().appimage.map(PathBuf::from);
            #[cfg(not(target_os = "linux"))]
            let appimage: Option<PathBuf> = None;
            let standard = dirs::data_local_dir().map(|root| root.join(identifier));
            launch::parse(std::env::args_os().skip(1))?
                .resolve(&executable, appimage.as_deref(), standard.as_deref(), &cwd)?
                .prepare()
        })();
        let error_webview = if location.is_err() {
            let mut builder = tempfile::Builder::new();
            builder.prefix("thronium-storage-error-");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(std::fs::Permissions::from_mode(0o700));
            }
            builder.tempdir().ok()
        } else {
            None
        };
        Self {
            location,
            error_webview,
        }
    }
    pub fn manual_window(&self) -> bool {
        self.location
            .as_ref()
            .map_or(true, |l| l.mode != Mode::System)
    }
    pub fn webview_directory(&self) -> Option<PathBuf> {
        self.location
            .as_ref()
            .ok()
            .and_then(Location::webview_directory)
            .or_else(|| self.error_webview.as_ref().map(|d| d.path().into()))
    }
    pub fn launch_arguments(&self) -> Result<Vec<String>, String> {
        self.location
            .as_ref()
            .map_err(Clone::clone)?
            .launch_arguments()
            .into_iter()
            .map(|a| {
                a.into_string()
                    .map_err(|_| "storage_launch_arguments_invalid".into())
            })
            .collect()
    }
}
pub fn directory(app: &AppHandle) -> Result<PathBuf, String> {
    app.state::<State>()
        .location
        .as_ref()
        .map(|l| l.directory.clone())
        .map_err(Clone::clone)
}
pub fn arguments(app: &AppHandle) -> Result<Vec<String>, String> {
    app.state::<State>().launch_arguments()
}
pub fn info(app: &AppHandle) -> serde_json::Value {
    match &app.state::<State>().location {
        Ok(location) => {
            serde_json::json!({"mode":location.mode,"directory":location.directory.to_string_lossy(),"error":null})
        }
        Err(error) => serde_json::json!({"mode":"error","directory":null,"error":error}),
    }
}
pub fn receive_launch(
    app: &AppHandle,
    args: impl IntoIterator<Item = std::ffi::OsString>,
    cwd: &std::path::Path,
) {
    if let Ok(parsed) = launch::parse(args.into_iter().skip(1)) {
        crate::incoming::receive(app, parsed.payloads, cwd);
    }
}
