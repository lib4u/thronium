//! Device-local window state; never transferred with a connection backup.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::{AppHandle, Manager, WindowEvent};
static READY: AtomicBool = AtomicBool::new(false);
static REVISION: AtomicU64 = AtomicU64::new(0);
#[derive(Serialize, Deserialize)]
struct Geometry {
    width: u32,
    height: u32,
    x: i32,
    y: i32,
    maximized: bool,
}
fn path(app: &AppHandle) -> Option<std::path::PathBuf> {
    Some(
        crate::storage::directory(app)
            .ok()?
            .join("window-state.json"),
    )
}
pub fn restore(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if let Some(g) = path(app)
            .and_then(|p| std::fs::read(p).ok())
            .filter(|v| v.len() < 4096)
            .and_then(|v| serde_json::from_slice::<Geometry>(&v).ok())
        {
            if (640..=16384).contains(&g.width) && (480..=16384).contains(&g.height) {
                let visible = window
                    .available_monitors()
                    .unwrap_or_default()
                    .iter()
                    .any(|m| {
                        let p = m.position();
                        let s = m.size();
                        g.x >= p.x
                            && g.y >= p.y
                            && (g.x as i64 + 100) < p.x as i64 + s.width as i64
                            && (g.y as i64 + 60) < p.y as i64 + s.height as i64
                    });
                // Position first: moved onto a monitor with another scale,
                // Windows rescales the window, and the saved physical size is
                // the one that must hold there.
                if visible {
                    let _ = window.set_position(tauri::PhysicalPosition::new(g.x, g.y));
                }
                let _ = window.set_size(tauri::PhysicalSize::new(g.width, g.height));
                if !visible {
                    let _ = window.center();
                }
                if g.maximized {
                    let _ = window.maximize();
                }
            }
        }
    }
    READY.store(true, Ordering::SeqCst);
}
pub fn changed(app: &AppHandle, event: &WindowEvent) {
    if !READY.load(Ordering::SeqCst)
        || !matches!(event, WindowEvent::Resized(_) | WindowEvent::Moved(_))
    {
        return;
    }
    let revision = REVISION.fetch_add(1, Ordering::SeqCst) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        if REVISION.load(Ordering::SeqCst) != revision {
            return;
        }
        let Some(w) = app.get_webview_window("main") else {
            return;
        };
        if w.is_minimized().unwrap_or(true) {
            return;
        }
        let (Ok(size), Ok(pos), Some(path)) = (w.inner_size(), w.outer_position(), path(&app))
        else {
            return;
        };
        let mut g = Geometry {
            width: size.width,
            height: size.height,
            x: pos.x,
            y: pos.y,
            maximized: w.is_maximized().unwrap_or(false),
        };
        if g.maximized {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(old) = serde_json::from_slice::<Geometry>(&bytes) {
                    g.width = old.width;
                    g.height = old.height;
                    g.x = old.x;
                    g.y = old.y;
                }
            }
        }
        if let Ok(bytes) = serde_json::to_vec(&g) {
            let temp = path.with_extension("tmp");
            if std::fs::write(&temp, bytes).is_ok() {
                let _ = std::fs::rename(temp, path);
            }
        }
    });
}
