//! Sign-out, restart and shutdown on Windows. The system first asks every
//! top-level window whether the session may end, then tells it that it does;
//! once that answer returns, the process may be terminated at any moment. So
//! the checked shutdown of a normal exit runs inside the answer: the system
//! proxy goes back to what it was before the process does.
//!
//! The answer is bounded. Windows shows its "apps are preventing shutdown"
//! screen after about five seconds, and the person must never be held there by
//! Thronium; whatever is left undone is restored by the next launch from the
//! proxy journal. Meanwhile the screen names the reason.
use crate::localization::{text, Language, TextKey};
use crate::{connection_preflight, Shared};
use std::ptr::{null, null_mut};
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, RegisterClassExW, WM_ENDSESSION, WM_QUERYENDSESSION,
    WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_POPUP,
};

const BUDGET: Duration = Duration::from_secs(4);

static APP: OnceLock<AppHandle> = OnceLock::new();

/// A hidden top-level window of its own: message-only windows receive no
/// session messages, and the main window may not exist while in the tray.
/// It lives on the thread that runs the app's event loop.
pub fn watch(app: &AppHandle) {
    if APP.set(app.clone()).is_err() {
        return;
    }
    let class: Vec<u16> = "io.thronium.desktop.SessionEnd"
        .encode_utf16()
        .chain([0])
        .collect();
    unsafe {
        let module = GetModuleHandleW(null());
        let description = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(procedure),
            hInstance: module,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassExW(&description);
        // Never shown; the tool-window style keeps it off the taskbar.
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class.as_ptr(),
            null(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            module,
            null(),
        );
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        // Thronium never vetoes the end of a session.
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                if let Some(app) = APP.get() {
                    end(app, window);
                }
            }
            0
        }
        _ => DefWindowProcW(window, message, wparam, lparam),
    }
}

fn end(app: &AppHandle, window: HWND) {
    let shared = app.state::<Shared>();
    let language = shared
        .engine
        .try_lock()
        .map(|engine| Language::of(&engine))
        .unwrap_or_else(|_| Language::default_preference());
    let reason: Vec<u16> = text(language, TextKey::WindowsSessionEndReason)
        .encode_utf16()
        .chain([0])
        .collect();
    unsafe { ShutdownBlockReasonCreate(window, reason.as_ptr()) };
    if shared.quitting.swap(true, Ordering::SeqCst) {
        // A normal exit is already under way and owns the cleanup; give it the
        // same time to finish.
        tauri::async_runtime::block_on(async {
            let _ = tokio::time::timeout(BUDGET, async {
                while !shared.exit_ready.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await;
        });
    } else {
        connection_preflight::cancel(app, None);
        let released =
            tauri::async_runtime::block_on(tokio::time::timeout(BUDGET, crate::release(app)));
        if !matches!(released, Ok(Ok(()))) {
            shared
                .logs
                .event("warn", "session_end_cleanup_incomplete", None);
        }
    }
    unsafe { ShutdownBlockReasonDestroy(window) };
}
