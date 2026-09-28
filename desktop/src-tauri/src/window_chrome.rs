//! What a frameless window loses on Windows and gets back here: the snap
//! layouts of Windows 11 and the system menu. Elsewhere both are no-ops.
//!
//! The pointer over the maximize button reaches the WebView2 child window, not
//! ours, so answering `HTMAXBUTTON` to hit testing is not possible. Like
//! tauri-plugin-decorum, a hover that lasts presses Win+Z instead, which opens
//! the layouts for the window in front — only while that window is ours.
use tauri::AppHandle;

#[cfg(target_os = "windows")]
fn main_window(app: &AppHandle) -> Option<windows_sys::Win32::Foundation::HWND> {
    use tauri::Manager;
    let window = app.get_webview_window("main")?;
    window.hwnd().ok().map(|hwnd| hwnd.0 as _)
}

pub fn snap_layouts(app: &AppHandle) {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VIRTUAL_KEY,
            VK_LWIN,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
        let Some(hwnd) = main_window(app) else {
            return;
        };
        if unsafe { GetForegroundWindow() } != hwnd {
            return;
        }
        const VK_Z: VIRTUAL_KEY = 0x5A;
        let key = |code: VIRTUAL_KEY, flags| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: code,
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let inputs = [
            key(VK_LWIN, 0),
            key(VK_Z, 0),
            key(VK_Z, KEYEVENTF_KEYUP),
            key(VK_LWIN, KEYEVENTF_KEYUP),
        ];
        unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            )
        };
    }
    #[cfg(not(target_os = "windows"))]
    let _ = app;
}

/// Alt+Space: the window's own system menu under its top-left corner, with
/// the entries that fit the current state; the choice goes back as the
/// system command Windows would have sent.
pub fn system_menu(app: &AppHandle) {
    #[cfg(target_os = "windows")]
    {
        let Some(hwnd) = main_window(app) else {
            return;
        };
        let hwnd = hwnd as isize;
        let _ = app.run_on_main_thread(move || unsafe {
            use windows_sys::Win32::Foundation::RECT;
            use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnableMenuItem, GetSystemMenu, GetWindowRect, IsZoomed, PostMessageW,
                SetForegroundWindow, TrackPopupMenu, MF_BYCOMMAND, MF_ENABLED, MF_GRAYED,
                SC_MAXIMIZE, SC_MOVE, SC_RESTORE, SC_SIZE, TPM_LEFTBUTTON, TPM_RETURNCMD,
                WM_SYSCOMMAND,
            };
            let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
            let menu = GetSystemMenu(hwnd, 0);
            if menu.is_null() {
                return;
            }
            let zoomed = IsZoomed(hwnd) != 0;
            let state = |on: bool| MF_BYCOMMAND | if on { MF_ENABLED } else { MF_GRAYED };
            EnableMenuItem(menu, SC_RESTORE, state(zoomed));
            EnableMenuItem(menu, SC_MOVE, state(!zoomed));
            EnableMenuItem(menu, SC_SIZE, state(!zoomed));
            EnableMenuItem(menu, SC_MAXIMIZE, state(!zoomed));
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            GetWindowRect(hwnd, &mut rect);
            // Under the title bar, which is 68 CSS pixels high.
            let scale = GetDpiForWindow(hwnd).max(96) as i32;
            SetForegroundWindow(hwnd);
            let command = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_LEFTBUTTON,
                rect.left + 8 * scale / 96,
                rect.top + 68 * scale / 96,
                0,
                hwnd,
                std::ptr::null(),
            );
            if command != 0 {
                PostMessageW(hwnd, WM_SYSCOMMAND, command as usize, 0);
            }
        });
    }
    #[cfg(not(target_os = "windows"))]
    let _ = app;
}
