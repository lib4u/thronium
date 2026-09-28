//! One running process per library directory. The first launch owns a mutex in
//! the session namespace and a message-only window named after the library; a
//! later launch of the same library passes its arguments to that window and
//! exits. Copies with different libraries do not see each other.
use super::handoff;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tauri::{
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, RunEvent, Wry,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HWND, LPARAM, LRESULT, WAIT_ABANDONED, WAIT_OBJECT_0, WPARAM,
};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, CreateWindowExW, DefWindowProcW, DestroyWindow, FindWindowExW,
    GetWindowThreadProcessId, RegisterClassExW, SendMessageTimeoutW, HWND_MESSAGE,
    SMTO_ABORTIFHUNG, WM_COPYDATA, WNDCLASSEXW,
};

/// Marks our message among other `WM_COPYDATA` a window may receive.
const TAG: usize = 0x5448_524E;
/// How long a later launch waits for a first one that is still starting.
const STARTUP: Duration = Duration::from_secs(10);
const DELIVERY_MS: u32 = 5000;

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Raw handles kept as integers so the app state stays `Send + Sync`.
struct Held {
    mutex: isize,
    window: isize,
}

pub fn plugin(name: String) -> TauriPlugin<Wry> {
    Builder::new("instance")
        .setup(move |app, _| {
            let mutex_name = wide(&format!("Local\\{name}"));
            let class = wide(&name);
            let mutex = unsafe { CreateMutexW(null(), 0, mutex_name.as_ptr()) };
            if mutex.is_null() {
                // Without the name there is nothing to coordinate with.
                return Ok(());
            }
            let deadline = Instant::now() + STARTUP;
            // Ownership, not mere existence: a first launch that died leaves an
            // abandoned mutex, which the next launch simply takes over.
            while !matches!(
                unsafe { WaitForSingleObject(mutex, 50) },
                WAIT_OBJECT_0 | WAIT_ABANDONED
            ) {
                // The owner creates its window only after taking the mutex, so
                // a missing window means it is still starting.
                let running =
                    unsafe { FindWindowExW(HWND_MESSAGE, null_mut(), class.as_ptr(), null()) };
                if !running.is_null() || Instant::now() >= deadline {
                    let delivered = !running.is_null() && hand_off(running);
                    app.cleanup_before_exit();
                    std::process::exit(if delivered { 0 } else { 1 });
                }
            }
            let _ = APP.set(app.clone());
            let window = listen(&class);
            app.manage(Held {
                mutex: mutex as isize,
                window: window as isize,
            });
            Ok(())
        })
        .on_event(|app, event| {
            // Released before the app's own Exit handler relaunches, so the new
            // process does not hand its launch back to this one.
            if let RunEvent::Exit = event {
                if let Some(held) = app.try_state::<Held>() {
                    unsafe {
                        DestroyWindow(held.window as HWND);
                        ReleaseMutex(held.mutex as _);
                        CloseHandle(held.mutex as _);
                    }
                }
            }
        })
        .build()
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn hand_off(window: HWND) -> bool {
    let mut process = 0;
    unsafe { GetWindowThreadProcessId(window, &mut process) };
    if process != 0 {
        // The person launched this process, so it may bring the running one
        // to the front; without this Windows only flashes its taskbar button.
        unsafe { AllowSetForegroundWindow(process) };
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let args: Vec<Vec<u16>> = std::env::args_os()
        .map(|arg| arg.encode_wide().collect())
        .collect();
    let Some(bytes) = handoff::encode(&cwd.as_os_str().encode_wide().collect::<Vec<_>>(), &args)
    else {
        return false;
    };
    let data = COPYDATASTRUCT {
        dwData: TAG,
        cbData: bytes.len() as u32,
        lpData: bytes.as_ptr() as *mut _,
    };
    let mut answer = 0;
    let sent = unsafe {
        SendMessageTimeoutW(
            window,
            WM_COPYDATA,
            0,
            &data as *const COPYDATASTRUCT as LPARAM,
            SMTO_ABORTIFHUNG,
            DELIVERY_MS,
            &mut answer,
        )
    };
    sent != 0 && answer == 1
}

/// The window lives on the thread that runs the app's event loop, which
/// already pumps its messages.
fn listen(class: &[u16]) -> HWND {
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
        CreateWindowExW(
            0,
            class.as_ptr(),
            null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            null_mut(),
            module,
            null(),
        )
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message != WM_COPYDATA {
        return DefWindowProcW(window, message, wparam, lparam);
    }
    let data = &*(lparam as *const COPYDATASTRUCT);
    if data.dwData != TAG || data.lpData.is_null() || data.cbData as usize > handoff::LIMIT {
        return 0;
    }
    let bytes = std::slice::from_raw_parts(data.lpData as *const u8, data.cbData as usize);
    let (Some(app), Some((cwd, args))) = (APP.get(), handoff::decode(bytes)) else {
        return 0;
    };
    super::received(
        app,
        args.iter().map(|arg| OsString::from_wide(arg)),
        &PathBuf::from(OsString::from_wide(&cwd)),
    );
    1
}
