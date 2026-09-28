//! An installed Qt Throne next to Thronium: where its library is, so importing
//! it is one choice in the open dialog, and whether it runs, since two
//! programs owning the system proxy, TUN or system DNS disturb each other.
use std::path::PathBuf;

/// Qt keeps `throne.db` in `config` under its per-user location
/// (`QStandardPaths::AppConfigLocation`), or beside a portable Throne.exe.
pub fn library_directory() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    if let Some(program) = running() {
        let beside = program.parent()?.join("config");
        if beside.join("throne.db").is_file() {
            return Some(beside);
        }
    }
    #[cfg(target_os = "windows")]
    let base = dirs::data_local_dir();
    #[cfg(not(target_os = "windows"))]
    let base = dirs::config_dir();
    base.map(|base| base.join("Throne").join("config"))
        .filter(|config| config.join("throne.db").is_file())
}

/// The program file of a running Qt Throne, if any.
#[cfg(target_os = "windows")]
pub fn running() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return None;
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut found = None;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let end = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(0);
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        if name.eq_ignore_ascii_case("Throne.exe") {
            found = Some(entry.th32ProcessID);
            break;
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, found?) };
    if process.is_null() {
        return None;
    }
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
    };
    unsafe { CloseHandle(process) };
    (ok != 0).then(|| std::ffi::OsString::from_wide(&buffer[..size as usize]).into())
}

/// Before the first connection of this run: a running Qt Throne is named
/// once, and the connection goes on.
#[cfg(target_os = "windows")]
pub async fn warn_once(app: &tauri::AppHandle) {
    use crate::localization::{text, Language, TextKey};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tauri::Manager;
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    if tokio::task::spawn_blocking(running)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return;
    }
    let shared = app.state::<crate::Shared>();
    shared.logs.event("warn", "qt_throne_running", None);
    let language = Language::of(&*shared.engine.lock().await);
    app.dialog()
        .message(text(language, TextKey::WindowsQtThroneRunning))
        .title("Thronium")
        .kind(MessageDialogKind::Warning)
        .show(|_| {});
}
