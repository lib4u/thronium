// The caller obtains this address from the current guarded core challenge.
// Never run a shell, pass submitted answers, or log the authentication URL.
pub fn open(url: &str) -> Result<(), String> {
    // Every launcher below would also open a local file or program; only web
    // addresses are ever handed to it.
    if !web_address(url) {
        return Err("vpn_browser_open_failed".into());
    }
    launch(url)
}

fn web_address(url: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        url.get(..scheme.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
    }) && !url.chars().any(char::is_control)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn launch(url: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/open");
        command.arg("--");
        command
    };
    let status = command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "vpn_browser_open_failed")?;
    if status.success() {
        Ok(())
    } else {
        Err("vpn_browser_open_failed".into())
    }
}

// The shell hands the address to the default browser as is, fragment included,
// and reports only a real refusal. `explorer.exe` exits with 1 even when it has
// opened the page, so its status could not tell success from failure.
#[cfg(target_os = "windows")]
fn launch(url: &str) -> Result<(), String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (verb, target) = (wide("open"), wide(url));
    // Shell handlers may use COM; this blocking worker thread gets its own
    // apartment and releases it only if it was the one to enter it.
    let apartment = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    let instance = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    if apartment >= 0 {
        unsafe { CoUninitialize() };
    }
    // Values above 32 mean success; anything else is the shell's error code.
    if instance as isize > 32 {
        Ok(())
    } else {
        Err("vpn_browser_open_failed".into())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn launch(_url: &str) -> Result<(), String> {
    Err("vpn_browser_open_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_web_addresses_reach_the_launcher() {
        for url in [
            "https://www.cloudflare.com/application/terms/",
            "http://127.0.0.1:9090/thronium-dashboard.html#secret=a%20b&language=en",
            "HTTPS://sso.example.test/login?x=1",
        ] {
            assert!(web_address(url), "{url}");
        }
        for url in [
            "",
            "https:",
            "file:///C:/Windows/System32/calc.exe",
            r"C:\Windows\System32\calc.exe",
            r"\\server\share\run.exe",
            "calc",
            "-https://example.test",
            " https://example.test",
            "https://example.test/\nnext",
            "javascript:alert(1)",
            "httpsх://example.test",
        ] {
            assert!(!web_address(url), "{url}");
            assert_eq!(open(url), Err("vpn_browser_open_failed".into()));
        }
    }
}
