//! The Windows system proxy: WinINet per-connection options.
//!
//! Qt sets the proxy through `INTERNET_OPTION_PER_CONNECTION_OPTION` for the
//! LAN entry and for every dial-up or VPN entry the machine has
//! (`3rdparty/qv2ray/v2/proxy/QvProxyConfigurator.cpp:150-240`), then tells
//! WinINet the settings changed. This does the same, and additionally records
//! what it found, so the person's own proxy, PAC file or autodetection comes
//! back exactly — Qt only turned the proxy off.
//!
//! Only two options are owned: the proxy address and the flags that decide
//! which source is used. The bypass list and the autoconfiguration URL keep the
//! person's values; the flags alone decide that they are not consulted while
//! this proxy is on.
use std::cell::RefCell;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::NetworkManagement::Rras::{
    RasEnumEntriesW, ERROR_BUFFER_TOO_SMALL, RASENTRYNAMEW,
};
use windows_sys::Win32::Networking::WinInet::{
    InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS,
    INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_PROXY_SERVER,
};

/// The proxy address first, the flags last: the proxy is published only once
/// the address behind it is already in place.
const OPTIONS: [u32; 2] = [INTERNET_PER_CONN_PROXY_SERVER, INTERNET_PER_CONN_FLAGS];

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn text(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0;
    // The buffer WinINet allocated is terminated; walk to it and copy out.
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(pointer, length) };
    std::ffi::OsString::from_wide(slice)
        .to_string_lossy()
        .into_owned()
}

/// Dial-up and VPN entries carry their own copy of these options.
fn connections() -> Vec<Vec<u16>> {
    let mut size = std::mem::size_of::<RASENTRYNAMEW>() as u32;
    let mut count = 0u32;
    let mut entries = vec![RASENTRYNAMEW {
        dwSize: std::mem::size_of::<RASENTRYNAMEW>() as u32,
        ..Default::default()
    }];
    let mut status = unsafe {
        RasEnumEntriesW(
            std::ptr::null(),
            std::ptr::null(),
            entries.as_mut_ptr(),
            &mut size,
            &mut count,
        )
    };
    if status == ERROR_BUFFER_TOO_SMALL && count > 0 {
        entries = vec![
            RASENTRYNAMEW {
                dwSize: std::mem::size_of::<RASENTRYNAMEW>() as u32,
                ..Default::default()
            };
            count as usize
        ];
        status = unsafe {
            RasEnumEntriesW(
                std::ptr::null(),
                std::ptr::null(),
                entries.as_mut_ptr(),
                &mut size,
                &mut count,
            )
        };
    }
    if status != 0 {
        return Vec::new();
    }
    entries
        .iter()
        .take(count as usize)
        .map(|entry| {
            let end = entry
                .szEntryName
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szEntryName.len());
            entry.szEntryName[..end]
                .iter()
                .copied()
                .chain(std::iter::once(0))
                .collect()
        })
        .collect()
}

#[derive(Default)]
pub(super) struct WinInet {
    pending: RefCell<[Option<String>; OPTIONS.len()]>,
}

// The pending values never leave the thread that writes them; the manager owns
// this backend and applies a change in one place.
unsafe impl Send for WinInet {}

impl WinInet {
    /// Applies one option list to the LAN entry and to every RAS entry.
    fn set(&self, options: &mut [INTERNET_PER_CONN_OPTIONW]) -> Result<(), String> {
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: std::ptr::null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        let size = list.dwSize;
        let ok = unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                std::ptr::addr_of!(list).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err("system_proxy_apply_failed".into());
        }
        for mut name in connections() {
            list.pszConnection = name.as_mut_ptr();
            // A single stale entry must not cancel a working change.
            unsafe {
                InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    std::ptr::addr_of!(list).cast(),
                    size,
                )
            };
        }
        unsafe {
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null(),
                0,
            );
        }
        Ok(())
    }
}

impl super::Backend for WinInet {
    fn kind(&self) -> super::BackendKind {
        super::BackendKind::WinInet
    }
    fn read(&self) -> Result<Vec<super::Value>, String> {
        let mut options: Vec<INTERNET_PER_CONN_OPTIONW> = OPTIONS
            .iter()
            .map(|option| INTERNET_PER_CONN_OPTIONW {
                dwOption: *option,
                ..Default::default()
            })
            .collect();
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: std::ptr::null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        let mut size = list.dwSize;
        let ok = unsafe {
            InternetQueryOptionW(
                std::ptr::null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                std::ptr::addr_of_mut!(list).cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err("system_proxy_unavailable".into());
        }
        let mut values = Vec::with_capacity(options.len());
        for option in &options {
            let effective = if option.dwOption == INTERNET_PER_CONN_FLAGS {
                unsafe { option.Value.dwValue }.to_string()
            } else {
                // WinINet allocated this string for us; copy it out and give it back.
                let pointer = unsafe { option.Value.pszValue };
                let value = text(pointer);
                if !pointer.is_null() {
                    unsafe { GlobalFree(pointer.cast()) };
                }
                value
            };
            // WinINet keeps one store, so what is in effect is also what the
            // person set: restoring writes this very value back.
            values.push(super::Value {
                user: Some(effective.clone()),
                effective,
            });
        }
        Ok(values)
    }
    fn writable(&self) -> Result<(), String> {
        self.read().map(|_| ())
    }
    fn write(&self, index: usize, value: Option<&str>) -> Result<(), String> {
        let mut pending = self.pending.borrow_mut();
        *pending
            .get_mut(index)
            .ok_or_else(|| "system_proxy_apply_failed".to_owned())? =
            Some(value.unwrap_or_default().to_owned());
        Ok(())
    }
    fn flush(&self) -> Result<(), String> {
        let pending = self.pending.take();
        let mut buffers: Vec<Vec<u16>> = Vec::new();
        let mut options = Vec::new();
        for (index, value) in pending.iter().enumerate() {
            let Some(value) = value else { continue };
            let option = OPTIONS[index];
            if option == INTERNET_PER_CONN_FLAGS {
                options.push(INTERNET_PER_CONN_OPTIONW {
                    dwOption: option,
                    Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                        dwValue: value
                            .parse::<u32>()
                            .map_err(|_| "system_proxy_apply_failed")?,
                    },
                });
            } else {
                buffers.push(wide(value));
                options.push(INTERNET_PER_CONN_OPTIONW {
                    dwOption: option,
                    Value: windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: buffers.last_mut().unwrap().as_mut_ptr(),
                    },
                });
            }
        }
        if options.is_empty() {
            return Ok(());
        }
        self.set(&mut options)
    }
}
