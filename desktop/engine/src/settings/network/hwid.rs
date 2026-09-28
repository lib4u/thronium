//! Device headers are request-only. Explicit group headers win; system fields
//! are resolved individually, only when sending is enabled and a value is absent.
use std::collections::BTreeMap;

const FIELDS: [(&str, &str); 4] = [
    ("hwid", "x-hwid"),
    ("os", "x-device-os"),
    ("osversion", "x-ver-os"),
    ("model", "x-device-model"),
];
pub(super) trait DeviceProvider {
    fn value(&mut self, field: &str) -> Option<String>;
}
pub(super) struct SystemDevice;
impl DeviceProvider for SystemDevice {
    fn value(&mut self, field: &str) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            linux_value(field, &mut |path| std::fs::read_to_string(path).ok())
        }
        #[cfg(windows)]
        {
            windows_value(
                field,
                &mut |path, name| registry::read(path, name),
                &mut || std::env::var("COMPUTERNAME").ok(),
            )
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            (field == "os").then(|| std::env::consts::OS.into())
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_value(field: &str, read: &mut impl FnMut(&str) -> Option<String>) -> Option<String> {
    let value = match field {
        // Qt only tries DBus when the primary file cannot be opened. A readable
        // empty primary file must not silently select another device identity.
        "hwid" => read("/etc/machine-id").or_else(|| read("/var/lib/dbus/machine-id")),
        "os" => Some("Linux".into()),
        "osversion" => read("/proc/sys/kernel/osrelease"),
        "model" => read("/etc/os-release").and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_owned())
            })
        }),
        _ => None,
    };
    value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// Windows device fields, following `DeviceDetailsHelper.cpp`. Qt reads the
/// machine GUID, a "major.minor.build" version and the pair of board names;
/// the registry holds the same values WMI reports, without a COM dependency.
#[cfg(any(windows, test))]
fn windows_value(
    field: &str,
    read: &mut impl FnMut(&str, &str) -> Option<String>,
    hostname: &mut impl FnMut() -> Option<String>,
) -> Option<String> {
    const VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";
    let text = |value: Option<String>| value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    match field {
        "hwid" => text(read(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")).or_else(|| {
            // Qt falls back to host name and product type. Its later
            // "empty hwid" branch cannot run once this one answered.
            text(hostname()).map(|name| format!("{name}-windows"))
        }),
        "os" => Some("Windows".into()),
        "osversion" => {
            let build = text(read(VERSION, "CurrentBuildNumber"))?;
            let major = text(read(VERSION, "CurrentMajorVersionNumber"));
            let minor = text(read(VERSION, "CurrentMinorVersionNumber"));
            match (major, minor) {
                (Some(major), Some(minor)) => Some(format!("{major}.{minor}.{build}")),
                // Builds before 10 keep only the string pair.
                _ => {
                    let legacy = text(read(VERSION, "CurrentVersion"))?;
                    Some(format!("{legacy}.{build}"))
                }
            }
        }
        "model" => {
            let model = text(read(BIOS, "SystemProductName"));
            let board = text(read(BIOS, "BaseBoardProduct"));
            match (model, board) {
                (Some(model), Some(board)) if model != board => Some(format!("{model}/{board}")),
                (Some(value), _) | (None, Some(value)) => Some(value),
                (None, None) => None,
            }
        }
        _ => None,
    }
}

#[cfg(windows)]
mod registry {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Read one string or DWORD value under HKEY_LOCAL_MACHINE. Device fields
    /// are advisory: any failure leaves the header out instead of failing.
    pub(super) fn read(path: &str, name: &str) -> Option<String> {
        let (path, name) = (wide(path), wide(name));
        let mut kind = 0u32;
        let mut size = 0u32;
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_DWORD;
        // The first call only measures; 64 KiB caps a hostile or corrupt value.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                name.as_ptr(),
                flags,
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS || size == 0 || size > 64 * 1024 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                name.as_ptr(),
                flags,
                &mut kind,
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        buffer.truncate(size as usize);
        if kind == REG_DWORD {
            let value: [u8; 4] = buffer.get(..4)?.try_into().ok()?;
            return Some(u32::from_le_bytes(value).to_string());
        }
        let wide: Vec<u16> = buffer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|unit| *unit != 0)
            .collect();
        Some(String::from_utf16_lossy(&wide))
    }
}

fn overrides(raw: &str) -> BTreeMap<String, String> {
    raw.split(',')
        .filter_map(|entry| entry.split_once('='))
        .filter_map(|(key, value)| {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            // Original HTTPRequestHelper keeps the last valid, nonempty value.
            // Empty duplicates must not erase an earlier custom override.
            (FIELDS.iter().any(|(name, _)| *name == key)
                && !value.is_empty()
                && !value.contains(['\r', '\n'])
                && value.encode_utf16().count() < 1000)
                .then(|| (key, value.to_owned()))
        })
        .collect()
}

pub(super) fn apply(
    headers: &mut BTreeMap<String, String>,
    enabled: bool,
    custom: &str,
    provider: &mut impl DeviceProvider,
) {
    if !enabled {
        return;
    }
    let custom = overrides(custom);
    for (field, header) in FIELDS {
        if headers.keys().any(|key| key.eq_ignore_ascii_case(header)) {
            continue;
        }
        let value = custom.get(field).cloned().or_else(|| provider.value(field));
        if let Some(value) = value.filter(|s| !s.is_empty()) {
            headers.insert(header.into(), value);
        }
    }
}

#[cfg(test)]
mod tests;
