//! The few registry values this application owns under the current user.
//!
//! Writing is deliberate and narrow: a value is created or removed by name, and
//! nothing else in the key is read or rewritten. The machine hive is never
//! touched, so no elevation is involved.
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
    RRF_RT_REG_BINARY, RRF_RT_REG_SZ,
};

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Creates the key when missing and replaces just this value.
pub fn set_string(subkey: &str, name: &str, value: &str) -> Result<(), String> {
    let data = wide(value);
    let bytes = std::mem::size_of_val(&data[..]) as u32;
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            wide(subkey).as_ptr(),
            wide(name).as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            bytes,
        )
    };
    (status == ERROR_SUCCESS).then_some(()).ok_or_else(|| {
        // The caller turns this into its own settings code; no value is echoed.
        format!("registry_write_failed:{status}")
    })
}

/// Removing a value that is already gone is success: the state is what matters.
pub fn remove_value(subkey: &str, name: &str) -> Result<(), String> {
    let status = unsafe {
        RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            wide(subkey).as_ptr(),
            wide(name).as_ptr(),
        )
    };
    match status {
        s if s == ERROR_SUCCESS || s == ERROR_FILE_NOT_FOUND => Ok(()),
        status => Err(format!("registry_delete_failed:{status}")),
    }
}

/// The value as text, or `None` when the key or value is absent.
pub fn string(subkey: &str, name: &str) -> Option<String> {
    let (key, value) = (wide(subkey), wide(name));
    let mut size = 0u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; size as usize / 2 + 1];
    let mut bytes = size;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

/// Removes the key and everything under it; absent is success.
pub fn remove_tree(subkey: &str) -> Result<(), String> {
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, wide(subkey).as_ptr()) };
    match status {
        s if s == ERROR_SUCCESS || s == ERROR_FILE_NOT_FOUND => Ok(()),
        status => Err(format!("registry_delete_failed:{status}")),
    }
}

/// A binary value, or `None` when the key or value is absent.
pub fn binary(subkey: &str, name: &str) -> Option<Vec<u8>> {
    let (key, value) = (wide(subkey), wide(name));
    let mut buffer = vec![0u8; 64];
    let mut size = buffer.len() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_BINARY,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    (status == ERROR_SUCCESS).then(|| {
        buffer.truncate(size as usize);
        buffer
    })
}
