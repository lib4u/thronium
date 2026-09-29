//! One place says that a path belongs to this person alone.
//!
//! Unix has said it with modes since the beginning: 0700 for a directory, 0600
//! for a file. Windows says the same with an explicit list: only the account
//! that runs this program, and inheritance from the parent folder switched off,
//! so a library under `%LOCALAPPDATA%` does not quietly widen to whoever the
//! parent folder allowed. A directory also lets SYSTEM read, as the parent
//! folder did: the TUN core runs as SYSTEM and opens the rule sets and other
//! files a configuration names there.

/// The list Windows understands: full access for this account and nothing
/// inherited. `P` protects the list from the parent, `OICI` hands it to the
/// entries a directory will hold, and `SY` may read them.
#[cfg(any(windows, test))]
fn descriptor(sid: &str, directory: bool) -> String {
    if directory {
        format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FR;;;SY)")
    } else {
        format!("D:P(A;;FA;;;{sid})")
    }
}

/// The same rule for a kernel object such as a named pipe: generic access for
/// this account alone, nothing inherited.
#[cfg(any(windows, test))]
fn object_descriptor(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// Security attributes for an object only this account may open; they stay
/// valid for as long as the value lives.
#[cfg(windows)]
pub(crate) use windows::Private;

/// A directory only this account may open.
pub(crate) fn restrict_directory(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        windows::restrict(path, true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// A file only this account may read.
pub(crate) fn restrict_file(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        windows::restrict(path, false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use super::descriptor;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, SetFileSecurityW, TokenUser, ACL,
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn text(pointer: *const u16) -> String {
        let mut length = 0;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
    }

    /// The account this program runs as, in the form the list names it.
    fn account() -> Result<String, String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err("storage_permissions_failed".into());
        }
        let token = Handle(token);
        let mut size = 0u32;
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size) };
        if size == 0 {
            return Err("storage_permissions_failed".into());
        }
        let mut buffer = vec![0u8; size as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err("storage_permissions_failed".into());
        }
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let mut string: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut string) } == 0 {
            return Err("storage_permissions_failed".into());
        }
        let sid = text(string);
        unsafe { LocalFree(string.cast()) };
        Ok(sid)
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }

    pub(crate) struct Private {
        attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    }
    impl Private {
        pub(crate) fn new() -> Result<Self, String> {
            let sddl = wide(std::ffi::OsStr::new(&super::object_descriptor(&account()?)));
            let mut security = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut security,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err("storage_permissions_failed".into());
            }
            Ok(Self {
                attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>(
                    ) as u32,
                    lpSecurityDescriptor: security,
                    bInheritHandle: 0,
                },
            })
        }
        pub(crate) fn as_ptr(&mut self) -> *mut std::ffi::c_void {
            (&mut self.attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast()
        }
    }
    impl Drop for Private {
        fn drop(&mut self) {
            unsafe { LocalFree(self.attributes.lpSecurityDescriptor) };
        }
    }
    // The descriptor is owned and only read by the kernel.
    unsafe impl Send for Private {}

    pub(super) fn restrict(path: &Path, directory: bool) -> Result<(), String> {
        let sddl = wide(std::ffi::OsStr::new(&descriptor(&account()?, directory)));
        let mut security = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("storage_permissions_failed".into());
        }
        let name = wide(path.as_os_str());
        let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // A directory hands the list on to what it already holds too, so files
        // written under an earlier list follow it; failing that, as before, the
        // directory alone takes the list.
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let applied = (directory
            && unsafe {
                GetSecurityDescriptorDacl(security, &mut present, &mut dacl, &mut defaulted)
            } != 0
            && present != 0
            && unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    information,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                )
            } == 0)
            || unsafe { SetFileSecurityW(name.as_ptr(), information, security) } != 0;
        unsafe { LocalFree(security.cast()) };
        if !applied {
            return Err("storage_permissions_failed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// The shape is fixed here because the machine that reads it is not
    /// available: a protected list, this account only, inherited by a
    /// directory's contents and by nothing else; SYSTEM may read a directory.
    #[test]
    fn a_path_is_handed_to_this_account_and_protected_from_the_parent() {
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        assert_eq!(
            super::descriptor(sid, true),
            format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FR;;;SY)")
        );
        assert_eq!(super::descriptor(sid, false), format!("D:P(A;;FA;;;{sid})"));
        // The core's pipe: the same account, generic access, nothing else.
        assert_eq!(super::object_descriptor(sid), format!("D:P(A;;GA;;;{sid})"));
        for kind in [true, false] {
            let value = super::descriptor(sid, kind);
            assert!(value.starts_with("D:P("), "the parent must not reach in");
            // The TUN core runs as SYSTEM and reads a configuration's files;
            // it never writes here, and no other account is named.
            let others = value.matches('(').count() - 1;
            assert_eq!(others, usize::from(kind), "SYSTEM only, and only to read");
            assert!(!value.contains("FA;;;SY"));
        }
    }
}
