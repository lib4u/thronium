//! The desktop's own key store. Thronium keeps one key there and asks for it
//! again on every start, so nothing of the library is readable from a stolen
//! disk while the person who owns the desktop never types a password.
use super::Key;

/// Why the library is written in the open instead of sealed. Each reason names
/// something of this desktop, never anything of the user's own data.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Absent {
    /// No Secret Service answers on this desktop's session bus, or Windows
    /// Credential Manager cannot be read.
    Unavailable,
    /// One answered but would not give or keep the key.
    Refused,
    /// The library moves between computers (portable or a chosen folder): a
    /// key of this computer would lock it out of the next one.
    Portable,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use gio::{glib, prelude::*};

    const SERVICE: &str = "org.freedesktop.secrets";
    const ROOT: &str = "/org/freedesktop/secrets";
    const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";
    const LABEL: &str = "Thronium library key";
    const TIMEOUT: i32 = 4000;

    /// What names this application's one item in the store. A dictionary, as
    /// the Secret Service interface asks for.
    fn attributes() -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("application".to_string(), "thronium".to_string()),
            ("purpose".to_string(), "library".to_string()),
        ])
    }

    struct Session {
        bus: gio::DBusConnection,
        path: String,
    }
    impl Session {
        fn open() -> Result<Self, Absent> {
            let bus = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)
                .map_err(|_| Absent::Unavailable)?;
            // "plain" keeps the secret on the session bus of this very desktop;
            // no key exchange is negotiated with the store.
            let reply = bus
                .call_sync(
                    Some(SERVICE),
                    ROOT,
                    "org.freedesktop.Secret.Service",
                    "OpenSession",
                    Some(&("plain", "".to_variant()).to_variant()),
                    None,
                    gio::DBusCallFlags::NONE,
                    TIMEOUT,
                    gio::Cancellable::NONE,
                )
                .map_err(|_| Absent::Unavailable)?;
            let path = reply
                .get::<(glib::Variant, glib::variant::ObjectPath)>()
                .ok_or(Absent::Refused)?
                .1;
            Ok(Self {
                bus,
                path: path.to_string(),
            })
        }
        fn call(
            &self,
            object: &str,
            interface: &str,
            method: &str,
            arguments: &glib::Variant,
        ) -> Result<glib::Variant, Absent> {
            self.bus
                .call_sync(
                    Some(SERVICE),
                    object,
                    interface,
                    method,
                    Some(arguments),
                    None,
                    gio::DBusCallFlags::NONE,
                    TIMEOUT,
                    gio::Cancellable::NONE,
                )
                .map_err(|error| {
                    if std::env::var_os("THRONIUM_KEYRING_DEBUG").is_some() {
                        eprintln!("keyring {method}: {error}");
                    }
                    Absent::Refused
                })
        }
        /// The one item this application owns, unlocked when the store allows it
        /// without asking the person anything.
        fn item(&self) -> Result<Option<String>, Absent> {
            let found = self.call(
                ROOT,
                "org.freedesktop.Secret.Service",
                "SearchItems",
                &(attributes(),).to_variant(),
            )?;
            let (unlocked, locked) = found
                .get::<(
                    Vec<glib::variant::ObjectPath>,
                    Vec<glib::variant::ObjectPath>,
                )>()
                .ok_or(Absent::Refused)?;
            if let Some(path) = unlocked.first() {
                return Ok(Some(path.to_string()));
            }
            let Some(path) = locked.first().cloned() else {
                return Ok(None);
            };
            let unlocked = self.call(
                ROOT,
                "org.freedesktop.Secret.Service",
                "Unlock",
                &(vec![path],).to_variant(),
            )?;
            let (opened, prompt) = unlocked
                .get::<(Vec<glib::variant::ObjectPath>, glib::variant::ObjectPath)>()
                .ok_or(Absent::Refused)?;
            // A prompt would put a dialog of the key store in front of the
            // person on every start; Thronium asks for nothing, so this stays plain.
            if prompt.as_str() != "/" {
                return Err(Absent::Refused);
            }
            Ok(opened.first().map(|path| path.to_string()))
        }
        fn session_path(&self) -> Result<glib::variant::ObjectPath, Absent> {
            glib::variant::ObjectPath::try_from(self.path.as_str()).map_err(|_| Absent::Refused)
        }
        fn secret(&self, item: &str) -> Result<Key, Absent> {
            let reply = self.call(
                item,
                "org.freedesktop.Secret.Item",
                "GetSecret",
                &(self.session_path()?,).to_variant(),
            )?;
            let (_session, _parameters, value, _kind) = reply
                .get::<((glib::variant::ObjectPath, Vec<u8>, Vec<u8>, String),)>()
                .ok_or(Absent::Refused)?
                .0;
            Key::from_bytes(&value).ok_or(Absent::Refused)
        }
        /// A locked collection is opened only when the store does it without
        /// putting a dialog in front of the person.
        fn unlock_default(&self) -> Result<(), Absent> {
            let path = glib::variant::ObjectPath::try_from(DEFAULT_COLLECTION)
                .map_err(|_| Absent::Refused)?;
            let reply = self.call(
                ROOT,
                "org.freedesktop.Secret.Service",
                "Unlock",
                &(vec![path],).to_variant(),
            )?;
            let (opened, prompt) = reply
                .get::<(Vec<glib::variant::ObjectPath>, glib::variant::ObjectPath)>()
                .ok_or(Absent::Refused)?;
            if opened.is_empty() || prompt.as_str() != "/" {
                return Err(Absent::Refused);
            }
            Ok(())
        }
        fn store(&self, key: &Key) -> Result<(), Absent> {
            self.unlock_default()?;
            let properties = std::collections::BTreeMap::from([
                (
                    "org.freedesktop.Secret.Item.Label".to_string(),
                    LABEL.to_variant(),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes".to_string(),
                    attributes().to_variant(),
                ),
            ]);
            let secret = (
                self.session_path()?,
                Vec::<u8>::new(),
                key.bytes().to_vec(),
                "application/octet-stream".to_string(),
            );
            let reply = self.call(
                DEFAULT_COLLECTION,
                "org.freedesktop.Secret.Collection",
                "CreateItem",
                &(properties, secret, true).to_variant(),
            )?;
            let (item, prompt) = reply
                .get::<(glib::variant::ObjectPath, glib::variant::ObjectPath)>()
                .ok_or(Absent::Refused)?;
            if item.as_str() == "/" || prompt.as_str() != "/" {
                return Err(Absent::Refused);
            }
            Ok(())
        }
    }

    /// The key of this desktop, created the first time and returned unchanged
    /// afterwards. Nothing is created when the store cannot keep it.
    pub(super) fn key() -> Result<Key, Absent> {
        let session = Session::open()?;
        if let Some(item) = session.item()? {
            return session.secret(&item);
        }
        let key = Key::generate().map_err(|_| Absent::Refused)?;
        session.store(&key)?;
        // Read it back, so a store that silently dropped it is not trusted.
        let item = session.item()?.ok_or(Absent::Refused)?;
        let stored = session.secret(&item)?;
        (stored.bytes() == key.bytes())
            .then_some(stored)
            .ok_or(Absent::Refused)
    }
}

/// Windows keeps the key as a generic credential of the signed-in person in
/// Credential Manager, which protects it with that person's DPAPI key: it
/// opens without a prompt for them and for nobody else.
#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NOT_FOUND},
        Security::Credentials::{
            CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC,
        },
    };

    const TARGET: &str = "Thronium/library";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn read() -> Result<Option<Key>, Absent> {
        let target = wide(TARGET);
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            return match unsafe { GetLastError() } {
                ERROR_NOT_FOUND => Ok(None),
                _ => Err(Absent::Unavailable),
            };
        }
        let key = unsafe {
            let found = &*credential;
            let blob = if found.CredentialBlob.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(found.CredentialBlob, found.CredentialBlobSize as usize)
            };
            let key = Key::from_bytes(blob);
            CredFree(credential as *const _);
            key
        };
        key.map(Some).ok_or(Absent::Refused)
    }

    fn write(key: &Key) -> Result<(), Absent> {
        let mut target = wide(TARGET);
        let mut blob = key.bytes().to_vec();
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(Absent::Refused);
        }
        Ok(())
    }

    /// Removes the key; true when none is left.
    pub(super) fn forget() -> bool {
        let target = wide(TARGET);
        let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        deleted != 0 || unsafe { GetLastError() } == ERROR_NOT_FOUND
    }

    /// The key of this person on this computer, created the first time and
    /// returned unchanged afterwards.
    pub(super) fn key() -> Result<Key, Absent> {
        if let Some(key) = read()? {
            return Ok(key);
        }
        let key = Key::generate().map_err(|_| Absent::Refused)?;
        write(&key)?;
        // Read it back, so a store that silently dropped it is not trusted.
        let stored = read()?.ok_or(Absent::Refused)?;
        (stored.bytes() == key.bytes())
            .then_some(stored)
            .ok_or(Absent::Refused)
    }
}

/// Removes this person's library key from Credential Manager, for an
/// uninstall that also deletes the library. True when none is left.
#[cfg(windows)]
pub fn forget_windows_key() -> bool {
    windows::forget()
}

// The key that seals this installation's files, or why there is none.
#[cfg(test)]
thread_local! {
    static INJECTED: std::cell::RefCell<Option<Key>> = const { std::cell::RefCell::new(None) };
}
/// A test states the key of its own installation instead of reaching the
/// desktop's key store.
#[cfg(test)]
pub(crate) fn inject_for_test(key: Option<Key>) {
    INJECTED.with(|slot| *slot.borrow_mut() = key);
}

pub fn key() -> Result<Key, Absent> {
    #[cfg(test)]
    if let Some(key) = INJECTED.with(|slot| slot.borrow().clone()) {
        return Ok(key);
    }
    // An ordinary test never reaches the desktop's own store; the one test that
    // is about the store says so. Integration tests link the library with
    // `isolated-keyring`, since `cfg(test)` does not reach them.
    if (cfg!(test) || cfg!(feature = "isolated-keyring"))
        && std::env::var_os("THRONIUM_KEYRING_TEST").is_none()
    {
        return Err(Absent::Unavailable);
    }
    // A copy told to keep nothing in the desktop store writes plain text.
    if std::env::var_os("THRONIUM_NO_KEYRING").is_some() {
        return Err(Absent::Unavailable);
    }
    #[cfg(target_os = "linux")]
    return linux::key();
    #[cfg(windows)]
    return windows::key();
    #[cfg(not(any(target_os = "linux", windows)))]
    Err(Absent::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a real Secret Service on the session bus (Credential Manager on
    /// Windows), so it is asked for explicitly rather than run with the
    /// ordinary suite.
    #[test]
    #[ignore]
    fn the_desktop_store_keeps_one_key_and_returns_it_again() {
        std::env::set_var("THRONIUM_KEYRING_TEST", "1");
        let first = key().expect("no Secret Service for this test");
        let second = key().expect("the key vanished between two reads");
        assert_eq!(first.bytes(), second.bytes());
        let sealed = super::super::seal(&first, b"library").unwrap();
        assert_eq!(super::super::unseal(&second, &sealed).unwrap(), b"library");
        // A copy told to keep nothing in the store never reaches it.
        std::env::set_var("THRONIUM_NO_KEYRING", "1");
        assert_eq!(key().unwrap_err(), Absent::Unavailable);
        std::env::remove_var("THRONIUM_NO_KEYRING");
        // An uninstall with its data takes the key; the next start makes another.
        #[cfg(windows)]
        {
            assert!(forget_windows_key());
            assert!(forget_windows_key());
            let third = key().expect("no key after forgetting");
            assert_ne!(third.bytes(), first.bytes());
            assert!(forget_windows_key());
        }
    }
}
