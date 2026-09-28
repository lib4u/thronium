mod durability;
mod lock;
use lock::LibraryLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileKind {
    ExternalCore,
    Chain,
    AutoSelector,
    SingBoxOutbound,
    SingBoxConfig,
    XrayOutbound,
    XrayConfig,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_policy: Option<crate::vpn_policy::Policy>,
    pub id: String,
    pub name: String,
    pub group_id: String,
    pub kind: ProfileKind,
    pub config: Value,
    pub favorite: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Group {
    #[serde(default, rename = "proxyChain")]
    pub proxy_chain: crate::group_chains::GroupChain,
    #[serde(default)]
    pub collapsed: bool,
    /// Qt's `auto_clear_unavailable`: a finished latency test removes the
    /// servers of this group that did not answer.
    #[serde(default, rename = "autoClearUnavailable")]
    pub auto_clear_unavailable: bool,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<crate::subscriptions::Subscription>,
}
impl Group {
    pub fn display_name(&self) -> &str {
        self.subscription
            .as_ref()
            .filter(|s| {
                reqwest::Url::parse(&s.settings.url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .as_deref()
                    == Some(self.name.as_str())
            })
            .and_then(|s| s.metadata.title.as_deref())
            .unwrap_or(&self.name)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    #[serde(default)]
    pub vless_core: crate::vless::Core,
    #[serde(default)]
    pub vless_overrides: std::collections::BTreeMap<String, crate::vless::Core>,
    #[serde(default)]
    pub close_behavior: CloseBehavior,
    #[serde(default)]
    pub connection_mode: crate::system_proxy::ConnectionMode,
    #[serde(default)]
    pub tun: crate::tun::Settings,
    #[serde(default)]
    pub ping: crate::probes::PingSettings,
    pub language: String,
    pub theme: String,
    pub inbound_port: u16,
    #[serde(default)]
    pub library_sort: LibrarySort,
    #[serde(default)]
    pub library_sort_descending: bool,
    #[serde(default)]
    pub auto_select: AutoSelect,
}

/// The always-on quick auto-select: whether its card is shown and the health
/// and balancing settings its pool is built with. The config is a free-form
/// auto-selector object so the configurator can edit any of its settings.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoSelect {
    pub enabled: bool,
    pub config: Value,
    #[serde(default = "enabled_by_default")]
    pub failover: bool,
    #[serde(default)]
    pub source_group_id: Option<String>,
}
fn enabled_by_default() -> bool {
    true
}
impl Default for AutoSelect {
    fn default() -> Self {
        Self {
            enabled: true,
            config: crate::auto_selector::default_quick_config(),
            failover: true,
            source_group_id: None,
        }
    }
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CloseBehavior {
    #[default]
    Quit,
    Background,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LibrarySort {
    #[default]
    Original,
    Name,
    Address,
    Protocol,
    Latency,
    Security,
    Traffic,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            vless_core: crate::vless::Core::Xray,
            vless_overrides: Default::default(),
            close_behavior: CloseBehavior::Quit,
            connection_mode: crate::system_proxy::ConnectionMode::Local,
            tun: crate::tun::Settings::default(),
            ping: crate::probes::PingSettings::default(),
            // The settings catalog owns the default interface language.
            language: crate::settings::fields()
                .iter()
                .find(|f| f.id == "language")
                .and_then(|f| f.default.as_str())
                .unwrap_or_else(crate::languages::source)
                .into(),
            theme: "light".into(),
            inbound_port: 2080,
            library_sort: LibrarySort::Original,
            library_sort_descending: false,
            auto_select: Default::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Library {
    #[serde(
        default,
        skip_serializing_if = "crate::routing::resources::Pack::is_empty"
    )]
    pub routing_resources: crate::routing::resources::Pack,
    #[serde(default, skip_serializing_if = "crate::tray_icons::Pack::is_empty")]
    pub tray_icons: crate::tray_icons::Pack,
    #[serde(skip)]
    pub country_measurements: crate::country_measurements::Cache,
    #[serde(skip)]
    pub latency_measurements: crate::latency_measurements::Cache,
    #[serde(skip)]
    pub selector_history: crate::auto_selector::history::Cache,
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        deserialize_with = "crate::vpn_otp_bindings::deserialize_map"
    )]
    pub vpn_otp_bindings: std::collections::BTreeMap<String, crate::vpn_otp_bindings::Binding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub otp: Vec<crate::otp::Entry>,
    #[serde(default)]
    pub settings: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    pub routing: crate::routing::Routing,
    pub version: u32,
    pub profiles: Vec<Profile>,
    pub groups: Vec<Group>,
    pub selected: Option<String>,
    pub preferences: Preferences,
}
impl Library {
    /// Subscriptions stop managing the profiles `released` selects, except the
    /// subscription of `kept_group`: a profile moved there stays its own.
    pub(crate) fn release_managed(
        &mut self,
        released: impl Fn(&str) -> bool,
        kept_group: Option<&str>,
    ) {
        for group in &mut self.groups {
            if Some(group.id.as_str()) == kept_group {
                continue;
            }
            if let Some(subscription) = &mut group.subscription {
                subscription.managed_ids.retain(|id| !released(id));
            }
        }
    }
    /// The selection names neither a stored profile nor the virtual auto-select
    /// entry, which never exists in `profiles`.
    pub(crate) fn selection_dangling(&self) -> bool {
        self.selected.as_ref().is_some_and(|id| {
            id != crate::auto_selector::AUTO_SELECT_ID && !self.profiles.iter().any(|p| &p.id == id)
        })
    }
}
impl Default for Library {
    fn default() -> Self {
        Self {
            routing_resources: Default::default(),
            tray_icons: Default::default(),
            country_measurements: Default::default(),
            latency_measurements: Default::default(),
            selector_history: Default::default(),
            vpn_otp_bindings: Default::default(),
            otp: Vec::new(),
            settings: Default::default(),
            routing: crate::routing::Routing::default(),
            version: 1,
            profiles: vec![],
            groups: vec![Group {
                proxy_chain: Default::default(),
                collapsed: false,
                auto_clear_unavailable: false,
                id: PERSONAL_GROUP.into(),
                name: "Personal".into(),
                subscription: None,
            }],
            selected: None,
            preferences: Preferences::default(),
        }
    }
}

pub struct Store {
    generation: u64,
    pub library: Library,
    path: PathBuf,
    _lock: LibraryLock,
    durability: durability::Durability,
    pub(crate) auto_select_source_repaired: bool,
    /// The key of this desktop, when its store keeps one. The library is then
    /// written sealed; without it the file stays as it always was.
    pub(crate) secrets: Result<crate::secrets::Key, crate::secrets::keyring::Absent>,
}
impl Store {
    /// Opens a store whose files are sealed with a key given directly, so a
    /// test never reaches the desktop's own key store.
    #[cfg(test)]
    pub(crate) fn open_sealed_for_test(
        directory: &Path,
        key: crate::secrets::Key,
    ) -> Result<Self, String> {
        crate::secrets::keyring::inject_for_test(Some(key));
        let opened = Self::open(directory);
        crate::secrets::keyring::inject_for_test(None);
        opened
    }
    pub fn open(directory: &Path) -> Result<Self, String> {
        Self::open_with(directory, true)
    }
    /// `seal: false` keeps the library plain for a copy that travels between
    /// computers; one sealed earlier is still read with this computer's key
    /// and written plain from then on.
    pub fn open_with(directory: &Path, seal: bool) -> Result<Self, String> {
        std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        crate::ownership::restrict_directory(directory)?;
        // Guard immediately: parse/validation failures also release ownership,
        // even if an unrelated concurrent fork inherited this open description.
        let lock = LibraryLock::acquire(&directory.join("library.lock"))?;
        let path = directory.join("library.json");
        let secrets = if seal {
            crate::secrets::keyring::key()
        } else {
            Err(crate::secrets::keyring::Absent::Portable)
        };
        let mut library: Library = match std::fs::read(&path) {
            Ok(bytes) => {
                // A sealed library is unreadable without this desktop's key; it
                // is never silently replaced by an empty one.
                let bytes = if crate::secrets::sealed(&bytes) {
                    let key = match &secrets {
                        Ok(key) => key.clone(),
                        Err(_) if !seal => {
                            crate::secrets::keyring::key().map_err(|_| "secrets_unavailable")?
                        }
                        Err(_) => return Err("secrets_unavailable".into()),
                    };
                    crate::secrets::unseal(&key, &bytes)?
                } else {
                    bytes
                };
                let mut value: Value =
                    serde_json::from_slice(&bytes).map_err(|_| "library_corrupt".to_string())?;
                if value["version"]
                    .as_u64()
                    .is_some_and(|version| !supported_version(version))
                {
                    return Err("library_version_unsupported".into());
                }
                crate::vpn_policy::validate_wire(&bytes, false).map_err(|_| "library_corrupt")?;
                crate::vpn_otp_bindings::validate_wire(&bytes, false)
                    .map_err(|_| "library_corrupt")?;
                crate::vless::migrate(&mut value);
                serde_json::from_value(value).map_err(|_| "library_corrupt".to_string())?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Library::default(),
            Err(e) => return Err(e.to_string()),
        };
        if !supported_version(u64::from(library.version)) {
            return Err("library_version_unsupported".into());
        }
        // Heal a library polluted by an earlier build that persisted the
        // virtual auto-select pool as a real profile.
        library
            .profiles
            .retain(|p| p.id != crate::auto_selector::AUTO_SELECT_ID);
        let auto_select_source_repaired = repair_auto_select_source(&mut library);
        validate_library(&library)?;
        // Reopening reconciles the exact observed file before HOTP is allowed.
        #[cfg(target_os = "linux")]
        if path.exists() {
            std::fs::File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())?;
            durability::sync_directory(directory)?;
        }
        library.country_measurements =
            crate::country_measurements::Cache::load(directory, &library);
        library.latency_measurements =
            crate::latency_measurements::Cache::load(directory, &library);
        library.selector_history = crate::auto_selector::history::Cache::load(directory, &library);
        let mut store = Self {
            generation: 0,
            library,
            path,
            _lock: lock,
            durability: Default::default(),
            auto_select_source_repaired,
            secrets,
        };
        if auto_select_source_repaired {
            store.commit(store.library.clone())?;
        }
        Ok(store)
    }

    // Once rename succeeds, publish that exact state even if directory fsync fails.
    // A failure never returns a HOTP code and locks reservations until reopen.
    // tempfile::persist replaces atomically on Windows as well as Unix.
    /// The new library replaced the file, but the directory sync failed: memory
    /// and disk hold the new state and only its durability is unconfirmed.
    pub(crate) const WRITTEN_UNCERTAIN: &'static str = "store_sync_uncertain";
    /// Whether a commit result left the new library in place, so the caller's
    /// follow-up bookkeeping must still run.
    pub(crate) fn written(result: &Result<(), String>) -> bool {
        match result {
            Ok(()) => true,
            Err(error) => error == Self::WRITTEN_UNCERTAIN,
        }
    }
    pub fn commit(&mut self, mut next: Library) -> Result<(), String> {
        next.country_measurements = self.library.country_measurements.clone();
        next.latency_measurements = self.library.latency_measurements.clone();
        next.selector_history = self.library.selector_history.clone();
        // Restore/removing the final binding or policy cannot downgrade its reader boundary.
        if self.library.version >= 3 {
            next.version = next.version.max(self.library.version);
        }
        // The always-on auto-select is a virtual pool; its reserved profile is
        // injected into the connect library and must never persist here.
        next.profiles
            .retain(|p| p.id != crate::auto_selector::AUTO_SELECT_ID);
        next.preferences
            .vless_overrides
            .retain(|id, _| next.profiles.iter().any(|p| p.id == *id));
        validate_library(&next)?;
        crate::routing::resources::prune(&mut next);
        let bytes = serde_json::to_vec_pretty(&next).map_err(|_| "store_write_failed")?;
        let bytes = match self.secrets.as_ref() {
            Ok(key) => crate::secrets::seal(key, &bytes)?,
            Err(_) => bytes,
        };
        let mut file = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())
            .map_err(|_| "store_write_failed")?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| "store_write_failed")?;
        #[cfg(test)]
        self.durability.fail(durability::Fault::BeforeRename)?;
        durability::replace(file, &self.path)?;
        self.library = next;
        self.generation = self.generation.wrapping_add(1);
        // From this point disk already contains next. Never resurrect old memory.
        let already_uncertain = self.durability.uncertain;
        self.durability.uncertain = true;
        #[cfg(test)]
        self.durability
            .fail(durability::Fault::AfterRename)
            .map_err(|_| Self::WRITTEN_UNCERTAIN)?;
        #[cfg(test)]
        self.durability
            .fail(durability::Fault::DirectorySync)
            .map_err(|_| Self::WRITTEN_UNCERTAIN)?;
        durability::sync_directory(self.path.parent().unwrap())
            .map_err(|_| Self::WRITTEN_UNCERTAIN)?;
        self.durability.uncertain = already_uncertain;
        Ok(())
    }
    pub(crate) fn save_latency_measurements(
        &mut self,
        next: crate::latency_measurements::Cache,
    ) -> Result<(), String> {
        next.save(self.path.parent().unwrap())?;
        self.library.latency_measurements = next;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }
    pub(crate) fn forget_latency_measurements(&mut self) {
        self.library.latency_measurements = Default::default();
        self.generation = self.generation.wrapping_add(1);
    }
    pub(crate) fn save_selector_history(
        &mut self,
        next: crate::auto_selector::history::Cache,
    ) -> Result<(), String> {
        next.save(self.path.parent().unwrap())?;
        self.library.selector_history = next;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn save_country_measurements(
        &mut self,
        next: crate::country_measurements::Cache,
    ) -> Result<(), String> {
        next.save(self.path.parent().unwrap())?;
        self.library.country_measurements = next;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }
    pub(crate) fn durability_uncertain(&self) -> bool {
        self.durability.uncertain
    }
    #[cfg(test)]
    pub(crate) fn fail_next_commit(&mut self, point: durability::Fault) {
        self.durability.fault = Some(point);
    }
}
#[cfg(test)]
pub(crate) use durability::Fault as CommitFault;

/// The built-in group every library has; it cannot be renamed or deleted.
pub const PERSONAL_GROUP: &str = "personal";
/// Most profiles one import, export or measurement batch handles.
pub const MAX_BATCH_PROFILES: usize = 1000;
/// Longest name of a profile or group, in bytes.
pub const MAX_NAME_BYTES: usize = 512;
/// Largest configuration of a profile, and of one batch of new profiles, in JSON bytes.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

#[cfg(test)]
mod tests;
mod validation;
pub use validation::*;
