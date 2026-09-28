//! Immutable, user-owned geodata. Stored profiles never contain machine-specific paths.
use crate::{
    store::{Library, Profile, ProfileKind},
    subscriptions::provider_routing::ProviderRouting,
};
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::routing::MAX_GEODATA_ASSET_BYTES as LIMIT;
pub(crate) mod catalog;
pub mod deferral;
pub mod manager;
pub(crate) use deferral::{prepare_for, Deferral};

/// Whether preparing assets may download. `Cached` is used under the Engine
/// lock: a needed download is reported as [`deferral::DOWNLOAD_REQUIRED`]
/// and performed by the host without the lock; `stale` accepts a cached file
/// whose refresh was already attempted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fetch {
    Download,
    Cached { stale: bool },
}
const DEFAULT_IP: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
const DEFAULT_SITE: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn provider<'a>(profile: &Profile, library: &'a Library) -> Option<&'a ProviderRouting> {
    library
        .groups
        .iter()
        .find(|g| g.id == profile.group_id)?
        .subscription
        .as_ref()?
        .metadata
        .routing
        .as_ref()
}
pub(crate) fn enabled(profile: &Profile, library: &Library) -> bool {
    !library.routing.customized()
        && !matches!(
            profile.kind,
            ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
        )
        && library
            .groups
            .iter()
            .find(|g| g.id == profile.group_id)
            .and_then(|g| g.subscription.as_ref())
            .is_some_and(|s| {
                s.settings.use_provider_routing
                    && s.metadata
                        .routing
                        .as_ref()
                        .is_some_and(|r| r.action != "off")
            })
}

pub(crate) struct Assets {
    directory: PathBuf,
    config: Value,
}
impl Assets {
    pub(crate) fn new(directory: &Path, routing: Option<&ProviderRouting>) -> Self {
        Self {
            directory: directory.join("xray-assets"),
            config: routing.map(|r| r.config.clone()).unwrap_or(json!({})),
        }
    }
    pub(crate) fn with_library(mut self, library: &Library) -> Self {
        for (key, setting) in [
            ("Geositeurl", "xray_geosite_url"),
            ("Geoipurl", "xray_geoip_url"),
        ] {
            if self.config[key].as_str().is_none_or(|s| s.is_empty()) {
                self.config[key] = crate::settings::value(library, setting);
            }
        }
        self
    }
    fn url(&self, sites: bool) -> &str {
        self.config[if sites { "Geositeurl" } else { "Geoipurl" }]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(if sites { DEFAULT_SITE } else { DEFAULT_IP })
    }
    fn manifest(&self, sites: bool) -> PathBuf {
        self.directory.join(format!(
            "{}.ref",
            digest(format!("{}:{}", self.url(sites), self.config["LastUpdated"]).as_bytes())
        ))
    }
    fn cached(&self, sites: bool) -> Result<PathBuf, String> {
        let (_, hash) = self.cached_reference(sites)?;
        let path = self.directory.join(format!("{hash}.dat"));
        if !path.is_file() {
            return Err("geodata_missing".into());
        }
        Ok(path)
    }
    pub(crate) fn cached_reference(&self, sites: bool) -> Result<(PathBuf, String), String> {
        use std::io::Read;
        let path = self.manifest(sites);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        crate::nofollow::open_link_itself(&mut options);
        let file = options.open(&path).map_err(|_| "geodata_missing")?;
        if !file.metadata().is_ok_and(|m| m.is_file() && m.len() == 64) {
            return Err("geodata_invalid".into());
        }
        let mut hash = String::new();
        file.take(65)
            .read_to_string(&mut hash)
            .map_err(|_| "geodata_invalid")?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("geodata_invalid".into());
        }
        Ok((path, hash))
    }
    pub(crate) async fn prepare(
        &self,
        values: &[&Value],
        library: &Library,
        proxy: Option<&str>,
        fetch: Fetch,
    ) -> Result<(), String> {
        let mut kinds = BTreeSet::new();
        for value in values {
            visit(value, &mut |s| {
                if s.starts_with("geosite:") {
                    kinds.insert(true);
                }
                if s.starts_with("geoip:") {
                    kinds.insert(false);
                }
            });
        }
        if kinds.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.directory).map_err(|_| "geodata_write_failed")?;
        crate::ownership::restrict_directory(&self.directory)
            .map_err(|_| "geodata_write_failed")?;
        for sites in kinds {
            let cached = self.cached(sites).is_ok();
            let fresh = std::fs::metadata(self.manifest(sites))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < Duration::from_secs(7 * 24 * 3600));
            if cached && (fresh || fetch == Fetch::Cached { stale: true }) {
                continue;
            }
            if fetch != Fetch::Download {
                return Err(deferral::DOWNLOAD_REQUIRED.into());
            }
            match self.refresh(sites, library, proxy).await {
                Ok(()) => {}
                // A valid cached file keeps working when a refresh is impossible:
                // offline, a blocked source, or downloads that must go through a
                // tunnel that is not up yet.
                Err(_) if cached => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    /// Only a real download needs a client, so a fresh cache never depends on
    /// the download proxy being available.
    async fn refresh(
        &self,
        sites: bool,
        library: &Library,
        proxy: Option<&str>,
    ) -> Result<(), String> {
        let url = reqwest::Url::parse(self.url(sites)).map_err(|_| "geodata_url_invalid")?;
        if !crate::bounded_download::secure_url(&url) {
            return Err("geodata_url_invalid".into());
        }
        // Redirects follow the same HTTPS rule as the first address.
        let client = crate::settings::network::client(library, proxy)?
            .redirect(crate::bounded_download::redirects(
                crate::bounded_download::secure_url,
            ))
            .build()
            .map_err(|_| "geodata_download_failed")?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| "geodata_download_failed")?
            .error_for_status()
            .map_err(|_| "geodata_download_failed")?;
        let bytes = crate::bounded_download::body(response, LIMIT)
            .await
            .map_err(|error| match error {
                crate::bounded_download::BodyError::TooLarge => "geodata_too_large",
                crate::bounded_download::BodyError::Network(_) => "geodata_download_failed",
            })?;
        let valid = if sites {
            SiteList::decode(bytes.as_slice()).is_ok_and(|l| !l.entry.is_empty())
        } else {
            IpList::decode(bytes.as_slice()).is_ok_and(|l| !l.entry.is_empty())
        };
        if !valid {
            return Err("geodata_invalid".into());
        }
        let hash = digest(&bytes);
        write(&self.directory.join(format!("{hash}.dat")), &bytes)?;
        write(&self.manifest(sites), hash.as_bytes())
    }
    pub(crate) fn rewrite_xray(&self, config: &mut Value) -> Result<(), String> {
        let mut known = BTreeMap::new();
        for rule in config
            .get_mut("routing")
            .and_then(|v| v.get_mut("rules"))
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            for key in ["domain", "ip", "source"] {
                if let Some(value) = rule.get_mut(key) {
                    self.rewrite_reference(value, &mut known)?;
                }
            }
        }
        for server in config
            .get_mut("dns")
            .and_then(|v| v.get_mut("servers"))
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            for key in ["domains", "expectIPs", "unexpectedIPs"] {
                if let Some(value) = server.get_mut(key) {
                    self.rewrite_reference(value, &mut known)?;
                }
            }
        }
        // Host-map keys need a separate representation; never leave an implicit
        // dependency on whichever default geosite.dat happens to be installed.
        if config["dns"]["hosts"].as_object().is_some_and(|hosts| {
            hosts
                .keys()
                .any(|k| k.starts_with("geosite:") || k.starts_with("ext:"))
        }) {
            return Err("geodata_external_file_unsupported".into());
        }
        Ok(())
    }
    /// Xray reports a missing list category only when it starts, so every
    /// referenced category is checked against the cached file first.
    fn rewrite_reference(
        &self,
        config: &mut Value,
        known: &mut BTreeMap<bool, BTreeSet<String>>,
    ) -> Result<(), String> {
        match config {
            Value::String(s) => {
                if s.starts_with("ext:") || s.starts_with("ext-ip:") || s.starts_with("ext-domain:")
                {
                    // A file the person supplied travels as a portable copy and
                    // is resolved when the request is built; anything else names
                    // a file of the host this app cannot carry.
                    if crate::routing::resources::profiles::bound_asset(s) {
                        return Ok(());
                    }
                    return Err("geodata_external_file_unsupported".into());
                }
                for (prefix, sites) in [("geosite:", true), ("geoip:", false)] {
                    if let Some(code) = s.strip_prefix(prefix) {
                        let path = self.cached(sites)?;
                        let category = if sites {
                            code.split('@').next().unwrap_or_default()
                        } else {
                            code.trim_start_matches('!')
                        };
                        let listed = match known.entry(sites) {
                            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(categories(&path, sites)?)
                            }
                        };
                        if !listed.contains(&category.to_ascii_lowercase()) {
                            return Err("geodata_category_missing".into());
                        }
                        *s = format!("ext:{}:{code}", path.file_name().unwrap().to_string_lossy());
                        break;
                    }
                }
            }
            Value::Array(list) => {
                for v in list {
                    self.rewrite_reference(v, known)?
                }
            }
            Value::Object(map) => {
                for v in map.values_mut() {
                    self.rewrite_reference(v, known)?
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn rule_set(&self, reference: &str) -> Result<Value, String> {
        let (kind, code) = reference
            .split_once(':')
            .ok_or("geodata_reference_invalid")?;
        let sites = match kind {
            "geosite" => true,
            "geoip" => false,
            _ => return Err("geodata_reference_invalid".into()),
        };
        let source = self.cached(sites)?;
        let hash = digest(format!("{}:{reference}:v1", source.display()).as_bytes());
        let target = self.directory.join(format!("{hash}.json"));
        if !target.exists() {
            let bytes = std::fs::read(source).map_err(|_| "geodata_missing")?;
            let rules = convert(&bytes, sites, code)?;
            write(
                &target,
                json!({"version":3,"rules":rules}).to_string().as_bytes(),
            )?;
        }
        Ok(json!({"type":"local","tag":format!("geo-{hash}"),"format":"source","path":target}))
    }
}
/// Lower-case category names of a cached list. The index beside the immutable,
/// content-addressed file is written once, so builds do not decode the list.
/// The categories of a geo file a person supplied, if it is one at all. Xray
/// reads a site list and an address list the same way, so either shape counts.
pub(crate) fn file_categories(bytes: &[u8]) -> Option<BTreeSet<String>> {
    let sites = SiteList::decode(bytes)
        .ok()
        .map(|list| list.entry)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .into_iter()
                .map(|e| e.code.to_ascii_lowercase())
                .collect::<BTreeSet<String>>()
        });
    let addresses = || {
        IpList::decode(bytes)
            .ok()
            .map(|list| list.entry)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .into_iter()
                    .map(|e| e.code.to_ascii_lowercase())
                    .collect::<BTreeSet<String>>()
            })
    };
    let codes = sites.or_else(addresses)?;
    codes
        .iter()
        .all(|code| !code.is_empty() && code.len() <= 128 && !code.chars().any(char::is_control))
        .then_some(codes)
}
fn categories(path: &Path, sites: bool) -> Result<BTreeSet<String>, String> {
    let index = path.with_extension("categories.json");
    if let Some(codes) = std::fs::read(&index)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        return Ok(codes);
    }
    let bytes = std::fs::read(path).map_err(|_| "geodata_missing")?;
    let codes: BTreeSet<String> = if sites {
        SiteList::decode(bytes.as_slice())
            .map_err(|_| "geodata_invalid")?
            .entry
            .into_iter()
            .map(|e| e.code.to_ascii_lowercase())
            .collect()
    } else {
        IpList::decode(bytes.as_slice())
            .map_err(|_| "geodata_invalid")?
            .entry
            .into_iter()
            .map(|e| e.code.to_ascii_lowercase())
            .collect()
    };
    // A missing index only costs the next build another decode.
    let _ = write(&index, json!(codes).to_string().as_bytes());
    Ok(codes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())
        .map_err(|_| "geodata_write_failed")?;
    file.write_all(bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "geodata_write_failed")?;
    file.persist(path).map_err(|_| "geodata_write_failed")?;
    Ok(())
}
fn visit(value: &Value, f: &mut impl FnMut(&str)) {
    match value {
        Value::String(s) => f(s),
        Value::Array(a) => {
            for v in a {
                visit(v, f)
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                visit(v, f)
            }
        }
        _ => {}
    }
}

fn xray_references(config: &Value) -> Value {
    let mut values = Vec::new();
    for rule in config["routing"]["rules"].as_array().into_iter().flatten() {
        for key in ["domain", "ip", "source"] {
            if let Some(v) = rule.get(key) {
                values.push(v.clone());
            }
        }
    }
    for server in config["dns"]["servers"].as_array().into_iter().flatten() {
        for key in ["domains", "expectIPs", "unexpectedIPs"] {
            if let Some(v) = server.get(key) {
                values.push(v.clone());
            }
        }
    }
    json!(values)
}

pub(crate) async fn prepare(
    profile: &Profile,
    library: &Library,
    directory: &Path,
    proxy: Option<&str>,
    fetch: Fetch,
) -> Result<(), String> {
    // Reject unsupported policy graphs before fetching or materializing assets.
    crate::vpn_policy::validate_context(library, profile)?;
    if !matches!(
        profile.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) && !enabled(profile, library)
    {
        catalog::prepare(library.routing.active()?, directory, library, proxy, fetch).await?;
    }
    let needed = crate::vless::relevant(library, profile)?;
    for member in library.profiles.iter().filter(|p| {
        needed.contains(&p.id) && p.id != profile.id && p.kind == ProfileKind::XrayConfig
    }) {
        Assets::new(directory, provider(member, library))
            .with_library(library)
            .prepare(&[&xray_references(&member.config)], library, proxy, fetch)
            .await?;
    }
    let routing = provider(profile, library);
    let assets = Assets::new(directory, routing).with_library(library);
    let profile_refs = if profile.kind == ProfileKind::XrayConfig {
        xray_references(&profile.config)
    } else {
        Value::Null
    };
    let mut values = vec![&profile_refs];
    if enabled(profile, library) {
        if let Some(r) = routing {
            values.push(&r.config)
        }
    }
    assets.prepare(&values, library, proxy, fetch).await
}

mod format;
#[cfg(test)]
mod tests;
pub(crate) use format::*;
