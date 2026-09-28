//! Portable copies of explicitly selected policy files. Library clones share
//! immutable bytes; runtime paths are content-addressed and never the source path.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PACK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FILES: usize = 64;
const PREFIX: &str = "thronium-resource:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Hosts,
    RuleSetSource,
    RuleSetBinary,
    /// Certificates and keys referenced by TLS/SSH fields of a profile.
    Pem,
    /// Other text inputs of a profile (known hosts, ECH/OpenVPN config files).
    Text,
    /// A list of sites or addresses an Xray configuration names with `ext:`.
    Geodata,
}
impl Kind {
    fn extension(self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::RuleSetSource => "json",
            Self::RuleSetBinary => "srs",
            Self::Pem => "pem",
            Self::Text => "txt",
            Self::Geodata => "dat",
        }
    }
    /// Kinds first understood by Library version 7 readers.
    pub(crate) fn profile_only(self) -> bool {
        matches!(self, Self::Pem | Self::Text | Self::Geodata)
    }
    /// Kinds first understood by Library version 8 readers.
    pub(crate) fn asset(self) -> bool {
        matches!(self, Self::Geodata)
    }
}
struct Data {
    kind: Kind,
    bytes: Vec<u8>,
    encoded: String,
}
#[derive(Clone)]
pub struct Resource(Arc<Data>);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    kind: Kind,
    data: String,
}
impl Resource {
    pub fn parse(kind: Kind, bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err("routing_resource_too_large".into());
        }
        match kind {
            Kind::Hosts => {
                let text = std::str::from_utf8(&bytes).map_err(|_| "routing_resource_invalid")?;
                for line in text.lines() {
                    let mut fields = line
                        .split('#')
                        .next()
                        .unwrap_or_default()
                        .split_whitespace();
                    let Some(ip) = fields.next() else { continue };
                    ip.parse::<std::net::IpAddr>()
                        .map_err(|_| "routing_resource_invalid")?;
                    let names: Vec<_> = fields.collect();
                    if names.is_empty()
                        || names
                            .iter()
                            .any(|n| n.len() > 253 || n.chars().any(char::is_control))
                    {
                        return Err("routing_resource_invalid".into());
                    }
                }
            }
            Kind::RuleSetSource => {
                let text = std::str::from_utf8(&bytes).map_err(|_| "routing_resource_invalid")?;
                let value =
                    crate::strict_json::parse(text).map_err(|_| "routing_resource_invalid")?;
                if !matches!(value["version"].as_u64(), Some(1..=5))
                    || value
                        .as_object()
                        .is_none_or(|m| m.keys().any(|k| k != "version" && k != "rules"))
                    || value["rules"]
                        .as_array()
                        .is_none_or(|r| r.len() > 100_000 || r.iter().any(|v| !v.is_object()))
                {
                    return Err("routing_resource_invalid".into());
                }
            }
            Kind::Pem => {
                let text = std::str::from_utf8(&bytes).map_err(|_| "routing_resource_invalid")?;
                if !text.contains("-----BEGIN ") {
                    return Err("routing_resource_invalid".into());
                }
            }
            Kind::Text => {
                std::str::from_utf8(&bytes).map_err(|_| "routing_resource_invalid")?;
            }
            Kind::Geodata => {
                // The same shape Xray reads: a list of named categories. The
                // rules inside stay the business of the pinned core.
                if crate::geodata::file_categories(&bytes).is_none() {
                    return Err("routing_resource_invalid".into());
                }
            }
            Kind::RuleSetBinary => {
                // This is a bounded envelope check, not a second SRS compiler.
                // The actual rule semantics are validated by the pinned Core.
                if bytes.get(..3) != Some(b"SRS")
                    || !bytes.get(3).is_some_and(|v| (1..=5).contains(v))
                {
                    return Err("routing_resource_invalid".into());
                }
                let mut decoded = Vec::new();
                flate2::read::ZlibDecoder::new(&bytes[4..])
                    .take((MAX_PACK_BYTES + 1) as u64)
                    .read_to_end(&mut decoded)
                    .map_err(|_| "routing_resource_invalid")?;
                if decoded.is_empty() || decoded.len() > MAX_PACK_BYTES {
                    return Err("routing_resource_too_large".into());
                }
            }
        }
        Ok(Self(Arc::new(Data {
            kind,
            encoded: STANDARD.encode(&bytes),
            bytes,
        })))
    }
    pub fn kind(&self) -> Kind {
        self.0.kind
    }
    pub fn len(&self) -> usize {
        self.0.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.bytes.is_empty()
    }
    pub fn reference(&self) -> String {
        format!("{PREFIX}{}", self.id())
    }
    fn id(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(self.0.kind.extension());
        hash.update([0]);
        hash.update(&self.0.bytes);
        format!("{:x}", hash.finalize())
    }
}
impl Serialize for Resource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("Resource", 2)?;
        value.serialize_field("kind", &self.0.kind)?;
        value.serialize_field("data", &self.0.encoded)?;
        value.end()
    }
}
impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Wire::deserialize(deserializer)?;
        if value.data.len() > MAX_FILE_BYTES.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("routing_resource_too_large"));
        }
        let bytes = STANDARD
            .decode(value.data)
            .map_err(serde::de::Error::custom)?;
        Self::parse(value.kind, bytes).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Pack(BTreeMap<String, Resource>);
impl<'de> Deserialize<'de> for Pack {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = BTreeMap::<String, Resource>::deserialize(deserializer)?;
        let mut result = Self::default();
        for (id, value) in values {
            if id != value.id() {
                return Err(serde::de::Error::custom("routing_resource_invalid"));
            }
            result.insert(value).map_err(serde::de::Error::custom)?;
        }
        Ok(result)
    }
}
impl Pack {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn insert(&mut self, value: Resource) -> Result<String, String> {
        let id = value.id();
        if !self.0.contains_key(&id)
            && (self.0.len() >= MAX_FILES
                || self.0.values().map(Resource::len).sum::<usize>() + value.len() > MAX_PACK_BYTES)
        {
            return Err("routing_resource_too_large".into());
        }
        self.0.insert(id.clone(), value);
        Ok(format!("{PREFIX}{id}"))
    }
    pub(crate) fn kinds(&self) -> impl Iterator<Item = Kind> + '_ {
        self.0.values().map(Resource::kind)
    }
    pub(crate) fn merge(&mut self, other: &Self) -> Result<(), String> {
        for value in other.0.values() {
            self.insert(value.clone())?;
        }
        Ok(())
    }
    fn get(&self, reference: &str, kind: Kind) -> Result<&Resource, String> {
        reference
            .strip_prefix(PREFIX)
            .and_then(|id| self.0.get(id))
            .filter(|r| r.kind() == kind)
            .ok_or_else(|| "routing_resource_missing".into())
    }
}
pub(crate) fn reference(value: &str) -> bool {
    value
        .strip_prefix(PREFIX)
        .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub(crate) fn visit_document(
    value: &mut Value,
    dns: bool,
    mut visit: impl FnMut(&mut Value, Kind) -> Result<(), String>,
) -> Result<(), String> {
    if dns {
        for server in value
            .get_mut("servers")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if server["type"] == "hosts" {
                if let Some(path) = server.get_mut("path") {
                    if let Some(paths) = path.as_array_mut() {
                        for path in paths {
                            visit(path, Kind::Hosts)?;
                        }
                    } else {
                        visit(path, Kind::Hosts)?;
                    }
                }
            }
        }
    } else {
        for set in value
            .get_mut("rule_set")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if set["type"] != "local" {
                continue;
            }
            let kind = match set["format"].as_str() {
                Some("source") => Kind::RuleSetSource,
                Some("binary") => Kind::RuleSetBinary,
                None | Some("") if set["path"].as_str().is_some_and(|s| s.ends_with(".srs")) => {
                    Kind::RuleSetBinary
                }
                None | Some("") if set["path"].as_str().is_some_and(|s| s.ends_with(".json")) => {
                    Kind::RuleSetSource
                }
                _ if set["path"].as_str().is_some_and(|s| s.starts_with(PREFIX)) => {
                    return Err("routing_resource_invalid".into())
                }
                _ => continue,
            };
            if let Some(path) = set.get_mut("path") {
                visit(path, kind)?;
            }
            if set["path"].as_str().is_some_and(reference) {
                set["format"] = serde_json::json!(if kind == Kind::RuleSetSource {
                    "source"
                } else {
                    "binary"
                });
            }
        }
    }
    Ok(())
}
fn paths(
    profile: &mut super::RoutingProfile,
    mut visit: impl FnMut(&mut Value, Kind) -> Result<(), String>,
) -> Result<(), String> {
    visit_document(&mut profile.dns, true, &mut visit)?;
    visit_document(&mut profile.route, false, visit)
}
pub(crate) fn validate(library: &crate::store::Library) -> Result<(), String> {
    let check = |path: &mut Value, kind| {
        if let Some(reference) = path.as_str().filter(|s| s.starts_with(PREFIX)) {
            library.routing_resources.get(reference, kind)?;
        }
        Ok(())
    };
    for profile in &library.routing.profiles {
        paths(&mut profile.clone(), check)?;
    }
    for profile in library.profiles.iter().filter(|p| profiles::carries(p)) {
        profiles::visit_profile(&mut profile.config.clone(), check)?;
    }
    Ok(())
}
pub(crate) fn resolve(
    profile: &mut super::RoutingProfile,
    pack: &Pack,
    directory: &Path,
) -> Result<(), String> {
    paths(profile, |path, kind| {
        let Some(reference) = path.as_str().filter(|s| s.starts_with(PREFIX)) else {
            return Ok(());
        };
        let value = pack.get(reference, kind)?;
        let target = materialize(directory, value)?;
        *path = serde_json::json!(target);
        Ok(())
    })
}
pub(crate) fn prune(library: &mut crate::store::Library) {
    let mut needed = std::collections::BTreeSet::new();
    let mut collect = |path: &mut Value, _| {
        if let Some(id) = path.as_str().and_then(|s| s.strip_prefix(PREFIX)) {
            needed.insert(id.to_owned());
        }
        Ok(())
    };
    for profile in &library.routing.profiles {
        let _ = paths(&mut profile.clone(), &mut collect);
    }
    for profile in library.profiles.iter().filter(|p| profiles::carries(p)) {
        let _ = profiles::visit_profile(&mut profile.config.clone(), &mut collect);
    }
    library
        .routing_resources
        .0
        .retain(|id, _| needed.contains(id));
}
fn cached(path: &Path, expected: &[u8]) -> Result<Option<bool>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    crate::nofollow::open_link_itself(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("routing_resource_write_failed".into()),
    };
    let meta = file
        .metadata()
        .map_err(|_| "routing_resource_write_failed")?;
    if !meta.is_file() || meta.len() != expected.len() as u64 {
        return Ok(Some(false));
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "routing_resource_write_failed")?;
    Ok(Some(bytes == expected))
}
fn materialize(root: &Path, value: &Resource) -> Result<PathBuf, String> {
    materialize_in(&root.join("routing-resources"), value)
}
/// Xray reads a list named by `ext:` from its asset directory, so a copy the
/// person supplied is placed there under its own content name.
pub(crate) fn materialize_in(root: &Path, value: &Resource) -> Result<PathBuf, String> {
    let root = root.to_path_buf();
    std::fs::create_dir_all(&root).map_err(|_| "routing_resource_write_failed")?;
    let target = root.join(format!("{}.{}", value.id(), value.kind().extension()));
    // Never replace an inode an active session might be reading. A modified
    // cached file is an error, rather than silently changing a running policy.
    match cached(&target, &value.0.bytes)? {
        Some(true) => return Ok(target),
        Some(false) => return Err("routing_resource_write_failed".into()),
        None => {}
    }
    let mut file =
        tempfile::NamedTempFile::new_in(&root).map_err(|_| "routing_resource_write_failed")?;
    file.write_all(&value.0.bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "routing_resource_write_failed")?;
    match file.persist_noclobber(&target) {
        Ok(_) => Ok(target),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if cached(&target, &value.0.bytes)? == Some(true) {
                Ok(target)
            } else {
                Err("routing_resource_write_failed".into())
            }
        }
        Err(_) => Err("routing_resource_write_failed".into()),
    }
}

pub fn read(path: &Path, kind: Kind) -> Result<Resource, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "routing_resource_read_failed")?;
    if !file
        .metadata()
        .map_err(|_| "routing_resource_read_failed")?
        .is_file()
    {
        return Err("routing_resource_read_failed".into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "routing_resource_read_failed")?;
    Resource::parse(kind, bytes)
}

pub mod profiles;
#[cfg(test)]
mod tests;
