//! User-selected category databases. Source references stay portable; generated
//! rule sets are immutable so updating a source cannot alter a running session.
use super::{convert, digest, write, IpList, SiteList};
use crate::{
    routing::{RoutingProfile, MAX_CATEGORY_DATABASE_BYTES},
    store::Library,
    Engine,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub mod downloads;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Category {
    code: String,
    count: usize,
    attributes: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    kind: String,
    url: String,
    name: String,
    hash: String,
    bytes: usize,
    updated_at: u64,
    categories: Vec<Category>,
}
fn sites(kind: &str) -> Result<bool, String> {
    match kind {
        "geosite" => Ok(true),
        "geoip" => Ok(false),
        _ => Err("geodata_invalid".into()),
    }
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}
fn directory(root: &Path) -> PathBuf {
    root.join("routing-geodata")
}
fn manifest(root: &Path, kind: &str, url: &str) -> PathBuf {
    directory(root).join(format!(
        "{}.source.json",
        digest(format!("{kind}:{url}").as_bytes())
    ))
}
fn load(root: &Path, kind: &str, url: &str) -> Result<Source, String> {
    sites(kind)?;
    let source: Source = serde_json::from_slice(
        &std::fs::read(manifest(root, kind, url)).map_err(|_| "geodata_missing")?,
    )
    .map_err(|_| "geodata_invalid")?;
    if source.kind != kind
        || source.url != url
        || !hash_valid(&source.hash)
        || !directory(root)
            .join(format!("{}.dat", source.hash))
            .is_file()
    {
        return Err("geodata_missing".into());
    }
    Ok(source)
}
fn source_bytes(root: &Path, source: &Source) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(directory(root).join(format!("{}.dat", source.hash)))
        .map_err(|_| "geodata_missing")?;
    if bytes.len() > MAX_CATEGORY_DATABASE_BYTES || digest(&bytes) != source.hash {
        return Err("geodata_invalid".into());
    }
    Ok(bytes)
}
fn categories(bytes: &[u8], kind: &str) -> Result<Vec<Category>, String> {
    if bytes.is_empty() {
        return Err("geodata_invalid".into());
    }
    if bytes.len() > MAX_CATEGORY_DATABASE_BYTES {
        return Err("routing_geodata_too_large".into());
    }
    let mut result = vec![];
    if sites(kind)? {
        for entry in SiteList::decode(bytes)
            .map_err(|_| "geodata_invalid")?
            .entry
        {
            if entry
                .domain
                .iter()
                .any(|d| !(0..4).contains(&d.kind) || d.value.is_empty())
            {
                return Err("geodata_invalid".into());
            }
            let attributes: BTreeSet<_> = entry
                .domain
                .iter()
                .flat_map(|d| d.attribute.iter().map(|a| a.key.clone()))
                .collect();
            result.push(Category {
                code: entry.code.to_lowercase(),
                count: entry.domain.len(),
                attributes: attributes.into_iter().collect(),
            });
        }
    } else {
        for entry in IpList::decode(bytes).map_err(|_| "geodata_invalid")?.entry {
            if entry
                .cidr
                .iter()
                .any(|c| !matches!((c.ip.len(), c.prefix), (4, 0..=32) | (16, 0..=128)))
            {
                return Err("geodata_invalid".into());
            }
            result.push(Category {
                code: entry.code.to_lowercase(),
                count: entry.cidr.len(),
                attributes: vec![],
            });
        }
    }
    result.sort_by(|a, b| a.code.cmp(&b.code));
    if result.is_empty()
        || result.iter().any(|c| c.code.is_empty())
        || result.windows(2).any(|c| c[0].code == c[1].code)
    {
        return Err("geodata_invalid".into());
    }
    Ok(result)
}
pub(crate) fn valid_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|_| "geodata_url_invalid")?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err("geodata_url_invalid".into());
    }
    Ok(url)
}
async fn download(raw: &str, library: &Library, proxy: Option<&str>) -> Result<Vec<u8>, String> {
    downloads::Fetch::prepare(
        raw,
        library,
        proxy,
        (MAX_CATEGORY_DATABASE_BYTES, "routing_geodata_too_large"),
    )?
    .execute()
    .await
}

fn sets(profile: &RoutingProfile) -> impl Iterator<Item = &Value> {
    profile.route["rule_set"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["type"] == "geodata")
}
fn descriptor(value: &Value) -> Result<(&str, &str, &str), String> {
    let kind = value["kind"].as_str().ok_or("geodata_invalid")?;
    sites(kind)?;
    let url = value["url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("geodata_url_invalid")?;
    let category = value["category"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("geodata_category_missing")?;
    let valid_tag = value["tag"].as_str().is_some_and(|s| !s.is_empty())
        || value["tag"].as_array().is_some_and(|a| {
            !a.is_empty() && a.iter().all(|t| t.as_str().is_some_and(|s| !s.is_empty()))
        });
    if !valid_tag {
        return Err("resource_tag_required".into());
    }
    // Reject unrecognised parameters rather than silently discard routing options.
    if value.as_object().is_none_or(|m| {
        m.keys()
            .any(|k| !["type", "tag", "kind", "url", "category"].contains(&k.as_str()))
    }) {
        return Err("geodata_invalid".into());
    }
    Ok((kind, url, category))
}
fn install(
    root: &Path,
    library: &Library,
    kind: &str,
    url: &str,
    name: &str,
    bytes: &[u8],
) -> Result<Source, String> {
    let categories = categories(bytes, kind)?;
    // A failed refresh must leave every saved profile usable with its previous database.
    let mut used = BTreeSet::new();
    for set in library.routing.profiles.iter().flat_map(sets) {
        let (k, u, c) = descriptor(set)?;
        if k == kind && u == url {
            used.insert(c);
        }
    }
    for category in used {
        convert(bytes, sites(kind)?, category)?;
    }
    let source = Source {
        kind: kind.into(),
        url: url.into(),
        name: name.chars().take(512).collect(),
        hash: digest(bytes),
        bytes: bytes.len(),
        updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        categories,
    };
    let dir = directory(root);
    std::fs::create_dir_all(&dir).map_err(|_| "geodata_write_failed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "geodata_write_failed")?;
    }
    write(&dir.join(format!("{}.dat", source.hash)), bytes)?;
    write(
        &manifest(root, kind, url),
        &serde_json::to_vec(&source).map_err(|_| "geodata_invalid")?,
    )?;
    Ok(source)
}
pub(crate) async fn prepare(
    profile: &RoutingProfile,
    root: &Path,
    library: &Library,
    proxy: Option<&str>,
    fetch: super::Fetch,
) -> Result<(), String> {
    let mut sources = BTreeMap::new();
    for value in sets(profile) {
        let (kind, url, _) = descriptor(value)?;
        sources.insert((kind, url), ());
    }
    for ((kind, url), _) in sources {
        if load(root, kind, url).is_err() {
            if url.starts_with("local:") {
                return Err("geodata_local_missing".into());
            }
            if fetch != super::Fetch::Download {
                return Err(super::deferral::DOWNLOAD_REQUIRED.into());
            }
            let bytes = download(url, library, proxy).await?;
            install(root, library, kind, url, url, &bytes)?;
        }
    }
    Ok(())
}
pub(crate) fn resolve(profile: &RoutingProfile, root: &Path) -> Result<RoutingProfile, String> {
    let mut result = profile.clone();
    for value in result
        .route
        .get_mut("rule_set")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if value["type"] != "geodata" {
            continue;
        }
        let (kind, url, category) = descriptor(value)?;
        let source = load(root, kind, url)?;
        let hash = digest(format!("{}:{kind}:{category}:v1", source.hash).as_bytes());
        let path = directory(root).join(format!("{hash}.json"));
        if !path.is_file() {
            let rules = convert(&source_bytes(root, &source)?, sites(kind)?, category)?;
            write(
                &path,
                &serde_json::to_vec(&json!({"version":3,"rules":rules}))
                    .map_err(|_| "geodata_invalid")?,
            )?;
        }
        *value = json!({"type":"local","tag":value["tag"],"format":"source","path":path});
    }
    Ok(result)
}

impl Engine {
    pub fn geodata_sources(&self) -> Result<Value, String> {
        let mut sources = vec![];
        if let Ok(entries) = std::fs::read_dir(directory(&self.data_dir)) {
            for entry in entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".source.json"))
            {
                if let Ok(source) = std::fs::read(entry.path())
                    .map_err(|_| ())
                    .and_then(|b| serde_json::from_slice::<Source>(&b).map_err(|_| ()))
                {
                    if load(&self.data_dir, &source.kind, &source.url).is_ok() {
                        sources.push(json!({"kind":source.kind,"url":source.url,"name":source.name,"hash":source.hash,
                            "bytes":source.bytes,"updatedAt":source.updated_at,"count":source.categories.len()}));
                    }
                }
            }
        }
        Ok(json!(sources))
    }
    pub async fn load_geodata(&mut self, payload: Value) -> Result<Value, String> {
        match self.prepare_geodata_load(payload)? {
            downloads::Preparation::Ready(value) => Ok(value),
            downloads::Preparation::Download(download) => {
                let (_owner, cancelled) = tokio::sync::watch::channel(false);
                let prepared = download.execute(cancelled).await?;
                self.commit_routing_download(prepared)
            }
        }
    }
    pub fn geodata_category(&self, payload: Value) -> Result<Value, String> {
        let kind = payload["kind"].as_str().ok_or("geodata_invalid")?;
        let url = payload["url"].as_str().ok_or("geodata_url_invalid")?;
        let category = payload["category"]
            .as_str()
            .ok_or("geodata_category_missing")?;
        let source = load(&self.data_dir, kind, url)?;
        Ok(json!({"rules":convert(&source_bytes(&self.data_dir,&source)?,sites(kind)?,category)?}))
    }
    pub async fn fetch_routing_source(&mut self, url: &str) -> Result<Value, String> {
        let (_owner, cancelled) = tokio::sync::watch::channel(false);
        let prepared = self.prepare_routing_source(url)?.execute(cancelled).await?;
        self.commit_routing_download(prepared)
    }
    /// A new, unsaved routing profile from Throne route text; updates of its
    /// source later use the same converter.
    pub fn import_throne_route(
        &self,
        text: &str,
        name: &str,
        url: Option<&str>,
    ) -> Result<RoutingProfile, String> {
        if text.len() > crate::routing::MAX_PROFILE_BYTES {
            return Err("routing_import_too_large".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        crate::legacy_backup::routes::remote::import(text, name, url, now)
    }
    pub fn export_routing_profile(&self, id: &str) -> Result<Value, String> {
        let mut profile = self
            .store
            .library
            .routing
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("routing_profile_missing")?
            .clone();
        // A local upload has no portable URL. Export its selected categories as
        // editable inline copies; HTTPS databases keep their source references.
        for set in profile
            .route
            .get_mut("rule_set")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if set["type"] == "geodata"
                && set["url"].as_str().is_some_and(|u| u.starts_with("local:"))
            {
                let rules = self.geodata_category(set.clone())?["rules"].clone();
                *set = json!({"type":"inline","tag":set["tag"],"rules":rules});
            }
        }
        Ok(json!({"format":"thronium-routing-profile","version":1,"profile":profile}))
    }
}

#[cfg(test)]
mod tests;
