//! Disposable HTTP checks of a complete Xray client policy.
use crate::{
    proto,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const LIMIT: u64 = crate::routing::MAX_GEODATA_ASSET_BYTES as u64;

// This is a structural check only: no sockets, files, core or geodata downloads.
pub(crate) fn supported(library: &Library, profile: &Profile) -> bool {
    profile.kind == ProfileKind::XrayConfig
        && profile.vpn_policy.is_none()
        && crate::group_chains::policy(library, profile)
            .ids()
            .next()
            .is_none()
        && client_shape(&profile.config)
}

pub(crate) fn client_shape(config: &Value) -> bool {
    let Some(object) = config.as_object() else {
        return false;
    };
    // Go's JSON decoder also recognizes case variants. Requiring the canonical
    // client keys prevents a differently cased Env/API field bypassing this
    // short-lived test's structural contract. Saved JSON is never rewritten.
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "log"
                | "routing"
                | "dns"
                | "inbounds"
                | "outbounds"
                | "policy"
                | "stats"
                | "fakeDns"
                | "version"
                | "remarks"
                | "meta"
        )
    }) {
        return false;
    }
    // These features may start background traffic or additional listeners, or
    // select routes using state that a short isolated check cannot reproduce.
    for key in [
        "reverse",
        "api",
        "metrics",
        "observatory",
        "burstObservatory",
    ] {
        if object.get(key).is_some_and(|v| !v.is_null()) {
            return false;
        }
    }
    if config["routing"].as_object().is_some_and(|r| {
        r.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("balancers")
                && (k != "balancers" || v.as_array().is_none_or(|a| !a.is_empty()))
        })
    }) {
        return false;
    }
    let Some(outbounds) = config["outbounds"].as_array().filter(|a| !a.is_empty()) else {
        return false;
    };
    if outbounds.iter().any(|outbound| {
        !matches!(
            outbound["protocol"].as_str(),
            Some(
                "vless"
                    | "vmess"
                    | "trojan"
                    | "shadowsocks"
                    | "socks"
                    | "http"
                    | "freedom"
                    | "blackhole"
                    | "dns"
                    | "loopback"
            )
        )
    }) {
        return false;
    }
    let inbounds = match object.get("inbounds") {
        None => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        _ => return false,
    };
    if inbounds
        .iter()
        .any(|i| !matches!(i["protocol"].as_str(), Some("socks" | "http")))
    {
        return false;
    }
    if inbounds.iter().any(|i| {
        i.as_object().is_some_and(|o| {
            o.keys().any(|k| {
                ["protocol", "tag", "sniffing"]
                    .iter()
                    .any(|known| k.eq_ignore_ascii_case(known) && k != known)
            })
        })
    }) {
        return false;
    }
    let source = inbounds
        .iter()
        .find(|i| i["protocol"] == "socks")
        .or(inbounds.first());
    let tag = source
        .and_then(|i| i.get("tag"))
        .cloned()
        .unwrap_or(json!("thronium-in"));
    for rule in config["routing"]["rules"].as_array().into_iter().flatten() {
        if rule.as_object().is_some_and(|o| {
            o.keys()
                .any(|k| k.eq_ignore_ascii_case("inboundTag") && k != "inboundTag")
        }) {
            return false;
        }
        if let Some(tags) = rule.get("inboundTag") {
            match tags {
                Value::Array(tags) if tags.iter().all(|v| v == &tag) => {}
                value if value == &tag => {}
                _ => return false,
            }
        }
    }
    true
}

pub(crate) fn diagnostic_profile(profile: &Profile) -> Profile {
    let mut profile = profile.clone();
    // The saved client log files must not be shared with a disposable core.
    profile.config["log"] = json!({"loglevel":"warning"});
    if let Some(object) = profile.config.as_object_mut() {
        object.remove("remarks");
        object.remove("meta");
    }
    profile
}

#[derive(Clone, Default)]
pub(crate) struct Assets {
    files: Vec<(PathBuf, String)>,
    pub(crate) context: Option<Context>,
}

#[derive(Clone, Debug)]
pub(crate) struct Context {
    references: Vec<(PathBuf, String)>,
    selection: Value,
}
fn selection(library: &Library, profile: &Profile) -> Value {
    json!([
        crate::settings::value(library, "xray_geosite_url"),
        crate::settings::value(library, "xray_geoip_url"),
        crate::geodata::provider(profile, library).map(|p| &p.config)
    ])
}
impl Context {
    pub(crate) fn identity(&self) -> Value {
        json!([
            self.selection,
            self.references
                .iter()
                .map(|(path, hash)| json!([path.file_name().and_then(|s| s.to_str()), hash]))
                .collect::<Vec<_>>()
        ])
    }
    // Evaluated once on completion, not on every snapshot of historical results.
    pub(crate) fn matches(&self, library: &Library, profile: &Profile) -> bool {
        use std::io::Read;
        self.selection == selection(library, profile)
            && self.references.iter().all(|(path, expected)| {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                }
                #[cfg(windows)]
                crate::nofollow::open_link_itself(&mut options);
                let Ok(file) = options.open(path) else {
                    return false;
                };
                if !file.metadata().is_ok_and(|m| m.is_file() && m.len() == 64) {
                    return false;
                }
                let mut actual = String::new();
                file.take(65).read_to_string(&mut actual).is_ok() && actual == *expected
            })
    }
}

fn referenced_kinds(config: &Value) -> BTreeSet<bool> {
    let mut kinds = BTreeSet::new();
    fn kinds_in(value: &Value, kinds: &mut BTreeSet<bool>) {
        match value {
            Value::String(s) if s.starts_with("geosite:") => {
                kinds.insert(true);
            }
            Value::String(s) if s.starts_with("geoip:") => {
                kinds.insert(false);
            }
            Value::Array(a) => {
                for v in a {
                    kinds_in(v, kinds);
                }
            }
            Value::Object(o) => {
                for v in o.values() {
                    kinds_in(v, kinds);
                }
            }
            _ => {}
        }
    }
    for rule in config["routing"]["rules"].as_array().into_iter().flatten() {
        for key in ["domain", "ip", "source"] {
            kinds_in(&rule[key], &mut kinds);
        }
    }
    for server in config["dns"]["servers"].as_array().into_iter().flatten() {
        for key in ["domains", "expectIPs", "unexpectedIPs"] {
            kinds_in(&server[key], &mut kinds);
        }
    }
    kinds
}

// Country observations depend on the selected data version. This identity omits
// the local directory so a moved portable library keeps matching its own cache.
// Reads at most two bounded manifests; no config compilation, sockets or downloads.
pub(crate) fn asset_identity(
    directory: &Path,
    library: &Library,
    profile: &Profile,
) -> Result<Value, String> {
    let cache = crate::geodata::Assets::new(directory, crate::geodata::provider(profile, library))
        .with_library(library);
    let references = referenced_kinds(&profile.config)
        .into_iter()
        .map(|sites| {
            let (path, hash) = cache.cached_reference(sites)?;
            Ok(json!([
                path.file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("geodata_invalid")?,
                hash
            ]))
        })
        .collect::<Result<Vec<Value>, String>>()?;
    Ok(json!([selection(library, profile), references]))
}

impl Assets {
    // Rewrite only against already cached immutable geodata. Missing resources
    // are reported to the caller; an HTTP probe does not download new datasets.
    pub(crate) fn prepare(
        request: &mut proto::TestReq,
        directory: &Path,
        library: &Library,
        profile: &Profile,
    ) -> Result<Self, String> {
        let mut config: Value = serde_json::from_str(
            request
                .xray_config
                .as_deref()
                .ok_or("probe_configuration_failed")?,
        )
        .map_err(|_| "probe_configuration_failed")?;
        let cache =
            crate::geodata::Assets::new(directory, crate::geodata::provider(profile, library))
                .with_library(library);
        let references = referenced_kinds(&config)
            .into_iter()
            .map(|sites| cache.cached_reference(sites))
            .collect::<Result<Vec<_>, _>>()?;
        cache.rewrite_xray(&mut config)?;
        let mut files = BTreeSet::new();
        fn visit(value: &Value, files: &mut BTreeSet<String>) -> Result<(), String> {
            match value {
                Value::String(s) if s.starts_with("ext:") => {
                    let (file, _) = s[4..]
                        .split_once(':')
                        .ok_or("geodata_external_file_unsupported")?;
                    let hash = file
                        .strip_suffix(".dat")
                        .ok_or("geodata_external_file_unsupported")?;
                    if hash.len() != 64
                        || !hash
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        return Err("geodata_external_file_unsupported".into());
                    }
                    files.insert(file.to_owned());
                }
                Value::Array(values) => {
                    for value in values {
                        visit(value, files)?;
                    }
                }
                Value::Object(values) => {
                    for value in values.values() {
                        visit(value, files)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        for rule in config["routing"]["rules"].as_array().into_iter().flatten() {
            for key in ["domain", "ip", "source"] {
                visit(&rule[key], &mut files)?;
            }
        }
        for server in config["dns"]["servers"].as_array().into_iter().flatten() {
            for key in ["domains", "expectIPs", "unexpectedIPs"] {
                visit(&server[key], &mut files)?;
            }
        }
        if files.len() > 2 {
            return Err("geodata_invalid".into());
        }
        let context = Context {
            references,
            selection: selection(library, profile),
        };
        if !context.matches(library, profile)
            || context
                .references
                .iter()
                .any(|(_, hash)| !files.contains(&format!("{hash}.dat")))
        {
            return Err("probe_stale".into());
        }
        request.xray_config = Some(config.to_string());
        Ok(Self {
            files: files
                .into_iter()
                .map(|file| (directory.join("xray-assets").join(&file), file))
                .collect(),
            context: Some(context),
        })
    }

    pub(crate) async fn stage(
        self,
        directory: tempfile::TempDir,
    ) -> Result<tempfile::TempDir, String> {
        if self.files.is_empty() {
            return Ok(directory);
        }
        struct Cancel(Arc<AtomicBool>);
        impl Drop for Cancel {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let canceled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = Cancel(canceled.clone());
        // The blocking task owns the temporary directory until every file is
        // closed. Dropping a canceled future cannot leave a detached copy writing
        // into the next operation's directory or start an unowned core.
        tokio::task::spawn_blocking(move || {
            use sha2::{Digest, Sha256};
            use std::io::{Read, Write};
            let target = directory.path().join("xray-assets");
            std::fs::create_dir(&target).map_err(|_| "geodata_write_failed")?;
            for (source, name) in self.files {
                if canceled.load(Ordering::Acquire) {
                    return Err("probe_cancelled".into());
                }
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                }
                #[cfg(windows)]
                crate::nofollow::open_link_itself(&mut options);
                let mut source = options.open(source).map_err(|_| "geodata_missing")?;
                let info = source.metadata().map_err(|_| "geodata_invalid")?;
                if !info.is_file() || info.len() > LIMIT {
                    return Err("geodata_invalid".into());
                }
                let path = target.join(&name);
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|_| "geodata_write_failed")?;
                let mut digest = Sha256::new();
                let mut size = 0;
                let mut buffer = [0u8; 65536];
                loop {
                    if canceled.load(Ordering::Acquire) {
                        return Err("probe_cancelled".into());
                    }
                    let n = source.read(&mut buffer).map_err(|_| "geodata_invalid")?;
                    if n == 0 {
                        break;
                    }
                    size += n as u64;
                    if size > LIMIT {
                        return Err("geodata_too_large".into());
                    }
                    digest.update(&buffer[..n]);
                    output
                        .write_all(&buffer[..n])
                        .map_err(|_| "geodata_write_failed")?;
                }
                if format!("{:x}.dat", digest.finalize()) != name {
                    return Err("geodata_invalid".into());
                }
                drop(output);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444))
                        .map_err(|_| "geodata_write_failed")?;
                }
            }
            if canceled.load(Ordering::Acquire) {
                return Err("probe_cancelled".into());
            }
            Ok(directory)
        })
        .await
        .map_err(|_| "geodata_write_failed".to_owned())?
    }
}

#[cfg(test)]
mod tests;
