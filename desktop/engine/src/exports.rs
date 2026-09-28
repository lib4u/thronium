//! Explicit profile exports. Snapshots never contain export bodies or credentials.
use crate::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::{io::Write, path::Path};

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
/// Largest ZIP archive (QR images, WireGuard files) the window asks the host to save.
pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
/// Largest image the host decodes when importing a QR code.
pub const MAX_QR_IMAGE_BYTES: usize = 20 * 1024 * 1024;
/// Largest image, in pixels, the host decodes when importing a QR code.
pub const MAX_QR_IMAGE_PIXELS: u64 = 32 * 1024 * 1024;
#[cfg(test)]
mod selector_tests;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Profiles,
    Configurations,
}
#[derive(Deserialize)]
pub struct ImportProfile {
    #[serde(default, rename = "vlessCore")]
    pub vless_core: Option<crate::vless::Core>,
    #[serde(flatten)]
    pub draft: crate::ProfileDraft,
    pub reference: Option<String>,
}

/// The file name offered for text the window exports in `format`.
pub fn shared_text_file_name(format: &str) -> Result<&'static str, String> {
    Ok(match format {
        "links" | "thronium-link" => "thronium-links.txt",
        "wireguard" => "thronium.conf",
        "profiles" | "configurations" => "thronium-profiles.json",
        "routing-profile" => "thronium-routing.json",
        "otp-json" => "thronium-otp.json",
        "otp-links" => "thronium-otp.txt",
        _ => return Err("invalid_export_format".into()),
    })
}

impl Engine {
    /// Text of one configuration shown in the window. A profile with a VPN
    /// policy is exported only as a bundle that keeps the policy.
    pub fn configuration_export(
        &self,
        source_profile: Option<&str>,
        config: &Value,
    ) -> Result<String, String> {
        if let Some(id) = source_profile {
            if self.profile(id)?.vpn_policy.is_some() {
                return Err("vpn_policy_export_requires_bundle".into());
            }
        }
        if !config.is_object() {
            return Err("invalid_profile".into());
        }
        let text = serde_json::to_string_pretty(config).map_err(|_| "export_failed")?;
        if text.len() > MAX_BYTES {
            return Err("export_too_large".into());
        }
        Ok(text)
    }
    pub fn export_profiles(&self, ids: Vec<String>, format: Format) -> Result<String, String> {
        let mut selected = self.selected_profiles(ids)?;
        let library = selector_snapshot(&self.store.library, &selected)?;
        let has_references = library
            .profiles
            .iter()
            .any(|p| selected.contains(&p.id) && crate::references::key(p.kind).is_some());
        if has_references {
            if matches!(format, Format::Configurations) {
                return Err("export_chain_format".into());
            }
            let mut pending: Vec<_> = selected.iter().cloned().collect();
            while let Some(id) = pending.pop() {
                let p = library
                    .profiles
                    .iter()
                    .find(|p| p.id == id)
                    .ok_or("profile_not_found")?;
                for member in crate::references::members(p)? {
                    if selected.insert(member.into()) {
                        pending.push(member.into());
                    }
                }
                if selected.len() > crate::store::MAX_BATCH_PROFILES {
                    return Err("export_reference_limit".into());
                }
            }
        }
        let profiles: Vec<_> = library
            .profiles
            .iter()
            .filter(|p| selected.contains(&p.id))
            .collect();
        let has_policy = profiles.iter().any(|p| p.vpn_policy.is_some());
        if has_policy && matches!(format, Format::Configurations) {
            return Err("vpn_policy_export_requires_bundle".into());
        }
        let aliases: HashMap<_, _> = profiles
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.as_str(), format!("p{i}")))
            .collect();
        let value = match format {
            Format::Profiles => {
                let entries = profiles
                    .iter()
                    .map(|p| {
                        let mut config = p.config.clone();
                        if let Some(key) = crate::references::key(p.kind) {
                            config[key] = json!(crate::references::members(p)
                                .unwrap()
                                .iter()
                                .map(|id| &aliases[id])
                                .collect::<Vec<_>>());
                            if p.kind == crate::store::ProfileKind::AutoSelector {
                                if let Some(pin) = p
                                    .config
                                    .get("pinned_profile")
                                    .and_then(Value::as_str)
                                    .filter(|v| !v.is_empty())
                                {
                                    config["pinned_profile"] = json!(aliases[pin]);
                                }
                            }
                        }
                        let mut entry = json!({"name":p.name,"kind":p.kind,"config":config});
                        if let Some(policy) = p.vpn_policy {
                            entry["vpnPolicy"] = json!(policy);
                        }
                        if crate::vless::is_vless(p) {
                            entry["vlessCore"] = json!(self
                                .store
                                .library
                                .preferences
                                .vless_overrides
                                .get(&p.id)
                                .copied()
                                .unwrap_or(self.store.library.preferences.vless_core));
                        }
                        if has_references {
                            entry["reference"] = json!(aliases[p.id.as_str()]);
                        }
                        entry
                    })
                    .collect::<Vec<_>>();
                json!({"format":"thronium-profiles", "version":if has_policy {2} else {1}, "profiles":entries})
            }
            Format::Configurations if profiles.len() == 1 => profiles[0].config.clone(),
            Format::Configurations => {
                Value::Array(profiles.iter().map(|p| p.config.clone()).collect())
            }
        };
        let text = serde_json::to_string_pretty(&value).map_err(|_| "export_failed")?;
        if text.len() > MAX_BYTES {
            return Err("export_too_large".into());
        }
        Ok(text)
    }
}

/// Portable profile files capture explicit members or today's dynamic pool.
/// Group IDs and filters belong to native backups; generated chains preserve this selector's group
/// front/landing policy without making it depend on the destination's groups.
fn selector_snapshot(
    source: &crate::store::Library,
    selected: &std::collections::HashSet<String>,
) -> Result<crate::store::Library, String> {
    use crate::{
        auto_selector, chains, references,
        store::{Profile, ProfileKind},
    };
    let mut library = source.clone();
    let mut occupied: std::collections::HashSet<_> =
        source.profiles.iter().map(|p| p.id.clone()).collect();
    for original in source
        .profiles
        .iter()
        .filter(|p| selected.contains(&p.id) && p.kind == ProfileKind::AutoSelector)
    {
        let mut profile = auto_selector::materialize(original, source)?;
        let policy = crate::group_chains::policy(source, original);
        if policy.enabled() {
            let mut members = Vec::new();
            let mut member_aliases = HashMap::new();
            for member in references::members(&profile)? {
                let raw = source
                    .profiles
                    .iter()
                    .find(|p| p.id == member)
                    .ok_or("selector_profile_missing")?;
                let mut hops = Vec::new();
                for id in policy
                    .front
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(member))
                    .chain(policy.landing.iter().map(String::as_str))
                {
                    let p = source
                        .profiles
                        .iter()
                        .find(|p| p.id == id)
                        .ok_or("group_chain_profile_missing")?;
                    hops.extend(
                        chains::flatten(p, &source.profiles)?
                            .into_iter()
                            .map(|p| p.id.clone()),
                    );
                }
                if hops.len() > chains::MAX_HOPS {
                    return Err("chain_too_long".into());
                }
                let mut id = format!("selector-export-{}-{member}", original.id);
                while !occupied.insert(id.clone()) {
                    id.push('_');
                }
                member_aliases.insert(member.to_owned(), id.clone());
                members.push(id.clone());
                library.profiles.push(Profile {
                    id,
                    kind: ProfileKind::Chain,
                    config: json!({"type":"chain","hops":hops}),
                    ..raw.clone()
                });
            }
            profile.config["members"] = json!(members);
            if let Some(pin) = profile
                .config
                .get("pinned_profile")
                .and_then(Value::as_str)
                .filter(|pin| !pin.is_empty())
            {
                profile.config["pinned_profile"] =
                    json!(member_aliases.get(pin).ok_or("invalid_selector_pin")?);
            }
        }
        *library
            .profiles
            .iter_mut()
            .find(|p| p.id == original.id)
            .unwrap() = profile;
    }
    Ok(library)
}

/// Called only after the native save dialog returns the user-selected path.
/// Replacement is atomic and new exports have private permissions on Unix.
pub fn save_text(path: &Path, text: &str) -> Result<(), String> {
    save_text_limited(path, text, MAX_BYTES)
}
pub fn save_text_limited(path: &Path, text: &str, limit: usize) -> Result<(), String> {
    save_bytes_limited(path, text.as_bytes(), limit)
}
pub fn save_bytes_limited(path: &Path, bytes: &[u8], limit: usize) -> Result<(), String> {
    if bytes.len() > limit {
        return Err("export_too_large".into());
    }
    let write = || -> Result<(), std::io::Error> {
        let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
        // A temporary file is born readable by its owner alone on Unix; on
        // Windows it would inherit whatever the folder allows, so say it.
        crate::ownership::restrict_file(path).map_err(std::io::Error::other)?;
        Ok(())
    };
    write().map_err(|_| "export_write_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::ProfileKind, ProfileDraft};
    #[test]
    fn export_retains_names_kinds_unknown_fields_and_full_configs_without_library_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), Path::new("missing")).unwrap();
        let configs = [
            json!({"type":"wireguard","private_key":"fixture-secret","future":{"list":[1,2]}}),
            json!({"inbounds":[],"outbounds":[],"routing":{"domainStrategy":"AsIs"},"future":true}),
        ];
        let mut ids = vec![];
        for (i, kind) in [ProfileKind::SingBoxOutbound, ProfileKind::XrayConfig]
            .into_iter()
            .enumerate()
        {
            ids.push(
                e.save_profile(ProfileDraft {
                    vpn_policy: Default::default(),
                    id: None,
                    name: format!("Тест {i}"),
                    group_id: "personal".into(),
                    kind,
                    config: configs[i].clone(),
                })
                .unwrap(),
            );
        }
        let before = serde_json::to_value(&e.store.library).unwrap();
        e.running = Some(ids[0].clone());
        let text = e
            .export_profiles(
                vec![ids[1].clone(), ids[0].clone(), ids[0].clone()],
                Format::Profiles,
            )
            .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["profiles"].as_array().unwrap().len(), 2);
        assert_eq!(value["profiles"][0]["config"], configs[0]);
        assert_eq!(value["profiles"][1]["config"], configs[1]);
        assert_eq!(value["profiles"][1]["kind"], "xray-config");
        assert_eq!(value["profiles"][0]["name"], "Тест 0");
        assert!(!text.contains(&ids[0]));
        assert!(!text.contains("personal"));
        assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
        let raw: Value = serde_json::from_str(
            &e.export_profiles(vec![ids[1].clone()], Format::Configurations)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw, configs[1]);
        assert!(e
            .export_profiles(vec![ids[0].clone(), "missing".into()], Format::Profiles)
            .is_err());
        assert!(e.export_profiles(vec![], Format::Profiles).is_err());
    }
    #[test]
    fn atomic_file_export_preserves_old_file_on_error_and_sets_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("profiles.json");
        save_text(&file, "old").unwrap();
        assert!(save_text(&file, &"x".repeat(MAX_BYTES + 1)).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "old");
        assert!(save_text(dir.path(), "failure").is_err());
        save_text(&file, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
