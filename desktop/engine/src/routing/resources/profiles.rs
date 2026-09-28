//! Portable files referenced from profile configurations: full sing-box/Xray
//! JSON, TLS and SSH inputs of outbounds. The walker names only known input
//! fields; log outputs, HTTP paths and remote URLs are never treated as files.
use super::{materialize, visit_document, Kind, Pack, PREFIX};
use crate::{
    proto::LoadConfigReq,
    store::{Profile, ProfileKind},
};
use serde_json::Value;
use std::path::Path;

/// sing-box and Xray fields whose string value is a certificate or key file,
/// including OpenVPN/OpenConnect CA, CRL, static and control-channel keys.
const PEM_KEYS: [&str; 12] = [
    "certificate_path",
    "client_certificate_path",
    "key_path",
    "client_key_path",
    "private_key_path",
    "certificateFile",
    "keyFile",
    "certificate_authority_path",
    "mca_certificate_path",
    "mca_key_path",
    "crl_path",
    "static_key_path",
];
/// Other text inputs: ECH and Tailscale configuration files and OpenConnect
/// token secrets. SSH has no known hosts file in the pinned core, so such a key
/// is not offered as an input.
const TEXT_KEYS: [&str; 2] = ["config_path", "secret_path"];

/// Whether a configuration key names an input file the resource pack can carry.
pub(crate) fn file_key(key: &str) -> bool {
    PEM_KEYS.contains(&key) || TEXT_KEYS.contains(&key)
}

pub(crate) fn carries(profile: &Profile) -> bool {
    matches!(
        profile.kind,
        ProfileKind::SingBoxOutbound
            | ProfileKind::SingBoxConfig
            | ProfileKind::XrayOutbound
            | ProfileKind::XrayConfig
    )
}

fn visit_keys(
    value: &mut Value,
    depth: usize,
    visit: &mut impl FnMut(&mut Value, Kind) -> Result<(), String>,
) -> Result<(), String> {
    if depth > 64 {
        return Err("invalid_configuration".into());
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if value.is_string() {
                    if PEM_KEYS.contains(&key.as_str()) {
                        visit(value, Kind::Pem)?;
                    } else if TEXT_KEYS.contains(&key.as_str()) {
                        visit(value, Kind::Text)?;
                    }
                } else {
                    visit_keys(value, depth + 1, visit)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                visit_keys(item, depth + 1, visit)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The three ways an Xray configuration names a list of its own.
const EXT_PREFIXES: [&str; 3] = ["ext:", "ext-ip:", "ext-domain:"];

/// Whether this `ext:` value already names a copy the app carries.
pub(crate) fn bound_asset(value: &str) -> bool {
    split_ext(value).is_some_and(|(_, file, _)| super::reference(file))
}
/// `ext:<file>:<code>` split into its prefix, the file it names and the code.
fn split_ext(value: &str) -> Option<(&'static str, &str, &str)> {
    let prefix = EXT_PREFIXES
        .into_iter()
        .find(|prefix| value.starts_with(prefix))?;
    let rest = &value[prefix.len()..];
    // The file part may itself be a reference, which carries a colon; the code
    // is what follows the last one.
    let (file, code) = rest.rsplit_once(':')?;
    (!file.is_empty() && !code.is_empty()).then_some((prefix, file, code))
}
/// Xray lists named by `ext:` inside the routing and DNS sections of a full
/// configuration: the same places the app's own geo references live.
fn visit_ext(
    config: &mut Value,
    visit: &mut impl FnMut(&mut Value, Kind) -> Result<(), String>,
) -> Result<(), String> {
    fn listed(
        list: &mut Value,
        visit: &mut impl FnMut(&mut Value, Kind) -> Result<(), String>,
    ) -> Result<(), String> {
        for value in list.as_array_mut().into_iter().flatten() {
            let Some((prefix, file, code)) = value.as_str().and_then(split_ext) else {
                continue;
            };
            let code = code.to_owned();
            let mut named = Value::String(file.to_owned());
            visit(&mut named, Kind::Geodata)?;
            if let Some(named) = named.as_str() {
                *value = Value::String(format!("{prefix}{named}:{code}"));
            }
        }
        Ok(())
    }
    for rule in config
        .get_mut("routing")
        .and_then(|routing| routing.get_mut("rules"))
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        for key in ["domain", "ip", "source"] {
            if let Some(list) = rule.get_mut(key) {
                listed(list, visit)?;
            }
        }
    }
    for server in config
        .get_mut("dns")
        .and_then(|dns| dns.get_mut("servers"))
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        for key in ["domains", "expectIPs", "unexpectedIPs"] {
            if let Some(list) = server.get_mut(key) {
                listed(list, visit)?;
            }
        }
    }
    Ok(())
}

/// Every file field of one profile configuration: hosts and local rule sets of
/// a full sing-box document, then TLS/SSH inputs anywhere in the JSON, and the
/// lists an Xray configuration names by `ext:`.
pub(crate) fn visit_profile(
    config: &mut Value,
    mut visit: impl FnMut(&mut Value, Kind) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(dns) = config.get_mut("dns") {
        visit_document(dns, true, &mut visit)?;
    }
    if let Some(route) = config.get_mut("route") {
        visit_document(route, false, &mut visit)?;
    }
    visit_ext(config, &mut visit)?;
    visit_keys(config, 0, &mut visit)
}

/// Replace references with cached absolute paths; other values stay verbatim.
/// A list named by `ext:` becomes the file name Xray reads from its own asset
/// directory, because that is the only form that core resolves.
pub(crate) fn resolve_profile(
    config: &mut Value,
    pack: &Pack,
    directory: &Path,
) -> Result<(), String> {
    visit_profile(config, |path, kind| {
        let Some(reference) = path.as_str().filter(|s| s.starts_with(PREFIX)) else {
            return Ok(());
        };
        let resource = pack.get(reference, kind)?;
        if kind == Kind::Geodata {
            let assets = directory.join("xray-assets");
            std::fs::create_dir_all(&assets).map_err(|_| "routing_resource_write_failed")?;
            let target = super::materialize_in(&assets, resource)?;
            *path = serde_json::json!(target
                .file_name()
                .ok_or("routing_resource_write_failed")?
                .to_string_lossy());
            return Ok(());
        }
        let target = materialize(directory, resource)?;
        *path = serde_json::json!(target);
        Ok(())
    })
}

fn resolve_text(text: &mut String, pack: &Pack, directory: &Path) -> Result<(), String> {
    if !text.contains(PREFIX) {
        return Ok(());
    }
    let mut value: Value = serde_json::from_str(text).map_err(|_| "invalid_configuration")?;
    resolve_profile(&mut value, pack, directory)?;
    *text = value.to_string();
    Ok(())
}

/// Resolve references in every compiled document of a Core request.
pub(crate) fn resolve_request(
    request: &mut LoadConfigReq,
    pack: &Pack,
    directory: &Path,
) -> Result<(), String> {
    for text in request
        .core_config
        .iter_mut()
        .chain(request.xray_config.iter_mut())
        .chain(request.xray_full_configs.iter_mut())
    {
        resolve_text(text, pack, directory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::resources::Resource;
    use serde_json::json;

    const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n";

    #[test]
    fn walker_names_only_input_files_and_resolves_references_into_private_copies() {
        let root = tempfile::tempdir().unwrap();
        let mut pack = Pack::default();
        let pem = pack
            .insert(Resource::parse(Kind::Pem, PEM.to_vec()).unwrap())
            .unwrap();
        let hosts = pack
            .insert(Resource::parse(Kind::Hosts, b"127.0.0.1 fixture.invalid\n".to_vec()).unwrap())
            .unwrap();
        let text = pack
            .insert(
                Resource::parse(Kind::Text, b"fixture.invalid ssh-ed25519 AAAA\n".to_vec())
                    .unwrap(),
            )
            .unwrap();
        let mut config = json!({
            "log":{"output":"/var/log/keep.log"},
            "dns":{"servers":[{"type":"hosts","tag":"h","path":[hosts]},{"type":"https","path":"/dns-query"}]},
            "route":{"rule_set":[{"type":"local","tag":"x","format":"binary","path":"/kept/absolute.srs"}]},
            "outbounds":[{"type":"ssh","private_key_path":pem,"tls":{"certificate_path":pem,"ech":{"config_path":text}}}],
            "streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":pem,"keyFile":"relative/key.pem"}]}}
        });
        let mut kinds = vec![];
        visit_profile(&mut config.clone(), |_, kind| {
            kinds.push(kind);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            kinds,
            [
                Kind::Hosts,
                Kind::RuleSetBinary,
                Kind::Pem,
                Kind::Pem,
                Kind::Text,
                Kind::Pem,
                Kind::Pem
            ]
        );
        resolve_profile(&mut config, &pack, root.path()).unwrap();
        let cached = root.path().join("routing-resources");
        for pointer in [
            "/dns/servers/0/path/0",
            "/outbounds/0/private_key_path",
            "/outbounds/0/tls/ech/config_path",
            "/outbounds/0/tls/certificate_path",
            "/streamSettings/tlsSettings/certificates/0/certificateFile",
        ] {
            let path = config.pointer(pointer).unwrap().as_str().unwrap();
            assert!(Path::new(path).starts_with(&cached), "{pointer}");
        }
        assert_eq!(config["log"]["output"], "/var/log/keep.log");
        assert_eq!(config["dns"]["servers"][1]["path"], "/dns-query");
        assert_eq!(config["route"]["rule_set"][0]["path"], "/kept/absolute.srs");
        assert_eq!(
            config["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"],
            "relative/key.pem"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key = config["outbounds"][0]["private_key_path"].as_str().unwrap();
            let mode = std::fs::metadata(key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "materialised keys stay private");
        }
        let missing = json!({"outbounds":[{"type":"ssh","private_key_path":format!("{PREFIX}{}", "0".repeat(64))}]});
        assert_eq!(
            resolve_profile(&mut missing.clone(), &pack, root.path()).unwrap_err(),
            "routing_resource_missing"
        );
        let mut request = LoadConfigReq {
            core_config: Some(json!({"outbounds":[{"type":"ssh","private_key_path":pem}]}).to_string()),
            xray_config: Some(json!({"outbounds":[]}).to_string()),
            xray_full_configs: vec![json!({"inbounds":[{"streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":pem}]}}}]}).to_string()],
            ..Default::default()
        };
        let untouched = request.xray_config.clone();
        resolve_request(&mut request, &pack, root.path()).unwrap();
        assert!(!request.core_config.as_ref().unwrap().contains(PREFIX));
        assert!(!request.xray_full_configs[0].contains(PREFIX));
        assert_eq!(request.xray_config, untouched);
    }

    #[test]
    fn pem_and_text_resources_are_validated_and_gated_by_library_version_seven() {
        assert!(Resource::parse(Kind::Pem, b"not a certificate".to_vec()).is_err());
        assert!(Resource::parse(Kind::Pem, vec![0xff, 0xfe]).is_err());
        assert!(Resource::parse(Kind::Text, vec![0xff]).is_err());
        let pem = Resource::parse(Kind::Pem, PEM.to_vec()).unwrap();
        let mut library = crate::store::Library::default();
        let reference = library.routing_resources.insert(pem).unwrap();
        library.version = 6;
        library.profiles.push(Profile {
            vpn_policy: None,
            id: "ssh".into(),
            name: "SSH".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"ssh","server":"192.0.2.1","private_key_path":reference}),
            favorite: false,
        });
        assert_eq!(
            crate::store::validate_library(&library).unwrap_err(),
            "library_version_unsupported"
        );
        library.version = 7;
        crate::store::validate_library(&library).unwrap();
        library.profiles[0].config["private_key_path"] =
            json!(format!("{PREFIX}{}", "1".repeat(64)));
        assert_eq!(
            crate::store::validate_library(&library).unwrap_err(),
            "routing_resource_missing"
        );
        library.profiles[0].config["private_key_path"] = json!("/local/key.pem");
        crate::store::validate_library(&library).unwrap();
        let mut pruned = library.clone();
        crate::routing::resources::prune(&mut pruned);
        assert!(pruned.routing_resources.is_empty());
        pruned.profiles[0].config["private_key_path"] = json!(reference);
        pruned.routing_resources = library.routing_resources.clone();
        crate::routing::resources::prune(&mut pruned);
        assert!(!pruned.routing_resources.is_empty());
    }

    /// One category named "test": the shape Xray reads from a list file.
    const GEODATA: &[u8] = &[0x0A, 0x06, 0x0A, 0x04, b't', b'e', b's', b't'];

    /// A list an Xray configuration names by `ext:` travels as a portable
    /// copy. It is placed where that core looks for it — its asset directory —
    /// and the reference keeps naming a file, never a path.
    #[test]
    fn an_xray_list_named_by_ext_is_carried_and_resolved_in_the_asset_directory() {
        assert!(Resource::parse(Kind::Geodata, b"not a list".to_vec()).is_err());
        assert!(Resource::parse(Kind::Geodata, vec![]).is_err());
        let root = tempfile::tempdir().unwrap();
        let mut pack = Pack::default();
        let reference = pack
            .insert(Resource::parse(Kind::Geodata, GEODATA.to_vec()).unwrap())
            .unwrap();
        let mut config = json!({
            "outbounds":[{"protocol":"freedom"}],
            "routing":{"rules":[{"type":"field","domain":["ext:private.dat:test","geosite:kept"],
                                 "ip":["ext-ip:private.dat:test"],"outboundTag":"direct"}]},
            "dns":{"servers":[{"address":"1.1.1.1","domains":["ext-domain:private.dat:test"]}]}
        });
        // The walker names the file of every `ext:` form and nothing else.
        let mut named = vec![];
        visit_profile(&mut config.clone(), |value, kind| {
            named.push((value.as_str().unwrap().to_owned(), kind));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            named,
            [
                ("private.dat".to_owned(), Kind::Geodata),
                ("private.dat".to_owned(), Kind::Geodata),
                ("private.dat".to_owned(), Kind::Geodata)
            ]
        );
        visit_profile(&mut config, |value, _| {
            if value == "private.dat" {
                *value = json!(reference);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            config["routing"]["rules"][0]["domain"][0],
            json!(format!("ext:{reference}:test"))
        );
        assert!(bound_asset(
            config["routing"]["rules"][0]["domain"][0].as_str().unwrap()
        ));
        assert_eq!(config["routing"]["rules"][0]["domain"][1], "geosite:kept");
        resolve_profile(&mut config, &pack, root.path()).unwrap();
        let name = config["routing"]["rules"][0]["domain"][0]
            .as_str()
            .unwrap()
            .strip_prefix("ext:")
            .and_then(|rest| rest.strip_suffix(":test"))
            .unwrap()
            .to_owned();
        assert!(name.ends_with(".dat") && !name.contains('/'), "{name}");
        assert_eq!(
            std::fs::read(root.path().join("xray-assets").join(&name)).unwrap(),
            GEODATA
        );
        assert_eq!(
            config["routing"]["rules"][0]["ip"][0],
            json!(format!("ext-ip:{name}:test"))
        );
        assert_eq!(
            config["dns"]["servers"][0]["domains"][0],
            json!(format!("ext-domain:{name}:test"))
        );
        // A list the app carries needs version 8 readers; a name nobody
        // answered is still refused by the core-facing rewrite.
        let mut library = crate::store::Library::default();
        let reference = library
            .routing_resources
            .insert(Resource::parse(Kind::Geodata, GEODATA.to_vec()).unwrap())
            .unwrap();
        library.profiles.push(Profile {
            vpn_policy: None,
            id: "xray".into(),
            name: "Xray".into(),
            group_id: "personal".into(),
            kind: ProfileKind::XrayConfig,
            config: json!({"outbounds":[{"protocol":"freedom"}],
                "routing":{"rules":[{"type":"field","domain":[format!("ext:{reference}:test")],"outboundTag":"direct"}]}}),
            favorite: false,
        });
        library.version = 7;
        assert_eq!(
            crate::store::validate_library(&library).unwrap_err(),
            "library_version_unsupported"
        );
        library.version = 8;
        crate::store::validate_library(&library).unwrap();
        let assets = crate::geodata::Assets::new(root.path(), None);
        let mut carried = library.profiles[0].config.clone();
        assets.rewrite_xray(&mut carried).unwrap();
        let mut unanswered = json!({"routing":{"rules":[{"domain":["ext:private.dat:test"]}]}});
        assert_eq!(
            assets.rewrite_xray(&mut unanswered).unwrap_err(),
            "geodata_external_file_unsupported"
        );
    }
}
