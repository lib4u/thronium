//! Pure Qt ordinary VPN Export -> static endpoint source. Never resolve an OTP
//! or read a path here; live templates remain private source until bound Build.
use super::SourceProfile;
use crate::{
    store::{Profile, ProfileKind},
    vpn_policy::Policy,
};
use serde_json::{json, Map, Value};

type Result<T> = std::result::Result<T, &'static str>;
const STRUCTURE: &str = "legacy_profile_structure";
const FIELD: &str = "legacy_profile_field_unsupported";
#[derive(Clone)]
pub struct BindingSource {
    pub source_id: i64,
    pub otp_source_id: i64,
    pub revision: String,
    pub manual_allowed: bool,
}
pub struct Converted {
    pub config: Value,
    pub policy: Policy,
    pub otp_source_id: Option<i64>,
    pub manual_allowed: bool,
}

#[derive(Default)]
struct Fields<'a> {
    strings: &'a [&'a str],
    bools: &'a [&'a str],
    ints: &'a [&'a str],
    longs: &'a [&'a str],
    lists: &'a [&'a str],
    other: &'a [&'a str],
}
fn text(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|s| !s.contains('\0'))
        .ok_or(STRUCTURE)
}
fn list(value: &Value) -> Result<Vec<Value>> {
    match value {
        Value::String(_) => Ok(text(value)?
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| json!(s))
            .collect()),
        Value::Array(a) => a.iter().map(|v| text(v).map(|s| json!(s))).collect(),
        _ => Err(STRUCTURE),
    }
}
fn normalize(value: &Value, fields: Fields<'_>) -> Result<Map<String, Value>> {
    let source = value.as_object().ok_or(STRUCTURE)?;
    let mut out = Map::new();
    for (key, value) in source {
        let k = key.as_str();
        let next = if fields.strings.contains(&k) {
            let s = text(value)?;
            (!s.is_empty()).then(|| json!(s))
        } else if fields.bools.contains(&k) {
            value.as_bool().ok_or(STRUCTURE)?.then_some(json!(true))
        } else if fields.ints.contains(&k) || fields.longs.contains(&k) {
            let n = value.as_i64().filter(|n| *n >= 0).ok_or(STRUCTURE)?;
            if fields.ints.contains(&k) && n > i32::MAX as i64 {
                return Err(STRUCTURE);
            }
            (n > 0).then(|| json!(n))
        } else if fields.lists.contains(&k) {
            let a = list(value)?;
            // Qt tests the parsed list's presence before QListStr2QJsonArray
            // removes whitespace-only items. A nonempty all-blank source
            // therefore emits [], whereas a source [] remains absent.
            (!a.is_empty()).then(|| {
                json!(a
                    .into_iter()
                    .filter(|v| !v.as_str().unwrap().trim().is_empty())
                    .collect::<Vec<_>>())
            })
        } else if fields.other.contains(&k) {
            None
        } else {
            return Err(FIELD);
        };
        if let Some(value) = next {
            out.insert(key.clone(), value);
        }
    }
    Ok(out)
}
fn nested(
    target: &mut Map<String, Value>,
    source: &Value,
    key: &str,
    fields: Fields<'_>,
) -> Result<()> {
    if let Some(value) = source.get(key) {
        let normalized = normalize(value, fields)?;
        if !normalized.is_empty() {
            target.insert(key.into(), json!(normalized));
        }
    }
    Ok(())
}
fn paths(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            // Certificate, key and secret files are offered by the review as
            // resources; helper programs (`wrapper_path`) have no portable form.
            (key.ends_with("_path")
                && key != "server_path"
                && !crate::routing::resources::profiles::file_key(key)
                && value.as_str().is_some_and(|s| !s.is_empty()))
                || paths(value)
        }),
        Value::Array(items) => items.iter().any(paths),
        _ => false,
    }
}
fn bool_default(c: &Value, key: &str, default: bool) -> Result<bool> {
    c.get(key)
        .map(|v| v.as_bool().ok_or(STRUCTURE))
        .unwrap_or(Ok(default))
}
fn port(c: &Value, key: &str) -> Result<Option<u16>> {
    c.get(key)
        .map(|v| {
            v.as_u64()
                .filter(|n| *n <= 65535)
                .map(|n| n as u16)
                .ok_or(STRUCTURE)
        })
        .transpose()
}
fn ipv6_host(host: &str) -> Result<String> {
    let bracketed = host.contains(['[', ']']);
    let bare = if bracketed {
        host.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .filter(|s| !s.contains(['[', ']']))
            .ok_or(STRUCTURE)?
    } else {
        host
    };
    let address = if let Some((address, scope)) = bare.split_once('%') {
        // Preserve a conventional interface/index scope verbatim. Refuse
        // unproven scope spellings instead of repairing a destination.
        if scope.is_empty()
            || !scope
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            return Err(STRUCTURE);
        }
        address
    } else {
        bare
    };
    if address.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(format!("[{bare}]"))
    } else if bracketed || bare.contains('%') {
        Err(STRUCTURE)
    } else {
        Ok(host.to_owned())
    }
}
fn common(source: &SourceProfile, extra: Fields<'_>) -> Result<Map<String, Value>> {
    let c = &source.outbound;
    if paths(c) {
        return Err("legacy_profile_external_resource");
    }
    if bool_default(c, "system", false)?
        || c.get("name")
            .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
    {
        return Err("legacy_vpn_system_unsupported");
    }
    let mut strings = vec![
        "type",
        "tag",
        "server",
        "username",
        "password",
        "connect_timeout",
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "name",
        "udp_timeout",
        "udp_mapping",
        "udp_filtering",
    ];
    strings.extend(extra.strings);
    let mut bools = vec![
        "reuse_addr",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "system",
    ];
    bools.extend(extra.bools);
    let mut ints = vec!["server_port", "mtu", "udp_nat_max"];
    ints.extend(extra.ints);
    let mut other = vec![
        "only_advertised_routes",
        "use_tunnel_dns",
        "block_outside_dns",
        "otp_profile_id",
    ];
    other.extend(extra.other);
    let result = normalize(
        c,
        Fields {
            strings: &strings,
            bools: &bools,
            ints: &ints,
            longs: extra.longs,
            lists: extra.lists,
            other: &other,
        },
    )?;
    port(c, "server_port")?;
    Ok(result)
}
fn live_templates(config: &Value) -> bool {
    config["form_entries"].as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry["promote"] != true && entry["value"].as_str().is_some_and(|s| s.contains("{otp}"))
        })
    })
}
pub fn convert(source: &SourceProfile) -> Result<Converted> {
    let c = &source.outbound;
    if !matches!(
        (source.kind.as_str(), c["type"].as_str()),
        ("openvpn", Some("openvpn" | "openvpn-client"))
            | ("openvpn-client", Some("openvpn-client" | "openvpn"))
            | ("openconnect", Some("openconnect"))
    ) {
        return Err("legacy_profile_discriminator");
    }
    let policy = Policy {
        only_advertised_routes: bool_default(c, "only_advertised_routes", true)?,
        use_tunnel_dns: bool_default(c, "use_tunnel_dns", true)?,
        block_outside_dns: bool_default(c, "block_outside_dns", false)?,
    };
    let otp_source_id = match c.get("otp_profile_id") {
        None => None,
        Some(v) => match v.as_i64() {
            Some(-1) => None,
            Some(id) if (0..=i32::MAX as i64).contains(&id) => Some(id),
            _ => return Err(STRUCTURE),
        },
    };
    let config = json!(if source.kind == "openconnect" {
        openconnect(source)?
    } else {
        openvpn(source)?
    });
    let has_templates = live_templates(&config)
        || ["username", "password"]
            .iter()
            .any(|key| config[*key].as_str().is_some_and(|s| s.contains("{otp}")));
    if has_templates && otp_source_id.is_none() {
        return Err("legacy_vpn_binding_required");
    }
    let profile = Profile {
        vpn_policy: Some(policy),
        id: String::new(),
        name: String::new(),
        group_id: String::new(),
        kind: ProfileKind::SingBoxOutbound,
        config: config.clone(),
        favorite: false,
    };
    // The mode itself is decided when the profile is used; this only refuses
    // what could never be automated at all.
    crate::vpn_auth::otp::recommended_mode(&profile).map_err(|code| match code.as_str() {
        "vpn_otp_start_placeholder_unsupported" | "vpn_otp_start_mode_required" => {
            "vpn_otp_start_placeholder_unsupported"
        }
        "vpn_otp_form_shadowed" => "vpn_otp_form_shadowed",
        "vpn_otp_form_cache_unsupported" => "vpn_otp_form_cache_unsupported",
        _ => "legacy_vpn_binding_unsupported",
    })?;
    // An OpenVPN binding without a configured challenge is answered when the
    // server asks: the dynamic CRV1 challenge of a refusal is a live challenge
    // like any other, so it is imported rather than refused.
    Ok(Converted {
        config,
        policy,
        otp_source_id,
        manual_allowed: !has_templates,
    })
}

mod protocols;
#[cfg(test)]
mod tests;
use protocols::{openconnect, openvpn};
