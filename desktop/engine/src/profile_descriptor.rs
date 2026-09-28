//! Read-only display metadata. This is neither a probe endpoint nor subscription identity.
use crate::store::{Profile, ProfileKind};
use serde_json::{json, Value};

/// Security classes ordered like Qt's `SecurityLevel`: unknown, none, weak, secure.
pub const SECURITY_UNKNOWN: u8 = 0;
pub const SECURITY_NONE: u8 = 1;
pub const SECURITY_WEAK: u8 = 2;
pub const SECURITY_SECURE: u8 = 3;

pub struct ProfileDescriptor<'a> {
    pub protocol: &'a str,
    pub address: &'a str,
    pub port: Option<u16>,
    pub security: String,
    pub security_level: u8,
}

/// Outbounds of a full sing-box or Xray config that route between or around
/// servers rather than being one: direct, block, DNS, groups and loopback.
pub(crate) fn infrastructure_outbound(outbound: &Value) -> bool {
    matches!(
        outbound["type"].as_str().or(outbound["protocol"].as_str()),
        Some(
            "direct"
                | "block"
                | "dns"
                | "selector"
                | "urltest"
                | "freedom"
                | "blackhole"
                | "loopback"
        )
    )
}

/// A full config only has one displayable server when its outbound is unambiguous.
pub(crate) fn single_outbound(config: &Value) -> Option<&Value> {
    let mut candidates = ["outbounds", "endpoints"]
        .into_iter()
        .flat_map(|key| config[key].as_array().into_iter().flatten())
        .filter(|outbound| !infrastructure_outbound(outbound));
    let first = candidates.next()?;
    candidates.next().is_none().then_some(first)
}

fn single_entry(value: &Value) -> Option<&Value> {
    let entries = value.as_array()?;
    (entries.len() == 1).then(|| &entries[0])
}

fn port_of(value: &Value) -> Option<u16> {
    value.as_u64().and_then(|port| u16::try_from(port).ok())
}

/// Host and port of the displayed server: the outbound's own fields, else the
/// single entry of an Xray/WireGuard server list.
fn endpoint(config: &Value) -> (Option<&str>, Option<u16>) {
    if let Some(host) = config["server"].as_str() {
        return (Some(host), port_of(&config["server_port"]));
    }
    if let Some(host) = config["settings"]["address"].as_str() {
        return (Some(host), port_of(&config["settings"]["port"]));
    }
    for list in [
        &config["settings"]["vnext"],
        &config["settings"]["servers"],
        &config["peers"],
        &config["settings"]["peers"],
    ] {
        if let Some(entry) = single_entry(list) {
            if let Some(host) = entry["address"].as_str() {
                return (Some(host), port_of(&entry["port"]));
            }
            if let Some(endpoint) = entry["endpoint"].as_str() {
                return endpoint
                    .rsplit_once(':')
                    .map(|(host, port)| (Some(host.trim_matches(['[', ']'])), port.parse().ok()))
                    .unwrap_or((None, None));
            }
        }
    }
    (None, None)
}

/// Writes a resolved address where [`endpoint`] read the server name, so Qt's
/// "resolve domain to IP" keeps the rest of the configuration untouched.
pub(crate) fn set_host(config: &mut Value, host: &str) -> bool {
    if config["server"].is_string() {
        config["server"] = json!(host);
        return true;
    }
    if config["settings"]["address"].is_string() {
        config["settings"]["address"] = json!(host);
        return true;
    }
    for key in [
        &["settings", "vnext"][..],
        &["settings", "servers"],
        &["peers"],
        &["settings", "peers"],
    ] {
        let list = key
            .iter()
            .fold(&mut *config, |value, step| &mut value[*step]);
        let Some([entry]) = list.as_array_mut().map(|items| &mut items[..]) else {
            continue;
        };
        if entry["address"].is_string() {
            entry["address"] = json!(host);
            return true;
        }
        if let Some(endpoint) = entry["endpoint"].as_str() {
            let Some((_, port)) = endpoint.rsplit_once(':') else {
                continue;
            };
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            entry["endpoint"] = json!(format!("{host}:{port}"));
            return true;
        }
    }
    false
}

/// Protocol codes for profiles without one outbound type; the window names them.
pub const EXTERNAL_CORE: &str = "external-core";
pub const CUSTOM: &str = "custom";

pub fn describe(profile: &Profile) -> ProfileDescriptor<'_> {
    if profile.kind == ProfileKind::ExternalCore {
        return ProfileDescriptor {
            protocol: EXTERNAL_CORE,
            address: "127.0.0.1",
            port: port_of(&profile.config["socks_port"]),
            security: String::new(),
            security_level: SECURITY_UNKNOWN,
        };
    }
    let config = if matches!(
        profile.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) {
        single_outbound(&profile.config)
    } else if matches!(profile.kind, ProfileKind::Chain | ProfileKind::AutoSelector) {
        None
    } else {
        Some(&profile.config)
    };
    let Some(config) = config else {
        return ProfileDescriptor {
            protocol: CUSTOM,
            address: "",
            port: None,
            security: String::new(),
            security_level: SECURITY_UNKNOWN,
        };
    };
    let (address, port) = endpoint(config);
    ProfileDescriptor {
        protocol: if let Some(awg) = config.get("amnezia_wg") {
            amnezia_version(awg)
        } else {
            config["type"]
                .as_str()
                .or(config["protocol"].as_str())
                .unwrap_or(CUSTOM)
        },
        address: address.unwrap_or(""),
        port,
        security: security(config),
        security_level: security_level(config),
    }
}

/// Amnezia's own version names: 1.5 adds the special junk packets, 2 the
/// cookie-reply and transport junk sizes, 3.1 header protection, content
/// padding, timing ranges, random trailers and cookie control
/// (amnezia-client `protocolConstants.h`, `PageProtocolAwgSettings.qml`).
/// A switch counts only when on, a size only when non-zero.
pub(crate) fn amnezia_version(awg: &Value) -> &'static str {
    let set = |keys: &[&str]| {
        keys.iter().any(|key| match &awg[*key] {
            Value::Bool(flag) => *flag,
            Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
            Value::String(text) => !text.is_empty(),
            Value::Null => false,
            _ => true,
        })
    };
    if set(&[
        "header_protection_key",
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
        "random_trailers",
        "disable_cookies",
    ]) {
        "AmneziaWG 3.1"
    } else if set(&["s3", "s4"]) {
        "AmneziaWG 2.0"
    } else if set(&["i1", "i2", "i3", "i4", "i5"]) {
        "AmneziaWG 1.5"
    } else {
        "AmneziaWG 1.0"
    }
}

pub(crate) fn security(config: &Value) -> String {
    let mut parts = Vec::new();
    let stream = &config["streamSettings"];
    if config["tls"]["reality"]["enabled"] == true || stream["security"] == "reality" {
        parts.push("Reality");
    } else if config["tls"]["enabled"] == true || stream["security"] == "tls" {
        parts.push("TLS");
    }
    // As Qt's `DisplayTransportName`: plain TCP (sing-box `tcp`, Xray `raw`)
    // is no transport, so neither it nor a missing type gets a label.
    match config["transport"]["type"]
        .as_str()
        .or(stream["network"].as_str())
    {
        None | Some("" | "tcp" | "raw") => {}
        Some("splithttp") => parts.push("xhttp"),
        Some(transport) => parts.push(transport),
    }
    parts.join(" · ")
}

/// Qt's `SecurityFromTLS`: Reality is secure, TLS without certificate
/// verification is weak, a TLS-transport protocol without TLS sends raw
/// traffic. Protocols with their own encryption stay unknown, not "none".
pub(crate) fn security_level(config: &Value) -> u8 {
    let stream = &config["streamSettings"];
    if config["tls"]["reality"]["enabled"] == true || stream["security"] == "reality" {
        return SECURITY_SECURE;
    }
    if config["tls"]["enabled"] == true || stream["security"] == "tls" {
        return if config["tls"]["insecure"] == true
            || stream["tlsSettings"]["allowInsecure"] == true
        {
            SECURITY_WEAK
        } else {
            SECURITY_SECURE
        };
    }
    let protocol = config["type"].as_str().or(config["protocol"].as_str());
    if matches!(
        protocol,
        Some("vless" | "vmess" | "trojan" | "http" | "socks")
    ) {
        SECURITY_NONE
    } else {
        SECURITY_UNKNOWN
    }
}

#[cfg(test)]
mod tests;
