//! Qt DNS address text (`remote_dns`, `direct_dns`, bootstrap) to one sing-box
//! server object, following buildDnsObj's scheme/authority/path parsing.
use super::Result;
use serde_json::{json, Value};

pub(super) fn server(address: &str, remote: bool) -> Result<Value> {
    if matches!(address, "local" | "localhost") {
        if remote {
            return Err("legacy_dns_remote_transport_unsupported");
        }
        return Ok(json!({"type":"local"}));
    }
    if address.is_empty()
        || address.len() > 4096
        || !address.is_ascii()
        || address.chars().any(char::is_whitespace)
        || address.contains(['#', '\\'])
        || address.starts_with("local")
    {
        return Err("legacy_dns_address_unsupported");
    }
    let (kind, raw) = match address.split_once("://") {
        Some((kind, raw)) if matches!(kind, "tcp" | "tls" | "https" | "quic" | "h3") => (kind, raw),
        Some(_) => return Err("legacy_dns_address_unsupported"),
        None => ("udp", address),
    };
    // Qt replaces scheme strings globally; reject that ambiguous query/path
    // form rather than silently retaining text that its builder would remove.
    if raw.contains("://") {
        return Err("legacy_dns_address_unsupported");
    }
    let (authority, path) = match raw.split_once('/') {
        Some((authority, _)) if matches!(kind, "https" | "h3") => {
            (authority, Some(&raw[authority.len()..]))
        }
        Some(_) => return Err("legacy_dns_address_unsupported"),
        None => (raw, None),
    };
    if authority.contains(['?', '@', '[', ']', '%']) || authority.matches(':').count() > 1 {
        return Err("legacy_dns_address_unsupported");
    }
    if let Some(path) = path {
        let bytes = path.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    return Err("legacy_dns_address_unsupported");
                }
                index += 2;
            }
            index += 1;
        }
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err("legacy_dns_address_unsupported");
            }
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or("legacy_dns_address_unsupported")?;
            (host, Some(port))
        }
        None => (authority, None),
    };
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("legacy_dns_address_unsupported");
    }
    // Numeric hosts must be unambiguous IPv4; Qt's colon parser cannot carry IPv6.
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && host.parse::<std::net::Ipv4Addr>().is_err()
    {
        return Err("legacy_dns_address_unsupported");
    }
    let mut result = json!({"type":kind,"server":host});
    if let Some(port) = port {
        result["server_port"] = json!(port);
    }
    if let Some(path) = path {
        result["path"] = json!(path);
    }
    Ok(result)
}
