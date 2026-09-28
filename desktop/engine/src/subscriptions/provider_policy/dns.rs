//! Happ DNS keys to sing-box servers: DoU/DoH/DoT remote and domestic
//! resolvers, provider hosts records and the FakeIP server FakeDNS maps to.
use serde_json::{json, Value};
use std::net::IpAddr;

pub(super) const FAKE_TAG: &str = "dns-fake";

pub(super) fn server(c: &Value, prefix: &str, tag: &str, detour: &str) -> Result<Value, String> {
    let kind = c[format!("{prefix}DNSType")].as_str().unwrap_or("DoH");
    let default_ip = if prefix == "Remote" {
        "1.1.1.1"
    } else {
        "8.8.8.8"
    };
    let ip = c[format!("{prefix}DNSIP")]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_ip);
    ip.parse::<IpAddr>()
        .map_err(|_| "subscription_dns_unsupported")?;
    let mut server = json!({"tag":tag,"server":ip});
    if detour != "direct" {
        server["detour"] = json!(detour);
    }
    match kind {
        "DoU" => {
            server["type"] = json!("udp");
            server["server_port"] = json!(53)
        }
        "DoH" => {
            let default_domain = if prefix == "Remote" {
                "https://cloudflare-dns.com/dns-query"
            } else {
                "https://dns.google/dns-query"
            };
            let domain = c[format!("{prefix}DNSDomain")]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(default_domain);
            let url = reqwest::Url::parse(domain).map_err(|_| "subscription_dns_unsupported")?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("subscription_dns_unsupported".into());
            }
            server["type"] = json!("https");
            server["server_port"] = json!(url.port().unwrap_or(443));
            server["path"] = json!(url.path());
            server["tls"] = json!({"enabled":true,"server_name":url.host_str().ok_or("subscription_dns_unsupported")?});
        }
        "DoT" => {
            let host = c[format!("{prefix}DNSDomain")]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or("subscription_dns_unsupported")?;
            if host.contains('/') {
                return Err("subscription_dns_unsupported".into());
            }
            server["type"] = json!("tls");
            server["server_port"] = json!(853);
            server["tls"] = json!({"enabled":true,"server_name":host});
        }
        _ => return Err("subscription_dns_unsupported".into()),
    }
    Ok(server)
}

/// `DnsHosts` as a hosts server plus the rule that consults it first.
pub(super) fn hosts(c: &Value) -> Result<Option<(Value, Value)>, String> {
    let Some(hosts) = c.get("DnsHosts").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let hosts = hosts.as_object().ok_or("subscription_dns_unsupported")?;
    let mut names = vec![];
    for (name, addresses) in hosts {
        if name.contains(':') || name.is_empty() {
            return Err("subscription_dns_unsupported".into());
        }
        let addresses = addresses
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![addresses.clone()]);
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|v| v.as_str().is_none_or(|s| s.parse::<IpAddr>().is_err()))
        {
            return Err("subscription_dns_unsupported".into());
        }
        names.push(name);
    }
    if names.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        json!({"type":"hosts","tag":"dns-hosts","predefined":hosts}),
        json!({"domain":names,"action":"route","server":"dns-hosts"}),
    )))
}

/// Xray FakeDNS becomes sing-box FakeIP with the ranges Throne's own
/// converter uses; `sniff` in the first route rule recovers the domain.
pub(super) fn fake_ip() -> (Value, Value) {
    (
        json!({"type":"fakeip","tag":FAKE_TAG,"inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}),
        json!({"query_type":["A","AAAA"],"action":"route","server":FAKE_TAG}),
    )
}

/// Outbounds named by hosts records resolve through them, as Xray does.
pub(super) fn pin_resolvers(core: &mut Value, c: &Value) {
    let Some(hosts) = c["DnsHosts"].as_object() else {
        return;
    };
    for outbound in core["outbounds"].as_array_mut().into_iter().flatten() {
        if outbound.get("domain_resolver").is_none()
            && outbound["server"].as_str().is_some_and(|name| {
                hosts.keys().any(|k| {
                    k.trim_end_matches('.')
                        .eq_ignore_ascii_case(name.trim_end_matches('.'))
                })
            })
        {
            outbound["domain_resolver"] = json!("dns-hosts");
        }
    }
}
