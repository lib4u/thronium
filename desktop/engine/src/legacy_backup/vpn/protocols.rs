//! Throne OpenVPN and OpenConnect profiles converted to sing-box endpoint settings.
use super::*;

pub(crate) fn openvpn(source: &SourceProfile) -> Result<Map<String, Value>> {
    let c = &source.outbound;
    let mut out = common(
        source,
        Fields {
            strings: &[
                "mode",
                "network",
                "peer_address",
                "peer_address_ipv6",
                "topology",
                "auth_retry",
                "static_challenge",
                "static_key_path",
                "key_direction",
                "cipher",
                "data_ciphers_fallback",
                "auth",
                "mss_fix_mode",
                "replay_window_time",
                "compression",
                "compression_lzo",
                "allow_compression",
                "route_gateway",
                "ping_interval",
                "ping_restart",
                "renegotiate_interval",
                "tls_timeout",
                "handshake_window",
            ],
            bools: &[
                "remote_random",
                "static_challenge_echo",
                "mss_fix_disabled",
                "route_no_pull",
                "redirect_gateway",
                "redirect_private",
                "block_ipv6",
                "ping_restart_disabled",
                "renegotiate_disabled",
            ],
            ints: &[
                "mss_fix",
                "fragment",
                "replay_window",
                "route_metric",
                "explicit_exit_notify",
            ],
            longs: &["renegotiate_bytes", "renegotiate_packets"],
            lists: &[
                "address",
                "static_key",
                "data_ciphers",
                "routes",
                "redirect_gateway_flags",
            ],
            other: &["tls", "servers", "pull_filters"],
        },
    )?;
    out.insert("type".into(), json!("openvpn-client"));
    let random = out.remove("remote_random");
    if let Some(servers) = c.get("servers") {
        let servers = servers.as_array().ok_or(STRUCTURE)?;
        if !servers.is_empty() {
            let mut remotes = Vec::new();
            for server in servers {
                let remote = normalize(
                    server,
                    Fields {
                        strings: &["server", "network"],
                        ints: &["server_port"],
                        ..Default::default()
                    },
                )?;
                port(server, "server_port")?;
                if !remote
                    .get("server")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty())
                {
                    return Err(STRUCTURE);
                }
                remotes.push(remote);
            }
            out.remove("server");
            out.remove("server_port");
            out.insert("servers".into(), json!(remotes));
            if let Some(random) = random {
                out.insert("remote_random".into(), random);
            }
        }
    }
    if !out.contains_key("servers")
        && !out
            .get("server")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    {
        return Err(STRUCTURE);
    }
    if let Some(filters) = c.get("pull_filters") {
        let mut values = Vec::new();
        for filter in filters.as_array().ok_or(STRUCTURE)? {
            let f = normalize(
                filter,
                Fields {
                    strings: &["action", "text"],
                    ..Default::default()
                },
            )?;
            if f.is_empty() {
                return Err(STRUCTURE);
            }
            values.push(json!({"action":f.get("action").cloned().unwrap_or(json!("")),"text":f.get("text").cloned().unwrap_or(json!(""))}));
        }
        if !values.is_empty() {
            out.insert("pull_filters".into(), json!(values));
        }
    }
    if let Some(tls) = c.get("tls") {
        let mut t = normalize(
            tls,
            Fields {
                strings: &[
                    "server_name",
                    "server_name_type",
                    "certificate_path",
                    "client_certificate_path",
                    "client_key_path",
                    "crl_path",
                    "remote_certificate_eku",
                    "remote_certificate_tls",
                    "certificate_profile",
                    "ns_certificate_type",
                    "version_min",
                    "version_max",
                    "cipher",
                    "groups",
                ],
                lists: &[
                    "certificate",
                    "client_certificate",
                    "client_key",
                    "peer_fingerprint",
                    "remote_certificate_ku",
                ],
                other: &["control_wrap"],
                ..Default::default()
            },
        )?;
        if let Some(wrap) = tls.get("control_wrap") {
            let w = normalize(
                wrap,
                Fields {
                    strings: &["type", "key_path", "direction"],
                    lists: &["key"],
                    ..Default::default()
                },
            )?;
            if !w.is_empty() {
                if !w.contains_key("type") {
                    return Err(STRUCTURE);
                }
                t.insert("control_wrap".into(), json!(w));
            }
        }
        if !t.is_empty() {
            out.insert("tls".into(), json!(t));
        }
    }
    Ok(out)
}
pub(crate) fn openconnect(source: &SourceProfile) -> Result<Map<String, Value>> {
    let c = &source.outbound;
    let mut out = common(
        source,
        Fields {
            strings: &[
                "flavor",
                "auth_group",
                "server_path",
                "cookie",
                "reported_os",
                "user_agent",
                "version",
                "local_hostname",
                "compression_mode",
                "dpd_interval",
                "reconnect_timeout",
                "trojan_interval",
            ],
            bools: &[
                "no_udp",
                "compression_disabled",
                "ipv6_disabled",
                "http_keepalive_disabled",
                "xml_post_disabled",
                "external_auth_disabled",
                "password_authentication_disabled",
                "tcp_keep_alive_enabled",
                "pfs",
                "allow_insecure_crypto",
            ],
            ints: &["dtls_local_port", "base_mtu", "queue_length"],
            other: &[
                "tls",
                "token",
                "mobile",
                "csd",
                "hip",
                "tncc",
                "fortinet_host_check",
                "form_entries",
            ],
            ..Default::default()
        },
    )?;
    if !matches!(
        out.get("flavor").and_then(Value::as_str),
        None | Some("anyconnect")
    ) || out.contains_key("cookie")
        || out.get("password_authentication_disabled") == Some(&json!(true))
    {
        return Err("legacy_vpn_auth_unsupported");
    }
    for key in ["token", "csd", "hip", "tncc", "fortinet_host_check"] {
        if let Some(value) = c.get(key) {
            if !value.as_object().ok_or(STRUCTURE)?.is_empty() {
                return Err("legacy_vpn_auth_unsupported");
            }
        }
    }
    port(c, "dtls_local_port")?;
    let host = out
        .get("server")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or(STRUCTURE)?;
    // Qt wraps valid IPv6 (including a scope) without changing its text.
    // Malformed bracket spellings are refused, never canonicalized.
    let mut server = ipv6_host(host)?;
    if let Some(port) = port(c, "server_port")?.filter(|p| *p > 0 && *p != 443) {
        server.push_str(&format!(":{port}"));
    }
    if let Some(path) = out.remove("server_path") {
        let path = path.as_str().unwrap();
        if !path.starts_with('/') {
            server.push('/');
        }
        server.push_str(path);
    }
    out.insert("server".into(), json!(server));
    out.remove("server_port");
    nested(
        &mut out,
        c,
        "tls",
        Fields {
            bools: &["insecure", "system_trust_disabled"],
            strings: &[
                "server_name",
                "certificate_authority_path",
                "client_certificate_path",
                "client_key_path",
                "client_key_password",
                "mca_certificate_path",
                "mca_key_path",
                "mca_key_password",
            ],
            lists: &[
                "certificate_authority",
                "client_certificate",
                "client_key",
                "peer_fingerprint",
                "mca_certificate",
                "mca_key",
            ],
            ..Default::default()
        },
    )?;
    if let Some(mobile) = c.get("mobile") {
        let mut m = normalize(
            mobile,
            Fields {
                strings: &["platform_version", "device_type", "device_unique_id"],
                ..Default::default()
            },
        )?;
        if !m.is_empty() {
            for key in ["platform_version", "device_type", "device_unique_id"] {
                m.entry(key).or_insert(json!(""));
            }
            out.insert("mobile".into(), json!(m));
        }
    }
    if let Some(entries) = c.get("form_entries") {
        let entries = entries
            .as_array()
            .filter(|a| a.len() <= 128)
            .ok_or(STRUCTURE)?;
        let mut values = Vec::new();
        for entry in entries {
            let e = normalize(
                entry,
                Fields {
                    strings: &["form_id", "submission_key", "name", "value"],
                    bools: &["promote"],
                    ..Default::default()
                },
            )?;
            if !e.contains_key("submission_key")
                && !(e.contains_key("form_id") && e.contains_key("name"))
            {
                return Err(STRUCTURE);
            }
            values.push(json!(e));
        }
        if !values.is_empty() {
            out.insert("form_entries".into(), json!(values));
        }
    }
    Ok(out)
}
