//! Throne outbounds beyond the V2Ray family (Qt `src/configs/outbounds`):
//! Hysteria 1/2, TUIC, Juicity, AnyTLS, TrustTunnel, Mieru, Snell, ShadowTLS,
//! Naive, SSH, Tailscale and Direct. Rows hold `ExportToJson`; each conversion
//! applies what that class's `Build` changes, so the profile sends the core the
//! same outbound Throne did.
use super::*;
use outbound::tls_with;
mod quic;
use quic::{hysteria, hysteria2, quic_defaults};
mod peers;
use peers::{direct, tailscale};

/// Outbound fields and dial fields every server outbound exports.
const COMMON: [&str; 12] = [
    "type",
    "tag",
    "server",
    "server_port",
    "reuse_addr",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
];
const QUIC: [&str; 7] = [
    "idle_timeout",
    "keep_alive_period",
    "stream_receive_window",
    "connection_receive_window",
    "max_concurrent_streams",
    "initial_packet_size",
    "disable_path_mtu_discovery",
];
/// `hysteriaBBRProfiles`; any other value would stop the core from starting.
const BBR_PROFILES: [&str; 3] = ["standard", "conservative", "aggressive"];

type Converted = Result<(ProfileKind, Value), &'static str>;

pub(super) fn supports(kind: &str) -> bool {
    matches!(
        kind,
        "hysteria"
            | "hysteria2"
            | "tuic"
            | "juicity"
            | "anytls"
            | "trusttunnel"
            | "mieru"
            | "snell"
            | "shadowtls"
            | "naive"
            | "ssh"
            | "tailscale"
            | "direct"
    )
}

pub(super) fn convert(
    source: &SourceProfile,
    defaults: &Defaults,
    report: &mut Vec<Issue>,
) -> Converted {
    let mut config = source.outbound.clone();
    // One Qt class serves both versions; the exported type names the version.
    let kind = match (source.kind.as_str(), source.outbound["type"].as_str()) {
        ("hysteria" | "hysteria2", Some(version @ ("hysteria" | "hysteria2"))) => version,
        (kind, _) => kind,
    };
    let (specific, utls): (&[&str], Option<bool>) = match kind {
        "hysteria" => (
            &[
                "server_ports",
                "hop_interval",
                "up_mbps",
                "down_mbps",
                "obfs",
                "auth",
                "auth_str",
                "recv_window_conn",
                "recv_window",
                "disable_mtu_discovery",
                "tls",
            ],
            Some(false),
        ),
        "hysteria2" => (
            &[
                "server_ports",
                "hop_interval",
                "hop_interval_max",
                "up_mbps",
                "down_mbps",
                "obfs",
                "password",
                "bbr_profile",
                "disable_chrome_parrot",
                "realm",
                "tls",
            ],
            Some(false),
        ),
        "tuic" => (
            &[
                "uuid",
                "password",
                "congestion_control",
                "udp_relay_mode",
                "udp_over_stream",
                "zero_rtt_handshake",
                "heartbeat",
                "tls",
            ],
            Some(false),
        ),
        "juicity" => (&["uuid", "password", "tls"], Some(false)),
        "anytls" => (
            &[
                "password",
                "idle_session_check_interval",
                "idle_session_timeout",
                "min_idle_session",
                "tls",
            ],
            Some(true),
        ),
        "trusttunnel" => (
            &[
                "username",
                "password",
                "health_check",
                "quic",
                "quic_congestion_control",
                "tls",
            ],
            Some(true),
        ),
        "naive" => (
            &[
                "username",
                "password",
                "udp_over_tcp",
                "quic",
                "quic_congestion_control",
                "tls",
            ],
            Some(false),
        ),
        "shadowtls" => (&["version", "password", "tls"], Some(true)),
        "mieru" => (
            &[
                "transport",
                "username",
                "password",
                "multiplexing",
                "traffic_pattern",
                "server_ports",
            ],
            None,
        ),
        "snell" => (
            &[
                "version",
                "psk",
                "userkey",
                "reuse",
                "network",
                "mode",
                "obfs_mode",
                "obfs_host",
            ],
            None,
        ),
        "ssh" => (
            &[
                "user",
                "password",
                "private_key",
                "private_key_path",
                "private_key_passphrase",
                "host_key",
                "host_key_algorithms",
                "client_version",
            ],
            None,
        ),
        "tailscale" => return tailscale(source, report),
        "direct" => return direct(source),
        _ => return Err("legacy_profile_type_unsupported"),
    };
    let quic = matches!(kind, "hysteria" | "hysteria2" | "tuic");
    let allowed: Vec<_> = COMMON
        .iter()
        .chain(specific)
        .chain(if quic { &QUIC[..] } else { &[] })
        .copied()
        .collect();
    keys(&config, &allowed)?;
    if config["type"].as_str() != Some(kind) {
        return Err("legacy_profile_discriminator");
    }
    dial(&config)?;
    let realm = config.get("realm").is_some();
    let ports = config
        .get("server_ports")
        .map(|ports| {
            ports
                .as_array()
                .filter(|p| p.iter().all(Value::is_string))
                .map(|p| !p.is_empty())
                .ok_or("legacy_profile_structure")
        })
        .transpose()?
        .unwrap_or(false);
    // Realm replaces the address; port hopping and Mieru ranges replace the port.
    if !realm {
        if !config["server"]
            .as_str()
            .is_some_and(|s| !s.trim().is_empty())
        {
            return Err("legacy_profile_structure");
        }
        match config.get("server_port") {
            Some(port) if port.as_u64().is_some_and(|p| (1..=65535).contains(&p)) => {}
            None if ports => {}
            _ => return Err("legacy_profile_structure"),
        }
    }
    match kind {
        "hysteria" => hysteria(&mut config)?,
        "hysteria2" => hysteria2(&mut config)?,
        "tuic" => {
            uuid(&config)?;
            strings(
                &config,
                &[
                    "password",
                    "congestion_control",
                    "udp_relay_mode",
                    "heartbeat",
                ],
            )?;
            booleans(&config, &["udp_over_stream", "zero_rtt_handshake"])?;
        }
        "juicity" => {
            uuid(&config)?;
            strings(&config, &["password"])?;
        }
        "anytls" => {
            strings(
                &config,
                &[
                    "password",
                    "idle_session_check_interval",
                    "idle_session_timeout",
                ],
            )?;
            counts(&config, &["min_idle_session"])?;
        }
        "trusttunnel" | "naive" => {
            strings(
                &config,
                &["username", "password", "quic_congestion_control"],
            )?;
            booleans(&config, &["health_check", "quic", "udp_over_tcp"])?;
        }
        "shadowtls" => {
            strings(&config, &["password"])?;
            version(&config, &[1, 2, 3])?;
        }
        "mieru" => {
            strings(
                &config,
                &[
                    "transport",
                    "username",
                    "password",
                    "multiplexing",
                    "traffic_pattern",
                ],
            )?;
        }
        "snell" => {
            strings(
                &config,
                &[
                    "psk",
                    "userkey",
                    "network",
                    "mode",
                    "obfs_mode",
                    "obfs_host",
                ],
            )?;
            booleans(&config, &["reuse"])?;
            version(&config, &[1, 2, 3, 4, 5, 6])?;
        }
        "ssh" => {
            strings(
                &config,
                &[
                    "user",
                    "password",
                    "private_key",
                    "private_key_path",
                    "private_key_passphrase",
                    "client_version",
                ],
            )?;
            for key in ["host_key", "host_key_algorithms"] {
                if config.get(key).is_some_and(|v| {
                    !v.as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
                }) {
                    return Err("legacy_profile_structure");
                }
            }
        }
        _ => {}
    }
    if let Some(utls) = utls {
        let secure = config.get("tls").is_some();
        if secure {
            tls_with(&mut config, defaults, utls)?;
        } else if matches!(kind, "hysteria" | "hysteria2" | "anytls") {
            // These classes export and build TLS unconditionally.
            return Err("legacy_profile_structure");
        }
    }
    if quic {
        quic_defaults(&mut config, defaults)?;
    }
    Ok((ProfileKind::SingBoxOutbound, config))
}

fn dial(config: &Value) -> Result<(), &'static str> {
    booleans(
        config,
        &[
            "reuse_addr",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
        ],
    )?;
    strings(
        config,
        &[
            "tag",
            "connect_timeout",
            "bind_interface",
            "inet4_bind_address",
            "inet6_bind_address",
        ],
    )
}

fn strings(config: &Value, list: &[&str]) -> Result<(), &'static str> {
    for key in list {
        optional_string(config, key)?;
    }
    Ok(())
}

fn booleans(config: &Value, list: &[&str]) -> Result<(), &'static str> {
    for key in list {
        optional_bool(config, key)?;
    }
    Ok(())
}

fn counts(config: &Value, list: &[&str]) -> Result<(), &'static str> {
    for key in list {
        if config
            .get(*key)
            .is_some_and(|v| !v.as_u64().is_some_and(|n| n <= u32::MAX as u64))
        {
            return Err("legacy_profile_structure");
        }
    }
    Ok(())
}

fn version(config: &Value, known: &[u64]) -> Result<(), &'static str> {
    match config.get("version").and_then(Value::as_u64) {
        Some(v) if known.contains(&v) => Ok(()),
        _ => Err("legacy_profile_structure"),
    }
}

fn uuid(config: &Value) -> Result<(), &'static str> {
    match optional_string(config, "uuid")? {
        Some(value) if uuid::Uuid::parse_str(value).is_err() => Err("legacy_profile_structure"),
        _ => Ok(()),
    }
}
