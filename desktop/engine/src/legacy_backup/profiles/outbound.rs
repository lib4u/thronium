//! Throne outbound settings (TLS, multiplex, VLESS core) converted into profile configurations.
use super::*;

pub(super) struct Defaults<'a> {
    pub(super) values: BTreeMap<&'a str, &'a str>,
}
impl<'a> Defaults<'a> {
    pub(super) fn new(db: &'a SourceDatabase) -> Result<Self, Vec<Issue>> {
        let mut values = BTreeMap::new();
        for setting in &db.settings {
            let invalid = if matches!(
                setting.key.as_str(),
                "mux_default_on"
                    | "quic_disable_path_mtu_discovery"
                    | "mux_padding"
                    | "fragment_default_on"
                    | "tls_spoof_default_on"
                    | "tls_tricks_default_on"
                    | "skip_cert"
                    | "xray_mux_default_on"
                    | "net_use_proxy"
            ) {
                !matches!(setting.value.as_str(), "true" | "false" | "1" | "0")
            } else if matches!(
                setting.key.as_str(),
                "mux_concurrency" | "h2_max_concurrent_streams" | "quic_initial_packet_size"
            ) {
                setting.value.parse::<i64>().is_err()
            } else {
                false
            };
            if invalid {
                return Err(vec![issue(
                    "legacy_profile_defaults_invalid",
                    Some("database"),
                    None,
                    None,
                )]);
            }
            if values
                .insert(setting.key.as_str(), setting.value.as_str())
                .is_some()
            {
                return Err(vec![issue(
                    "legacy_settings_duplicate",
                    Some("database"),
                    None,
                    None,
                )]);
            }
        }
        Ok(Self { values })
    }
    pub(super) fn boolean(&self, key: &str) -> bool {
        matches!(self.values.get(key).copied(), Some("true" | "1"))
    }
    pub(super) fn string(&self, key: &str, default: &'a str) -> &'a str {
        self.values.get(key).copied().unwrap_or(default)
    }
    pub(super) fn integer(&self, key: &str, default: i64) -> i64 {
        self.values
            .get(key)
            .map(|s| s.parse().expect("consumed integer settings were validated"))
            .unwrap_or(default)
    }
}

pub(super) fn tls(config: &mut Value, defaults: &Defaults) -> Result<(), &'static str> {
    tls_with(config, defaults, true)
}
/// `utls` is false for classes whose TLS never builds a uTLS object
/// (`tls->utls->supported = false`: Hysteria, TUIC, Juicity, Naive).
pub(super) fn tls_with(
    config: &mut Value,
    defaults: &Defaults,
    utls_supported: bool,
) -> Result<(), &'static str> {
    let Some(tls) = config.get_mut("tls") else {
        return Ok(());
    };
    keys(
        tls,
        &[
            "enabled",
            "disable_sni",
            "server_name",
            "insecure",
            "alpn",
            "min_version",
            "max_version",
            "cipher_suites",
            "curve_preferences",
            "certificate",
            "certificate_path",
            "certificate_public_key_sha256",
            "client_certificate",
            "client_certificate_path",
            "client_key",
            "client_key_path",
            "fragment",
            "fragment_fallback_delay",
            "record_fragment",
            "spoof_enabled",
            "spoof",
            "spoof_method",
            "tls_tricks",
            "ech",
            "utls",
            "reality",
        ],
    )?;
    if optional_bool(tls, "enabled")? != Some(true) {
        return Err("legacy_profile_structure");
    }
    for key in [
        "disable_sni",
        "insecure",
        "fragment",
        "record_fragment",
        "spoof_enabled",
    ] {
        optional_bool(tls, key)?;
    }
    for key in [
        "server_name",
        "min_version",
        "max_version",
        "fragment_fallback_delay",
        "spoof",
        "spoof_method",
    ] {
        optional_string(tls, key)?;
    }
    for key in [
        "alpn",
        "cipher_suites",
        "curve_preferences",
        "certificate",
        "certificate_public_key_sha256",
        "client_certificate",
        "client_key",
    ] {
        if let Some(value) = tls.get(key) {
            if !value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
            {
                return Err("legacy_profile_structure");
            }
        }
    }
    // Certificate, key and ECH files stay as written; the review offers them as
    // selectable resources and the merge refuses unreplaced paths.
    // These three client tri-states do not exist as such in the core. Off is
    // frozen explicitly so the destination's current defaults cannot enable it.
    let fragment =
        optional_bool(tls, "fragment")?.unwrap_or_else(|| defaults.boolean("fragment_default_on"));
    let spoof = optional_string(tls, "spoof")?.unwrap_or("");
    let spoof_on = optional_bool(tls, "spoof_enabled")?
        .unwrap_or_else(|| !spoof.is_empty() || defaults.boolean("tls_spoof_default_on"));
    let spoof = if spoof_on {
        if spoof.is_empty() {
            defaults.string("tls_spoof", "").trim()
        } else {
            spoof
        }
    } else {
        ""
    }
    .to_owned();
    let method = optional_string(tls, "spoof_method")?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| defaults.string("tls_spoof_method", "").trim())
        .to_owned();
    let tricks = if let Some(value) = tls.get("tls_tricks") {
        keys(value, &["mixedcase_sni"])?;
        optional_bool(value, "mixedcase_sni")?.ok_or("legacy_profile_structure")?
    } else {
        defaults.boolean("tls_tricks_default_on")
    };
    // Privileged spoofing, fragment implementations and TLS tricks need their
    // own cross-core fixtures before we claim a legacy conversion for them.
    if fragment
        || !spoof.is_empty()
        || tricks
        || optional_bool(tls, "record_fragment")? == Some(true)
    {
        return Err("legacy_profile_tls_tricks_unsupported");
    }
    tls.as_object_mut().unwrap().remove("spoof_enabled");
    tls["spoof"] = json!(spoof);
    tls["spoof_method"] = json!(if spoof_on { method } else { String::new() });
    tls["fragment"] = json!(false);
    tls["tls_tricks"] = json!({"mixedcase_sni":false});
    tls["insecure"] =
        json!(optional_bool(tls, "insecure")?.unwrap_or(false) || defaults.boolean("skip_cert"));
    // Qt writes `query_server_name` (src/configs/common/TLS.cpp); it never
    // wrote a plain `server_name` under `ech`.
    if let Some(ech) = tls.get("ech") {
        keys(
            ech,
            &["enabled", "config", "config_path", "query_server_name"],
        )?;
    }
    if let Some(reality) = tls.get("reality") {
        keys(reality, &["enabled", "public_key", "short_id"])?;
    }
    if !utls_supported {
        tls.as_object_mut().unwrap().remove("utls");
        return Ok(());
    }
    let mut utls = tls
        .get("utls")
        .cloned()
        .unwrap_or_else(|| json!({"enabled":false}));
    keys(&utls, &["enabled", "fingerprint"])?;
    let enabled = optional_bool(&utls, "enabled")?.unwrap_or(false);
    let fingerprint = optional_string(&utls, "fingerprint")?.unwrap_or("");
    let global = defaults.string("utlsFingerprint", "");
    if (!enabled || fingerprint.is_empty()) && !global.is_empty() {
        utls = json!({"enabled":true,"fingerprint":global});
    } else if !enabled && tls["reality"]["enabled"] == true {
        utls = json!({"enabled":true,"fingerprint":"random"});
    }
    tls["utls"] = utls;
    Ok(())
}
pub(super) fn multiplex(config: &mut Value, defaults: &Defaults) -> Result<(), &'static str> {
    let mut mux = config
        .get("multiplex")
        .cloned()
        .unwrap_or_else(|| json!({}));
    keys(
        &mux,
        &[
            "enabled",
            "protocol",
            "max_connections",
            "min_streams",
            "max_streams",
            "padding",
            "brutal",
        ],
    )?;
    for key in ["max_connections", "min_streams", "max_streams"] {
        if mux.get(key).is_some_and(|value| {
            !value
                .as_u64()
                .is_some_and(|n| n > 0 && n <= u32::MAX as u64)
        }) {
            return Err("legacy_profile_structure");
        }
    }
    let enabled =
        optional_bool(&mux, "enabled")?.unwrap_or_else(|| defaults.boolean("mux_default_on"));
    if !enabled {
        config["multiplex"] = json!({"enabled":false});
        return Ok(());
    }
    mux["enabled"] = json!(true);
    if optional_string(&mux, "protocol")?.unwrap_or("").is_empty() {
        mux["protocol"] = json!(defaults.string("mux_protocol", "smux"));
    }
    if !matches!(mux["protocol"].as_str(), Some("smux" | "yamux" | "h2mux")) {
        return Err("legacy_profile_mux_unsupported");
    }
    if !["max_connections", "min_streams", "max_streams"]
        .iter()
        .any(|key| mux[*key].as_i64().is_some_and(|n| n > 0))
    {
        mux["max_streams"] = json!(defaults.integer("mux_concurrency", 8));
    }
    mux["padding"] =
        json!(optional_bool(&mux, "padding")?.unwrap_or(false) || defaults.boolean("mux_padding"));
    if let Some(brutal) = mux.get("brutal") {
        keys(brutal, &["enabled", "up_mbps", "down_mbps"])?;
    }
    config["multiplex"] = mux;
    Ok(())
}
