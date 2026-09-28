use crate::{
    proto::LoadConfigReq,
    store::{Profile, ProfileKind},
};
use serde_json::{json, Value};

pub fn build(
    profile: &Profile,
    inbound_port: u16,
    xray_port: Option<u16>,
) -> Result<LoadConfigReq, String> {
    build_with_sources(
        profile,
        inbound_port,
        xray_port,
        &mut crate::vpn_auth::otp::Build::default(),
    )
}

pub(crate) fn build_with_sources(
    profile: &Profile,
    inbound_port: u16,
    xray_port: Option<u16>,
    sources: &mut crate::vpn_auth::otp::Build,
) -> Result<LoadConfigReq, String> {
    if crate::references::key(profile.kind).is_some() {
        return Err("chain_requires_library".into());
    }
    if !profile.config.is_object() || inbound_port == 0 {
        return Err("invalid_configuration".into());
    }
    // proto2's implicit defaults are not pointers in Go. Set the fields dereferenced by
    // the upstream Start implementation explicitly, even when their value is false.
    let mut request = LoadConfigReq {
        core_config: Some(String::new()),
        need_extra_process: Some(false),
        extra_no_out: Some(false),
        need_xray: Some(false),
        disable_stats: Some(false),
        ..Default::default()
    };
    if profile.kind == ProfileKind::SingBoxConfig {
        request.core_config = Some(profile.config.to_string());
        return Ok(request);
    }
    if profile.kind == ProfileKind::ExternalCore {
        let draft = crate::external_core::parse(&profile.config)?;
        let adapter = Profile {
            kind: ProfileKind::SingBoxOutbound,
            config: draft.socks_outbound("proxy")?,
            ..profile.clone()
        };
        let mut request = build(&adapter, inbound_port, None)?;
        crate::external_core::runtime::attach(&mut request, profile)?;
        return Ok(request);
    }
    let mut outbound = profile.config.clone();
    if matches!(
        profile.kind,
        ProfileKind::XrayConfig | ProfileKind::XrayOutbound
    ) {
        let port = xray_port.ok_or("xray_port_missing")?;
        let mut xray = if profile.kind == ProfileKind::XrayConfig {
            profile.config.clone()
        } else {
            outbound["tag"] = json!("proxy");
            json!({"outbounds":[outbound]})
        };
        let inbound = json!({"tag":"thronium-in", "listen":"127.0.0.1", "port":port, "protocol":"socks", "settings":{"auth":"noauth", "udp":true}});
        if profile.kind == ProfileKind::XrayConfig {
            xray = managed_xray_inbound(&xray, inbound)?;
        } else {
            match xray.get_mut("inbounds") {
                Some(Value::Array(list)) => list.push(inbound),
                None => {
                    xray["inbounds"] = json!([inbound]);
                }
                _ => return Err("invalid_xray_inbounds".into()),
            }
        }
        request.need_xray = Some(true);
        request.xray_config = Some(xray.to_string());
        outbound = json!({"type":"socks", "server":"127.0.0.1", "server_port":port, "version":"5"});
    }
    if outbound.get("type").and_then(Value::as_str).is_none() {
        return Err("protocol_type_required".into());
    }
    outbound["tag"] = json!("proxy");
    let endpoint = crate::chains::is_endpoint_type(&outbound);
    let mut core = json!({
        "log":{"level":"warn", "disabled":false},
        "services":[{"type":"api", "listen":"127.0.0.1", "listen_port":0}],
        "inbounds":[{"type":"mixed", "tag":"mixed-in", "listen":"127.0.0.1", "listen_port":inbound_port}],
        "outbounds":[{"type":"direct", "tag":"direct"}],
        "route":{"final":"proxy", "auto_detect_interface":true, "default_domain_resolver":"dns-direct", "rules":[]},
        "dns":{"servers":[{"type":"local", "tag":"dns-direct"}], "final":"dns-direct"}
    });
    if endpoint {
        sources.emit(profile, "proxy", &outbound)?;
        core["endpoints"] = json!([outbound]);
    } else {
        core["outbounds"]
            .as_array_mut()
            .unwrap()
            .insert(0, outbound);
    }
    if profile.kind == ProfileKind::XrayConfig && profile.config.get("dns").is_some() {
        let (port, _listener) =
            crate::loopback_ports::claim(&Default::default()).ok_or("xray_port_missing")?;
        let mut xray: Value = serde_json::from_str(request.xray_config.as_deref().unwrap())
            .map_err(|_| "invalid_configuration")?;
        if xray["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|o| o["tag"] == "thronium-dns")
            || xray["inbounds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|o| o["tag"] == "thronium-dns")
        {
            return Err("route_tag_conflict".into());
        }
        xray["inbounds"].as_array_mut().unwrap().push(json!({"tag":"thronium-dns","listen":"127.0.0.1","port":port,"protocol":"dokodemo-door","settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}}));
        xray["outbounds"]
            .as_array_mut()
            .ok_or("invalid_configuration")?
            .push(
                json!({"tag":"thronium-dns","protocol":"dns","settings":{"nonIPQuery":"reject"}}),
            );
        if xray.get("routing").is_none() {
            xray["routing"] = json!({"rules":[]})
        }
        if xray["routing"].get("rules").is_none() {
            xray["routing"]["rules"] = json!([])
        }
        xray["routing"]["rules"]
            .as_array_mut()
            .ok_or("invalid_configuration")?
            .insert(
                0,
                json!({"type":"field","inboundTag":["thronium-dns"],"outboundTag":"thronium-dns"}),
            );
        core["dns"] = json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":port}],"final":"dns-direct","reverse_mapping":true});
        request.xray_config = Some(xray.to_string());
    }
    request.core_config = Some(core.to_string());
    Ok(request)
}

/// A managed client exposes exactly one local proxy: replace the user's
/// socks/http inbounds by `inbound`, keeping their first socks inbound's tag and
/// sniffing so their own routing rules still match. Rules bound to any other
/// inbound cannot be transferred silently. Outbounds, routing and DNS stay theirs.
pub(crate) fn managed_xray_inbound(config: &Value, mut inbound: Value) -> Result<Value, String> {
    let mut xray = config.clone();
    let original = xray["inbounds"].as_array().cloned().unwrap_or_default();
    if original
        .iter()
        .any(|i| !matches!(i["protocol"].as_str(), Some("socks" | "http")))
    {
        return Err("xray_client_inbounds_unsupported".into());
    }
    let source = original
        .iter()
        .find(|i| i["protocol"] == "socks")
        .or(original.first());
    if let Some(source) = source {
        if let Some(sniffing) = source.get("sniffing") {
            inbound["sniffing"] = sniffing.clone();
        }
        if let Some(tag) = source.get("tag") {
            inbound["tag"] = tag.clone();
        }
    }
    for rule in xray["routing"]["rules"].as_array().into_iter().flatten() {
        if let Some(tags) = rule.get("inboundTag") {
            let tags = tags
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![tags.clone()]);
            if tags.iter().any(|tag| tag != &inbound["tag"]) {
                return Err("xray_client_inbound_rules_unsupported".into());
            }
        }
    }
    xray["inbounds"] = json!([inbound]);
    Ok(xray)
}

// Complete configurations own their inbounds. Do not advertise a proxy that
// was never configured, or silently replace their routing/inbound settings.
/// Inbound kinds a program can use as an HTTP proxy, such as the OS proxy.
pub const HTTP_PROXY: &[&str] = &["mixed", "http"];
/// Inbound kinds shown as the local proxy address, where SOCKS is usable too.
pub const ANY_PROXY: &[&str] = &["mixed", "http", "socks"];

/// A listener of a core configuration that other programs connect to.
pub struct LocalInbound<'a> {
    pub host: &'a str,
    pub port: u16,
    pub inbound: &'a Value,
}
impl LocalInbound<'_> {
    /// `host:port`, with IPv6 in brackets and wildcard hosts as loopback.
    pub fn address(&self) -> String {
        let host = match self.host {
            "0.0.0.0" => "127.0.0.1",
            "::" => "::1",
            host => host,
        };
        if host.contains(':') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }
}
/// The listener programs reach: Thronium's own `mixed-in` when present,
/// otherwise the first listener of one of `kinds`. Every caller that hands a
/// proxy to another program chooses through this one rule.
pub fn local_inbound<'a>(core: &'a Value, kinds: &[&str]) -> Option<LocalInbound<'a>> {
    let inbounds = core.get("inbounds")?.as_array()?;
    let usable = |inbound: &&'a Value| {
        inbound["type"]
            .as_str()
            .is_some_and(|kind| kinds.contains(&kind))
            && inbound["listen_port"]
                .as_u64()
                .is_some_and(|port| port > 0 && port <= 65535)
    };
    let inbound = inbounds
        .iter()
        .filter(usable)
        .find(|inbound| inbound["tag"] == "mixed-in")
        .or_else(|| inbounds.iter().find(usable))?;
    Some(LocalInbound {
        host: inbound["listen"].as_str().unwrap_or("127.0.0.1"),
        port: inbound["listen_port"].as_u64()? as u16,
        inbound,
    })
}
/// Inbound port of configurations built only to be inspected or measured in
/// isolation; a real start replaces it with the user's or a free port.
pub const PLACEHOLDER_INBOUND_PORT: u16 = 2080;
pub fn local_proxy(profile: &Profile, port: u16) -> Option<String> {
    if profile.kind != ProfileKind::SingBoxConfig {
        return Some(format!("127.0.0.1:{port}"));
    }
    local_inbound(&profile.config, ANY_PROXY).map(|inbound| inbound.address())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(kind: ProfileKind, config: Value) -> Profile {
        Profile {
            vpn_policy: None,
            id: "p".into(),
            name: "P".into(),
            group_id: "personal".into(),
            config,
            kind,
            favorite: false,
        }
    }
    #[test]
    fn amnezia_parameters_reserved_bytes_and_udp_timeout_reach_the_endpoint_unchanged() {
        let awg = json!({"h1":"10-20", "i1":"<b 0xabcdef>", "random_trailers":true, "future":1});
        let peers = json!([{"address":"203.0.113.5","port":51820,"public_key":"cHVibGlj","reserved":[1,2,3],"allowed_ips":["0.0.0.0/0"]}]);
        let p = profile(
            ProfileKind::SingBoxOutbound,
            json!({"type":"wireguard", "amnezia_wg":awg, "private_key":"secret", "udp_timeout":"30s", "peers":peers}),
        );
        let req = build(&p, 2080, None).unwrap();
        let config: Value = serde_json::from_str(&req.core_config.unwrap()).unwrap();
        assert_eq!(config["endpoints"][0]["amnezia_wg"], awg);
        assert_eq!(config["endpoints"][0]["private_key"], "secret");
        assert_eq!(config["endpoints"][0]["udp_timeout"], "30s");
        assert_eq!(config["endpoints"][0]["peers"], peers);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    }
    #[test]
    fn opaque_full_config_retains_routing_and_inbounds() {
        let raw = json!({"inbounds":[],"route":{"rules":[{"action":"reject"}]}, "experimental":{"cache_file":{"enabled":true}}});
        let req = build(
            &profile(ProfileKind::SingBoxConfig, raw.clone()),
            2080,
            None,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&req.core_config.unwrap()).unwrap(),
            raw
        );
        assert_eq!(req.need_extra_process, Some(false));
        assert_eq!(
            local_proxy(&profile(ProfileKind::SingBoxConfig, raw), 2080),
            None
        );
        assert_eq!(
            local_proxy(
                &profile(
                    ProfileKind::SingBoxConfig,
                    json!({"inbounds":[{"type":"mixed", "listen":"::1", "listen_port":2090}]})
                ),
                2080
            ),
            Some("[::1]:2090".into())
        );
    }
    #[test]
    fn programs_get_the_http_capable_listener_and_prefer_thronium_mixed_in() {
        let core = json!({"inbounds":[
            {"type":"socks","tag":"custom","listen":"127.0.0.1","listen_port":1080},
            {"type":"http","tag":"other","listen":"0.0.0.0","listen_port":8080},
            {"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":40123}
        ]});
        assert_eq!(local_inbound(&core, HTTP_PROXY).unwrap().port, 40123);
        let without_mixed = json!({"inbounds":[
            {"type":"socks","listen":"127.0.0.1","listen_port":1080},
            {"type":"http","listen":"0.0.0.0","listen_port":8080}
        ]});
        let http = local_inbound(&without_mixed, HTTP_PROXY).unwrap();
        assert_eq!(
            http.address(),
            "127.0.0.1:8080",
            "a SOCKS port is never an HTTP proxy"
        );
        assert_eq!(local_inbound(&without_mixed, ANY_PROXY).unwrap().port, 1080);
        let socks_only =
            json!({"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":1080}]});
        assert!(local_inbound(&socks_only, HTTP_PROXY).is_none());
    }
    #[test]
    fn xray_transport_and_reality_survive_bridge_generation() {
        let stream = json!({"network":"xhttp", "security":"reality", "realitySettings":{"serverName":"example.com"}, "xhttpSettings":{"path":"/route"}});
        let req = build(
            &profile(
                ProfileKind::XrayOutbound,
                json!({"protocol":"vless", "settings":{}, "streamSettings":stream}),
            ),
            2080,
            Some(2190),
        )
        .unwrap();
        let xray: Value = serde_json::from_str(&req.xray_config.unwrap()).unwrap();
        assert_eq!(xray["outbounds"][0]["streamSettings"], stream);
        assert_eq!(xray["inbounds"][0]["port"], 2190);
        assert_eq!(req.need_xray, Some(true));
    }
}
