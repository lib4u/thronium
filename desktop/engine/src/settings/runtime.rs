use super::{boolean as b, integer as n, string as s, value as v};
use crate::{
    proto::LoadConfigReq,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};
mod tls;
fn inherit(o: &mut Value, key: &str, value: Value) {
    if o.get(key).is_none() {
        o[key] = value;
    }
}
fn h2(o: &mut Value, l: &Library) {
    for (key, setting) in [
        ("idle_timeout", "h2_idle_timeout"),
        ("keep_alive_period", "h2_keep_alive_period"),
        ("stream_receive_window", "h2_stream_receive_window"),
        ("connection_receive_window", "h2_connection_receive_window"),
    ] {
        if !s(l, setting).is_empty() {
            inherit(o, key, v(l, setting));
        }
    }
    if n(l, "h2_max_concurrent_streams") > 0 {
        inherit(
            o,
            "max_concurrent_streams",
            v(l, "h2_max_concurrent_streams"),
        );
    }
}
fn preset(p: &mut Profile, l: &Library) {
    let o = &mut p.config;
    if p.kind == ProfileKind::SingBoxOutbound {
        tls::prepare(o, l);
        if matches!(
            o["type"].as_str(),
            Some("shadowsocks" | "vmess" | "trojan" | "vless")
        ) {
            if o.get("multiplex").is_none() && b(l, "mux_default_on") {
                o["multiplex"] = json!({"enabled":true});
            }
            if o["multiplex"]["enabled"] == true {
                let mux = &mut o["multiplex"];
                inherit(mux, "protocol", v(l, "mux_protocol"));
                super::singbox::mux_limits(mux, l);
                if b(l, "mux_padding") {
                    inherit(mux, "padding", json!(true));
                }
            }
        }
        if o["tls"]["enabled"] == true {
            let tls = &mut o["tls"];
            if b(l, "skip_cert") {
                inherit(tls, "insecure", json!(true));
            }
            if !s(l, "utlsFingerprint").is_empty() {
                inherit(
                    tls,
                    "utls",
                    json!({"enabled":true,"fingerprint":s(l,"utlsFingerprint")}),
                );
            }
            if b(l, "fragment_default_on")
                && tls.get("fragment").is_none()
                && o.get("tls_fragment").is_none()
            {
                if s(l, "fragment_implementation") == "custom" {
                    if o["tcp_fast_open"] != true {
                        o["tls_fragment"] = json!({"enabled":true,"size":s(l,"fragment_size"),"sleep":s(l,"fragment_sleep")});
                    }
                } else {
                    o["tls"]["fragment"] = json!(true);
                }
            }
        }
        if o["transport"]["type"] == "http" && !s(l, "h2_idle_timeout").is_empty() {
            inherit(&mut o["transport"], "idle_timeout", v(l, "h2_idle_timeout"));
        }
        if matches!(
            o["type"].as_str(),
            Some("hysteria" | "hysteria2" | "tuic" | "juicity")
        ) {
            h2(o, l);
            if n(l, "quic_initial_packet_size") > 0 {
                inherit(o, "initial_packet_size", v(l, "quic_initial_packet_size"));
            }
            if b(l, "quic_disable_path_mtu_discovery") {
                inherit(o, "disable_path_mtu_discovery", json!(true));
            }
        }
        super::singbox::prepare_outbound(o, l);
    } else if p.kind == ProfileKind::XrayOutbound {
        super::xray::prepare_outbound(o, l);
        for key in ["tlsSettings", "realitySettings"] {
            if o["streamSettings"][key].is_object() {
                let tls = &mut o["streamSettings"][key];
                if key == "tlsSettings" && b(l, "skip_cert") {
                    inherit(tls, "allowInsecure", json!(true));
                }
                if !s(l, "utlsFingerprint").is_empty() {
                    inherit(tls, "fingerprint", v(l, "utlsFingerprint"));
                }
            }
        }
    }
}
pub fn prepare_profiles(library: &mut Library, profile: &mut Profile) {
    let settings = library.clone();
    for p in &mut library.profiles {
        preset(p, &settings);
    }
    preset(profile, &settings);
}
// A disposable single-endpoint probe has no graph to normalize. Borrow the
// settings so a measurement cache check never clones unrelated credentials.
pub(crate) fn prepare_profile(profile: &mut Profile, library: &Library) {
    preset(profile, library);
}
pub fn apply(request: &mut LoadConfigReq, profile: &Profile, l: &Library) -> Result<(), String> {
    if profile.kind == ProfileKind::SingBoxConfig {
        return Ok(());
    }
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    core["log"] = json!({"level":s(l,"log_level"),"disabled":false});
    request.disable_stats = Some(b(l, "disable_traffic_stats"));
    let inbounds = core["inbounds"]
        .as_array_mut()
        .ok_or("invalid_configuration")?;
    if b(l, "disable_mixed_inbound") {
        inbounds.retain(|i| i["tag"] != "mixed-in");
    } else if let Some(inbound) = inbounds.iter_mut().find(|i| i["tag"] == "mixed-in") {
        inbound["listen"] = v(l, "inbound_address");
        if b(l, "random_inbound_port") {
            let host = s(l, "inbound_address")
                .parse::<std::net::IpAddr>()
                .map_err(|_| "settings_invalid:inbound_address")?;
            let listener = std::net::TcpListener::bind((host, 0))
                .map_err(|_| "settings_invalid:inbound_address")?;
            inbound["listen_port"] = json!(listener
                .local_addr()
                .map_err(|_| "invalid_configuration")?
                .port());
        }
        if b(l, "inbound_auth") {
            inbound["users"] =
                json!([{"username":s(l,"inbound_user"),"password":s(l,"inbound_pass")}]);
        }
    }
    for inbound in v(l, "custom_inbound").as_array().into_iter().flatten() {
        if !inbound.is_object()
            || inbound["tag"]
                .as_str()
                .is_some_and(|tag| inbounds.iter().any(|i| i["tag"] == tag))
        {
            return Err("settings_invalid:custom_inbound".into());
        }
        inbounds.push(inbound.clone());
    }
    if b(l, "use_mozilla_certs") {
        core["certificate"] = json!({"store":"mozilla"});
    }
    if b(l, "core_box_clash_enabled") {
        if !core["experimental"].is_object() {
            core["experimental"] = json!({});
        }
        let host = s(l, "core_box_clash_listen_addr");
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        core["experimental"]["clash_api"] = json!({"external_controller":format!("{}:{}",host,n(l,"core_box_clash_api")),"secret":s(l,"core_box_clash_api_secret")});
        if !s(l, "core_box_clash_ui").is_empty() {
            core["experimental"]["clash_api"]["external_ui"] = v(l, "core_box_clash_ui");
        }
    }
    if b(l, "core_box_api_enabled") {
        let services = core["services"]
            .as_array_mut()
            .ok_or("invalid_configuration")?;
        if let Some(api) = services.iter_mut().find(|service| service["type"] == "api") {
            api["listen_port"] = v(l, "core_box_api_port");
            api["dashboard"] = v(l, "core_box_api_dashboard");
            api["access_control_allow_origin"] =
                json!([format!("http://127.0.0.1:{}", n(l, "core_box_api_port"))]);
            if !s(l, "core_box_api_secret").is_empty() {
                api["secret"] = v(l, "core_box_api_secret");
            }
        }
    }
    if !b(l, "enable_stats") && !b(l, "core_box_api_enabled") {
        if let Some(services) = core["services"].as_array_mut() {
            services.retain(|s| s["type"] != "api");
        }
    }
    if b(l, "enable_ntp") {
        core["ntp"] = json!({"enabled":true,"server":s(l,"ntp_server_address"),"server_port":n(l,"ntp_server_port"),"interval":s(l,"ntp_interval"),"detour":s(l,"ntp_outbound")});
    }
    super::intercept::apply(&mut core, l, &profile.kind)?;
    super::intercept::follow_routing(&mut core, l)?;
    request.core_config = Some(core.to_string());
    super::xray::apply(request, profile, l)
}
