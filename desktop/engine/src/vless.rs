//! VLESS core selection changes the runtime, never the saved source configuration.
use crate::{
    store::{Library, Profile, ProfileKind},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Core {
    #[default]
    Xray,
    SingBox,
}

pub fn is_vless(p: &Profile) -> bool {
    match p.kind {
        ProfileKind::SingBoxOutbound => p.config["type"] == "vless",
        ProfileKind::XrayOutbound => p.config["protocol"] == "vless",
        _ => false,
    }
}
pub(crate) fn compile(
    p: &Profile,
    default: Core,
    overrides: &BTreeMap<String, Core>,
) -> Result<Profile, String> {
    if !is_vless(p) {
        return Ok(p.clone());
    }
    let mut result = p.clone();
    match overrides.get(&p.id).copied().unwrap_or(default) {
        Core::Xray if p.kind == ProfileKind::SingBoxOutbound => {
            result.config = to_xray(&p.config)?;
            result.kind = ProfileKind::XrayOutbound;
        }
        Core::SingBox if p.kind == ProfileKind::XrayOutbound => {
            result.config = to_singbox(&p.config)?;
            result.kind = ProfileKind::SingBoxOutbound;
        }
        _ => {}
    }
    Ok(result)
}
// Preserve the core of pre-existing profiles during the one-time schema migration.
pub(crate) fn migrate(value: &mut Value) {
    if value["preferences"].get("vlessCore").is_none() {
        let mut overrides = json!({});
        for p in value["profiles"].as_array().into_iter().flatten() {
            if let Some(id) = p["id"].as_str() {
                if p["kind"] == "sing-box-outbound" && p["config"]["type"] == "vless" {
                    overrides[id] = json!("sing-box")
                }
                if p["kind"] == "xray-outbound" && p["config"]["protocol"] == "vless" {
                    overrides[id] = json!("xray")
                }
            }
        }
        value["preferences"]["vlessCore"] = json!("xray");
        value["preferences"]["vlessOverrides"] = overrides;
    }
}
pub(crate) fn roots(
    source: &Library,
    selected: &Profile,
) -> Result<std::collections::HashSet<String>, String> {
    let mut needed = std::collections::HashSet::from([selected.id.clone()]);
    // Auxiliary routing targets, including nested chains, use the same compiler.
    fn refs(v: &Value, ids: &mut std::collections::HashSet<String>) {
        match v {
            Value::String(s) => {
                if let Some(id) = s.strip_prefix("profile:") {
                    ids.insert(id.into());
                }
            }
            Value::Array(a) => {
                for v in a {
                    refs(v, ids)
                }
            }
            Value::Object(o) => {
                for v in o.values() {
                    refs(v, ids)
                }
            }
            _ => {}
        }
    }
    if !matches!(
        selected.kind,
        ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
    ) && !crate::geodata::enabled(selected, source)
    {
        refs(
            &serde_json::to_value(source.routing.active()?).map_err(|_| "invalid_routing")?,
            &mut needed,
        )
    }
    Ok(needed)
}
pub(crate) fn relevant(
    source: &Library,
    selected: &Profile,
) -> Result<std::collections::HashSet<String>, String> {
    let mut library = source.clone();
    if let Some(p) = library.profiles.iter_mut().find(|p| p.id == selected.id) {
        *p = selected.clone();
    } else {
        library.profiles.push(selected.clone());
    }
    Ok(crate::group_chains::dependencies(
        &library,
        &roots(source, selected)?,
    ))
}
pub(crate) fn library(source: &Library, selected: &Profile) -> Result<(Library, Profile), String> {
    let mut library = source.clone();
    if let Some(profile) = library.profiles.iter_mut().find(|p| p.id == selected.id) {
        *profile = selected.clone();
    } else {
        library.profiles.push(selected.clone());
    }
    let resolution_source = library.clone();
    let needed = relevant(source, selected)?;
    // Resolve a fresh pool for each build, before compiling the members' core
    // choices. The persisted group/filter and active request remain unchanged.
    for p in &mut library.profiles {
        if needed.contains(&p.id) {
            *p = crate::auto_selector::materialize(p, &resolution_source)?;
            *p = compile(
                p,
                source.preferences.vless_core,
                &source.preferences.vless_overrides,
            )?
        }
    }
    let selected = compile(
        &crate::auto_selector::materialize(selected, &resolution_source)?,
        source.preferences.vless_core,
        &source.preferences.vless_overrides,
    )?;
    Ok((library, selected))
}
impl Engine {
    pub async fn check_vless_choice(
        &mut self,
        mut profile: Profile,
        core: Option<Core>,
    ) -> Result<(), String> {
        if !is_vless(&profile) {
            return Err("vless_core_profile_required".into());
        }
        if profile.id.is_empty() {
            profile.id = uuid::Uuid::new_v4().to_string();
        }
        let mut next = self.store.library.clone();
        match core {
            Some(c) => {
                next.preferences
                    .vless_overrides
                    .insert(profile.id.clone(), c);
            }
            None => {
                next.preferences.vless_overrides.remove(&profile.id);
            }
        }
        // Keep the ID so client routing references to this server also validate
        // against the proposed configuration, without modifying the library.
        next.profiles.retain(|p| p.id != profile.id);
        next.profiles.push(profile.clone());
        crate::store::validate_library(&next)?;
        self.check_with_library(&profile, &next).await
    }
    pub fn vless_core(&mut self, id: &str, core: Option<Core>) -> Result<(), String> {
        let p = self.profile(id)?;
        if !is_vless(&p) {
            return Err("vless_core_profile_required".into());
        }
        let mut next = self.store.library.clone();
        match core {
            Some(c) => {
                next.preferences.vless_overrides.insert(id.into(), c);
            }
            None => {
                next.preferences.vless_overrides.remove(id);
            }
        }
        compile(
            &p,
            next.preferences.vless_core,
            &next.preferences.vless_overrides,
        )?;
        self.url_tests_resettable()?;
        let committed = self.store.commit(next);
        if crate::store::Store::written(&committed) {
            self.reset_url_tests_after_commit();
            if self.running_uses(id) {
                self.routing_revision = None;
            }
        }
        committed
    }
}
fn keys(v: &Value, allowed: &[&str]) -> Result<(), String> {
    if v.is_null() {
        return Ok(());
    }
    if v.as_object()
        .is_none_or(|o| o.keys().any(|k| !allowed.contains(&k.as_str())))
    {
        return Err("vless_core_conversion_unsupported".into());
    }
    Ok(())
}
fn copy(source: &Value, target: &mut Value, mapping: &[(&str, &str)]) {
    for (from, to) in mapping {
        if let Some(v) = source.get(from) {
            target[*to] = v.clone()
        }
    }
}
/// Xray WebSocket and HTTPUpgrade headers are single strings; sing-box allows
/// lists, so only one-element lists convert.
fn single_valued_headers(settings: &mut Value) -> Result<(), String> {
    let Some(headers) = settings["headers"].as_object_mut() else {
        return Ok(());
    };
    for v in headers.values_mut() {
        if let Some(a) = v.as_array() {
            if a.len() != 1 {
                return Err("vless_core_conversion_unsupported".into());
            }
            *v = a[0].clone()
        }
    }
    Ok(())
}
fn to_xray(c: &Value) -> Result<Value, String> {
    keys(
        c,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "flow",
            "tls",
            "transport",
            "packet_encoding",
        ],
    )?;
    // sing-box's default XUDP is also the normal Xray VLESS UDP mode.
    // Its explicit packetaddr/disabled modes have no lossless outbound mapping.
    if c.get("packet_encoding").is_some_and(|v| v != "xudp") {
        return Err("vless_core_conversion_unsupported".into());
    }
    let mut settings = json!({"encryption":"none"});
    copy(
        c,
        &mut settings,
        &[
            ("server", "address"),
            ("server_port", "port"),
            ("uuid", "id"),
            ("flow", "flow"),
        ],
    );
    let mut stream = json!({"network":"raw","security":"none"});
    if let Some(tls) = c.get("tls") {
        keys(
            tls,
            &[
                "enabled",
                "server_name",
                "insecure",
                "alpn",
                "utls",
                "reality",
            ],
        )?;
        if tls["enabled"] == true {
            keys(&tls["utls"], &["enabled", "fingerprint"])?;
            keys(&tls["reality"], &["enabled", "public_key", "short_id"])?;
            let reality = tls["reality"]["enabled"] == true;
            let mut secure = json!({});
            copy(
                tls,
                &mut secure,
                &[
                    ("server_name", "serverName"),
                    ("insecure", "allowInsecure"),
                    ("alpn", "alpn"),
                ],
            );
            if tls["utls"]["enabled"] == true {
                copy(&tls["utls"], &mut secure, &[("fingerprint", "fingerprint")]);
            }
            if reality {
                if tls.get("insecure").is_some() || tls.get("alpn").is_some() {
                    return Err("vless_core_conversion_unsupported".into());
                }
                copy(
                    &tls["reality"],
                    &mut secure,
                    &[("public_key", "password"), ("short_id", "shortId")],
                );
            }
            stream["security"] = json!(if reality { "reality" } else { "tls" });
            stream[if reality {
                "realitySettings"
            } else {
                "tlsSettings"
            }] = secure;
        }
    }
    if let Some(t) = c.get("transport") {
        let kind = t["type"]
            .as_str()
            .ok_or("vless_core_conversion_unsupported")?;
        let mut out = json!({});
        match kind {
            "grpc" => {
                keys(t, &["type", "service_name"])?;
                copy(t, &mut out, &[("service_name", "serviceName")]);
            }
            "ws" => {
                keys(t, &["type", "path", "headers"])?;
                copy(t, &mut out, &[("path", "path"), ("headers", "headers")]);
                single_valued_headers(&mut out)?;
            }
            "httpupgrade" => {
                keys(t, &["type", "path", "host", "headers"])?;
                copy(
                    t,
                    &mut out,
                    &[("path", "path"), ("host", "host"), ("headers", "headers")],
                );
                single_valued_headers(&mut out)?;
            }
            _ => return Err("vless_core_conversion_unsupported".into()),
        }
        stream["network"] = json!(kind);
        stream[format!("{kind}Settings")] = out;
    }
    let mut out = json!({"protocol":"vless","settings":settings,"streamSettings":stream});
    copy(c, &mut out, &[("tag", "tag")]);
    Ok(out)
}
fn to_singbox(c: &Value) -> Result<Value, String> {
    keys(c, &["protocol", "tag", "settings", "streamSettings"])?;
    let s = &c["settings"];
    keys(s, &["address", "port", "id", "encryption", "flow", "vnext"])?;
    let (address, user) = if let Some(v) = s.get("vnext") {
        let a = v
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("vless_core_conversion_unsupported")?;
        keys(&a[0], &["address", "port", "users"])?;
        let users = a[0]["users"]
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("vless_core_conversion_unsupported")?;
        keys(&users[0], &["id", "encryption", "flow"])?;
        (&a[0], &users[0])
    } else {
        (s, s)
    };
    if user["encryption"]
        .as_str()
        .is_some_and(|e| e != "none" && !e.is_empty())
    {
        return Err("vless_requires_xray".into());
    }
    let mut out = json!({"type":"vless"});
    copy(
        address,
        &mut out,
        &[("address", "server"), ("port", "server_port")],
    );
    copy(user, &mut out, &[("id", "uuid"), ("flow", "flow")]);
    copy(c, &mut out, &[("tag", "tag")]);
    let stream = &c["streamSettings"];
    if matches!(stream["network"].as_str(), Some("xhttp" | "splithttp")) {
        return Err("vless_requires_xray".into());
    }
    keys(
        stream,
        &[
            "network",
            "security",
            "tlsSettings",
            "realitySettings",
            "grpcSettings",
            "wsSettings",
            "httpupgradeSettings",
            "tcpSettings",
            "rawSettings",
        ],
    )?;
    let network = stream["network"].as_str().unwrap_or("raw");
    match network {
        "raw" | "tcp" => {
            for key in ["rawSettings", "tcpSettings"] {
                keys(&stream[key], &[])?
            }
        }
        "grpc" | "ws" | "httpupgrade" => {
            let t = &stream[format!("{network}Settings")];
            let mut tr = json!({"type":network});
            match network {
                "grpc" => {
                    keys(t, &["serviceName", "multiMode"])?;
                    if t["multiMode"] == true {
                        return Err("vless_requires_xray".into());
                    }
                    copy(t, &mut tr, &[("serviceName", "service_name")]);
                }
                "ws" => {
                    keys(t, &["path", "headers", "host"])?;
                    copy(t, &mut tr, &[("path", "path"), ("headers", "headers")]);
                    if t.get("host").is_some() {
                        if tr.get("headers").is_none() {
                            tr["headers"] = json!({})
                        }
                        tr["headers"]["Host"] = t["host"].clone()
                    }
                }
                _ => {
                    keys(t, &["path", "host", "headers"])?;
                    copy(
                        t,
                        &mut tr,
                        &[("path", "path"), ("host", "host"), ("headers", "headers")],
                    );
                }
            }
            out["transport"] = tr;
        }
        _ => return Err("vless_requires_xray".into()),
    }
    match stream["security"].as_str().unwrap_or("none") {
        "none" | "" => {}
        security @ ("tls" | "reality") => {
            let s = &stream[format!("{security}Settings")];
            keys(
                s,
                if security == "tls" {
                    &["serverName", "fingerprint", "allowInsecure", "alpn"]
                } else {
                    &[
                        "serverName",
                        "fingerprint",
                        "password",
                        "publicKey",
                        "shortId",
                    ]
                },
            )?;
            let mut tls = json!({"enabled":true});
            copy(
                s,
                &mut tls,
                &[
                    ("serverName", "server_name"),
                    ("allowInsecure", "insecure"),
                    ("alpn", "alpn"),
                ],
            );
            if let Some(fp) = s.get("fingerprint") {
                tls["utls"] = json!({"enabled":true,"fingerprint":fp})
            }
            if security == "reality" {
                tls["reality"] = json!({"enabled":true,"public_key":s.get("password").or(s.get("publicKey")).ok_or("vless_core_conversion_unsupported")?,"short_id":s["shortId"].as_str().unwrap_or("")})
            }
            out["tls"] = tls;
        }
        _ => return Err("vless_core_conversion_unsupported".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
