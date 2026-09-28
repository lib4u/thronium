//! Single userspace WireGuard/AmneziaWG endpoints measured in a disposable core.
//! The same `config::build` that starts the connection compiles the test box;
//! only the listener and services are dropped. Chains, pools and group
//! wrappers around endpoints stay refused until they are proven.
use crate::{
    config, proto, settings,
    store::{Library, Profile, ProfileKind},
};
use serde_json::{json, Value};

pub(crate) fn is_profile(p: &Profile) -> bool {
    p.kind == ProfileKind::SingBoxOutbound && p.config["type"] == "wireguard"
}

/// Contexts that a disposable core cannot own: a system interface, a named
/// interface, a detour through another outbound or the group's proxy wrappers.
fn eligible(p: &Profile, l: &Library) -> Result<(), String> {
    if !is_profile(p) {
        return Err("probe_unsupported".into());
    }
    let c = &p.config;
    let set = |key: &str| {
        c.get(key)
            .is_some_and(|v| !v.is_null() && v != "" && v != false)
    };
    if set("system")
        || set("name")
        || set("detour")
        || l.groups
            .iter()
            .any(|g| g.id == p.group_id && g.proxy_chain.enabled())
    {
        return Err("probe_endpoint_context_unsupported".into());
    }
    Ok(())
}

/// Pure capability check shared by the snapshot and both diagnostic RPCs: a
/// runnable endpoint has key material and at least one reachable peer.
pub(crate) fn diagnostics_supported(p: &Profile, l: &Library) -> bool {
    let c = &p.config;
    let text = |v: &Value| v.as_str().is_some_and(|s| !s.trim().is_empty());
    text(&c["private_key"])
        && c["peers"].as_array().is_some_and(|peers| {
            !peers.is_empty()
                && peers.iter().all(|peer| {
                    text(&peer["public_key"]) && (text(&peer["address"]) || text(&peer["endpoint"]))
                })
        })
        && eligible(p, l).is_ok()
}

pub(super) fn request(
    l: &Library,
    p: &Profile,
    url: &str,
    timeout_ms: u32,
) -> Result<proto::TestReq, String> {
    eligible(p, l)?;
    // Without key material or a reachable peer there is nothing to measure.
    if !diagnostics_supported(p, l) {
        return Err("probe_unsupported".into());
    }
    let mut profile = p.clone();
    settings::prepare_profile(&mut profile, l);
    let built = config::build(&profile, config::PLACEHOLDER_INBOUND_PORT, None)
        .map_err(|_| "probe_configuration_failed")?;
    let mut core: Value = serde_json::from_str(built.core_config.as_deref().unwrap_or(""))
        .map_err(|_| "probe_configuration_failed")?;
    core["inbounds"] = json!([]);
    core["services"] = json!([]);
    Ok(proto::TestReq {
        config: Some(core.to_string()),
        outbound_tags: vec!["proxy".into()],
        use_default_outbound: Some(false),
        test_current: Some(false),
        max_concurrency: Some(1),
        url: Some(url.into()),
        test_timeout_ms: Some(timeout_ms as i32),
        need_xray: Some(false),
        ..Default::default()
    })
}
