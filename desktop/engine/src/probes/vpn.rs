//! Disposable VPN URL tests never use the main session or its OTP automation.
//! A bare VPN profile is compiled alone; a VPN hop inside a chain or group
//! wrapper follows the chain compiler and keeps the same per-hop rules.
use super::Outcome;
use crate::{
    config, group_chains, proto, settings,
    store::{Library, Profile, ProfileKind},
    vpn_policy,
};
use serde_json::{json, Value};

pub(crate) fn is_profile(p: &Profile) -> bool {
    vpn_policy::protocol(p).is_some()
}
/// Whether measuring this profile starts a VPN session in the disposable core:
/// the profile itself or any hop of its physical sequence.
pub(crate) fn involves(l: &Library, p: &Profile) -> bool {
    is_profile(p)
        || (p.kind == ProfileKind::SingBoxConfig && !endpoint_tags(&p.config).is_empty())
        || hops(l, p).is_ok_and(|hops| hops.iter().any(|hop| is_profile(hop)))
}
/// The physical sequence when the profile compiles through the chain builder.
fn hops<'a>(l: &'a Library, p: &'a Profile) -> Result<Vec<&'a Profile>, String> {
    let policy = group_chains::policy(l, p);
    if p.kind != ProfileKind::Chain && !policy.enabled() {
        return Ok(vec![]);
    }
    group_chains::sequence(l, p, &policy)
}
/// A bare VPN profile inside a group wrapper is measured through the wrapper.
pub(crate) fn wrapped(l: &Library, p: &Profile) -> bool {
    is_profile(p) && group_chains::policy(l, p).enabled()
}

pub(super) fn terminal(code: &str) -> bool {
    matches!(
        code,
        "probe_vpn_auth_unsupported"
            | "probe_vpn_context_unsupported"
            | "probe_vpn_otp_binding_required"
            | "probe_vpn_otp_manual_only"
            | "probe_vpn_otp_failed"
            | "probe_cleanup_failed"
    )
}

pub(crate) fn stamp(p: &Profile, l: &Library) -> Value {
    use sha2::{Digest, Sha256};
    // Fingerprint the effective pure compilation, including inherited TLS and
    // policy/context refusals. Retain no additional credentials or OTP secrets.
    let compiled = eligible(p, l).map(|()| {
        let mut profile = p.clone();
        settings::prepare_profile(&mut profile, l);
        format!(
            "{:x}",
            Sha256::digest(profile.config.to_string().as_bytes())
        )
    });
    json!([
        p.vpn_policy,
        l.vpn_otp_bindings.get(&p.id),
        l.preferences.connection_mode,
        compiled
    ])
}

/// The disposable core must own the interface: Linux, no managed TUN
/// preference, no host or named interface.
fn owned_context(p: &Profile, l: &Library) -> Result<(), String> {
    if !cfg!(target_os = "linux")
        || !is_profile(p)
        || l.preferences.connection_mode == crate::system_proxy::ConnectionMode::Tun
        || p.config.get("system").is_some_and(|v| v != false)
        || p.config.get("name").is_some_and(|v| v != "")
    {
        return Err("probe_vpn_context_unsupported".into());
    }
    Ok(())
}
/// Whether the profile expects an application-minted code somewhere.
fn otp_template(c: &Value) -> bool {
    let has = |v: &Value| v.as_str().is_some_and(|s| s.contains("{otp}"));
    has(&c["username"])
        || has(&c["password"])
        || has(&c["token"]["pin"])
        || has(&c["token"]["password"])
        || c["form_entries"]
            .as_array()
            .is_some_and(|items| items.iter().any(|e| has(&e["value"])))
}
/// Authentication a test box can complete without a challenge channel: a bound
/// template gets its code baked at issue; an unbound one has no code source;
/// core-side tokens and host scripts stay out.
fn auth_shape(p: &Profile, bound: bool) -> Result<(), String> {
    let c = &p.config;
    if otp_template(c) && !bound {
        return Err("probe_vpn_otp_binding_required".into());
    }
    if c.get("token").is_some_and(|v| !v.is_null())
        && !(bound && (otp_template(&json!({"token": c["token"]}))))
    {
        return Err("probe_vpn_auth_unsupported".into());
    }
    if c["type"] == "openconnect"
        && (c
            .get("flavor")
            .is_some_and(|v| !matches!(v.as_str(), Some("" | "anyconnect")))
            || ["cookie", "csd", "hip", "tncc", "fortinet_host_check"]
                .iter()
                .any(|key| {
                    c.get(*key)
                        .is_some_and(|v| !v.is_null() && v != "" && v != &json!({}))
                })
            || c.get("password_authentication_disabled")
                .is_some_and(|v| v != false))
    {
        return Err("probe_vpn_auth_unsupported".into());
    }
    Ok(())
}
/// Rules for a chain hop: the wrapper announces the tag it compiles the hop
/// under, so a bound hop receives its code there like any other node.
pub(crate) fn hop_eligible(p: &Profile, l: &Library) -> Result<(), String> {
    owned_context(p, l)?;
    auth_shape(p, l.vpn_otp_bindings.contains_key(&p.id))
}
/// A bare profile additionally owns its whole routing context: no user detour
/// and a policy the disposable core can apply. A bound profile is measured
/// with its code baked at issue.
fn eligible(p: &Profile, l: &Library) -> Result<(), String> {
    owned_context(p, l)?;
    auth_shape(p, l.vpn_otp_bindings.contains_key(&p.id))?;
    if wrapped(l, p)
        || p.config
            .get("detour")
            .is_some_and(|v| !v.is_null() && v != "")
    {
        return Err("probe_vpn_context_unsupported".into());
    }
    vpn_policy::validate_context(l, p).map_err(|_| "probe_vpn_context_unsupported".into())
}
/// Every VPN hop of a chain or wrapper passes the per-hop rules before the
/// wrapper is compiled. Tailscale hops are not measured: Qt skips them in
/// tests and no fixture proves them.
pub(crate) fn hops_eligible(l: &Library, p: &Profile) -> Result<(), String> {
    for hop in hops(l, p)? {
        if hop.config["type"] == "tailscale" {
            return Err("probe_unsupported".into());
        }
        if is_profile(hop) {
            hop_eligible(hop, l)?;
        }
    }
    Ok(())
}

/// Pure capability check; malformed drafts and unsupported ownership/auth
/// contexts must not advertise a runnable IP/speed operation.
pub(crate) fn diagnostics_supported(p: &Profile, l: &Library) -> bool {
    p.config["server"]
        .as_str()
        .is_some_and(|s| !s.trim().is_empty())
        && if wrapped(l, p) {
            hops_eligible(l, p).is_ok()
        } else {
            eligible(p, l).is_ok()
        }
}

/// Tags of the VPN endpoints in a compiled core: the readiness the URL test
/// waits for before measuring.
pub(crate) fn endpoint_tags(core: &Value) -> Vec<String> {
    core["endpoints"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| crate::vpn_endpoint::is_vpn(e))
        .filter_map(|e| e["tag"].as_str().map(str::to_owned))
        .collect()
}

pub(super) fn request(
    l: &Library,
    p: &Profile,
    url: &str,
    timeout_ms: u32,
    sources: &mut crate::vpn_auth::otp::Build,
) -> Result<proto::TestReq, String> {
    eligible(p, l)?;
    let mut profile = p.clone();
    settings::prepare_profile(&mut profile, l);
    let mut built =
        config::build_with_sources(&profile, config::PLACEHOLDER_INBOUND_PORT, None, sources)
            .map_err(|_| "probe_configuration_failed")?;
    vpn_policy::apply(&mut built, &profile).map_err(|_| "probe_vpn_context_unsupported")?;
    let mut core: Value = serde_json::from_str(built.core_config.as_deref().unwrap_or(""))
        .map_err(|_| "probe_configuration_failed")?;
    core["inbounds"] = json!([]);
    core["services"] = json!([]);
    Ok(proto::TestReq {
        config: Some(core.to_string()),
        outbound_tags: vec!["proxy".into()],
        vpn_endpoint_tags: vec!["proxy".into()],
        use_default_outbound: Some(false),
        test_current: Some(false),
        max_concurrency: Some(1),
        url: Some(url.into()),
        test_timeout_ms: Some(timeout_ms as i32),
        vpn_status_timeout_ms: Some(super::VPN_STATUS_TIMEOUT_MS),
        need_xray: Some(false),
        ..Default::default()
    })
}

/// `tags` are the VPN endpoints the request waited for; `outbound` is the
/// single measured outbound (`proxy`, or a complete client's private bridge).
pub(super) fn decode(
    response: proto::TestResp,
    tags: &[String],
    outbound: &str,
) -> Result<Outcome, String> {
    let [result] = response.results.as_slice() else {
        return Err("probe_failed".into());
    };
    if result.outbound_tag.as_deref() != Some(outbound) {
        return Err("probe_failed".into());
    }
    let error = result.error.as_deref().ok_or("probe_failed")?;
    if error.is_empty() {
        return result
            .latency_ms
            .filter(|v| *v >= 0)
            .map(Outcome::Latency)
            .ok_or("probe_failed".into());
    }
    if let Some(outcome) = failure_status(&response.vpn_status, tags)? {
        return Ok(outcome);
    }
    Err(super::http_error(error))
}

// Shared interpretation for failed HTTP, IP and speed measurements: one status
// per requested endpoint, in any order. Authentication outranks a connected
// tunnel that still failed the exchange.
pub(crate) fn failure_status(
    statuses: &[proto::VpnEndpointStatus],
    tags: &[String],
) -> Result<Option<Outcome>, String> {
    if statuses.is_empty() {
        return Ok(None);
    }
    if statuses.len() != tags.len()
        || !statuses.iter().all(|s| {
            s.tag
                .as_deref()
                .is_some_and(|t| tags.contains(&t.to_owned()))
        })
        || (1..statuses.len()).any(|i| statuses[..i].iter().any(|s| s.tag == statuses[i].tag))
    {
        return Err("probe_failed".into());
    }
    let mut outcome = None;
    for status in statuses {
        let own = |c: &proto::VpnChallenge| {
            c.endpoint_tag == status.tag && c.id.as_ref().is_some_and(|id| !id.is_empty())
        };
        match (
            status.state.as_deref(),
            status.connected,
            status.auth_failed,
        ) {
            (Some("connected"), Some(true), Some(false)) if status.challenge.is_none() => {
                outcome.get_or_insert(Outcome::ConnectedOnly);
            }
            (Some("error"), Some(false), Some(true)) if status.challenge.is_none() => {
                outcome = Some(Outcome::AuthRequired);
            }
            (Some("auth-pending"), Some(false), Some(false))
                if status.challenge.as_ref().is_some_and(own) =>
            {
                outcome = Some(Outcome::AuthRequired);
            }
            (Some("connecting" | "error"), Some(false), Some(false))
                if status.challenge.is_none() => {}
            _ => return Err("probe_failed".into()),
        }
    }
    Ok(outcome)
}
