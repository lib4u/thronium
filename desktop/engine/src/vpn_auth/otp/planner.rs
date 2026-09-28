//! Pure Qt live-answer rules with complete validation before any counter commit,
//! plus the Start-time placement of an OpenVPN code.
use crate::{
    proto,
    store::Profile,
    vpn_auth::{validate, ChallengeRequest, SubmitRequest},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::collections::BTreeMap;

/// Where a Start request needs the code. Only OpenVPN credentials qualify today.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Placement {
    None,
    Credentials,
    StaticChallenge,
}

#[derive(Clone)]
pub(crate) struct Source {
    pub(crate) profile_id: String,
    pub(crate) placement: Placement,
    pub(crate) protocol: String,
    pub(crate) flavor: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) entries: Vec<Value>,
}
impl Source {
    pub(crate) fn from_profile(profile: &Profile) -> Result<Self, String> {
        let c = &profile.config;
        let protocol =
            crate::vpn_endpoint::profile_protocol(profile).ok_or("vpn_otp_profile_unsupported")?;
        let text = |key: &str| -> Result<String, String> {
            match c.get(key) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(v)) if crate::vpn_auth::valid_text(v) => Ok(v.clone()),
                _ => Err("vpn_otp_manual_required".into()),
            }
        };
        let username = text("username")?;
        let password = text("password")?;
        let credentials_template = [&username, &password].iter().any(|s| s.contains("{otp}"));
        let token_template = ["pin", "password"]
            .iter()
            .any(|k| c["token"][*k].as_str().is_some_and(|s| s.contains("{otp}")));
        // OpenConnect token and credential templates stay live-only until the
        // core reports which form fields it caches.
        if token_template || (credentials_template && protocol == "openconnect") {
            return Err("vpn_otp_start_placeholder_unsupported".into());
        }
        let placement = if !credentials_template {
            Placement::None
        } else if c["static_challenge"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        {
            Placement::StaticChallenge
        } else {
            Placement::Credentials
        };
        // A baked code must not be resent by the core, so only auth_retry "none" fits.
        if placement != Placement::None
            && c.get("auth_retry")
                .filter(|v| !v.is_null())
                .is_some_and(|v| v != "none")
        {
            return Err("vpn_otp_start_retry_unsupported".into());
        }
        let entries = match c.get("form_entries") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) if a.len() <= 128 => a.clone(),
            _ => return Err("vpn_otp_manual_required".into()),
        };
        for entry in &entries {
            if !entry.is_object() {
                return Err("vpn_otp_manual_required".into());
            }
            for k in ["submission_key", "name", "value", "form_id"] {
                if entry.get(k).is_some_and(|v| {
                    !v.is_string() || v.as_str().is_some_and(|s| !crate::vpn_auth::valid_text(s))
                }) {
                    return Err("vpn_otp_manual_required".into());
                }
            }
            if entry.get("promote").is_some_and(|v| !v.is_boolean()) {
                return Err("vpn_otp_manual_required".into());
            }
        }
        if protocol == "openconnect" && shadowed_template(&entries) {
            return Err("vpn_otp_form_shadowed".into());
        }
        if protocol == "openconnect" && entries.iter().any(otp_template) {
            let flavor = c["flavor"].as_str().unwrap_or("");
            if !matches!(flavor, "" | "anyconnect")
                || c.get("token").is_some_and(|v| !v.is_null())
                || entries
                    .iter()
                    .filter(|entry| otp_template(entry))
                    .any(|entry| {
                        let name = entry["name"].as_str().unwrap_or("");
                        !entry["submission_key"].as_str().unwrap_or("").is_empty()
                            || !noncached_anyconnect_name(name)
                    })
            {
                // Other flavors and key-only entries do not prove the target
                // field's cache semantics. AnyConnect stores stable username,
                // password and auth-group answers even when Start was empty.
                return Err("vpn_otp_form_cache_unsupported".into());
            }
        }
        Ok(Self {
            profile_id: profile.id.clone(),
            placement,
            protocol: protocol.into(),
            flavor: c["flavor"].as_str().unwrap_or("").into(),
            username,
            password,
            entries,
        })
    }
}

fn noncached_anyconnect_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    !name.is_empty()
        && !matches!(name, "password" | "group_list" | "secondary_username")
        && !lower.starts_with("user")
        && !lower.starts_with("uname")
}

fn otp_template(entry: &Value) -> bool {
    // Promote exposes hidden fields and ignores its Value in the core.
    entry["promote"] != true
        && entry["value"]
            .as_str()
            .is_some_and(|value| value.contains("{otp}"))
}

fn shadowed_template(entries: &[Value]) -> bool {
    let selector = |entry: &Value| {
        let key = entry["submission_key"].as_str().unwrap_or("");
        if !key.is_empty() {
            (true, key.to_owned())
        } else {
            (false, entry["name"].as_str().unwrap_or("").to_owned())
        }
    };
    entries
        .iter()
        .filter(|entry| otp_template(entry))
        .any(|otp| {
            entries
                .iter()
                .filter(|entry| !otp_template(entry) && entry["promote"] != true)
                .any(|fixed| {
                    let (key_a, value_a) = selector(otp);
                    let (key_b, value_b) = selector(fixed);
                    // A surviving fixed entry is automatic, even when its value is
                    // empty. A field can have both a key and a name; without the live
                    // form we cannot prove those mixed selectors do not overlap.
                    // Qt's live name matcher deliberately ignores form_id.
                    key_a != key_b || value_a == value_b
                })
        })
}

fn field_hints(f: &proto::VpnChallengeField) -> (bool, bool) {
    let hay = format!(
        "{} {}",
        f.name.as_deref().unwrap_or(""),
        f.label.as_deref().unwrap_or("")
    )
    .to_lowercase();
    (
        [
            "token",
            "otp",
            "passcode",
            "one-time",
            "onetime",
            "second",
            "challenge",
            "verification",
            "authenticator",
        ]
        .iter()
        .any(|h| hay.contains(h)),
        ["user", "login", "account"].iter().any(|h| hay.contains(h)),
    )
}

pub(crate) struct Planned {
    pub(crate) request: SubmitRequest,
    pub(crate) uses_otp: bool,
}

pub(crate) fn dependency(
    source: &Source,
    challenge: &proto::VpnChallenge,
    identity: &ChallengeRequest,
) -> Result<bool, String> {
    plan(source, challenge, identity, "__otp_dependency__").map(|p| p.uses_otp)
}
pub(crate) fn answer(
    source: &Source,
    challenge: &proto::VpnChallenge,
    identity: &ChallengeRequest,
    code: &str,
) -> Result<Planned, String> {
    let planned = plan(source, challenge, identity, code)?;
    if planned.uses_otp && code.is_empty() {
        return Err("vpn_otp_manual_required".into());
    }
    validate::answer(challenge, &source.protocol, &planned.request)?;
    Ok(planned)
}
fn plan(
    source: &Source,
    challenge: &proto::VpnChallenge,
    identity: &ChallengeRequest,
    code: &str,
) -> Result<Planned, String> {
    validate::details(challenge, &source.protocol)?;
    let mut uses_otp = false;
    let mut answer = SubmitRequest {
        session_id: identity.session_id.clone(),
        endpoint_tag: identity.endpoint_tag.clone(),
        challenge_id: identity.challenge_id.clone(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::new(),
    };
    match (
        source.protocol.as_str(),
        challenge.kind.as_deref().unwrap_or(""),
    ) {
        ("openvpn", "secret") => {
            answer.secret = code.into();
            uses_otp = true;
        }
        ("openvpn", "credentials")
            if !source.username.is_empty() || !source.password.is_empty() =>
        {
            answer.username = source.username.replace("{otp}", code);
            answer.password = source.password.replace("{otp}", code);
            answer.secret = code.into();
            uses_otp = true;
        }
        ("openconnect", "form") => {
            let mut password_used = false;
            for field in &challenge.fields {
                let key = field.submission_key.as_deref().unwrap_or("");
                let name = field.name.as_deref().unwrap_or("");
                let mut resolved = None;
                for entry in &source.entries {
                    if entry["promote"].as_bool() == Some(true) {
                        continue;
                    }
                    let entry_key = entry["submission_key"].as_str().unwrap_or("");
                    let entry_name = entry["name"].as_str().unwrap_or("");
                    let value = entry["value"].as_str().unwrap_or("");
                    if (!entry_key.is_empty() && entry_key == key)
                        || (entry_key.is_empty()
                            && !entry_name.is_empty()
                            && entry_name == name
                            && value.contains("{otp}"))
                    {
                        resolved = Some((value.replace("{otp}", code), value.contains("{otp}")));
                        // Qt's last match wins.
                    }
                }
                let (token, user) = field_hints(field);
                if resolved.is_none() && field.kind.as_deref() == Some("password") {
                    resolved = Some(if !password_used && !token && !source.password.is_empty() {
                        password_used = true;
                        (
                            source.password.replace("{otp}", code),
                            source.password.contains("{otp}"),
                        )
                    } else {
                        (code.into(), true)
                    });
                }
                if resolved.is_none() && user && !source.username.is_empty() {
                    resolved = Some((
                        source.username.replace("{otp}", code),
                        source.username.contains("{otp}"),
                    ));
                }
                if resolved.is_none() {
                    resolved = field
                        .value
                        .clone()
                        .filter(|s| !s.is_empty())
                        .map(|v| (v, false));
                }
                let (value, used) = resolved.ok_or("vpn_otp_manual_required")?;
                if used
                    && (!matches!(source.flavor.as_str(), "" | "anyconnect")
                        || !noncached_anyconnect_name(name))
                {
                    // A reply to a stable credential field is retained by the
                    // core and can be replayed without another Engine challenge.
                    return Err("vpn_otp_form_cache_unsupported".into());
                }
                uses_otp |= used;
                answer.form_values.insert(key.into(), value);
            }
        }
        _ => return Err("vpn_otp_manual_required".into()),
    }
    Ok(Planned {
        request: answer,
        uses_otp,
    })
}

/// Remove only live OTP templates from the compiled copy. Source JSON is intact.
pub(crate) fn withhold(config: &mut Value) {
    if config["type"] == "openconnect" {
        if let Some(entries) = config.get_mut("form_entries").and_then(Value::as_array_mut) {
            entries.retain(|entry| !otp_template(entry));
            if entries.is_empty() {
                config.as_object_mut().unwrap().remove("form_entries");
            }
        }
    }
    if config["type"] == crate::vpn_endpoint::OPENVPN
        && config["static_challenge"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && config.get("auth_retry").is_none()
    {
        config["auth_retry"] = Value::String("interact".into());
    }
}

/// Put the minted code into the disposable test copy the way Qt's test build
/// does: OpenVPN credentials or static challenge (packed even without a
/// placeholder), OpenConnect credentials, token and live form entries. Returns
/// whether anything was placed; nothing placed means no code to spend. Source
/// JSON is untouched.
pub(crate) fn bake_probe(config: &mut Value, code: &str, source: &Source) -> Result<bool, String> {
    if code.is_empty() {
        return Err("vpn_otp_manual_required".into());
    }
    if source.protocol == "openvpn" {
        let placement = match source.placement {
            Placement::None
                if config["static_challenge"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()) =>
            {
                Placement::StaticChallenge
            }
            placement => placement,
        };
        bake(config, code, placement)?;
        return Ok(placement != Placement::None);
    }
    let object = config
        .as_object_mut()
        .ok_or("vpn_otp_profile_unsupported")?;
    let mut placed = false;
    let mut replace = |value: &mut Value| {
        if let Value::String(text) = value {
            if text.contains("{otp}") {
                *text = text.replace("{otp}", code);
                placed = true;
            }
        }
    };
    for key in ["username", "password"] {
        if let Some(value) = object.get_mut(key) {
            replace(value);
        }
    }
    if let Some(token) = object.get_mut("token").and_then(Value::as_object_mut) {
        for key in ["pin", "password"] {
            if let Some(value) = token.get_mut(key) {
                replace(value);
            }
        }
    }
    if let Some(entries) = object.get_mut("form_entries").and_then(Value::as_array_mut) {
        for entry in entries.iter_mut().filter(|entry| entry["promote"] != true) {
            if let Some(value) = entry.get_mut("value") {
                replace(value);
            }
        }
    }
    Ok(placed)
}

/// Put the minted code into the Start copy of an OpenVPN endpoint the way Qt
/// does: placeholders in credentials, SCRV1 packing for a static challenge, and
/// no core-side retry that could resend the same code. Source JSON is untouched.
pub(crate) fn bake(config: &mut Value, code: &str, placement: Placement) -> Result<(), String> {
    if placement == Placement::None {
        return Ok(());
    }
    if code.is_empty() {
        return Err("vpn_otp_manual_required".into());
    }
    let object = config
        .as_object_mut()
        .ok_or("vpn_otp_profile_unsupported")?;
    for key in ["username", "password"] {
        if let Some(Value::String(text)) = object.get_mut(key) {
            *text = text.replace("{otp}", code);
        }
    }
    if placement == Placement::StaticChallenge {
        let password = object.get("password").and_then(Value::as_str).unwrap_or("");
        let packed = format!(
            "SCRV1:{}:{}",
            STANDARD.encode(password),
            STANDARD.encode(code)
        );
        object.insert("password".into(), Value::String(packed));
        object.remove("static_challenge");
        object.remove("static_challenge_echo");
    }
    match object.get("auth_retry").filter(|v| !v.is_null()) {
        None => {
            object.insert("auth_retry".into(), Value::String("none".into()));
        }
        Some(retry) if retry == "none" => {}
        Some(_) => return Err("vpn_otp_start_retry_unsupported".into()),
    }
    object.insert("single_use_auth".into(), Value::Bool(true));
    Ok(())
}
