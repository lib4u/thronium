//! Frozen OTP automation. A code reaches a Start request only through an
//! explicit before-Start binding, reserved durably first and never replayed.
mod automatic;
mod planner;
pub(crate) mod probe;
mod start_codes;
#[cfg(test)]
mod start_tests;
#[cfg(test)]
mod tests;
use super::*;
use crate::{
    otp::{Entry, Kind},
    store::{Library, Profile},
    vpn_otp_bindings::Mode,
};
use automatic::candidate_code;
use serde_json::Value;
use std::collections::HashMap;

/// Classify one profile without minting a code or changing its source fields.
pub(crate) fn recommended_mode(profile: &Profile) -> Result<Mode, String> {
    Ok(match planner::Source::from_profile(profile)?.placement {
        planner::Placement::None => Mode::AutoLive,
        _ => Mode::AutoStart,
    })
}
/// Live automation: the profile must not need a code before Start.
pub(crate) fn support(profile: &Profile) -> Result<(), String> {
    if recommended_mode(profile)? == Mode::AutoLive {
        Ok(())
    } else {
        Err("vpn_otp_start_mode_required".into())
    }
}
/// Before-Start substitution: an OpenVPN placeholder in credentials qualifies.
pub(crate) fn start_support(profile: &Profile) -> Result<(), String> {
    if recommended_mode(profile)? == Mode::AutoStart {
        Ok(())
    } else {
        Err("vpn_otp_start_unsupported".into())
    }
}
/// Why a request is built. Only an explicit Connect or a manual disposable
/// test may spend a code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Intent {
    Check,
    Start,
    Background,
    /// A disposable test box has no challenge channel: every template is baked
    /// at issue, exactly like Qt's test build.
    Probe,
}
/// Proof that a Start request carried a minted code: enough to refuse replay,
/// never the code itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct StartMark {
    pub(crate) otp_id: String,
    pub(crate) counter: Option<String>,
}
pub(crate) type StartMarks = BTreeMap<String, StartMark>;
pub(crate) type Bindings = BTreeMap<String, Frozen>;

#[derive(Clone)]
pub(crate) struct Frozen {
    source: planner::Source,
    original_config: Value,
    binding_revision: String,
    identity: Entry,
    disabled: bool,
    pub(crate) mode: Mode,
}
impl Frozen {
    pub(super) fn credentials_supported(&self) -> bool {
        // A baked credential field must not be overwritten by a manual session.
        self.mode == Mode::AutoLive
            && (self.source.protocol != "openconnect" || self.source.entries.is_empty())
    }

    // Ephemeral manual credentials follow this cloned session through recovery;
    // the original library fingerprint and rollback source remain unchanged.
    pub(super) fn session_credentials(&mut self, username: &str, password: &str) {
        self.source.username = username.into();
        self.source.password = password.into();
    }

    pub(crate) fn current<'a>(&self, library: &'a Library) -> Option<&'a Entry> {
        if self.disabled {
            return None;
        }
        let binding = library.vpn_otp_bindings.get(&self.source.profile_id)?;
        if binding.revision != self.binding_revision || binding.otp_id != self.identity.id {
            return None;
        }
        let profile = library
            .profiles
            .iter()
            .find(|p| p.id == self.source.profile_id)?;
        if profile.kind != crate::store::ProfileKind::SingBoxOutbound
            || profile.config != self.original_config
        {
            return None;
        }
        library
            .otp
            .iter()
            .find(|e| crate::vpn_otp_bindings::same_identity(&self.identity, e))
    }
}

#[derive(Default)]
pub(crate) struct Build {
    candidates: Bindings,
    pub(crate) emitted: Bindings,
    /// Group wrappers compile hops as renamed copies; a copy answers for its
    /// original binding.
    aliases: HashMap<String, String>,
}
impl Build {
    pub(crate) fn alias(&mut self, aliases: HashMap<String, String>) {
        self.aliases.extend(aliases);
    }
    pub(crate) fn prepare(
        library: &mut Library,
        selected: &mut Profile,
        needed: &HashSet<String>,
        original: &Library,
        intent: Intent,
    ) -> Result<Self, String> {
        let mut result = Self::default();
        // Full configs do not opt into app credentials by reusing a tag or UUID.
        if matches!(
            selected.kind,
            crate::store::ProfileKind::SingBoxConfig | crate::store::ProfileKind::XrayConfig
        ) {
            return Ok(result);
        }
        for profile in &mut library.profiles {
            if !needed.contains(&profile.id) {
                continue;
            }
            let Some(binding) = library.vpn_otp_bindings.get(&profile.id) else {
                continue;
            };
            let identity = library
                .otp
                .iter()
                .find(|e| e.id == binding.otp_id)
                .ok_or("vpn_otp_missing")?
                .clone();
            let source = planner::Source::from_profile(profile)?;
            match (binding.mode, source.placement) {
                (Mode::AutoLive, planner::Placement::None) => {}
                (Mode::AutoLive, _) => return Err("vpn_otp_start_mode_required".into()),
                (Mode::AutoStart, planner::Placement::None) => {
                    return Err("vpn_otp_start_unsupported".into())
                }
                (Mode::AutoStart, _) => {
                    // Only an explicit Connect may spend a code, and it spends it
                    // for every VPN node that connection carries: the selected
                    // profile itself as readily as a hop of its chain or an
                    // endpoint one of its routes sends traffic to. A pool never
                    // holds such an endpoint, and a background rebuild never
                    // spends a code at all. TUN's host recovery is disabled on
                    // the marked request before Start.
                    if intent == Intent::Background {
                        return Err("vpn_otp_start_background_unsupported".into());
                    }
                }
            }
            let original_config = original
                .profiles
                .iter()
                .find(|p| p.id == profile.id)
                .ok_or("profile_missing")?
                .config
                .clone();
            result.candidates.insert(
                profile.id.clone(),
                Frozen {
                    source,
                    original_config,
                    binding_revision: binding.revision.clone(),
                    identity,
                    disabled: false,
                    mode: binding.mode,
                },
            );
            if binding.mode == Mode::AutoLive {
                if intent != Intent::Probe {
                    planner::withhold(&mut profile.config);
                }
            } else {
                // CheckConfig verifies Core support before a code is reserved.
                profile.config["single_use_auth"] = serde_json::json!(true);
            }
        }
        if let Some(frozen) = result.candidates.get(&selected.id) {
            if frozen.mode == Mode::AutoLive {
                if intent != Intent::Probe {
                    planner::withhold(&mut selected.config);
                }
            } else {
                selected.config["single_use_auth"] = serde_json::json!(true);
            }
        }
        Ok(result)
    }
    /// The frozen binding prepared for one profile, before any compiler has
    /// announced where that profile ended up.
    #[cfg(test)]
    pub(crate) fn take(&mut self, id: &str) -> Option<Frozen> {
        self.candidates.remove(id)
    }
    /// Whether this build carries a bound node at all: a test of one spends a
    /// code only when a person asked for it, even when nothing is baked.
    pub(crate) fn bound(&self) -> bool {
        !self.candidates.is_empty()
    }
    /// Called by the builder emitting this endpoint, never by parsing a tag prefix.
    pub(crate) fn emit(
        &mut self,
        profile: &Profile,
        tag: &str,
        outbound: &Value,
    ) -> Result<(), String> {
        let origin = self.aliases.get(&profile.id).unwrap_or(&profile.id);
        let Some(source) = self.candidates.get(origin) else {
            return Ok(());
        };
        let expected = crate::vpn_endpoint::endpoint_type(&source.source.protocol);
        if profile.kind != crate::store::ProfileKind::SingBoxOutbound
            || expected.is_none_or(|expected| outbound["type"] != expected)
            || outbound["tag"] != tag
        {
            return Err("vpn_otp_profile_unsupported".into());
        }
        if self.emitted.insert(tag.into(), source.clone()).is_some() {
            return Err("route_tag_conflict".into());
        }
        Ok(())
    }
    pub(crate) fn finish(self, request: &proto::LoadConfigReq) -> Result<Bindings, String> {
        if self.emitted.is_empty() {
            return Ok(self.emitted);
        }
        let core: Value = serde_json::from_str(
            request
                .core_config
                .as_deref()
                .ok_or("invalid_configuration")?,
        )
        .map_err(|_| "invalid_configuration")?;
        for (tag, frozen) in &self.emitted {
            let matches: Vec<_> = core["endpoints"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["tag"] == *tag)
                .collect();
            let expected = crate::vpn_endpoint::endpoint_type(&frozen.source.protocol);
            if matches.len() != 1 || expected.is_none_or(|expected| matches[0]["type"] != expected)
            {
                return Err("vpn_otp_profile_unsupported".into());
            }
        }
        Ok(self.emitted)
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub state: String,
    pub error: Option<String>,
}
impl Metadata {
    fn new(state: &str, error: Option<&str>) -> Self {
        Self {
            state: state.into(),
            error: error.map(str::to_owned),
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    attempted: HashSet<String>,
    rejects: u8,
    last_code: Option<String>,
    rejected_codes: HashSet<String>,
    terminal: bool,
    metadata: Option<Metadata>,
}
impl State {
    fn wait_for_new_code(&mut self, code: &str, failed: bool) -> bool {
        if failed {
            if let Some(last) = &self.last_code {
                self.rejected_codes.insert(last.clone());
            }
        }
        self.rejected_codes.contains(code)
    }
}

impl Engine {
    pub(super) fn otp_manual_answer(&mut self, tag: &str, id: &str, cancel: bool) {
        let Some(frozen) = self
            .active_connection
            .as_mut()
            .and_then(|a| a.vpn_otp.get_mut(tag))
        else {
            return;
        };
        let state = self.vpn.otp.entry(tag.into()).or_default();
        if state.attempted.len() < 128 {
            state.attempted.insert(id.into());
        } else {
            state.terminal = true;
        }
        if cancel {
            frozen.disabled = true;
            self.otp_metadata(tag, "disabled", Some("vpn_otp_auto_disabled"));
        } else {
            self.otp_metadata(tag, "manual", Some("vpn_otp_manual_required"));
        }
    }
    pub(super) async fn auto_vpn_otp(&mut self, response: &proto::VpnStatusResponse) {
        self.refresh_vpn_otp_bindings();
        let Some(session) = self.vpn.status.session_id.clone() else {
            return;
        };
        for status in &response.results {
            if self.vpn.status.session_id.as_deref() != Some(session.as_str()) {
                break;
            }
            let tag = status.tag.as_deref().unwrap_or("");
            let Some(frozen) = self
                .active_connection
                .as_ref()
                .and_then(|a| a.vpn_otp.get(tag))
                .cloned()
            else {
                continue;
            };
            if frozen.disabled {
                continue;
            }
            if frozen.mode == Mode::AutoStart {
                // The code went into Start; a live challenge is never answered from it.
                if status.connected == Some(true) {
                    self.otp_metadata(tag, "ready", None);
                    self.vpn_start_restarts
                        .remove(&(self.running.clone().unwrap_or_default(), tag.to_owned()));
                } else if status.auth_failed == Some(true) && status.challenge.is_none() {
                    self.restart_for_fresh_start_code(tag, &frozen).await;
                }
                continue;
            }
            if status.connected == Some(true) {
                let state = self.vpn.otp.entry(tag.into()).or_default();
                state.rejects = 0;
                if !state.terminal {
                    self.otp_metadata(tag, "ready", None);
                }
                continue;
            }
            let Some(challenge) = &status.challenge else {
                continue;
            };
            let Some(id) = challenge.id.as_ref() else {
                continue;
            };
            let state = self.vpn.otp.entry(tag.into()).or_default();
            if state.terminal || state.attempted.contains(id) {
                continue;
            }
            // Cap retained IDs rather than evicting one and replaying it later.
            if state.attempted.len() >= 128 {
                state.terminal = true;
                self.otp_metadata(tag, "manual", Some("vpn_otp_manual_required"));
                continue;
            }
            let identity = ChallengeRequest {
                session_id: session.clone(),
                endpoint_tag: tag.into(),
                challenge_id: id.clone(),
            };
            if let Err(error) = self.auto_vpn_otp_one(&frozen, &identity).await {
                if error == "vpn_auth_stale" {
                    break;
                }
                let state = self.vpn.otp.entry(tag.into()).or_default();
                state.attempted.insert(id.clone());
                // Shape fallback applies to this challenge. Uncertain delivery
                // or persistence remains blocked for the whole active session.
                state.terminal = matches!(
                    error.as_str(),
                    "vpn_otp_save_failed" | "vpn_otp_counter_exhausted" | "vpn_auth_submit_failed"
                );
                self.otp_metadata(
                    tag,
                    if matches!(
                        error.as_str(),
                        "vpn_otp_save_failed" | "vpn_otp_counter_exhausted"
                    ) {
                        "error"
                    } else {
                        "manual"
                    },
                    Some(match error.as_str() {
                        "vpn_otp_save_failed" => "vpn_otp_save_failed",
                        "vpn_otp_counter_exhausted" => "vpn_otp_counter_exhausted",
                        "vpn_otp_form_cache_unsupported" => "vpn_otp_form_cache_unsupported",
                        _ => "vpn_otp_manual_required",
                    }),
                );
            }
        }
    }
}

impl crate::connection::ActiveConnection {
    /// The active request with Start-time codes replaced by their source templates.
    pub(crate) fn redacted_request(&self) -> Result<proto::LoadConfigReq, String> {
        let mut request = self.request.clone();
        if self.vpn_otp_start.is_empty() {
            return Ok(request);
        }
        let mut core: Value = serde_json::from_str(
            request
                .core_config
                .as_deref()
                .ok_or("invalid_configuration")?,
        )
        .map_err(|_| "invalid_configuration")?;
        for endpoint in core["endpoints"].as_array_mut().into_iter().flatten() {
            let Some(tag) = endpoint["tag"].as_str().map(str::to_owned) else {
                continue;
            };
            let Some(frozen) = self
                .vpn_otp
                .get(&tag)
                .filter(|_| self.vpn_otp_start.contains_key(&tag))
            else {
                continue;
            };
            endpoint["username"] = Value::String(frozen.source.username.clone());
            endpoint["password"] = Value::String(frozen.source.password.clone());
        }
        request.core_config = Some(core.to_string());
        Ok(request)
    }
}
