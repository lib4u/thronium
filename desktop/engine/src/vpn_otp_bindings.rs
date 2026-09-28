//! Local, explicit references to OTP entries. No credentials or codes in views.
use crate::{
    otp::Entry,
    store::{Library, Profile},
    Engine,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    AutoLive,
    /// The code is inserted into the credentials before Start (primary OpenVPN).
    AutoStart,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub revision: String,
    pub otp_id: String,
    pub mode: Mode,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingView {
    pub binding: Option<Binding>,
    pub edit_token: String,
    pub supported: bool,
    pub hotp_supported: bool,
    pub reason: Option<String>,
    pub start_supported: bool,
    pub start_reason: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveRequest {
    pub profile_id: String,
    pub edit_token: String,
    pub otp_id: Option<String>,
    pub otp_revision: Option<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
}

// Private fingerprint never appears in a view; tokens retain no profile secrets.
struct Edit {
    token: String,
    profile_id: String,
    fingerprint: [u8; 32],
    binding: Option<Binding>,
    created: Instant,
}
#[derive(Default)]
pub(crate) struct Edits(VecDeque<Edit>);
const MAX_EDITS: usize = 64;
const EDIT_TTL: Duration = Duration::from_secs(15 * 60);
fn fingerprint(profile: &Profile) -> Result<[u8; 32], String> {
    let bytes = serde_json::to_vec(profile).map_err(|_| "vpn_otp_binding_changed")?;
    Ok(Sha256::digest(bytes).into())
}
pub(crate) fn same_identity(a: &Entry, b: &Entry) -> bool {
    a.id == b.id
        && crate::otp::decode_secret(&a.value.secret)
            .ok()
            .zip(crate::otp::decode_secret(&b.value.secret).ok())
            .is_some_and(|(a, b)| a == b)
        && a.value.algorithm == b.value.algorithm
        && a.value.kind == b.value.kind
        && a.value.digits == b.value.digits
        && a.value.period == b.value.period
}
/// A counter may only be spent where the library's replacement reaches the disk
/// before the write returns: Linux syncs the directory, Windows moves the file
/// write-through. Elsewhere a power cut could hand the same code out twice.
pub(crate) fn durable_counters() -> bool {
    cfg!(any(target_os = "linux", target_os = "windows"))
}
fn platform_support(entry: &Entry) -> Result<(), String> {
    if entry.value.kind == crate::otp::Kind::Hotp && !durable_counters() {
        Err("vpn_otp_platform_unsupported".into())
    } else {
        Ok(())
    }
}
pub(crate) fn validate(library: &Library) -> Result<(), String> {
    for (id, binding) in &library.vpn_otp_bindings {
        if uuid::Uuid::parse_str(id).is_err()
            || uuid::Uuid::parse_str(&binding.revision).is_err()
            || !library.otp.iter().any(|entry| entry.id == binding.otp_id)
            || !library.profiles.iter().any(|profile| {
                profile.id == *id && crate::vpn_endpoint::profile_protocol(profile).is_some()
            })
        {
            return Err("vpn_otp_binding_invalid".into());
        }
    }
    Ok(())
}
/// Deliberate deletion paths call this after removing profiles, never at generic import validation.
pub(crate) fn remove_deleted(library: &mut Library) {
    library
        .vpn_otp_bindings
        .retain(|id, _| library.profiles.iter().any(|profile| profile.id == *id));
}

pub(crate) fn deserialize_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Binding>, D::Error> {
    struct Map;
    impl<'de> serde::de::Visitor<'de> for Map {
        type Value = BTreeMap<String, Binding>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique OTP binding map")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut input: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = input.next_entry::<String, Binding>()? {
                if result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate OTP binding"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Map)
}
// Value-based compatibility migrations must not erase duplicate keys first.
#[derive(Deserialize)]
struct BindingFields {
    #[serde(
        default,
        rename = "vpnOtpBindings",
        deserialize_with = "deserialize_map"
    )]
    _bindings: BTreeMap<String, Binding>,
}
pub(crate) fn validate_wire(bytes: &[u8], backup: bool) -> Result<(), String> {
    if backup {
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "library")]
            _library: BindingFields,
        }
        serde_json::from_slice::<Envelope>(bytes).map_err(|_| "vpn_otp_binding_invalid")?;
    } else {
        serde_json::from_slice::<BindingFields>(bytes).map_err(|_| "vpn_otp_binding_invalid")?;
    }
    Ok(())
}

impl Engine {
    pub fn get_vpn_otp_binding(&mut self, profile_id: &str) -> Result<BindingView, String> {
        let profile = self
            .store
            .library
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .ok_or("profile_not_found")?
            .clone();
        let binding = self.store.library.vpn_otp_bindings.get(profile_id).cloned();
        let platform_reason = binding
            .as_ref()
            .and_then(|binding| {
                self.store
                    .library
                    .otp
                    .iter()
                    .find(|entry| entry.id == binding.otp_id)
            })
            .and_then(|entry| platform_support(entry).err());
        let profile_reason = crate::vpn_auth::otp::support(&profile).err();
        let start_profile_reason = crate::vpn_auth::otp::start_support(&profile).err();
        let supported = profile_reason.is_none();
        let start_supported = start_profile_reason.is_none();
        let reason = profile_reason.or_else(|| platform_reason.clone());
        let start_reason = start_profile_reason.or(platform_reason);
        let token = uuid::Uuid::new_v4().to_string();
        self.vpn_otp_binding_edits
            .0
            .retain(|edit| edit.created.elapsed() <= EDIT_TTL);
        while self.vpn_otp_binding_edits.0.len() >= MAX_EDITS {
            self.vpn_otp_binding_edits.0.pop_front();
        }
        self.vpn_otp_binding_edits.0.push_back(Edit {
            token: token.clone(),
            profile_id: profile.id.clone(),
            fingerprint: fingerprint(&profile)?,
            binding: binding.clone(),
            created: Instant::now(),
        });
        Ok(BindingView {
            binding,
            edit_token: token,
            supported,
            hotp_supported: cfg!(target_os = "linux"),
            reason,
            start_supported,
            start_reason,
        })
    }
    pub fn save_vpn_otp_binding(&mut self, request: SaveRequest) -> Result<BindingView, String> {
        let current = self
            .store
            .library
            .profiles
            .iter()
            .find(|profile| profile.id == request.profile_id)
            .ok_or("profile_not_found")?;
        let binding = self.store.library.vpn_otp_bindings.get(&request.profile_id);
        let edit = self
            .vpn_otp_binding_edits
            .0
            .iter()
            .find(|edit| edit.token == request.edit_token)
            .ok_or("vpn_otp_binding_changed")?;
        if edit.created.elapsed() > EDIT_TTL
            || edit.profile_id != current.id
            || edit.fingerprint != fingerprint(current)?
            || edit.binding.as_ref() != binding
        {
            return Err("vpn_otp_binding_changed".into());
        }
        let mut next = self.store.library.clone();
        let mode = request.mode.unwrap_or(Mode::AutoLive);
        match (request.otp_id.as_deref(), request.otp_revision.as_deref()) {
            (Some(id), Some(revision)) => {
                match mode {
                    Mode::AutoLive => crate::vpn_auth::otp::support(current)?,
                    Mode::AutoStart => crate::vpn_auth::otp::start_support(current)?,
                }
                let entry = next
                    .otp
                    .iter()
                    .find(|entry| entry.id == id)
                    .ok_or("vpn_otp_missing")?;
                if entry.revision != revision {
                    return Err("otp_changed".into());
                }
                entry.validate().map_err(str::to_owned)?;
                platform_support(entry)?;
                next.vpn_otp_bindings.insert(
                    request.profile_id.clone(),
                    Binding {
                        revision: uuid::Uuid::new_v4().to_string(),
                        otp_id: id.into(),
                        mode,
                    },
                );
                // Readers below v4 must refuse a before-Start binding instead of running it live.
                next.version = next
                    .version
                    .max(if mode == Mode::AutoStart { 4 } else { 3 });
            }
            (None, None) => {
                next.vpn_otp_bindings.remove(&request.profile_id);
            }
            _ => return Err("otp_changed".into()),
        }
        let result = self.store.commit(next);
        // Even a post-rename durability failure may have changed the visible binding.
        self.refresh_vpn_otp_bindings();
        result.map_err(|_| "vpn_otp_binding_save_failed")?;
        self.vpn_otp_binding_edits
            .0
            .retain(|edit| edit.token != request.edit_token);
        self.get_vpn_otp_binding(&request.profile_id)
    }
    /// Candidate code/full form must be validated before calling this. This method
    /// never returns a code and never rolls a committed counter back after IPC loss.
    /// A TOTP code stays valid for its whole time step, and a single-use server
    /// refuses the same digits twice. The spent step is kept per entry for the
    /// Engine lifetime, so a new VPN session, a Start retry or a manual test in
    /// the same step cannot hand the digits out again.
    pub(crate) fn totp_step_spent(&self, entry: &Entry, at: u64) -> bool {
        let step = at / u64::from(entry.value.period.max(1));
        self.spent_totp_steps
            .get(&entry.id)
            .is_some_and(|spent| *spent >= step)
    }
    pub(crate) fn reserve_vpn_totp(&mut self, entry: &Entry, at: u64) -> Result<(), String> {
        if self.totp_step_spent(entry, at) {
            return Err("vpn_otp_code_spent".into());
        }
        let step = at / u64::from(entry.value.period.max(1));
        self.spent_totp_steps.insert(entry.id.clone(), step);
        Ok(())
    }
    pub(crate) fn reserve_vpn_hotp(&mut self, expected: &Entry) -> Result<Entry, String> {
        platform_support(expected)?;
        if self.store.durability_uncertain() {
            return Err("vpn_otp_save_failed".into());
        }
        let current = self
            .store
            .library
            .otp
            .iter()
            .find(|entry| entry.id == expected.id)
            .ok_or("vpn_otp_missing")?;
        if current != expected {
            return Err("otp_changed".into());
        }
        if current.value.kind != crate::otp::Kind::Hotp {
            return Err("otp_type_invalid".into());
        }
        let counter = crate::otp::counter(&current.value.counter).map_err(str::to_owned)?;
        if counter == i64::MAX as u64 {
            return Err("vpn_otp_counter_exhausted".into());
        }
        let mut updated = current.clone();
        updated.value.counter = (counter + 1).to_string();
        updated.revision = uuid::Uuid::new_v4().to_string();
        let mut next = self.store.library.clone();
        *next
            .otp
            .iter_mut()
            .find(|entry| entry.id == expected.id)
            .unwrap() = updated.clone();
        self.store.commit(next).map_err(|_| "vpn_otp_save_failed")?;
        Ok(updated)
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests;
