//! One-time codes for disposable tests. A test box has no challenge channel,
//! so a bound profile gets its code baked at issue (Qt's test build); HOTP is
//! reserved durably first, at the single consumption point, and the baked
//! request lives only in the issued test, never in a snapshot or journal.
use super::{candidate_code, now, planner, Build, Frozen, Intent};
use crate::{otp::Kind, store::Library, store::Profile, Engine};
use serde_json::Value;
use std::collections::HashSet;

/// The bindings a disposable test must honour: the profile itself and every
/// node the tested configuration carries. The compiler announces the tag of
/// each one, so a code is baked where that node actually is. Planner refusals
/// surface here, before any code is reserved.
pub(crate) fn sources(library: &Library, profile: &Profile) -> Result<Build, String> {
    // A configuration the compiler refuses is measured by nobody; that build
    // states the reason itself.
    let needed = crate::vless::relevant(library, profile)
        .unwrap_or_else(|_| HashSet::from([profile.id.clone()]));
    if !needed
        .iter()
        .any(|id| library.vpn_otp_bindings.contains_key(id))
    {
        return Ok(Build::default());
    }
    // The test compiles from the library as it stands; only the frozen
    // bindings travel, never this preparation copy.
    let mut copy = library.clone();
    let mut selected = profile.clone();
    Build::prepare(&mut copy, &mut selected, &needed, library, Intent::Probe)
}

/// Proof that a test carried a minted code: enough for tests, never the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProbeMark {
    pub(crate) otp_id: String,
    pub(crate) counter: Option<String>,
}

impl Engine {
    /// Bake the reserved code of every announced node into the test copy.
    pub(crate) fn commit_probe_codes(
        &mut self,
        core: &mut Value,
        bindings: &super::Bindings,
    ) -> Result<(), String> {
        for (tag, frozen) in bindings {
            self.commit_probe_code(core, tag, frozen)?;
        }
        Ok(())
    }
    /// Reserve the HOTP step durably, then bake the code into the test copy of
    /// the endpoint `tag`. A failure leaves the library and the test untouched;
    /// a template that needs no code spends nothing.
    pub(crate) fn commit_probe_code(
        &mut self,
        core: &mut Value,
        tag: &str,
        frozen: &Frozen,
    ) -> Result<Option<ProbeMark>, String> {
        let entry = frozen
            .current(&self.store.library)
            .ok_or("vpn_otp_auto_disabled")?
            .clone();
        let at = now();
        let code = candidate_code(&entry, true, at)?;
        let endpoint = core["endpoints"]
            .as_array_mut()
            .into_iter()
            .flatten()
            .find(|endpoint| endpoint["tag"] == tag)
            .ok_or("vpn_otp_profile_unsupported")?;
        // Validate the whole placement before spending anything.
        let mut baked = endpoint.clone();
        if !planner::bake_probe(&mut baked, &code, &frozen.source)? {
            return Ok(None);
        }
        let counter = if entry.value.kind == Kind::Hotp {
            Some(self.reserve_vpn_hotp(&entry)?.value.counter)
        } else {
            self.reserve_vpn_totp(&entry, at as u64)?;
            None
        };
        *endpoint = baked;
        Ok(Some(ProbeMark {
            otp_id: entry.id.clone(),
            counter,
        }))
    }
}
