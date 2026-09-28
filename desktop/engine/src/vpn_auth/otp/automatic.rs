//! Automatic OTP codes for running VPN endpoints: metadata, candidates and refreshes.
use super::*;

pub(crate) fn candidate_code(entry: &Entry, uses_otp: bool, at: i64) -> Result<String, String> {
    if !uses_otp {
        return Ok(String::new());
    }
    if at < 0 {
        return Err("otp_clock_invalid".into());
    }
    let mut candidate = entry.value.clone();
    if candidate.kind == Kind::Hotp {
        let counter = candidate
            .counter
            .parse::<u64>()
            .map_err(|_| "vpn_otp_counter_exhausted")?;
        candidate.counter = counter
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("vpn_otp_counter_exhausted")?
            .to_string();
    }
    candidate
        .code_at(at as u64)
        .map(|c| c.code)
        .map_err(str::to_owned)
}

impl Engine {
    pub(crate) fn disable_vpn_otp_for_entry(&mut self, id: &str) {
        if let Some(active) = &mut self.active_connection {
            for frozen in active.vpn_otp.values_mut().filter(|f| f.identity.id == id) {
                frozen.disabled = true;
            }
        }
        self.refresh_vpn_otp_bindings();
    }
    pub(crate) fn refresh_vpn_otp_bindings(&mut self) {
        let Some(active) = &mut self.active_connection else {
            return;
        };
        for (tag, frozen) in &mut active.vpn_otp {
            if frozen.current(&self.store.library).is_none() {
                frozen.disabled = true;
            }
            if let Some(endpoint) = self.vpn.status.endpoints.iter_mut().find(|e| &e.tag == tag) {
                let state = self.vpn.otp.entry(tag.clone()).or_default();
                if frozen.disabled {
                    state.metadata = Some(Metadata::new("disabled", Some("vpn_otp_auto_disabled")));
                } else if state.metadata.is_none() {
                    // A baked code is "start" until the endpoint confirms the session.
                    let state_name = if frozen.mode == Mode::AutoStart {
                        "start"
                    } else {
                        "ready"
                    };
                    state.metadata = Some(Metadata::new(state_name, None));
                }
                endpoint.otp = state.metadata.clone();
            }
        }
    }
    pub(crate) fn otp_metadata(&mut self, tag: &str, state: &str, error: Option<&str>) {
        let metadata = Metadata::new(state, error);
        self.vpn.otp.entry(tag.into()).or_default().metadata = Some(metadata.clone());
        if let Some(endpoint) = self.vpn.status.endpoints.iter_mut().find(|e| e.tag == tag) {
            endpoint.otp = Some(metadata);
        }
    }
    /// Qt reconnects with a code of its own after the server refuses the one
    /// baked before Start: this mode has no challenge to answer, so the whole
    /// connection is started again. The digits the server refused are never
    /// sent twice, and only an explicit Connect resets how many times this may
    /// happen.
    pub(crate) async fn restart_for_fresh_start_code(&mut self, tag: &str, frozen: &Frozen) {
        const MAX_RESTARTS: u32 = 3;
        let Some(id) = self.running.clone() else {
            return;
        };
        let Some(entry) = frozen.current(&self.store.library).cloned() else {
            return;
        };
        let attempts = self
            .vpn_start_restarts
            .entry((id.clone(), tag.to_owned()))
            .or_default();
        if *attempts >= MAX_RESTARTS {
            self.otp_metadata(tag, "limited", Some("vpn_otp_retry_limited"));
            return;
        }
        let at = now();
        if at < 0 {
            return;
        }
        // A time-based code of the same step is the same digits: wait for the
        // next one rather than offer what was just refused.
        if entry.value.kind == Kind::Totp && self.totp_step_spent(&entry, at as u64) {
            self.otp_metadata(tag, "waiting", None);
            return;
        }
        *self
            .vpn_start_restarts
            .entry((id.clone(), tag.to_owned()))
            .or_default() += 1;
        self.logs.event("info", "vpn_otp_restarted", None);
        self.otp_metadata(tag, "start", None);
        let _ = self
            .connect_using_library(&id, None, super::Intent::Start)
            .await;
    }

    pub(crate) async fn auto_vpn_otp_one(
        &mut self,
        frozen: &Frozen,
        identity: &ChallengeRequest,
    ) -> Result<(), String> {
        // Fresh Query and action share this session's original managed generation.
        let (challenge, _, generation) = self.current_vpn_challenge(identity).await?;
        let entry = frozen
            .current(&self.store.library)
            .ok_or("vpn_otp_auto_disabled")?
            .clone();
        let failed = challenge.error.as_ref().is_some_and(|e| !e.is_empty());
        let state = self
            .vpn
            .otp
            .entry(identity.endpoint_tag.clone())
            .or_default();
        // The last refusal still matters when the retry budget is exhausted.
        // Connected resets that budget, but must never permit these digits again.
        if failed && entry.value.kind == Kind::Totp {
            if let Some(last) = &state.last_code {
                state.rejected_codes.insert(last.clone());
            }
        }
        if failed && state.rejects >= 3 {
            self.otp_metadata(
                &identity.endpoint_tag,
                "limited",
                Some("vpn_otp_retry_limited"),
            );
            return Ok(());
        }
        let uses_otp = planner::dependency(&frozen.source, &challenge, identity)?;
        let at = now();
        let code = candidate_code(&entry, uses_otp, at)?;
        if uses_otp && entry.value.kind == Kind::Totp {
            let spent = at >= 0 && self.totp_step_spent(&entry, at as u64);
            let state = self
                .vpn
                .otp
                .entry(identity.endpoint_tag.clone())
                .or_default();
            // Accepted digits are as spent as refused ones: wait for the next step.
            if state.wait_for_new_code(&code, failed) || spent {
                self.otp_metadata(&identity.endpoint_tag, "waiting", None);
                return Ok(());
            }
        }
        let answer = planner::answer(&frozen.source, &challenge, identity, &code)?;
        unexpired(&challenge, now())?;
        // Mark before any fallible persistence or await; cancellation cannot replay.
        let state = self
            .vpn
            .otp
            .entry(identity.endpoint_tag.clone())
            .or_default();
        state.attempted.insert(identity.challenge_id.clone());
        if failed {
            state.rejects += 1;
        }
        if uses_otp {
            state.last_code = Some(code);
            if entry.value.kind == Kind::Totp && at >= 0 {
                self.reserve_vpn_totp(&entry, at as u64)?;
            }
        }
        if answer.uses_otp && entry.value.kind == Kind::Hotp {
            self.reserve_vpn_hotp(&entry)?;
        }
        let answer = answer.request;
        unexpired(&challenge, now())?;
        self.otp_metadata(&identity.endpoint_tag, "ready", None);
        self.vpn_answer(
            generation,
            false,
            proto::SubmitVpnChallengeRequest {
                endpoint_tag: Some(answer.endpoint_tag),
                challenge_id: Some(answer.challenge_id),
                username: Some(answer.username),
                password: Some(answer.password),
                secret: Some(answer.secret),
                form_values: answer.form_values.into_iter().collect(),
            },
        )
        .await
    }
}
