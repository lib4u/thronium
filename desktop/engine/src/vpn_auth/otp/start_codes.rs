//! One-time codes baked into a connection request between CheckConfig and Start.
use super::*;

impl Engine {
    /// Called strictly between a successful CheckConfig and Start: reserve the
    /// HOTP step durably, then bake the code into the request copy in memory.
    /// A failure here leaves the running connection and the library untouched.
    pub(crate) fn commit_start_codes(
        &mut self,
        request: &mut proto::LoadConfigReq,
        bindings: &Bindings,
    ) -> Result<StartMarks, String> {
        let mut marks = StartMarks::new();
        if !bindings
            .values()
            .any(|frozen| frozen.mode == Mode::AutoStart)
        {
            return Ok(marks);
        }
        let mut core: Value = serde_json::from_str(
            request
                .core_config
                .as_deref()
                .ok_or("invalid_configuration")?,
        )
        .map_err(|_| "invalid_configuration")?;
        for (tag, frozen) in bindings
            .iter()
            .filter(|(_, frozen)| frozen.mode == Mode::AutoStart)
        {
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
                .find(|endpoint| endpoint["tag"] == *tag)
                .ok_or("vpn_otp_profile_unsupported")?;
            // Validate the whole placement before spending anything.
            let mut baked = endpoint.clone();
            planner::bake(&mut baked, &code, frozen.source.placement)?;
            let counter = if entry.value.kind == Kind::Hotp {
                Some(self.reserve_vpn_hotp(&entry)?.value.counter)
            } else {
                self.reserve_vpn_totp(&entry, at as u64)?;
                None
            };
            *endpoint = baked;
            marks.insert(
                tag.clone(),
                StartMark {
                    otp_id: entry.id.clone(),
                    counter,
                },
            );
        }
        request.core_config = Some(core.to_string());
        Ok(marks)
    }
}
