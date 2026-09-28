//! Starting single IP and speed tests for a profile and remembering measured countries.
use super::*;

impl Engine {
    pub fn remember_ip_country(
        &mut self,
        test: &ProfileTest,
        result: &Value,
    ) -> Result<(), String> {
        if !matches!(test.kind, Kind::Ip) || !self.test_matches(test) {
            return Err("probe_stale".into());
        }
        let code = match result.get("countryCode") {
            Some(Value::Null) => None,
            Some(Value::String(code)) => Some(code.as_str()),
            _ => return Err("ip_test_invalid_response".into()),
        };
        ip_result(result["ip"].as_str(), code)?;
        let next = self.store.library.country_measurements.updated(
            &self.store.library,
            test.measured_id(),
            code,
            test.assets.context.as_ref(),
        )?;
        self.store.save_country_measurements(next)
    }
    pub fn speed_test(&mut self, id: &str) -> Result<ProfileTest, String> {
        self.single_test(id, Kind::Speed)
    }
    pub fn ip_test(&mut self, id: &str) -> Result<ProfileTest, String> {
        self.single_test(id, Kind::Ip)
    }
    /// Dialog entry points: the shared probe slot is taken before a bound VPN
    /// profile bakes its one-time code, so a busy queue never spends a HOTP step.
    /// The caller releases `request_id` when the test finishes.
    pub fn reserved_speed_test(
        &mut self,
        request_id: &str,
        id: &str,
    ) -> Result<ProfileTest, String> {
        self.reserved_test(request_id, id, Kind::Speed)
    }
    pub fn reserved_ip_test(&mut self, request_id: &str, id: &str) -> Result<ProfileTest, String> {
        self.reserved_test(request_id, id, Kind::Ip)
    }
    pub(crate) fn reserved_test(
        &mut self,
        request_id: &str,
        id: &str,
        kind: Kind,
    ) -> Result<ProfileTest, String> {
        self.reserve_probe(request_id)?;
        let test = self.single_test(id, kind);
        if test.is_err() {
            self.release_probe(request_id);
        }
        test
    }
    /// A dialog test is manual: a bound VPN profile gets its code baked here,
    /// under the Engine lock, before the host executes the test.
    pub(crate) fn single_test(&mut self, id: &str, kind: Kind) -> Result<ProfileTest, String> {
        let Some(profile) = self
            .store
            .library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
        else {
            return Err("profile_not_found".into());
        };
        // Prepared before the build: the compiler announces the tag of every
        // bound node, hop of a chain as readily as the profile itself.
        let mut sources = match crate::vpn_auth::otp::probe::sources(&self.store.library, &profile)
        {
            Ok(sources) => sources,
            Err(code) => return Err(self.otp_probe_failure(code)),
        };
        let mut test = prepare_with_sources(
            &self.store.library,
            &self.core,
            &self.data_dir,
            &self.logs,
            id,
            kind,
            &self.pool_selection(),
            &mut sources,
        )?;
        if !sources.bound() {
            return Ok(test);
        }
        let bindings = sources.emitted;
        if let Err(code) = test.bake(|core| self.commit_probe_codes(core, &bindings)) {
            return Err(self.otp_probe_failure(code));
        }
        Ok(test)
    }
    /// Whether the prepared test still describes the current library and the
    /// running pool selection it was issued against.
    pub fn test_matches(&self, test: &ProfileTest) -> bool {
        test.matches(&self.store.library, &self.pool_selection())
    }
}
