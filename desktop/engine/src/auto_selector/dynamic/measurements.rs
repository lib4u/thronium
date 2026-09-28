use super::*;
use sha2::{Digest, Sha256};

pub(super) struct Plan {
    pub(super) context: String,
    pub(super) ids: Vec<String>,
    pub(super) candidate_count: usize,
    pub(super) url: String,
    pub(super) timeout_ms: u32,
}

pub(super) fn plan(engine: &Engine, profile: &Profile) -> Result<Plan, String> {
    let library = &engine.store.library;
    let (source, _, _) = source(profile, library)?;
    if source.order != MemberOrder::SavedHttpLatency {
        return Err("selector_saved_order_required".into());
    }
    if source.result_validity_mins == 0 {
        return Err("selector_measurement_lifetime_required".into());
    }
    let url = profile
        .config
        .get("url")
        .map_or(Some(""), Value::as_str)
        .ok_or("probe_invalid_url")?;
    let timeout_ms = library.preferences.ping.timeout_ms;
    let url = crate::probes::PingSettings {
        method: crate::probes::Method::Http,
        url: if url.is_empty() {
            crate::probes::DEFAULT_TEST_URL
        } else {
            url
        }
        .into(),
        timeout_ms,
    }
    .validate()?
    .to_string();
    // This raw list is independent of the HTTP results this sweep will write.
    let (candidates, _) = resolve_plan(profile, library, Resolution::Candidates)?;
    let pool_policy = crate::group_chains::policy(library, profile);
    let saved_owner = library
        .profiles
        .iter()
        .find(|p| p.id == profile.id)
        .map(|p| json!([p.kind, p.group_id, p.config, p.vpn_policy]));
    let mut fingerprint = Sha256::new();
    fingerprint.update(
        serde_json::to_vec(&json!([
            "selector-measurements-v1",
            profile.id,
            profile.group_id,
            profile.kind,
            profile.config,
            profile.vpn_policy,
            saved_owner,
            pool_policy,
            library.preferences.connection_mode,
            library.preferences.tun,
            timeout_ms,
        ]))
        .map_err(|_| "selector_measurement_context")?,
    );
    let mut ids = Vec::new();
    for id in &candidates {
        let candidate = library
            .profiles
            .iter()
            .find(|p| &p.id == id)
            .ok_or("selector_measurement_context")?;
        if pool_policy != crate::group_chains::policy(library, candidate) {
            return Err("selector_measurement_context".into());
        }
        let context = crate::latency_measurements::fingerprint(library, id)
            .ok_or("selector_measurement_context")?;
        fingerprint.update(
            serde_json::to_vec(&json!([id, context]))
                .map_err(|_| "selector_measurement_context")?,
        );
        if http_in_pool(library, profile, id, &source).is_none() {
            ids.push(id.clone());
        }
    }
    Ok(Plan {
        context: format!("{:x}", fingerprint.finalize()),
        ids,
        candidate_count: candidates.len(),
        url,
        timeout_ms,
    })
}

impl Engine {
    /// Read-only plan. The caller executes ordinary HTTP batches outside Engine.
    pub fn plan_selector_measurements(&self, draft: crate::ProfileDraft) -> Result<Value, String> {
        let profile = self.selector_draft(draft)?;
        let plan = plan(self, &profile)?;
        Ok(json!({"context":plan.context, "ids":plan.ids,
                  "candidateCount":plan.candidate_count, "freshCount":plan.candidate_count-plan.ids.len(),
                  "url":plan.url, "timeoutMs":plan.timeout_ms}))
    }

    /// HTTP cache writes may advance; the network context and draft must match.
    pub fn rank_measured_selector(
        &self,
        draft: crate::ProfileDraft,
        expected_context: &str,
    ) -> Result<Value, String> {
        if expected_context.len() != 64 || !expected_context.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("selector_measurements_stale".into());
        }
        let profile = self.selector_draft(draft)?;
        let current = plan(self, &profile)?;
        if current.context != expected_context {
            return Err("selector_measurements_stale".into());
        }
        if !current.ids.is_empty() {
            return Err("selector_measurements_incomplete".into());
        }
        saved_order::rank_profile(self, &profile)
    }
}
