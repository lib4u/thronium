//! Finishing, cancelling and reading URL test results and cached measurements.
use super::*;

impl Engine {
    pub fn finish_url_test(&mut self, batch_id: &str, id: &str, result: Result<i32, String>) {
        self.finish_url_test_detailed(batch_id, id, result.map(Outcome::Latency));
    }
    pub fn finish_url_test_detailed(
        &mut self,
        batch_id: &str,
        id: &str,
        result: Result<Outcome, String>,
    ) {
        let selection = self.pool_selection();
        let managed_context = self.managed_probe_context();
        let Some(batch) = self.probes.batch.as_mut().filter(|b| b.id == batch_id) else {
            return;
        };
        let Some(entry) = batch
            .entries
            .iter_mut()
            .find(|e| e.profile_id == id && e.status == Status::Testing)
        else {
            return;
        };
        let current = self.store.library.profiles.iter().find(|p| p.id == id);
        if current.is_none_or(|p| {
            !entry.matches(p, &self.store.library)
                || entry
                    .http_asset_context
                    .as_ref()
                    .is_some_and(|context| !context.matches(&self.store.library, p))
        }) || (vpn::involves(&self.store.library, &entry.profile)
            && entry.managed_context != managed_context)
            || (batch.kind != Kind::Latency
                && crate::settings::tests_runtime::stamp_for(
                    &self.store.library,
                    id,
                    profile_kind(batch.kind),
                    &selection,
                ) != entry.test_stamp)
        {
            entry.finish(Status::Stale, None, Some("probe_stale".into()));
            let journal_entry = journal::Entry::from_measurement(entry, batch.source);
            self.record_measurement(journal_entry);
            return;
        }
        if entry.effective_method == Method::Http {
            match result {
                Ok(Outcome::Latency(ms)) if ms >= 0 => entry.http_sample = Some(Some(ms)),
                Ok(Outcome::HttpFailed(_)) => entry.http_sample = Some(None),
                _ => {}
            }
        }
        match result {
            Ok(Outcome::HttpFailed(failure)) => {
                entry.attempt(Status::Error, None, Some(failure.code().into()))
            }
            Ok(Outcome::Ip { ip, country }) => {
                entry.ip = Some(ip);
                entry.country_code = country.clone();
                entry.attempt(Status::Ok, None, None);
                // The same persistent country cache as the single IP test.
                let saved = self
                    .store
                    .library
                    .country_measurements
                    .updated(
                        &self.store.library,
                        id,
                        country.as_deref(),
                        entry.http_asset_context.as_ref(),
                    )
                    .and_then(|next| self.store.save_country_measurements(next));
                if saved.is_err() {
                    self.logs.event("warn", "country_cache_write_failed", None);
                }
            }
            Ok(Outcome::Speed(speed)) => {
                entry.download = Some(speed.download);
                entry.upload = Some(speed.upload);
                entry.download_bytes = Some(speed.download_bytes);
                entry.upload_bytes = Some(speed.upload_bytes);
                entry.attempt(Status::Ok, speed.latency_ms, None);
            }
            Ok(Outcome::Latency(ms)) if ms >= 0 => entry.attempt(Status::Ok, Some(ms), None),
            Ok(Outcome::ConnectedOnly) => entry.attempt(Status::ConnectedOnly, None, None),
            Ok(Outcome::AuthRequired) => entry.attempt(
                Status::AuthRequired,
                None,
                Some("probe_vpn_auth_required".into()),
            ),
            result => {
                let error = result.err().unwrap_or_default();
                let code = safe_error(error);
                entry.attempt(
                    if code == "probe_cancelled" {
                        Status::Cancelled
                    } else if unsupported(&code) {
                        Status::Unsupported
                    } else {
                        Status::Error
                    },
                    None,
                    Some(code),
                );
            }
        }
        let isolated = !row_measurement(batch.source);
        if !isolated {
            self.probes
                .cache
                .insert((id.into(), entry.method, entry.kind), entry.clone());
        }
        let journal_entry = journal::Entry::from_measurement(entry, batch.source);
        let completed = if !isolated
            && matches!(entry.status, Status::Ok | Status::Error)
            // Complete Xray configurations are pool members too; their result was
            // accepted above only while their cached lists were unchanged.
            && crate::auto_selector::member_kind(entry.profile.kind)
            && crate::chains::flatten(&entry.profile, &self.store.library.profiles).is_ok()
        {
            entry
                .http_sample
                .map(|latency| (batch.url.clone(), batch.timeout_ms, latency))
        } else {
            None
        };
        if let Some((url, timeout, latency)) = completed {
            let saved = self
                .store
                .library
                .latency_measurements
                .updated(&self.store.library, id, &url, timeout, latency)
                .and_then(|next| self.store.save_latency_measurements(next));
            if saved.is_err() {
                self.logs.event("warn", "latency_cache_write_failed", None);
            }
        }
        self.record_measurement(journal_entry);
        if self.probes.cleanup_failed.load(Ordering::Acquire) {
            self.cancel_queued_after_cleanup_failure();
        }
        // Qt clears unavailable servers when the whole user-run test is done.
        let failed: Vec<String> = self
            .probes
            .batch
            .as_ref()
            .filter(|batch| {
                batch.id == batch_id
                    && batch.source == Source::Manual
                    && batch.kind == Kind::Latency
                    && !batch.entries.iter().any(|entry| entry.status.active())
            })
            .map(|batch| {
                batch
                    .entries
                    .iter()
                    .filter(|entry| entry.status == Status::Error)
                    .map(|entry| entry.profile_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.clear_unavailable(&failed);
    }
    pub(crate) fn cancel_queued_after_cleanup_failure(&mut self) {
        if let Some(sender) = &self.probes.cancel {
            let _ = sender.send(true);
        }
        if let Some(batch) = self.probes.batch.as_mut() {
            for entry in &mut batch.entries {
                if entry.status == Status::Queued {
                    entry.finish(Status::Cancelled, None, Some("probe_cancelled".into()));
                }
            }
        }
    }
    pub fn cancel_url_test_batch(&mut self, id: &str) -> bool {
        if self
            .probes
            .batch
            .as_ref()
            .is_none_or(|batch| batch.id != id)
        {
            return false;
        }
        self.cancel_url_tests();
        true
    }
    pub fn cancel_url_tests(&mut self) {
        if let Some(sender) = self.probes.cancel.take() {
            let _ = sender.send(true);
        }
        if let Some(batch) = &mut self.probes.batch {
            for e in &mut batch.entries {
                if e.status.active() {
                    e.finish(Status::Cancelled, None, None);
                    if row_measurement(batch.source) {
                        self.probes
                            .cache
                            .insert((e.profile_id.clone(), e.method, e.kind), e.clone());
                    }
                }
            }
        }
    }
    pub fn clear_url_tests(&mut self) -> Result<(), String> {
        self.url_tests_resettable()?;
        self.store.save_latency_measurements(Default::default())?;
        self.forget_url_tests();
        Ok(())
    }
    /// A configuration change that invalidates measurements is refused before
    /// it is committed while a batch or a VPN probe still owns them.
    pub(crate) fn url_tests_resettable(&self) -> Result<(), String> {
        self.vpn_probe_guard()?;
        if self
            .probes
            .batch
            .as_ref()
            .is_some_and(|b| b.entries.iter().any(|e| e.status.active()))
        {
            return Err("probe_busy".into());
        }
        Ok(())
    }
    /// Measurements of a committed configuration change. The change is already
    /// saved, so a failed cache write is logged and the stale values are still
    /// dropped from memory.
    pub(crate) fn reset_url_tests_after_commit(&mut self) {
        if self
            .store
            .save_latency_measurements(Default::default())
            .is_err()
        {
            self.store.forget_latency_measurements();
            self.logs.event("warn", "latency_cache_write_failed", None);
        }
        self.forget_url_tests();
    }
    pub(crate) fn forget_url_tests(&mut self) {
        self.selector_health
            .clear_before(crate::auto_selector::health::now_ms());
        self.probes.batch = None;
        self.probes.cache.clear();
        self.clear_quick_memory();
    }
    pub(crate) fn url_tests_snapshot(&mut self) -> Option<Batch> {
        let managed_context = self.managed_probe_context();
        let library = &self.store.library;
        let profiles = &library.profiles;
        self.probes.cache.retain(|(id, _, _), e| {
            profiles.iter().any(|p| {
                p.id == *id
                    && e.matches(p, library)
                    && (!vpn::involves(&self.store.library, p)
                        || e.managed_context == managed_context)
            })
        });
        let mut batch = self.probes.batch.clone()?;
        for e in &mut batch.entries {
            if !e.status.active()
                && profiles
                    .iter()
                    .find(|p| p.id == e.profile_id)
                    .is_none_or(|p| {
                        !e.matches(p, library)
                            || (vpn::involves(&self.store.library, p)
                                && e.managed_context != managed_context)
                    })
            {
                e.status = Status::Stale;
                e.latency_ms = None;
                e.error = Some("probe_stale".into());
            }
        }
        Some(batch)
    }
    /// Accept only the exact, completed HTTP batch owned by this connection.
    /// Re-check fingerprints here; UI snapshots deliberately do not mutate it.
    pub(crate) fn quick_batch_results(
        &self,
        id: &str,
        ids: &[String],
        url: &str,
        timeout_ms: u32,
    ) -> Result<Vec<Option<i32>>, String> {
        let batch = self
            .probes
            .batch
            .as_ref()
            .filter(|b| {
                b.id == id
                    && b.kind == Kind::Latency
                    && b.source == Source::AutoSelect
                    && b.method == Method::Http
                    && b.url == url
                    && b.timeout_ms == timeout_ms
            })
            .ok_or("selector_measurements_interrupted")?;
        if batch.entries.len() != ids.len() {
            return Err("selector_measurements_interrupted".into());
        }
        batch
            .entries
            .iter()
            .zip(ids)
            .map(|(entry, id)| {
                if entry.profile_id != *id {
                    return Err("selector_measurements_interrupted".into());
                }
                let profile = self
                    .store
                    .library
                    .profiles
                    .iter()
                    .find(|p| p.id == *id)
                    .ok_or("selector_measurements_stale")?;
                if !entry.matches(profile, &self.store.library) {
                    return Err("selector_measurements_stale".into());
                }
                match entry.status {
                    Status::Ok => entry
                        .latency_ms
                        .filter(|ms| *ms >= 0)
                        .map(Some)
                        .ok_or_else(|| "selector_measurements_incomplete".into()),
                    Status::Error | Status::Unsupported => Ok(None),
                    _ => Err("selector_measurements_incomplete".into()),
                }
            })
            .collect()
    }
    pub(crate) fn context_matches(&self, p: &Profile, e: &Measurement) -> bool {
        !vpn::involves(&self.store.library, p) || e.managed_context == self.managed_probe_context()
    }
    pub(crate) fn cache_entry(
        &self,
        p: &Profile,
        method: Method,
        kind: Kind,
    ) -> Option<&Measurement> {
        self.probes
            .cache
            .get(&(p.id.clone(), method, kind))
            .filter(|e| e.matches(p, &self.store.library) && self.context_matches(p, e))
    }
    /// The last isolated IP or speed result of a profile while it is still
    /// valid for the current configuration and context.
    pub(crate) fn cached(&self, p: &Profile, kind: Kind) -> Option<&Measurement> {
        self.cache_entry(p, Method::Http, kind)
    }
    pub(crate) fn measurement(&self, p: &Profile) -> Option<&Measurement> {
        // Freeze the selected mode during a run. Auto labels each concrete method.
        // Rows show latency; IP and speed batches are read from the batch itself.
        let latency = self
            .probes
            .batch
            .as_ref()
            .filter(|b| b.kind == Kind::Latency && b.source != Source::AutoSelect);
        let method = latency
            .filter(|b| b.entries.iter().any(|e| e.status.active()))
            .map_or(self.store.library.preferences.ping.method, |b| b.method);
        latency
            .and_then(|b| {
                b.entries.iter().find(|e| {
                    e.method == method
                        && e.profile_id == p.id
                        && e.matches(p, &self.store.library)
                        && self.context_matches(p, e)
                })
            })
            .or_else(|| self.cache_entry(p, method, Kind::Latency))
    }
}
