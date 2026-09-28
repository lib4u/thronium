//! One batch at a time: preparation, completion, staleness and the snapshot view.
use super::*;
mod results;

impl Engine {
    /// The next queued test, with a bound VPN profile's one-time code baked in
    /// under the Engine lock. A refused code finishes that entry and moves on.
    pub fn next_url_test(&mut self, batch_id: &str) -> Option<Probe> {
        loop {
            let probe = self.next_url_test_inner(batch_id)?;
            match self.bake_probe_otp(batch_id, probe) {
                Ok(probe) => return Some(probe),
                Err((id, code)) => self.finish_url_test_detailed(batch_id, &id, Err(code)),
            }
        }
    }
    /// Only a manual test may spend a code; periodic and automatic sources
    /// are refused before anything is reserved.
    fn bake_probe_otp(
        &mut self,
        batch_id: &str,
        mut probe: Probe,
    ) -> Result<Probe, (String, String)> {
        let id = probe.id.clone();
        if !probe.otp.bound() {
            return Ok(probe);
        }
        let manual = self
            .probes
            .batch
            .as_ref()
            .is_some_and(|b| b.id == batch_id && b.source == Source::Manual);
        if !manual {
            return Err((id, "probe_vpn_otp_manual_only".into()));
        }
        // Every node the compiler announced receives its own code, wherever in
        // the configuration that node sits.
        let bindings = std::mem::take(&mut probe.otp).emitted;
        let baked = match &mut probe.request {
            Request::Http(request) => bake_config(request.config.as_mut(), |core| {
                self.commit_probe_codes(core, &bindings)
            }),
            Request::Profile(test) => test.bake(|core| self.commit_probe_codes(core, &bindings)),
            Request::Endpoint(_) => Ok(()),
        };
        match baked {
            Ok(()) => Ok(probe),
            Err(code) => Err((id, self.otp_probe_failure(code))),
        }
    }
    /// The reason stays in the log as a code; the row carries one probe code.
    pub(crate) fn otp_probe_failure(&mut self, code: String) -> String {
        self.logs.event("warn", &code, None);
        "probe_vpn_otp_failed".into()
    }
    fn next_url_test_inner(&mut self, batch_id: &str) -> Option<Probe> {
        if self.probes.cleanup_failed.load(Ordering::Acquire) {
            self.cancel_queued_after_cleanup_failure();
            return None;
        }
        let managed_context = self.managed_probe_context();
        let selection = self.pool_selection();
        let batch = self.probes.batch.as_mut().filter(|b| b.id == batch_id)?;
        if batch
            .entries
            .iter()
            .filter(|e| e.status == Status::Testing)
            .count()
            >= self.probes.concurrency.max(1)
        {
            return None;
        }
        for entry in &mut batch.entries {
            if entry.status != Status::Queued {
                continue;
            }
            let current = self
                .store
                .library
                .profiles
                .iter()
                .find(|p| p.id == entry.profile_id);
            if current.is_none_or(|p| !entry.matches(p, &self.store.library))
                || (vpn::involves(&self.store.library, &entry.profile)
                    && entry.managed_context != managed_context)
            {
                entry.finish(Status::Stale, None, Some("probe_stale".into()));
                continue;
            }
            // Unsupported methods can advance without issuing any network work.
            while entry.status == Status::Queued {
                let method = entry.effective_method;
                entry.http_asset_context = None;
                let mut assets = full_xray::Assets::default();
                // Prepared before the build, so the compiler can announce the
                // tag of every bound node it lays down.
                let mut sources =
                    match crate::vpn_auth::otp::probe::sources(&self.store.library, &entry.profile)
                    {
                        Ok(sources) => sources,
                        Err(code) => {
                            self.logs.event("warn", &code, None);
                            entry.attempt(Status::Error, None, Some("probe_vpn_otp_failed".into()));
                            if row_measurement(batch.source) {
                                self.probes.cache.insert(
                                    (entry.profile_id.clone(), entry.method, entry.kind),
                                    entry.clone(),
                                );
                            }
                            break;
                        }
                    };
                let prepared = if batch.kind != Kind::Latency {
                    // The isolated IP/speed test of the diagnostics dialog, prepared
                    // against the current library so its stamp guards publication.
                    crate::settings::tests_runtime::prepare_with_sources(
                        &self.store.library,
                        &self.core,
                        &self.data_dir,
                        &self.logs,
                        &entry.profile_id,
                        profile_kind(batch.kind),
                        &selection,
                        &mut sources,
                    )
                    .map(|test| {
                        entry.test_stamp = Some(test.stamp().clone());
                        entry.http_asset_context = test.asset_context().cloned();
                        entry.transport = Some(test.transport().into());
                        if let Some((id, name)) = test.member() {
                            entry.member_id = Some(id.to_owned());
                            entry.member_name = Some(name.to_owned());
                        }
                        entry.member_origin = test.member_origin();
                        Request::Profile(Box::new(test))
                    })
                } else if method == Method::Http {
                    if vpn::involves(&self.store.library, &entry.profile) && managed_context {
                        Err("probe_vpn_context_unsupported".into())
                    } else {
                        prepared_request_with_sources(
                            &self.store.library,
                            &entry.profile,
                            &batch.url,
                            batch.timeout_ms,
                            &mut sources,
                        )
                        .and_then(|mut request| {
                            if entry.profile.kind == ProfileKind::XrayConfig {
                                assets = full_xray::Assets::prepare(
                                    &mut request,
                                    &self.data_dir,
                                    &self.store.library,
                                    &entry.profile,
                                )?;
                                entry.http_asset_context = assets.context.clone();
                            }
                            Ok(Request::Http(request))
                        })
                    }
                } else {
                    endpoint::target(&entry.profile, &self.store.library, method).map(|target| {
                        entry.first_hop = target.first_hop;
                        Request::Endpoint(proto::EndpointProbeReq {
                            method: Some(if method == Method::Tcp { "tcp" } else { "icmp" }.into()),
                            host: Some(target.host),
                            port: Some(target.port as u32),
                            timeout_ms: Some(batch.timeout_ms),
                        })
                    })
                };
                match prepared {
                    Ok(request) => {
                        entry.status = Status::Testing;
                        return Some(Probe {
                            id: entry.profile_id.clone(),
                            core: self.core.clone(),
                            request,
                            timeout_ms: batch.timeout_ms,
                            assets,
                            otp: sources,
                            logs: self.logs.for_probe(
                                &entry.profile,
                                match method {
                                    Method::Http => "http",
                                    Method::Tcp => "tcp",
                                    Method::Icmp => "icmp",
                                    Method::Auto => "auto",
                                },
                            ),
                            vpn_permit: (method == Method::Http
                                && vpn::involves(&self.store.library, &entry.profile))
                            .then(|| {
                                owned::Permit::new(
                                    self.probes.vpn_owners.clone(),
                                    self.probes.cleanup_failed.clone(),
                                )
                            }),
                        });
                    }
                    Err(error) => {
                        if error == "probe_stale" {
                            entry.finish(Status::Stale, None, Some(error));
                        } else {
                            entry.attempt(
                                if unsupported(&error) {
                                    Status::Unsupported
                                } else {
                                    Status::Error
                                },
                                None,
                                Some(safe_error(error)),
                            );
                        }
                        if row_measurement(batch.source) {
                            self.probes.cache.insert(
                                (entry.profile_id.clone(), entry.method, entry.kind),
                                entry.clone(),
                            );
                        }
                    }
                }
            }
        }
        None
    }
}

fn profile_kind(kind: Kind) -> crate::settings::tests_runtime::Kind {
    match kind {
        Kind::Speed => crate::settings::tests_runtime::Kind::Speed,
        _ => crate::settings::tests_runtime::Kind::Ip,
    }
}

/// Apply a baking step to a request's serialized core configuration.
pub(crate) fn bake_config<T>(
    config: Option<&mut String>,
    bake: impl FnOnce(&mut Value) -> Result<T, String>,
) -> Result<(), String> {
    let config = config.ok_or("invalid_configuration")?;
    let mut core: Value = serde_json::from_str(config).map_err(|_| "invalid_configuration")?;
    bake(&mut core)?;
    *config = core.to_string();
    Ok(())
}

/// The auto-select sweep ranks its own pool only: none of its outcomes, even a
/// preparation error or a cancellation, becomes a library row measurement or
/// a saved HTTP latency.
fn row_measurement(source: Source) -> bool {
    source != Source::AutoSelect
}
