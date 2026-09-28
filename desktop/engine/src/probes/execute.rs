//! Disposable-core execution of one probe and the published error whitelist.
use super::*;

impl Probe {
    /// This operation already owns its TUN admission permit and never needs
    /// the main Engine lock. In particular, Quit may be awaiting its cleanup.
    pub fn is_disposable_vpn(&self) -> bool {
        self.vpn_permit.is_some()
    }
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
    /// IP and speed tests run their own disposable core and never use the
    /// managed probe path of a TUN session.
    pub fn owns_execution(&self) -> bool {
        matches!(self.request, Request::Profile(_))
    }
    pub async fn execute(self, cancelled: &mut watch::Receiver<bool>) -> Result<i32, String> {
        match self.execute_detailed(cancelled).await? {
            Outcome::Latency(ms) => Ok(ms),
            Outcome::HttpFailed(failure) => Err(failure.code().into()),
            Outcome::ConnectedOnly => Err("probe_vpn_connected_only".into()),
            Outcome::AuthRequired => Err("probe_vpn_auth_required".into()),
            Outcome::Ip { .. } | Outcome::Speed(_) => Err("probe_unsupported".into()),
        }
    }
    pub async fn execute_detailed(
        self,
        cancelled: &mut watch::Receiver<bool>,
    ) -> Result<Outcome, String> {
        if let Request::Profile(test) = &self.request {
            return profile_outcome(test.execute(cancelled).await?);
        }
        let configs: Vec<&str> = match &self.request {
            Request::Http(test) => [test.config.as_deref(), test.xray_config.as_deref()]
                .into_iter()
                .flatten()
                .chain(test.xray_full_configs.iter().map(String::as_str))
                .collect(),
            _ => vec![],
        };
        let log = self.logs.begin_probe(configs);
        let result = if self.vpn_permit.is_some() {
            owned::execute(self, cancelled).await
        } else {
            self.execute_latency(cancelled).await
        };
        let error = match &result {
            Err(e) => Some(safe_error(e.clone())),
            Ok(Outcome::HttpFailed(e)) => Some(e.code().into()),
            Ok(Outcome::ConnectedOnly) => Some("probe_vpn_connected_only".into()),
            Ok(Outcome::AuthRequired) => Some("probe_vpn_auth_required".into()),
            _ => None,
        };
        log.finish(error.as_deref());
        result
    }
    async fn execute_latency(
        self,
        cancelled: &mut watch::Receiver<bool>,
    ) -> Result<Outcome, String> {
        if *cancelled.borrow() {
            return Err("probe_cancelled".into());
        }
        tokio::select! {
            biased;
            _ = cancelled.changed() => Err("probe_cancelled".into()),
            result = tokio::time::timeout(Duration::from_millis(self.timeout_ms as u64 * 2 + 8000), async {
                // No shared cache files or listeners from the active core are reused.
                let directory = tempfile::tempdir().map_err(|_| "probe_core_failed")?;
                let directory = self.assets.stage(directory).await?;
                let mut rpc = Rpc::spawn_logged(&self.core, directory.path(), Some(self.logs)).await.map_err(|_| "probe_core_failed")?;
                let request = match self.request {
                    Request::Http(request) => request,
                    Request::Profile(_) => return Err("probe_unsupported".into()),
                    Request::Endpoint(request) => {
                        let response: proto::EndpointProbeResp = rpc.call("EndpointProbe", request).await.map_err(|_| "probe_core_failed")?;
                        if let Some(error) = response.error.filter(|e| !e.is_empty()) { return Err(error); }
                        return response.latency_ms.filter(|ms| *ms >= 0).map(Outcome::Latency).ok_or("probe_failed".into());
                    }
                };
                let response: proto::TestResp = rpc.call("Test", request).await.map_err(|_| "probe_configuration_failed")?;
                let result = response.results.first().filter(|_| response.results.len() == 1).ok_or("probe_failed")?;
                let error = result.error.as_deref().unwrap_or("");
                if !error.is_empty() {
                    let lower = error.to_ascii_lowercase();
                    if lower.contains("aborted") { return Err("probe_cancelled".into()); }
                    if lower.contains("no outbound found") { return Err("probe_configuration_failed".into()); }
                    return Ok(Outcome::HttpFailed(if lower.contains("timeout") || lower.contains("deadline exceeded") { HttpFailure::Timeout }
                        else if lower.contains("certificate") { HttpFailure::Tls } else { HttpFailure::Request }));
                }
                result.latency_ms.filter(|ms| *ms >= 0).map(Outcome::Latency).ok_or("probe_failed".into())
            }) => result.unwrap_or_else(|_| Err("probe_timeout".into())),
        }
    }
}

/// The isolated test publishes the same JSON as the diagnostics dialog.
fn profile_outcome(value: serde_json::Value) -> Result<Outcome, String> {
    if let Some(ip) = value["ip"].as_str() {
        return Ok(Outcome::Ip {
            ip: ip.into(),
            country: value["countryCode"].as_str().map(String::from),
        });
    }
    let text = |key: &str| value[key].as_str().unwrap_or("").to_owned();
    Ok(Outcome::Speed(SpeedResult {
        download: text("download"),
        upload: text("upload"),
        latency_ms: value["latencyMs"]
            .as_i64()
            .and_then(|v| i32::try_from(v).ok()),
        download_bytes: value["downloadBytes"].as_u64().unwrap_or(0),
        upload_bytes: value["uploadBytes"].as_u64().unwrap_or(0),
    }))
}

pub(crate) fn unsupported(error: &str) -> bool {
    matches!(
        error,
        "probe_unsupported"
            | "probe_full_config_unsupported"
            | "probe_tcp_inapplicable"
            | "probe_target_ambiguous"
            | "probe_target_missing"
            | "probe_icmp_unavailable"
            | "probe_direct_unavailable"
            | "probe_endpoint_context_unsupported"
            | "probe_vpn_auth_unsupported"
            | "probe_vpn_context_unsupported"
            | "probe_vpn_otp_binding_required"
            | "probe_vpn_otp_manual_only"
    )
}

pub(crate) fn safe_error(error: String) -> String {
    if unsupported(&error)
        || matches!(
            error.as_str(),
            "probe_timeout"
                | "probe_stale"
                | "probe_auto_failed"
                | "probe_auto_unsupported"
                | "geodata_missing"
                | "geodata_invalid"
                | "geodata_category_missing"
                | "geodata_too_large"
                | "geodata_write_failed"
                | "geodata_external_file_unsupported"
                | "probe_cancelled"
                | "probe_tls_failed"
                | "probe_core_failed"
                | "probe_dns_failed"
                | "probe_connection_refused"
                | "probe_unreachable"
                | "probe_icmp_no_reply"
                | "probe_configuration_failed"
                | "probe_cleanup_failed"
                | "probe_vpn_connected_only"
                | "probe_vpn_auth_required"
                | "probe_vpn_otp_failed"
        )
    {
        error
    } else {
        "probe_failed".into()
    }
}

pub(crate) fn http_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("deadline exceeded") {
        "probe_timeout"
    } else if lower.contains("certificate") {
        "probe_tls_failed"
    } else {
        "probe_failed"
    }
    .into()
}
