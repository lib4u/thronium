//! Managed-context probes: TUN workers issue endpoint probes through the live core.
use super::*;

impl Engine {
    pub(super) fn managed_probe_context(&self) -> bool {
        self.rpc.as_ref().is_some_and(|r| r.managed())
            || self.active_connection.as_ref().is_some_and(|c| c.tun)
            || self.vpn_credentials_transition.is_some()
    }
    pub(crate) fn vpn_probe_guard(&self) -> Result<(), String> {
        if self.probes.vpn_owners.load(Ordering::Acquire) > 0 {
            Err("probe_busy".into())
        } else {
            Ok(())
        }
    }
    pub(crate) async fn finish_probe_cleanup(&mut self) -> Result<(), String> {
        self.cancel_url_tests();
        // Capture only the shared counter: borrowing &Engine across this await
        // would require every backend/IPC stream to be Sync, while the Engine
        // deliberately requires only Send under the application mutex.
        let owners = self.probes.vpn_owners.clone();
        let result = tokio::time::timeout(Duration::from_secs(10), async move {
            while owners.load(Ordering::Acquire) > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "probe_cleanup_failed".to_string());
        if let Err(error) = &result {
            self.error = Some(error.clone());
        } else if self.error.as_deref() == Some("probe_cleanup_failed") {
            self.error = None;
        }
        result
    }
    /// A managed TUN worker can set its own output mark. Network work is a
    /// separate job; these IPC calls return immediately without waiting for it.
    pub async fn start_managed_probe(&mut self, probe: &Probe) -> Result<Option<String>, String> {
        let Request::Endpoint(request) = &probe.request else {
            return Ok(None);
        };
        let Some(rpc) = self.rpc.as_mut().filter(|r| r.managed()) else {
            return Ok(None);
        };
        let response: proto::EndpointProbeJob = rpc
            .call("StartEndpointProbe", request.clone())
            .await
            .map_err(|_| "probe_direct_unavailable")?;
        if let Some(error) = response.error.filter(|e| !e.is_empty()) {
            return Err(error);
        }
        Ok(Some(
            response
                .id
                .filter(|id| !id.is_empty())
                .ok_or("probe_direct_unavailable")?,
        ))
    }

    pub async fn query_managed_probe(&mut self, id: &str) -> Result<Option<i32>, String> {
        let rpc = self
            .rpc
            .as_mut()
            .filter(|r| r.managed())
            .ok_or("probe_direct_unavailable")?;
        let response: proto::EndpointProbeJob = rpc
            .call(
                "QueryEndpointProbe",
                proto::EndpointProbeJobReq {
                    id: Some(id.into()),
                },
            )
            .await
            .map_err(|_| "probe_direct_unavailable")?;
        if !response.done.unwrap_or(false) {
            return Ok(None);
        }
        if let Some(error) = response.error.filter(|e| !e.is_empty()) {
            return Err(error);
        }
        Ok(Some(
            response
                .latency_ms
                .filter(|n| *n >= 0)
                .ok_or("probe_failed")?,
        ))
    }

    pub async fn cancel_managed_probe(&mut self, id: &str) {
        if let Some(rpc) = self.rpc.as_mut().filter(|r| r.managed()) {
            let _: Result<proto::EmptyResp, _> = rpc
                .call(
                    "CancelEndpointProbe",
                    proto::EndpointProbeJobReq {
                        id: Some(id.into()),
                    },
                )
                .await;
        }
    }
}
