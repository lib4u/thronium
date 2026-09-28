//! Retain the existing GNOME lease; never acquire one during credential retry.
use super::*;
use crate::{system_proxy::RetainedProxy, transport::Rpc};

const CLEANUP: &str = "vpn_credentials_proxy_cleanup_failed";

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Preflight,
    Retiring,
    Starting,
    Cleanup,
}

pub(crate) struct ProxyTransition {
    instance: Option<u64>,
    port: u16,
    phase: Phase,
    closed_at: Option<Instant>,
}

enum Failure {
    Known(String),
    Ambiguous,
}

fn proxy_error(error: &str) -> String {
    match error {
        "system_proxy_changed"
        | "system_proxy_incompatible"
        | "system_proxy_unavailable"
        | "system_proxy_busy"
        | "system_proxy_not_writable"
        | "system_proxy_read_failed"
        | "system_proxy_journal_failed"
        | "system_proxy_recovery_failed" => error.into(),
        _ => "system_proxy_recovery_failed".into(),
    }
}

fn error_response(bytes: &[u8]) -> Result<proto::ErrorResp, String> {
    let response = proto::ErrorResp::decode(bytes).map_err(|_| CLEANUP)?;
    // Unknown/duplicate/noncanonical fields cannot masquerade as a typed Start
    // refusal authorizing rollback. The empty success message remains valid.
    if response.encode_to_vec() != bytes {
        return Err(CLEANUP.into());
    }
    Ok(response)
}

impl Engine {
    pub(crate) fn credentials_proxy_guard(&self) -> Result<(), String> {
        if self.vpn_credentials_proxy_transition.is_some() {
            Err(CLEANUP.into())
        } else {
            Ok(())
        }
    }

    fn retained_credentials_proxy(&mut self, port: u16) -> Result<(), Failure> {
        if self
            .vpn_credentials_proxy_transition
            .as_ref()
            .is_some_and(|transition| transition.port != port)
        {
            return Err(Failure::Known("system_proxy_incompatible".into()));
        }
        match self.system_proxy.check_retained(port) {
            Ok(RetainedProxy::Owned) => Ok(()),
            Ok(RetainedProxy::Lost) => Err(Failure::Known("system_proxy_changed".into())),
            Err(error) => Err(Failure::Known(proxy_error(&error))),
        }
    }

    fn begin_proxy_credentials(&mut self, capture: &Capture) -> Result<(), String> {
        self.credentials_transition_guard()?;
        let port = capture
            .connection
            .system_port
            .ok_or("vpn_credentials_unsupported")?;
        if capture.connection.tun || capture.generation.is_some() {
            return Err("vpn_credentials_unsupported".into());
        }
        if let Err(failure) = self.retained_credentials_proxy(port) {
            return Err(match failure {
                Failure::Known(error) => error,
                Failure::Ambiguous => CLEANUP.into(),
            });
        }
        self.vpn_credentials_proxy_transition = Some(ProxyTransition {
            instance: Some(capture.instance),
            port,
            phase: Phase::Preflight,
            closed_at: None,
        });
        Ok(())
    }

    fn proxy_rpc(&mut self) -> Result<&mut Rpc, Failure> {
        let transition = self
            .vpn_credentials_proxy_transition
            .as_ref()
            .ok_or(Failure::Ambiguous)?;
        let rpc = self.rpc.as_mut().ok_or(Failure::Ambiguous)?;
        if rpc.managed() || transition.instance != Some(rpc.instance()) || !rpc.is_alive() {
            return Err(Failure::Ambiguous);
        }
        Ok(rpc)
    }

    async fn proxy_query(&mut self, session: &str, capture: &Capture) -> Result<(), Failure> {
        if self.vpn.status.session_id.as_deref() != Some(session) {
            return Err(Failure::Known("vpn_credentials_stale".into()));
        }
        let tags = self
            .vpn
            .status
            .endpoints
            .iter()
            .map(|endpoint| endpoint.tag.clone())
            .collect();
        let response: proto::VpnStatusResponse = self
            .proxy_rpc()?
            .call_with_timeout(
                "QueryVPNStatus",
                proto::VpnStatusRequest {
                    endpoint_tags: tags,
                    timeout_ms: Some(0),
                },
                Duration::from_secs(5),
            )
            .await
            // A read changed nothing: with the exact IPC still healthy the
            // listener is kept; otherwise the preflight cleanup takes over.
            .map_err(|_| Failure::Known("vpn_status_unavailable".into()))?;
        if let Err(error) = self.vpn.update(&response) {
            return Err(Failure::Known(error));
        }
        self.retained_credentials_proxy(capture.connection.system_port.unwrap())?;
        if !response.results.iter().any(|endpoint| {
            endpoint.tag.as_deref() == Some("proxy")
                && endpoint.state.as_deref() == Some("error")
                && endpoint.auth_failed == Some(true)
                && endpoint.challenge.is_none()
        }) {
            return Err(Failure::Known("vpn_credentials_unavailable".into()));
        }
        Ok(())
    }

    async fn proxy_error_rpc(
        &mut self,
        method: &str,
        request: impl Message,
    ) -> Result<proto::ErrorResp, Failure> {
        self.proxy_rpc()?
            .call_checked(
                method,
                request,
                Duration::from_secs(30),
                16 * 1024,
                error_response,
            )
            .await
            .map_err(|_| Failure::Ambiguous)
    }

    fn finish_proxy_preflight(&mut self, result: Result<(), Failure>) -> Result<(), String> {
        match result {
            Ok(()) => {
                self.vpn_credentials_proxy_transition = None;
                Ok(())
            }
            Err(Failure::Known(error)) if self.proxy_rpc().is_ok() => {
                // No destructive action and a healthy exact IPC: preserve the
                // previous listener even when a read/ownership check refuses.
                self.vpn_credentials_proxy_transition = None;
                Err(error)
            }
            _ => {
                self.poll_proxy_credentials_cleanup();
                Err(if self.vpn_credentials_proxy_transition.is_some() {
                    CLEANUP
                } else {
                    "vpn_credentials_unavailable"
                }
                .into())
            }
        }
    }

    pub(super) async fn proxy_credentials_details(
        &mut self,
        request: &CredentialRequest,
        capture: &Capture,
    ) -> Result<(), String> {
        self.begin_proxy_credentials(capture)?;
        let result = self.proxy_query(&request.session_id, capture).await;
        self.finish_proxy_preflight(result)
    }

    async fn proxy_check(
        &mut self,
        request: &proto::LoadConfigReq,
        port: u16,
    ) -> Result<(), Failure> {
        let mut singbox = request.clone();
        singbox.need_xray = Some(false);
        let response = self.proxy_error_rpc("CheckConfig", singbox).await?;
        self.retained_credentials_proxy(port)?;
        if crate::core_result(response).is_err() {
            return Err(Failure::Known("vpn_credentials_check_failed".into()));
        }
        if request.need_xray == Some(true) {
            let response = self.proxy_error_rpc("CheckConfig", request.clone()).await?;
            self.retained_credentials_proxy(port)?;
            if crate::core_result(response).is_err() {
                return Err(Failure::Known("vpn_credentials_check_failed".into()));
            }
        }
        Ok(())
    }

    async fn retire_proxy_child(&mut self) -> Result<(), Failure> {
        let transition = self
            .vpn_credentials_proxy_transition
            .as_mut()
            .ok_or(Failure::Ambiguous)?;
        transition.phase = Phase::Retiring;
        let rpc = self.rpc.as_mut().ok_or(Failure::Ambiguous)?;
        if transition.instance != Some(rpc.instance()) || rpc.managed() {
            return Err(Failure::Ambiguous);
        }
        rpc.reap_local().await.map_err(|_| Failure::Ambiguous)?;
        // Reap, not missing IPC or port availability, authorizes dropping this owner.
        self.rpc = None;
        transition.instance = None;
        Ok(())
    }

    async fn start_retained_credentials(
        &mut self,
        connection: &ActiveConnection,
    ) -> Result<bool, Failure> {
        let port = connection.system_port.ok_or(Failure::Ambiguous)?;
        self.retained_credentials_proxy(port)?;
        let transition = self
            .vpn_credentials_proxy_transition
            .as_mut()
            .ok_or(Failure::Ambiguous)?;
        if transition.instance.is_some() || self.rpc.is_some() {
            return Err(Failure::Ambiguous);
        }
        transition.phase = Phase::Starting;
        Rpc::spawn_local_retained(&self.core, &self.data_dir, self.logs.clone(), &mut self.rpc)
            .await
            .map_err(|_| Failure::Ambiguous)?;
        transition.instance = Some(self.rpc.as_ref().ok_or(Failure::Ambiguous)?.instance());
        // The GNOME owner can change while the new child is handshaking.
        self.retained_credentials_proxy(port)?;
        let reply = self
            .proxy_error_rpc("Start", connection.request.clone())
            .await?;
        self.retained_credentials_proxy(port)?;
        Ok(crate::core_result(reply).is_ok())
    }

    fn accept_proxy_credentials(&mut self, connection: ActiveConnection, revision: Option<u64>) {
        self.vpn_credentials_proxy_transition = None;
        self.running = Some(connection.id.clone());
        self.active_connection = Some(connection);
        self.reset_vpn_session();
        self.routing_revision = revision;
        self.recovery = Default::default();
        self.traffic = Default::default();
        self.traffic_available = false;
        self.tun_reconnecting = false;
        self.tun_generation = 0;
        self.since = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.error = None;
    }

    pub(super) async fn restart_proxy_credentials(
        &mut self,
        identity: &CredentialEditRequest,
        capture: Capture,
        username: String,
        password: String,
    ) -> Result<(), String> {
        let mut candidate = capture.connection.clone();
        let (mut config, index) = endpoint_config(&candidate.request, &identity.endpoint_tag)?;
        config["endpoints"][index]["username"] = json!(username);
        config["endpoints"][index]["password"] = json!(password);
        candidate.request.core_config = Some(config.to_string());
        if let Some(binding) = candidate.vpn_otp.get_mut(&identity.endpoint_tag) {
            binding.session_credentials(&username, &password);
        }
        self.begin_proxy_credentials(&capture)?;
        let port = capture.connection.system_port.unwrap();
        let preflight = async {
            self.proxy_query(&identity.session_id, &capture).await?;
            self.proxy_check(&candidate.request, port).await?;
            self.proxy_query(&identity.session_id, &capture).await?;
            self.retained_credentials_proxy(port)
        }
        .await;
        if preflight.is_err() {
            return self.finish_proxy_preflight(preflight);
        }
        let revision = self.routing_revision;
        // Stop deliberately does not call Manager.restore. Only this retained
        // lease is eligible for candidate and (one typed-refusal) rollback.
        self.vpn_credentials_proxy_transition
            .as_mut()
            .unwrap()
            .phase = Phase::Retiring;
        let cutover = async {
            let response = self.proxy_error_rpc("Stop", proto::EmptyReq {}).await?;
            self.retained_credentials_proxy(port)?;
            if crate::core_result(response).is_err() {
                return Err(Failure::Ambiguous);
            }
            self.retire_proxy_child().await?;
            self.retained_credentials_proxy(port)?;
            if self.start_retained_credentials(&candidate).await? {
                return Ok(true);
            }
            self.retire_proxy_child().await?;
            self.retained_credentials_proxy(port)?;
            if self.start_retained_credentials(&capture.connection).await? {
                return Ok(false);
            }
            Err(Failure::Known("connection_restore_failed".into()))
        }
        .await;
        match cutover {
            Ok(true) => {
                self.accept_proxy_credentials(candidate, revision);
                Ok(())
            }
            Ok(false) => {
                self.accept_proxy_credentials(capture.connection, revision);
                self.error = Some("connection_restored".into());
                Err("connection_restored".into())
            }
            Err(failure) => {
                self.poll_proxy_credentials_cleanup();
                let cleanup = self.finish_proxy_credentials_cleanup().await;
                let error = if cleanup.is_err() {
                    CLEANUP.into()
                } else {
                    match failure {
                        Failure::Known(error) => error,
                        Failure::Ambiguous => "vpn_credentials_restart_failed".into(),
                    }
                };
                self.error = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Both ownership-safe restore and exact reap must finish. In particular a
    /// foreign listener is never waited for, signaled, or treated as our child.
    pub(crate) fn poll_proxy_credentials_cleanup(&mut self) {
        let Some(transition) = self.vpn_credentials_proxy_transition.as_mut() else {
            return;
        };
        // A canceled spawn owns its slot before handshake; only Starting may
        // adopt that newly retained instance, never an unrelated live owner.
        if transition.instance.is_none() && transition.phase == Phase::Starting {
            transition.instance = self.rpc.as_ref().map(Rpc::instance);
        }
        transition.phase = Phase::Cleanup;
        let restored = self.system_proxy.restore().is_ok();
        let mut reaped = transition.instance.is_none() && self.rpc.is_none();
        if let Some(rpc) = self
            .rpc
            .as_mut()
            .filter(|rpc| Some(rpc.instance()) == transition.instance && !rpc.managed())
        {
            if restored {
                rpc.close_ipc();
                let closed = transition.closed_at.get_or_insert_with(Instant::now);
                if closed.elapsed() >= Duration::from_secs(4) {
                    let _ = rpc.request_kill();
                }
            }
            if matches!(rpc.exit_success(), Ok(Some(_))) {
                reaped = true;
                self.rpc = None;
                transition.instance = None;
            }
        }
        if restored && reaped {
            self.vpn_credentials_proxy_transition = None;
        }
        self.clear_connection();
        self.error = Some(
            if self.vpn_credentials_proxy_transition.is_some() {
                CLEANUP
            } else {
                "vpn_credentials_restart_failed"
            }
            .into(),
        );
    }

    pub(crate) async fn finish_proxy_credentials_cleanup(&mut self) -> Result<(), String> {
        let until = Instant::now() + Duration::from_secs(8);
        while self.vpn_credentials_proxy_transition.is_some() {
            self.poll_proxy_credentials_cleanup();
            if self.vpn_credentials_proxy_transition.is_none() {
                return Ok(());
            }
            // GSettings itself may block on its existing GLib context; this is
            // a polling budget, not a wall-clock guarantee for backend I/O.
            if self.system_proxy.status().error.as_deref() == Some("system_proxy_recovery_failed")
                || Instant::now() >= until
            {
                return Err(CLEANUP.into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok(())
    }

    pub async fn retry_system_proxy_cleanup(&mut self) -> Result<(), String> {
        let pending = self.vpn_credentials_proxy_transition.is_some();
        self.finish_proxy_credentials_cleanup().await?;
        self.credentials_transition_guard()?;
        self.system_proxy.retry_recovery()?;
        if pending {
            self.error = None;
        }
        Ok(())
    }
}
