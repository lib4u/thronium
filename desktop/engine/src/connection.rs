use crate::{core_result, proto, store::ProfileKind, system_proxy, traffic, Engine};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

// Retain the exact running request, including generated bridge ports and routing.
// Never serialize it: it contains credentials and belongs only to this process.
#[derive(Clone)]
pub(crate) struct ActiveConnection {
    pub(crate) id: String,
    pub(crate) profiles: std::collections::HashSet<String>,
    pub(crate) groups: std::collections::HashSet<String>,
    pub(crate) request: proto::LoadConfigReq,
    pub(crate) routing_revision: u64,
    pub(crate) system_port: Option<u16>,
    pub(crate) tun: bool,
    pub(crate) external_instance: Option<String>,
    pub(crate) vpn_primary: bool,
    pub(crate) vpn_otp: crate::vpn_auth::otp::Bindings,
    /// Non-empty when Start carried a minted code: this request is never resent.
    pub(crate) vpn_otp_start: crate::vpn_auth::otp::StartMarks,
}

impl ActiveConnection {
    // A managed worker must never replay a request containing a spent code,
    // even when global TUN recovery remains enabled for ordinary connections.
    fn tun_auto_reconnect(&self, settings: &crate::tun::Settings) -> bool {
        self.vpn_otp_start.is_empty() && settings.auto_reconnect
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyActivation {
    Acquire,
    RetainExisting,
}

impl Engine {
    pub async fn connect(&mut self, id: &str) -> Result<(), String> {
        // Asking for this connection again is a fresh start, including for the
        // automatic restarts that spend a before-Start code.
        self.vpn_start_restarts.clear();
        self.connect_using_library(id, None, crate::vpn_auth::otp::Intent::Start)
            .await
    }

    pub(crate) async fn connect_using_library(
        &mut self,
        id: &str,
        prepared: Option<crate::store::Library>,
        intent: crate::vpn_auth::otp::Intent,
    ) -> Result<(), String> {
        if self.store.library.preferences.connection_mode == system_proxy::ConnectionMode::Tun {
            self.vpn_probe_guard()?;
        }
        self.finish_credentials_transition().await?;
        self.snapshot();
        self.cancel_recovery().await?;
        self.wait_external_cleanup().await?;
        let mut library = match prepared {
            Some(library) => library,
            None => self
                .connection_measurements(id)?
                .map(|plan| self.ranked_connection_library(&plan))
                .transpose()?
                .unwrap_or_else(|| self.store.library.clone()),
        };
        if id == crate::auto_selector::AUTO_SELECT_ID
            && !library.profiles.iter().any(|p| p.id == id)
        {
            library.profiles.push(
                self.auto_select_profile()
                    .ok_or("auto_select_unavailable")?,
            );
        }
        let profile = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or("profile_not_found")?;
        crate::external_core::runtime::context(&library, &profile)?;
        let mut system_port =
            if library.preferences.connection_mode == system_proxy::ConnectionMode::SystemProxy {
                if profile.kind == ProfileKind::SingBoxConfig {
                    return Err("system_proxy_incompatible".into());
                }
                self.system_proxy.preflight()?;
                Some(library.preferences.inbound_port)
            } else {
                None
            };
        let tun = library.preferences.connection_mode == system_proxy::ConnectionMode::Tun;
        crate::geodata::prepare_for(
            &self.geodata,
            &profile,
            &library,
            &self.data_dir,
            self.settings_download_proxy()?.as_deref(),
        )
        .await?;
        let (mut request, vpn_otp) =
            Self::build_with_vpn_sources(&profile, &library, &self.data_dir, intent)?;
        if system_port.is_some() {
            let core: serde_json::Value = serde_json::from_str(
                request
                    .core_config
                    .as_deref()
                    .ok_or("invalid_configuration")?,
            )
            .map_err(|_| "invalid_configuration")?;
            system_port = Some(
                crate::config::local_inbound(&core, crate::config::HTTP_PROXY)
                    .ok_or("system_proxy_incompatible")?
                    .port,
            );
        }
        crate::tun::apply(&mut request, &profile, &library.preferences)?;
        crate::tun::apply_settings(&mut request, &library)?;
        let roots = crate::vless::roots(&library, &profile)?;
        let policy_roots = crate::group_chains::policy_roots(&library, &roots);
        let mut candidate = ActiveConnection {
            profiles: crate::vless::relevant(&library, &profile)?,
            groups: library
                .profiles
                .iter()
                .filter(|p| policy_roots.contains(&p.id))
                .map(|p| p.group_id.clone())
                .collect(),
            id: id.into(),
            request,
            routing_revision: library.routing.revision,
            system_port,
            tun,
            external_instance: None,
            vpn_otp,
            vpn_otp_start: Default::default(),
            vpn_primary: crate::vpn_endpoint::profile_protocol(&profile).is_some(),
        };
        let selector_health =
            crate::auto_selector::health::State::capture(&library, id, &candidate.request);
        let selector_rebuild =
            crate::auto_selector::rebuild::State::capture(&library, id, &candidate.request);
        // CheckConfig must reject invalid input before stopping a working session.
        // These refusals happen before the working session is touched, so they
        // are this command's result only, not the session status banner.
        self.check_request(&candidate.request).await?;
        // Spend a before-Start code only after the request passed validation and
        // before the working session is touched; a refusal changes nothing.
        match self.commit_start_codes(&mut candidate.request, &candidate.vpn_otp) {
            Ok(marks) => {
                candidate.vpn_otp_start = marks;
                // The selection commit below must carry the reserved HOTP step.
                library.otp = self.store.library.otp.clone();
            }
            Err(error) => return Err(error),
        }
        if tun {
            let owned = self.active_connection.as_ref().is_some_and(|c| c.tun);
            if !owned {
                let automatic = candidate.tun_auto_reconnect(&library.preferences.tun);
                let addresses = crate::tun::configured_addresses(&library);
                self.ensure_tun_rpc()
                    .await?
                    .prepare_tun(
                        automatic,
                        &addresses,
                        candidate
                            .request
                            .managed_tun_dns_mode
                            .as_deref()
                            .unwrap_or(""),
                    )
                    .await?;
            } else {
                self.rpc
                    .as_mut()
                    .ok_or("core_disconnected")?
                    .require_tun_system_dns(
                        candidate
                            .request
                            .managed_tun_dns_mode
                            .as_deref()
                            .unwrap_or(""),
                    )
                    .await?;
            }
        }
        self.system_proxy.observe();
        let mut previous = self.active_connection.clone();
        if !self.system_proxy.status().active {
            if let Some(previous) = &mut previous {
                previous.system_port = None;
            }
        }
        if let Err(error) = self.disconnect().await {
            // An OS restore failure deliberately keeps the old listener alive.
            if self.running.is_some() {
                return Err(error);
            }
            return Err(self.recover_connection(previous, error).await);
        }
        let result = self.start_connection(candidate).await;
        // A failed atomic library write must not leave an unselected new session.
        let result = result.and_then(|()| {
            let mut next = library;
            next.selected = Some(id.into());
            self.store.commit(next)
        });
        match result {
            // The session runs and the selection is written; only the directory
            // sync is unconfirmed. Rolling back would discard a good state.
            Err(error) if error == crate::store::Store::WRITTEN_UNCERTAIN => {
                self.logs.event("warn", &error, None);
            }
            Err(error) => return Err(self.recover_connection(previous, error).await),
            Ok(()) => {}
        }
        self.recovery = crate::recovery::Recovery::default();
        // Count only a successful explicit Connect, after selection has committed.
        // Recovery and validation use other paths and never create a history entry.
        self.selector_health = selector_health;
        self.selector_rebuild = selector_rebuild;
        self.remember_selector_start();
        Ok(())
    }

    pub(crate) async fn start_connection(
        &mut self,
        connection: ActiveConnection,
    ) -> Result<(), String> {
        self.start_connection_mode(connection, ProxyActivation::Acquire)
            .await
    }

    pub(crate) async fn restart_connection(
        &mut self,
        connection: ActiveConnection,
    ) -> Result<(), String> {
        self.start_connection_mode(connection, ProxyActivation::RetainExisting)
            .await
    }

    fn require_retained_proxy(&mut self, port: u16) -> Result<(), String> {
        match self.system_proxy.check_retained(port)? {
            system_proxy::RetainedProxy::Owned => Ok(()),
            system_proxy::RetainedProxy::Lost => Err("system_proxy_changed".into()),
        }
    }

    async fn start_connection_mode(
        &mut self,
        mut connection: ActiveConnection,
        proxy: ProxyActivation,
    ) -> Result<(), String> {
        if connection.tun {
            self.vpn_probe_guard()?;
        }
        if proxy == ProxyActivation::RetainExisting {
            if let Some(port) = connection.system_port {
                self.require_retained_proxy(port)?;
            }
        }
        self.wait_external_cleanup().await?;
        if connection.tun {
            let automatic = connection.tun_auto_reconnect(&self.store.library.preferences.tun);
            let addresses = crate::tun::configured_addresses(&self.store.library);
            self.ensure_tun_rpc()
                .await?
                .prepare_tun(
                    automatic,
                    &addresses,
                    connection
                        .request
                        .managed_tun_dns_mode
                        .as_deref()
                        .unwrap_or(""),
                )
                .await?;
        }
        self.ensure_rpc().await?;
        self.vpn = crate::vpn_auth::Session::default();
        let external_port = crate::external_core::runtime::port(&connection.request);
        if let Some(port) = external_port {
            self.external_cleanup_ports.insert(port);
        }
        self.logs.protect(
            "session",
            crate::logs::redact::request_configs(&connection.request),
        );
        let reply: proto::ErrorResp = self
            .rpc
            .as_mut()
            .ok_or("core_disconnected")?
            .call("Start", connection.request.clone())
            .await?;
        if let Err(error) = core_result(reply) {
            // Every later log of this error sees it without request credentials.
            let error = crate::logs::redact::request_values(
                &error,
                connection.request.core_config.as_deref(),
            );
            // Protocol v1 acknowledges a failed attempt only after stopExtra
            // finishes. A foreign busy port was never ours to wait for. Lost
            // RPC replies and incomplete cleanup retain the pending endpoint.
            if error != "external_core_cleanup_failed" && error != "instance already started" {
                if let Some(port) = external_port {
                    self.external_cleanup_ports.remove(&port);
                }
            }
            return Err(error);
        }
        if crate::external_core::runtime::is_request(&connection.request) {
            connection.external_instance = Some(self.external_instance().await?);
        }
        if let Some(port) = connection.system_port {
            match proxy {
                ProxyActivation::Acquire => {
                    // Windows publishes one address; the scheme is the person's.
                    self.system_proxy
                        .set_scheme(crate::settings::string(&self.store.library, "proxy_scheme"));
                    self.system_proxy.enable(port)?
                }
                ProxyActivation::RetainExisting => self.require_retained_proxy(port)?,
            }
        }
        self.tun_reconnecting = false;
        self.tun_generation = 0;
        self.running = Some(connection.id.clone());
        self.routing_revision = Some(connection.routing_revision);
        self.active_connection = Some(connection);
        self.reset_vpn_session();
        if let Some(port) = external_port {
            self.external_cleanup_ports.remove(&port);
        }
        self.since = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.traffic = traffic::Traffic::default();
        self.traffic_available = false;
        self.error = None;
        self.logs.event("info", "connection_started", None);
        Ok(())
    }

    pub(crate) async fn abort_connection(&mut self) -> Result<(), String> {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            self.poll_credentials_cleanup();
            return self.credentials_transition_guard();
        }
        self.vpn = crate::vpn_auth::Session::default();
        let restored = self.system_proxy.restore();
        self.queue_external_cleanup();
        if let Some(rpc) = self.rpc.as_mut().filter(|r| r.managed()) {
            if rpc
                .call::<_, proto::ErrorResp>("Stop", proto::EmptyReq {})
                .await
                .and_then(core_result)
                .is_ok()
            {
                self.clear_connection();
                self.wait_external_cleanup().await?;
                return restored;
            }
        }
        // Start may have partially succeeded or lost its IPC response. Always reap
        // that process before starting anything else, including the old request.
        if let Some(mut rpc) = self.rpc.take() {
            rpc.terminate().await;
        }
        self.clear_connection();
        self.wait_external_cleanup().await?;
        restored
    }

    pub(crate) async fn recover_connection(
        &mut self,
        mut previous: Option<ActiveConnection>,
        error: String,
    ) -> String {
        self.logs
            .event("error", "connection_change_failed", Some(&error));
        if previous
            .as_ref()
            .is_some_and(|previous| !previous.vpn_otp_start.is_empty())
        {
            // That request carried a spent one-time code; restoring it would replay it.
            self.logs
                .event("warn", "connection_restore_skipped_otp", None);
            let _ = self.abort_connection().await;
            self.error = Some("vpn_otp_start_stale".into());
            return "vpn_otp_start_stale".into();
        }
        let cleanup = self.abort_connection().await;
        let result = if let Some(mut previous) = previous.take() {
            // Do not overwrite settings changed by another program during the attempt.
            if self.system_proxy.status().error.as_deref() == Some("system_proxy_changed") {
                previous.system_port = None;
            }
            let restored = match cleanup {
                Ok(()) => self.start_connection(previous).await,
                Err(error) => Err(error),
            };
            match restored {
                Ok(()) => {
                    self.logs
                        .event("warn", "connection_previous_restored", None);
                    "connection_restored".to_string()
                }
                Err(restore_error) => {
                    self.logs.event(
                        "error",
                        "connection_restore_error",
                        Some(crate::recovery::safe_failure(&restore_error)),
                    );
                    let _ = self.abort_connection().await;
                    "connection_restore_failed".to_string()
                }
            }
        } else {
            cleanup.err().unwrap_or(error)
        };
        self.error = Some(result.clone());
        result
    }

    pub(crate) fn clear_connection(&mut self) {
        self.vpn = crate::vpn_auth::Session::default();
        self.recovery.clear_pending();
        self.queue_external_cleanup();
        self.tun_reconnecting = false;
        self.tun_generation = 0;
        self.running = None;
        self.active_connection = None;
        self.since = None;
        self.routing_revision = None;
        self.traffic_available = false;
        self.traffic.stopped();
    }
}
