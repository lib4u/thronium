//! The running session: disconnecting, TUN observation, polling and shutdown.
use super::*;

impl Engine {
    pub async fn disconnect(&mut self) -> Result<(), String> {
        self.finish_credentials_transition().await?;
        self.cancel_recovery().await?;
        let _ = self.history.flush(&self.data_dir);
        // Keep the working listener alive if restoring the OS settings failed.
        self.system_proxy.restore()?;
        self.remember_quick_before_disconnect().await;
        self.vpn = vpn_auth::Session::default();
        self.queue_external_cleanup();
        let was_running = self.running.is_some();
        let was_tun = self.active_connection.as_ref().is_some_and(|c| c.tun);
        if let Some(rpc) = self.rpc.as_mut() {
            if self.running.is_some() {
                // A best-effort read just before Stop may have timed out and closed
                // IPC on purpose. The core stops on that EOF, so Stop over the closed
                // stream would only report core_disconnected for a finished stop.
                let result = if rpc.stream_open() {
                    let result: Result<proto::ErrorResp, _> =
                        rpc.call("Stop", proto::EmptyReq {}).await;
                    result.and_then(core_result)
                } else {
                    rpc.terminate().await;
                    Ok(())
                };
                let mut result = result;
                if result.is_ok() && was_tun && !rpc.managed() {
                    // Some stacks retain a TUN descriptor after box.Close. End
                    // the privileged session as well, then confirm kernel cleanup.
                    rpc.terminate().await;
                    result = rpc.wait_tun_release().await;
                }
                if let Err(error) = result {
                    let request = self.active_connection.as_ref();
                    let error = logs::redact::request_values(
                        &error,
                        request.and_then(|c| c.request.core_config.as_deref()),
                    );
                    self.logs
                        .event("error", "connection_stop_failed", Some(&error));
                    rpc.terminate().await;
                    self.rpc = None;
                    self.clear_connection();
                    let cleanup = self.wait_external_cleanup().await;
                    if let Err(cleanup) = cleanup {
                        self.error = Some(cleanup.clone());
                        return Err(cleanup);
                    }
                    self.error = Some(error.clone());
                    return Err(error);
                }
                rpc.release_tun();
            }
        }
        if was_tun && !self.rpc.as_ref().is_some_and(|r| r.managed())
            || self.rpc.as_ref().is_some_and(|r| !r.stream_open())
        {
            self.rpc = None;
        }
        self.clear_connection();
        if let Err(error) = self.wait_external_cleanup().await {
            self.error = Some(error.clone());
            return Err(error);
        }
        self.error = None;
        if was_running {
            self.logs.event("info", "connection_stopped", None);
        }
        Ok(())
    }

    // Called by both the window and the native tray, so status stays truthful
    // while WebKit timers are suspended in the background.
    pub async fn observe_tun(&mut self) {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            return;
        }
        if self.running.is_none() || !self.rpc.as_ref().is_some_and(|r| r.managed()) {
            return;
        }
        let status = self
            .rpc
            .as_mut()
            .unwrap()
            .call::<_, proto::ManagedTunStatus>("ManagedTunStatus", proto::EmptyReq {})
            .await;
        match status {
            Ok(status) => match status.phase.as_deref() {
                Some("reconnecting") => {
                    self.vpn = vpn_auth::Session::default();
                    if !self.tun_reconnecting {
                        self.logs.event("warn", "tun_reconnecting", None);
                    }
                    self.tun_reconnecting = true;
                    self.traffic_available = false;
                    self.traffic.stopped();
                    self.error = None;
                }
                Some("connected") => {
                    let generation = status.generation.unwrap_or_default();
                    if self.tun_generation != 0 && self.tun_generation != generation {
                        self.traffic.stopped();
                        self.logs.event("info", "tun_reconnected", None);
                    }
                    self.observe_vpn_generation(
                        generation,
                        status.vpn_auth_version.unwrap_or_default(),
                    );
                    self.observe_vpn_credentials_capability(
                        status.vpn_credentials_version.unwrap_or_default(),
                    );
                    self.tun_generation = generation;
                    self.tun_reconnecting = false;
                }
                _ => {
                    self.clear_connection();
                    self.error = Some(
                        match status.error.as_deref() {
                            Some("tun_reconnect_failed") => "tun_reconnect_failed",
                            Some("tun_recovery_failed") => "tun_recovery_failed",
                            _ => "core_disconnected",
                        }
                        .into(),
                    );
                }
            },
            Err(error) => {
                if let Some(mut rpc) = self.rpc.take() {
                    rpc.terminate().await;
                }
                self.clear_connection();
                self.error = Some(error);
            }
        }
    }

    pub async fn poll(&mut self) -> Snapshot {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            self.poll_credentials_cleanup();
            return self.snapshot();
        }
        self.snapshot();
        self.observe_tun().await;
        self.observe_external().await;
        self.vpn_tick().await;
        if self.running.is_some() && !self.tun_reconnecting && !self.recovery.pending() {
            if let Some(rpc) = self.rpc.as_mut() {
                match rpc
                    .call::<_, proto::QueryConnectionsResp>("QueryConnections", proto::EmptyReq {})
                    .await
                {
                    Ok(connections) => {
                        let deltas = self.traffic.update(connections);
                        if !settings::boolean(&self.store.library, "disable_traffic_aggregation") {
                            let id = self.running.as_deref().unwrap_or("");
                            let profile = self.store.library.profiles.iter().find(|p| p.id == id);
                            let group = profile.map(|p| p.group_id.as_str()).unwrap_or("");
                            // What it is called now, so the statistics still
                            // name it after a rename or a deletion.
                            if let Some(profile) = profile {
                                let name = self
                                    .store
                                    .library
                                    .groups
                                    .iter()
                                    .find(|g| g.id == profile.group_id)
                                    .map(|g| g.display_name().to_owned())
                                    .unwrap_or_default();
                                let (id, label) = (profile.id.clone(), profile.name.clone());
                                self.history.remember(&self.data_dir, &id, &label, &name);
                            }
                            self.history.record(
                                &self.data_dir,
                                id,
                                group,
                                deltas,
                                settings::integer(
                                    &self.store.library,
                                    "traffic_stats_retention_days",
                                ) as u64,
                            );
                        }
                        self.traffic_available = true;
                    }
                    // Opaque full configurations can intentionally omit a traffic tracker.
                    // A diagnostics error must not tear down a working VPN connection.
                    Err(error) if rpc.managed() && error == "tun_reconnecting" => {
                        self.tun_reconnecting = true;
                        self.traffic_available = false;
                        self.traffic.stopped();
                    }
                    Err(_) if rpc.is_alive() => {
                        self.traffic_available = false;
                        self.traffic.active.clear();
                    }
                    Err(e) => {
                        if rpc.child_exited() || rpc.remote_stream_lost() {
                            self.observe_core_exit();
                        } else {
                            self.error = Some(e);
                            rpc.terminate().await;
                            // A locally ended RPC is not a crash: without this the
                            // next snapshot reports an unexpected exit instead of e.
                            self.rpc = None;
                            self.clear_connection();
                        }
                    }
                }
            }
        }
        self.collect_selector_health().await;
        self.snapshot()
    }

    pub async fn generate_wg_keys(&mut self) -> Result<Value, String> {
        let reply: proto::GenWgKeyPairResponse = self
            .ensure_rpc()
            .await?
            .call("GenWgKeyPair", proto::EmptyReq {})
            .await?;
        if let Some(error) = reply.error.filter(|e| !e.is_empty()) {
            return Err(error);
        }
        let private = reply
            .private_key
            .filter(|key| !key.is_empty())
            .ok_or("key_generation_failed")?;
        let public = reply
            .public_key
            .filter(|key| !key.is_empty())
            .ok_or("key_generation_failed")?;
        Ok(json!({"privateKey": private, "publicKey": public}))
    }

    pub async fn close_connections(&mut self, ids: Vec<String>) -> Result<i32, String> {
        if self.running.is_none() {
            return Ok(0);
        }
        let reply: proto::CloseConnectionsResponse = self
            .ensure_rpc()
            .await?
            .call("CloseConnections", proto::CloseConnectionsRequest { ids })
            .await?;
        if let Some(error) = reply.error.filter(|e| !e.is_empty()) {
            return Err(error);
        }
        Ok(reply.closed.unwrap_or_default())
    }

    pub async fn shutdown(&mut self) {
        let _ = self.shutdown_checked().await;
    }

    pub async fn shutdown_checked(&mut self) -> Result<(), String> {
        self.finish_probe_cleanup().await?;
        self.disconnect().await?;
        if let Some(mut rpc) = self.rpc.take() {
            rpc.terminate().await;
        }
        Ok(())
    }
}
