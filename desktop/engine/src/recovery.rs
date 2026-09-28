//! In-memory recovery of an already running, owned Linux internal core.
//! The active request remains private; no library or runtime configuration is rebuilt.
use crate::{system_proxy::ConnectionMode, Engine};
use std::time::{Duration, Instant};

const RESTART_DELAY: Duration = Duration::from_millis(200);
/// A core that exits again within this window is not restarted automatically.
pub const RAPID_EXIT_WINDOW: Duration = Duration::from_secs(10);
const EXIT_OBSERVATION: Duration = Duration::from_millis(200);

// Core errors can include user configuration. Keep the background log useful
// without echoing endpoints, credentials, source paths or a complete request.
pub(crate) fn safe_failure(error: &str) -> &'static str {
    if let Some(code) = crate::ipc::registered(error) {
        return code;
    }
    if error.starts_with("core_launch:") {
        "core_launch_failed"
    } else if error.contains("address already in use") {
        "local_listener_busy"
    } else {
        "core_start_rejected"
    }
}

#[derive(Default)]
pub(crate) struct Recovery {
    pending: Option<Instant>,
    observing_exit: Option<Instant>,
    last_exit: Option<Instant>,
}

impl Recovery {
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some() || self.observing_exit.is_some()
    }

    pub(crate) fn clear_pending(&mut self) {
        self.pending = None;
        self.observing_exit = None;
    }

    fn arm(&mut self, now: Instant) -> bool {
        let rapid = self
            .last_exit
            .is_some_and(|last| now.duration_since(last) < RAPID_EXIT_WINDOW);
        self.last_exit = Some(now);
        self.pending = (!rapid).then_some(now + RESTART_DELAY);
        !rapid
    }
}

impl Engine {
    fn local_recovery_eligible(&self) -> bool {
        cfg!(target_os = "linux")
            && self.rpc.as_ref().is_some_and(|rpc| !rpc.managed())
            && self.active_connection.as_ref().is_some_and(|active| {
                !active.tun
                    && match self.store.library.preferences.connection_mode {
                        ConnectionMode::Local => {
                            active.system_port.is_none() && !self.system_proxy.status().active
                        }
                        ConnectionMode::SystemProxy => active.system_port.is_some(),
                        ConnectionMode::Tun => false,
                    }
                    && active.external_instance.is_none()
                    && !crate::external_core::runtime::is_request(&active.request)
                    && active
                        .request
                        .core_config
                        .as_deref()
                        .and_then(|config| serde_json::from_str::<serde_json::Value>(config).ok())
                        .is_some_and(|config| {
                            !config["inbounds"].as_array().is_some_and(|inbounds| {
                                inbounds.iter().any(|inbound| inbound["type"] == "tun")
                            })
                        })
            })
    }

    /// Synchronous callers may notice a death first. They only retain intent and
    /// a deadline; they never launch a process or execute a second connection.
    pub(crate) fn observe_core_exit(&mut self) {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            self.clear_connection();
            self.error = self.credentials_transition_guard().err();
            return;
        }
        let Some(rpc) = self.rpc.as_mut() else { return };
        if rpc.is_alive() {
            return;
        }
        // An auth form belongs to this exact process/session, never its retry.
        self.vpn = crate::vpn_auth::Session::default();
        // A lost/timed-out IPC stream is not evidence that our child exited.
        let confirmed_exit = rpc.child_exited();
        let allowed = rpc.recoverable_exit();
        let remote_lost = rpc.remote_stream_lost();
        let eligible = allowed && self.local_recovery_eligible();
        if !confirmed_exit && remote_lost && eligible {
            // A remote EOF can precede waitpid's exit notification. Retain the
            // owned Child until the backend tick observes it; never manufacture
            // that evidence by killing it from a synchronous snapshot.
            self.recovery
                .observing_exit
                .get_or_insert_with(|| Instant::now() + EXIT_OBSERVATION);
            self.since = None;
            self.traffic_available = false;
            self.traffic.stopped();
            self.error = None;
            return;
        }
        self.recovery.observing_exit = None;
        let recoverable = confirmed_exit && eligible;
        self.logs.event("error", "core_exited", None);
        self.rpc = None;
        if recoverable {
            if self.recovery.arm(Instant::now()) {
                self.since = None;
                self.traffic_available = false;
                self.traffic.stopped();
                self.error = None;
                self.logs.event("warn", "core_recovery_scheduled", None);
                return;
            }
            self.clear_connection();
            self.error = Some("core_restart_limited".into());
            self.logs.event("error", "core_recovery_stopped", None);
        } else {
            self.clear_connection();
            self.error = Some("core_disconnected".into());
        }
    }

    pub(crate) async fn cancel_recovery(&mut self) -> Result<(), String> {
        if self.recovery.pending() {
            let observing = self.recovery.observing_exit.is_some();
            self.recovery.clear_pending();
            if observing {
                if let Some(mut rpc) = self.rpc.take() {
                    rpc.terminate().await;
                }
            }
            self.clear_connection();
            self.error = None;
            // A new explicit Connect may fail before it reaches disconnect().
            // Release the retained OS proxy now, preserving the journal on error.
            self.system_proxy.restore()?;
        }
        Ok(())
    }

    /// Call from the application backend, including while its window is hidden
    /// and when no tray exists. The caller holds the same Engine mutex as RPCs.
    /// No sleeps or traffic queries occur between attempts.
    pub async fn recovery_tick(&mut self) {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            self.poll_credentials_cleanup();
            return;
        }
        self.observe_core_exit();
        if self.running.is_none() {
            // No WebView/tray snapshot is required for terminal-exit cleanup.
            // Manager retains the journal if the ownership-safe restore fails.
            let _ = self.system_proxy.restore();
        } else {
            // The guardian must remain supervised when WebKit is hidden and
            // there are no snapshot requests. This is just a child status check
            // while healthy; GSettings is accessed only after guardian failure.
            let _ = self.system_proxy.check_guardian();
        }
        if let Some(until) = self.recovery.observing_exit {
            if Instant::now() >= until {
                // Still alive after the bounded remote-EOF observation. Our
                // deliberate termination is terminal, never a new crash event.
                let _ = self.abort_connection().await;
                self.error = Some("core_disconnected".into());
            }
            return;
        }
        let Some(due) = self.recovery.pending else {
            return;
        };
        if Instant::now() < due {
            return;
        }
        self.recovery.pending = None;
        let Some(connection) = self.active_connection.clone() else {
            return;
        };
        if !connection.vpn_otp_start.is_empty() {
            // The request carried a spent one-time code; a silent restart would replay it.
            let _ = self.abort_connection().await;
            self.error = Some("vpn_otp_start_stale".into());
            self.logs.event("error", "core_recovery_skipped_otp", None);
            return;
        }
        // Saving settings can invalidate the applied revision without changing
        // Routing.revision. Preserve None as well as a previous numeric revision.
        let revision = self.routing_revision;
        match self.restart_connection(connection).await {
            Ok(()) => {
                self.routing_revision = revision;
                self.logs.event("info", "core_recovery_restored", None);
            }
            Err(error) => {
                // Start may bind some listeners before failing. Reap this owned
                // candidate once; no failed Start schedules another attempt.
                let cleanup = self.abort_connection().await;
                self.error = Some("core_reconnect_failed".into());
                self.logs
                    .event("error", "core_recovery_error", Some(safe_failure(&error)));
                if let Err(error) = cleanup {
                    self.logs.event(
                        "error",
                        "core_recovery_cleanup_failed",
                        Some(safe_failure(&error)),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
