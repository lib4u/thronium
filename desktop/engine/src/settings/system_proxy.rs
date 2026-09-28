//! Toggling the operating system proxy for the running connection.
use super::*;

impl Engine {
    pub async fn toggle_system_proxy(&mut self) -> Result<(), String> {
        if self.system_proxy.status().active {
            self.system_proxy.restore()?;
            // The OS proxy no longer belongs to this connection: recovery and
            // credential restarts must not expect to find it retained.
            if let Some(active) = &mut self.active_connection {
                active.system_port = None;
            }
            if boolean(&self.store.library, "reset_proxy_on_disable_sp") {
                if let Some(previous) = self.active_connection.clone() {
                    if !previous.vpn_otp_start.is_empty() {
                        // Its request carries a spent one-time code; starting it
                        // again would replay that code, so the session stays up.
                        self.logs.event("warn", "vpn_otp_start_stale", None);
                        return Ok(());
                    }
                    self.disconnect().await?;
                    self.start_connection(previous).await?;
                }
            }
            return Ok(());
        }
        if self.running.is_none() {
            return Err("not_connected".into());
        }
        if boolean(&self.store.library, "inbound_auth")
            || string(&self.store.library, "inbound_address") != "127.0.0.1"
        {
            return Err("settings_system_proxy_incompatible".into());
        }
        // The OS proxy speaks HTTP: take the running core's HTTP-capable
        // listener, never a SOCKS one or a port from settings that the core
        // replaced with a random port.
        let core: Value = self
            .active_connection
            .as_ref()
            .and_then(|c| c.request.core_config.as_deref())
            .and_then(|text| serde_json::from_str(text).ok())
            .ok_or("subscription_proxy_unavailable")?;
        let port = crate::config::local_inbound(&core, crate::config::HTTP_PROXY)
            .ok_or("settings_system_proxy_incompatible")?
            .port;
        self.system_proxy.enable(port)
    }
}
