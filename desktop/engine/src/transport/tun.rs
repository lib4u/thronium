//! TUN preparation, system DNS support and interface release over the core IPC.
use super::*;

pub(crate) fn supports_system_dns(mode: &str, version: Option<u32>) -> bool {
    matches!(
        (mode, version),
        ("resolved", Some(1 | 2)) | ("resolvconf", Some(2)) | ("interface", Some(1))
    )
}

impl Rpc {
    pub(crate) fn tun_preflight(&self, owns_interface: bool) -> Result<(), String> {
        crate::tun::preflight(self.child.id().ok_or("core_disconnected")?, owns_interface)
    }
    pub(crate) async fn require_tun_system_dns(&mut self, mode: &str) -> Result<(), String> {
        if mode.is_empty() {
            return Ok(());
        }
        if !matches!(mode, "resolved" | "resolvconf" | "interface") {
            return Err("invalid_tun_system_dns".into());
        }
        if !self.managed {
            return Err("tun_system_dns_core_unsupported".into());
        }
        let status: crate::proto::ManagedTunStatus = self
            .call("ManagedTunStatus", crate::proto::EmptyReq {})
            .await?;
        if !supports_system_dns(mode, status.system_dns_version) {
            return Err("tun_system_dns_core_unsupported".into());
        }
        Ok(())
    }
    pub(crate) async fn prepare_tun(
        &mut self,
        auto_reconnect: bool,
        addresses: &[String],
        system_dns: &str,
    ) -> Result<(), String> {
        self.require_tun_system_dns(system_dns).await?;
        if self.managed {
            let response: crate::proto::ErrorResp = self
                .call(
                    "ManagedTunReady",
                    crate::proto::ManagedTunOptions {
                        auto_reconnect: Some(auto_reconnect),
                    },
                )
                .await?;
            crate::core_result(response)?;
            // The service does not look at the network itself: a previous
            // session's adapter may still be going away.
            #[cfg(windows)]
            self.wait_tun_release().await?;
            return crate::tun::addresses_available_for(addresses);
        }
        self.tun_preflight(true)?;
        if self.tun_lease.is_none() {
            self.tun_lease = Some(crate::tun::Lease::acquire()?);
        }
        self.wait_tun_release().await?;
        crate::tun::addresses_available_for(addresses)
    }
    pub(crate) async fn wait_tun_release(&mut self) -> Result<(), String> {
        for _ in 0..120 {
            match crate::tun::network_clear() {
                Err(error) if error == "tun_conflict" => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                result => return result,
            }
        }
        crate::tun::network_clear()
    }
    pub(crate) fn release_tun(&mut self) {
        self.tun_lease = None;
    }
}
