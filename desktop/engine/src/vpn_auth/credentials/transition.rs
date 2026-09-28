//! A canceled replacement future must not erase its cleanup obligation.
use super::{managed, ActiveConnection, Capture, Duration, Engine, Instant};
use crate::{proto, transport::Rpc};

pub(crate) struct Transition {
    instance: u64,
    trusted_cleanup: bool,
    exited: bool,
}

impl Transition {
    fn new(instance: u64, trusted_cleanup: bool) -> Self {
        Self {
            instance,
            trusted_cleanup,
            exited: false,
        }
    }
}

impl Engine {
    pub(crate) fn credentials_transition_guard(&self) -> Result<(), String> {
        self.credentials_proxy_guard()?;
        if self.vpn_credentials_transition.is_some() {
            Err("tun_recovery_failed".into())
        } else {
            Ok(())
        }
    }

    /// Never waits or creates a guardian. Exit zero is meaningful only for the
    /// exact owned child whose capability promised journal/worker cleanup.
    pub(crate) fn poll_credentials_cleanup(&mut self) {
        if self.vpn_credentials_proxy_transition.is_some() {
            self.poll_proxy_credentials_cleanup();
            return;
        }
        let Some(transition) = self.vpn_credentials_transition.as_mut() else {
            return;
        };
        if let Some(rpc) = self
            .rpc
            .as_mut()
            .filter(|rpc| rpc.instance() == transition.instance)
        {
            rpc.close_ipc();
            if let Ok(Some(success)) = rpc.exit_success() {
                transition.exited = true;
                if success && transition.trusted_cleanup && crate::tun::network_clear().is_ok() {
                    self.vpn_credentials_transition = None;
                }
                // waitpid confirmed this exact child; dropping it cannot kill
                // another generation. A failed cleanup keeps the marker.
                self.rpc = None;
            }
        }
        self.clear_connection();
        self.error = Some("tun_recovery_failed".into());
    }

    /// Explicit Connect/Disconnect only. A live or unidentified former guardian
    /// never permits a new owner. Tick/poll have no path to this barrier.
    pub(crate) async fn finish_credentials_transition(&mut self) -> Result<(), String> {
        self.finish_proxy_credentials_cleanup().await?;
        if self.vpn_credentials_transition.is_none() {
            return Ok(());
        }
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            self.poll_credentials_cleanup();
            let Some(transition) = self.vpn_credentials_transition.as_ref() else {
                return Ok(());
            };
            if transition.exited {
                break;
            }
            if Instant::now() >= until {
                return Err("tun_recovery_failed".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if self.rpc.is_some() {
            return Err("tun_recovery_failed".into());
        }
        // Existing permission policy is intentionally unchanged. This guardian
        // may recover a journal, but neither Ready nor this function starts a worker.
        let rpc = Rpc::spawn_managed(
            &self.core,
            &self.data_dir,
            self.logs.clone(),
            self.store.library.preferences.tun.request_permission,
        )
        .await
        .map_err(|_| "tun_recovery_failed")?;
        self.vpn_credentials_transition = Some(Transition::new(rpc.instance(), false));
        self.rpc = Some(rpc);
        let result = self.credentials_cleanup_barrier().await;
        if result.is_ok() {
            self.vpn_credentials_transition = None;
            self.error = None;
        } else {
            self.poll_credentials_cleanup();
        }
        result
    }

    async fn credentials_cleanup_barrier(&mut self) -> Result<(), String> {
        let rpc = self.rpc.as_mut().ok_or("tun_recovery_failed")?;
        let status: proto::ManagedTunStatus = rpc
            .call("ManagedTunStatus", proto::EmptyReq {})
            .await
            .map_err(|_| "tun_recovery_failed")?;
        if status.vpn_credentials_version != Some(1) || status.phase.as_deref() != Some("idle") {
            return Err("tun_recovery_failed".into());
        }
        // Capability alone does not prove a prior crashed owner's journal was
        // recovered. Only Ready performs newOwner's namespace/lease checks.
        let response: proto::ErrorResp = rpc
            .call(
                "ManagedTunReady",
                proto::ManagedTunOptions {
                    auto_reconnect: Some(false),
                },
            )
            .await
            .map_err(|_| "tun_recovery_failed")?;
        crate::core_result(response).map_err(|_| "tun_recovery_failed")?;
        crate::tun::network_clear().map_err(|_| "tun_recovery_failed".into())
    }

    fn accept_credentials_connection(
        &mut self,
        connection: ActiveConnection,
        generation: u64,
        auth_version: u32,
        applied_revision: Option<u64>,
    ) {
        self.running = Some(connection.id.clone());
        self.active_connection = Some(connection);
        self.reset_vpn_session();
        self.observe_vpn_generation(generation, auth_version);
        self.observe_vpn_credentials_capability(1);
        self.tun_generation = generation;
        self.tun_reconnecting = false;
        self.routing_revision = applied_revision;
        self.recovery = Default::default();
        self.traffic = Default::default();
        self.traffic_available = false;
        self.since = Some(
            super::SystemTime::now()
                .duration_since(super::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.error = None;
    }

    pub(super) async fn replace_managed_credentials(
        &mut self,
        capture: Capture,
        candidate: ActiveConnection,
        generation: u64,
        username: String,
        password: String,
    ) -> Result<(), String> {
        let applied_revision = self.routing_revision;
        let auth_version = self.vpn.managed_version;
        let rpc = self.rpc.as_mut().ok_or("vpn_credentials_stale")?;
        if rpc.instance() != capture.instance {
            return Err("vpn_credentials_stale".into());
        }
        // Persistent Engine state, set BEFORE any request byte or await. Even a
        // caller dropping this future leaves automatic recovery disabled.
        self.vpn_credentials_transition = Some(Transition::new(capture.instance, true));
        let outcome = managed::replace(rpc, generation, username, password).await;
        match outcome {
            Ok(managed::Outcome::Applied(next)) => {
                self.vpn_credentials_transition = None;
                self.accept_credentials_connection(candidate, next, auth_version, applied_revision);
                Ok(())
            }
            Ok(managed::Outcome::Restored(next)) => {
                self.vpn_credentials_transition = None;
                self.accept_credentials_connection(
                    capture.connection,
                    next,
                    auth_version,
                    applied_revision,
                );
                self.error = Some("connection_restored".into());
                Err("connection_restored".into())
            }
            Ok(managed::Outcome::Rejected {
                generation: current,
                code,
            }) => {
                self.vpn_credentials_transition = None;
                if current != generation {
                    self.vpn_stale_generation();
                }
                Err(code.into())
            }
            Ok(managed::Outcome::Failed {
                generation: failed_generation,
                cleanup_failed: false,
            }) => {
                // Typed FAILED attests no desired request, worker or pending
                // cleanup. Retain only the idle guardian; never old rollback.
                self.vpn_credentials_transition = None;
                self.clear_connection();
                self.tun_generation = failed_generation;
                self.error = Some("connection_restore_failed".into());
                Err("connection_restore_failed".into())
            }
            _ => {
                self.logs
                    .event("error", "vpn_credentials_cleanup_required", None);
                self.poll_credentials_cleanup();
                Err("tun_recovery_failed".into())
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::{linux::net::SocketAddrExt, unix::fs::PermissionsExt};

    #[tokio::test]
    #[ignore = "requires pinned Core32 and private user/network/mount namespaces"]
    async fn actual_nonzero_guardian_exit_requires_ready_journal_barrier_without_start() {
        const TEST: &str = "vpn_auth::credentials::transition::tests::actual_nonzero_guardian_exit_requires_ready_journal_barrier_without_start";
        if std::env::var_os("THRONIUM_CREDENTIALS_BARRIER_CHILD").is_none() {
            let directory = tempfile::tempdir().unwrap();
            std::fs::copy(
                std::env::current_exe().unwrap(),
                directory.path().join("Thronium"),
            )
            .unwrap();
            std::fs::copy(
                std::env::var_os("THRONIUM_TEST_CORE").expect("pinned Core32"),
                directory.path().join("ThroniumCore"),
            )
            .unwrap();
            // The child runs as root of its own user, network and mount
            // namespaces; the host's namespaces go along to prove it.
            let host = |kind: &str| std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
            let output = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--net", "--mount", "sh", "-c"])
                .arg("mount --make-rprivate / && mount -t tmpfs -o mode=700 tmpfs /run && ip link set lo up && exec \"$@\"")
                .arg("sh")
                .arg(directory.path().join("Thronium"))
                .args(["--ignored", "--exact", TEST, "--nocapture"])
                .env("THRONIUM_CREDENTIALS_BARRIER_CHILD", "1")
                .env("THRONIUM_HOST_NET", host("net"))
                .env("THRONIUM_HOST_MNT", host("mnt"))
                .env("THRONIUM_HOST_USER", host("user"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        assert_eq!(unsafe { libc::geteuid() }, 0);
        for kind in ["net", "mnt", "user"] {
            assert_ne!(
                std::fs::read_link(format!("/proc/self/ns/{kind}"))
                    .unwrap()
                    .to_string_lossy(),
                std::env::var(format!("THRONIUM_HOST_{}", kind.to_uppercase()))
                    .expect("namespace guard")
            );
        }
        let core = std::env::current_exe()
            .unwrap()
            .with_file_name("ThroniumCore");
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let mut engine = Engine::open(directory.path(), &core).unwrap();
        engine
            .connection_settings(crate::system_proxy::ConnectionMode::Tun, port)
            .unwrap();
        let id = engine
            .save_profile(crate::ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Owned barrier fixture".into(),
                group_id: "personal".into(),
                kind: crate::store::ProfileKind::SingBoxOutbound,
                config: serde_json::json!({"type":"direct"}),
            })
            .unwrap();
        engine.connect(&id).await.unwrap();
        let guardian = engine.owned_core_process().unwrap();
        let status: proto::ManagedTunStatus = engine
            .rpc
            .as_mut()
            .unwrap()
            .call("ManagedTunStatus", proto::EmptyReq {})
            .await
            .unwrap();
        assert_eq!(status.vpn_credentials_version, Some(1));
        assert_eq!(status.phase.as_deref(), Some("connected"));
        // Controlled cleanup uncertainty, not a claim that an actual Replace
        // response was lost: the exact guardian is killed with its journal live.
        engine.vpn_credentials_transition = Some(Transition::new(guardian.instance, true));
        engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
        engine.recovery_tick().await;
        assert!(engine.rpc.is_none());
        assert!(engine.vpn_credentials_transition.is_some());
        engine.poll().await;
        engine.recovery_tick().await;
        assert!(engine.rpc.is_none());
        assert!(engine.vpn_credentials_transition.is_some());
        // Public Disconnect is the explicit authorization boundary for a new
        // guardian doing Ready/newOwner recovery; it must never start a worker.
        engine.disconnect().await.unwrap();
        let replacement = engine.owned_core_process().unwrap();
        assert_ne!(guardian.instance, replacement.instance);
        let status: proto::ManagedTunStatus = engine
            .rpc
            .as_mut()
            .unwrap()
            .call("ManagedTunStatus", proto::EmptyReq {})
            .await
            .unwrap();
        assert_eq!(status.phase.as_deref(), Some("idle"));
        assert_eq!(status.generation, Some(0));
        for task in std::fs::read_dir(format!("/proc/{}/task", replacement.pid)).unwrap() {
            if let Ok(children) = std::fs::read_to_string(task.unwrap().path().join("children")) {
                assert!(children.trim().is_empty());
            }
        }
        assert!(engine.vpn_credentials_transition.is_none());
        assert!(engine.active_connection.is_none());
        crate::tun::network_clear().unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        drop(listener);
        assert!(std::fs::read_dir("/run/thronium-tun")
            .unwrap()
            .all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")));
        let lease = std::os::unix::net::UnixListener::bind_addr(
            &std::os::unix::net::SocketAddr::from_abstract_name(b"thronium-tun-18900").unwrap(),
        )
        .unwrap();
        drop(lease);
        engine.shutdown_checked().await.unwrap();
        println!("actual32 nonzero guardian exit retained cleanup; explicit Disconnect Ready recovered journal, no worker/Start, exact lease/network cleanup");
    }
}
