//! Core stand-ins for tests: scripted, sleeping and killable RPC channels.
use super::*;

/// A child that only waits, standing in for the core's process.
#[cfg(test)]
fn sleeper() -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd.exe");
        command.args(["/c", "ping -n 30 127.0.0.1 >NUL"]);
        command
    }
    #[cfg(not(windows))]
    {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        command
    }
}

impl Rpc {
    #[cfg(test)]
    pub(crate) async fn kill_for_recovery_test(&mut self) {
        self.child.kill().await.unwrap();
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn managed_vpn_test_rpc() -> Self {
        let mut rpc = Self::sleeping_recovery_test_child(true);
        rpc.managed = true;
        rpc
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn owned_managed_ipc_test_rpc(core: &Path, directory: &Path) -> Self {
        let mut rpc = Self::spawn_mode(core, directory, None, false)
            .await
            .unwrap();
        rpc.managed = true;
        rpc
    }
    #[cfg(test)]
    pub(crate) fn scripted_local_test_rpc(
        handler: impl FnMut(&str, &[u8]) -> Vec<u8> + Send + 'static,
    ) -> Self {
        let mut rpc = Self::scripted_vpn_test_rpc(handler);
        rpc.managed = false;
        rpc
    }
    #[cfg(test)]
    pub(crate) fn scripted_vpn_test_rpc(
        mut handler: impl FnMut(&str, &[u8]) -> Vec<u8> + Send + 'static,
    ) -> Self {
        let child = sleeper().kill_on_drop(true).spawn().unwrap();
        let owned_process = owned_process(child.id().unwrap());
        let (stream, mut peer) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(async move {
            while let Ok(id) = peer.read_u32_le().await {
                let method_len = peer.read_u16_le().await.unwrap() as usize;
                let mut method = vec![0; method_len];
                peer.read_exact(&mut method).await.unwrap();
                let size = peer.read_u32_le().await.unwrap() as usize;
                assert!(size <= MAX_FRAME);
                let mut payload = vec![0; size];
                peer.read_exact(&mut payload).await.unwrap();
                let reply = handler(std::str::from_utf8(&method).unwrap(), &payload);
                peer.write_u32_le(id).await.unwrap();
                peer.write_u8(0).await.unwrap();
                peer.write_u32_le(reply.len() as u32).await.unwrap();
                peer.write_all(&reply).await.unwrap();
            }
        });
        Self {
            stream: Some(Box::new(stream)),
            stream_loss: StreamLoss::None,
            child: process::CoreProcess::Local(child),
            next_id: 0,
            _socket_dir: tempfile::tempdir().unwrap(),
            log_tasks: vec![task],
            tun_lease: None,
            managed: true,
            owned_process,
            #[cfg(windows)]
            _job: None,
        }
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn sleeping_recovery_test_child(stream_present: bool) -> Self {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let owned_process = owned_process(child.id().unwrap());
        let (stream, mut peer) = tokio::io::duplex(64);
        let log_tasks = if stream_present {
            vec![tokio::spawn(async move {
                // Deterministic remote EOF after receiving a real RPC frame,
                // while the independent owned child is deliberately still alive.
                let mut frame = [0u8; 64];
                let _ = peer.read(&mut frame).await;
            })]
        } else {
            Vec::new()
        };
        Self {
            child: process::CoreProcess::Local(child),
            stream: stream_present.then(|| Box::new(stream) as Box<dyn Stream>),
            stream_loss: if stream_present {
                StreamLoss::None
            } else {
                StreamLoss::Remote
            },
            next_id: 0,
            _socket_dir: tempfile::tempdir().unwrap(),
            log_tasks,
            tun_lease: None,
            managed: false,
            owned_process,
            #[cfg(windows)]
            _job: None,
        }
    }
}
