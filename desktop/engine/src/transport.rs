use prost::Message;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
};

const MAX_FRAME: usize = 16 * 1024 * 1024;
#[cfg(unix)]
mod socket_directory;

/// Identity of the exact process spawned and authenticated by this RPC.
/// `start_time` is Linux /proc stat field 22, captured once at spawn; it is not
/// refreshed from a possibly reused PID by a later metrics request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedProcess {
    pub pid: u32,
    pub instance: u64,
    pub start_time: Option<u64>,
}

fn owned_process(pid: u32) -> OwnedProcess {
    static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    #[cfg(target_os = "linux")]
    let start_time = (|| {
        use std::io::Read;
        let mut data = Vec::new();
        std::fs::File::open(format!("/proc/{pid}/stat"))
            .ok()?
            .take(8193)
            .read_to_end(&mut data)
            .ok()?;
        if data.len() > 8192 {
            return None;
        }
        let open = data.iter().position(|b| *b == b'(')?;
        let close = data.iter().rposition(|b| *b == b')')?;
        if open >= close
            || std::str::from_utf8(&data[..open])
                .ok()?
                .trim()
                .parse::<u32>()
                .ok()?
                != pid
        {
            return None;
        }
        std::str::from_utf8(&data[close + 1..])
            .ok()?
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    })();
    // Creation time in 100 ns units: a PID reused later has another.
    #[cfg(windows)]
    let start_time = job::start_time(pid);
    #[cfg(not(any(target_os = "linux", windows)))]
    let start_time = None;
    OwnedProcess {
        pid,
        instance: NEXT_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        start_time,
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum StreamLoss {
    #[default]
    None,
    Remote,
    Local,
}

fn remote_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

pub struct Rpc {
    stream: Option<Box<dyn Stream>>,
    stream_loss: StreamLoss,
    child: process::CoreProcess,
    next_id: u32,
    _socket_dir: tempfile::TempDir,
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    tun_lease: Option<crate::tun::Lease>,
    managed: bool,
    owned_process: OwnedProcess,
    // Closing it ends the core and everything it started, like kill_on_drop.
    #[cfg(windows)]
    _job: Option<job::Job>,
}

impl Rpc {
    /// No /proc I/O or process polling. Managed mode identifies the authenticated
    /// TUN supervisor; its workers are descendants of this same owned root.
    pub fn owned_process(&self) -> Option<OwnedProcess> {
        self.child
            .id()
            .filter(|pid| *pid == self.owned_process.pid)
            .map(|_| self.owned_process)
    }

    pub fn is_alive(&mut self) -> bool {
        self.stream.is_some() && matches!(self.child.try_wait(), Ok(None))
    }

    /// Confirm death of the exact Child owned by this RPC. A missing stream,
    /// timeout or failed status query alone must not arm automatic recovery.
    pub(crate) fn child_exited(&mut self) -> bool {
        // The service's worker is out of reach; the service closing the pipe
        // is the only sign its session ended.
        #[cfg(windows)]
        if matches!(self.child, process::CoreProcess::Service { .. }) && self.remote_stream_lost() {
            return true;
        }
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Local timeout, cancellation and malformed framing close our endpoint.
    /// The core's ensuing normal EOF exit must never be mistaken for a crash.
    pub(crate) fn recoverable_exit(&self) -> bool {
        self.stream_loss != StreamLoss::Local
    }

    pub(crate) fn remote_stream_lost(&self) -> bool {
        self.stream.is_none() && self.stream_loss == StreamLoss::Remote
    }

    /// Whether IPC is still usable. A timed-out or cancelled call closes it on
    /// purpose, and the core then shuts down on that EOF.
    pub(crate) fn stream_open(&self) -> bool {
        self.stream.is_some()
    }
    pub(crate) fn managed(&self) -> bool {
        self.managed
    }

    // Replacement cleanup retains this exact Child even after waitpid removes
    // its public PID. Never infer cleanup from a missing IPC stream.
    pub(crate) fn instance(&self) -> u64 {
        self.owned_process.instance
    }

    pub(crate) fn close_ipc(&mut self) {
        self.stream_loss = StreamLoss::Local;
        self.stream.take();
    }

    pub(crate) fn request_kill(&mut self) -> Result<(), String> {
        self.child
            .start_kill()
            .map_err(|_| "core_cleanup_failed".into())
    }

    pub(crate) async fn reap_local(&mut self) -> Result<(), String> {
        if self.managed {
            return Err("core_cleanup_failed".into());
        }
        self.close_ipc();
        if matches!(
            tokio::time::timeout(Duration::from_secs(4), self.child.wait()).await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        self.request_kill()?;
        match tokio::time::timeout(Duration::from_secs(4), self.child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            _ => Err("core_cleanup_failed".into()),
        }
    }

    pub(crate) fn exit_success(&mut self) -> Result<Option<bool>, String> {
        self.child
            .try_wait()
            .map(|status| status.map(|status| status.success()))
            .map_err(|_| "tun_recovery_failed".into())
    }

    pub async fn call<Req: Message, Resp: Message + Default>(
        &mut self,
        method: &str,
        request: Req,
    ) -> Result<Resp, String> {
        self.call_with_timeout(method, request, Duration::from_secs(30))
            .await
    }

    pub(crate) async fn call_with_timeout<Req: Message, Resp: Message + Default>(
        &mut self,
        method: &str,
        request: Req,
        timeout: Duration,
    ) -> Result<Resp, String> {
        self.call_checked(method, request, timeout, MAX_FRAME, |data| {
            Resp::decode(data).map_err(|e| format!("invalid_core_response: {e}"))
        })
        .await
    }

    /// A private typed operation may impose stricter wire and response limits.
    /// Existing RPCs retain their previous decoding and frame budget.
    pub(crate) async fn call_checked<Req: Message, Resp>(
        &mut self,
        method: &str,
        request: Req,
        timeout: Duration,
        response_limit: usize,
        decode: impl FnOnce(&[u8]) -> Result<Resp, String>,
    ) -> Result<Resp, String> {
        // Taking the stream makes cancellation/timeouts close IPC. A partial frame must never
        // be reused by the next request, nor may a late response be mistaken for its result.
        // A later diagnostics call on an already lost stream must not replace
        // the provenance of the original failure.
        if self.stream.is_none() {
            return Err("core_disconnected".into());
        }
        // Set the terminal provenance BEFORE take: dropping this future at any
        // await must not later classify the core's exit on our EOF as a crash.
        self.stream_loss = StreamLoss::Local;
        let mut stream = self.stream.take().ok_or("core_disconnected")?;
        self.next_id = self.next_id.checked_add(1).ok_or("request_id_exhausted")?;
        let id = self.next_id;
        let mut failure = StreamLoss::Local;
        let result = tokio::time::timeout(timeout, async {
            let bytes = request.encode_to_vec();
            let frame = request_frame(id, method, &bytes)?;
            stream.write_all(&frame).await.map_err(|e| {
                if remote_disconnect(&e) {
                    failure = StreamLoss::Remote;
                }
                "core_disconnected".to_string()
            })?;
            stream.flush().await.map_err(|e| {
                if remote_disconnect(&e) {
                    failure = StreamLoss::Remote;
                }
                "core_disconnected".to_string()
            })?;
            let mut header = [0; 9];
            stream.read_exact(&mut header).await.map_err(|e| {
                if remote_disconnect(&e) {
                    failure = StreamLoss::Remote;
                }
                "core_disconnected".to_string()
            })?;
            let (status, length) = response_header(id, header)?;
            if length > response_limit {
                return Err("invalid_core_frame".into());
            }
            let mut data = vec![0; length];
            stream.read_exact(&mut data).await.map_err(|e| {
                if remote_disconnect(&e) {
                    failure = StreamLoss::Remote;
                }
                "core_disconnected".to_string()
            })?;
            if status != 0 {
                return Ok(Err(String::from_utf8_lossy(&data).into_owned()));
            }
            Ok(decode(data.as_slice()))
        })
        .await;
        match result {
            Ok(Ok(response)) => {
                self.stream = Some(stream);
                self.stream_loss = StreamLoss::None;
                response
            }
            Ok(Err(error)) => {
                self.stream_loss = failure;
                Err(error)
            }
            Err(_) => Err("core_request_timeout".into()),
        }
    }

    pub async fn terminate(&mut self) {
        self.stream_loss = StreamLoss::Local;
        self.stream.take();
        // IPC EOF lets the core close its TUN and policy rules before reaping it.
        if matches!(
            tokio::time::timeout(
                Duration::from_secs(if self.managed { 8 } else { 4 }),
                self.child.wait()
            )
            .await,
            Ok(Ok(_))
        ) {
            return;
        }
        let _ = self.child.kill().await;
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        crate::logs::drain(std::mem::take(&mut self.log_tasks));
    }
}

fn request_frame(id: u32, method: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if method.is_empty() || method.len() > u16::MAX as usize || bytes.len() > MAX_FRAME {
        return Err("invalid_request_size".into());
    }
    let mut frame = Vec::with_capacity(10 + method.len() + bytes.len());
    frame.extend(id.to_le_bytes());
    frame.extend((method.len() as u16).to_le_bytes());
    frame.extend(method.as_bytes());
    frame.extend((bytes.len() as u32).to_le_bytes());
    frame.extend(bytes);
    Ok(frame)
}

fn response_header(id: u32, header: [u8; 9]) -> Result<(u8, usize), String> {
    let received = u32::from_le_bytes(header[..4].try_into().unwrap());
    let length = u32::from_le_bytes(header[5..].try_into().unwrap()) as usize;
    if received != id || length > MAX_FRAME {
        return Err("invalid_core_frame".into());
    }
    Ok((header[4], length))
}

#[cfg(windows)]
mod job;
pub mod pair;
mod process;
mod spawn;
mod test_support;
#[cfg(test)]
mod tests;
mod tun;
