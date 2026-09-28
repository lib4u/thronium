//! Starting the core process, owned or retained, and connecting its IPC stream.
use super::*;

impl Rpc {
    pub async fn spawn(core: &Path, working_dir: &Path) -> Result<Self, String> {
        Self::spawn_logged(core, working_dir, None).await
    }
    pub async fn spawn_logged(
        core: &Path,
        working_dir: &Path,
        logs: Option<crate::logs::Logs>,
    ) -> Result<Self, String> {
        Self::spawn_mode(core, working_dir, logs, false).await
    }
    pub(crate) async fn spawn_managed(
        core: &Path,
        working_dir: &Path,
        logs: crate::logs::Logs,
        request_permission: bool,
    ) -> Result<Self, String> {
        if !crate::tun::supported() {
            return Err(crate::tun::unavailable());
        }
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() } != 0 && !request_permission {
            return Err("tun_permission_required".into());
        }
        // Root cannot reach a core inside an AppImage's FUSE mount; pkexec
        // runs a verified copy of it from the data directory instead.
        #[cfg(target_os = "linux")]
        let reachable;
        #[cfg(target_os = "linux")]
        let core = if unsafe { libc::geteuid() } != 0 && !crate::tun::root_can_reach(core) {
            reachable = crate::tun::reachable_copy(core, working_dir)?;
            reachable.as_path()
        } else {
            core
        };
        #[cfg(windows)]
        {
            let _ = (core, working_dir, request_permission);
            Self::connect_service(logs).await
        }
        // Every other platform is refused by tun::supported above, so no
        // privilege question can reach this point yet.
        #[cfg(not(any(target_os = "linux", windows)))]
        let _ = request_permission;
        #[cfg(not(windows))]
        Self::spawn_mode(core, working_dir, Some(logs), true).await
    }
    /// Windows TUN: the session belongs to ThroniumService. The pipe is
    /// accepted only when its server is the process the service control
    /// manager runs as the service; the service in turn accepts only the
    /// installed application.
    #[cfg(windows)]
    async fn connect_service(logs: crate::logs::Logs) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        pair::required()?;
        let pid = tokio::task::spawn_blocking(crate::tun::windows::running)
            .await
            .map_err(|_| "tun_service_unavailable")??;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let client = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new()
                .open(crate::tun::windows::PIPE)
            {
                Ok(client) => break client,
                // ERROR_PIPE_BUSY: the service is between two clients.
                Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(_) => return Err("tun_service_unavailable".into()),
            }
        };
        let mut server = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                client.as_raw_handle(),
                &mut server,
            )
        };
        if ok == 0 || server != pid {
            return Err("core_peer_mismatch".into());
        }
        logs.event("info", "tun_service_connected", None);
        let socket_dir = tempfile::Builder::new()
            .prefix("thronium-")
            .tempdir()
            .map_err(|_| "core_socket_path")?;
        Ok(Self {
            stream: Some(Box::new(client)),
            stream_loss: StreamLoss::None,
            child: process::CoreProcess::Service { released: false },
            next_id: 0,
            _socket_dir: socket_dir,
            log_tasks: Vec::new(),
            tun_lease: None,
            managed: true,
            owned_process: owned_process(pid),
            _job: None,
        })
    }
    pub(crate) async fn spawn_mode(
        core: &Path,
        working_dir: &Path,
        logs: Option<crate::logs::Logs>,
        managed: bool,
    ) -> Result<Self, String> {
        let mut slot = None;
        Self::spawn_into(core, working_dir, logs, managed, &mut slot, false).await?;
        slot.ok_or_else(|| "core_exited".into())
    }
    /// The caller retains the Child before awaiting its IPC handshake. A canceled
    /// future leaves an exact owner available for mandatory cleanup and reap.
    pub(crate) async fn spawn_local_retained(
        core: &Path,
        directory: &Path,
        logs: crate::logs::Logs,
        slot: &mut Option<Self>,
    ) -> Result<(), String> {
        if slot.is_some() {
            return Err("core_already_owned".into());
        }
        Self::spawn_into(core, directory, Some(logs), false, slot, true).await
    }
    pub(crate) async fn spawn_into(
        core: &Path,
        working_dir: &Path,
        logs: Option<crate::logs::Logs>,
        managed: bool,
        slot: &mut Option<Self>,
        retain_failed_child: bool,
    ) -> Result<(), String> {
        pair::required()?;
        let core = core
            .canonicalize()
            .map_err(|_| "core_missing".to_string())?;
        #[cfg(unix)]
        let socket_dir =
            socket_directory::create(&std::env::temp_dir()).map_err(|_| "core_socket_path")?;
        #[cfg(windows)]
        let socket_dir = tempfile::Builder::new()
            .prefix("thronium-")
            .tempdir()
            .map_err(|_| "core_socket_path")?;
        #[cfg(unix)]
        let (socket, listener) = {
            let path = socket_dir.path().join(socket_directory::SOCKET_NAME);
            let listener = tokio::net::UnixListener::bind(&path).map_err(|_| "core_socket_path")?;
            (path.to_string_lossy().into_owned(), listener)
        };
        #[cfg(windows)]
        let (socket, listener) = {
            let path = format!(r"\\.\pipe\thronium-{}", uuid::Uuid::new_v4());
            // Only this account may open the pipe; the PID check below then
            // tells the core apart from any other process of the same account.
            let mut private = crate::ownership::Private::new().map_err(|_| "core_socket_path")?;
            let listener = unsafe {
                tokio::net::windows::named_pipe::ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(&path, private.as_ptr())
            }
            .map_err(|_| "core_socket_path")?;
            drop(private);
            (path, listener)
        };
        let mut command = Command::new(&core);
        if managed {
            #[cfg(target_os = "linux")]
            if unsafe { libc::geteuid() } != 0 {
                command = Command::new("/usr/bin/pkexec");
                command.arg("--disable-internal-agent").arg(&core);
            }
            command
                .arg("--thronium-tun-supervisor")
                .arg(&socket)
                .arg(working_dir);
        }
        command
            .current_dir(working_dir)
            .env("THRONE_CORE_SOCKET", socket)
            .env("XRAY_LOCATION_ASSET", working_dir.join("xray-assets"))
            .env_remove("THRONE_CORE_DEBUG")
            .stdin(Stdio::null())
            .stdout(if logs.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(if logs.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let mut child = command.spawn().map_err(|e| {
            if managed && e.kind() == std::io::ErrorKind::NotFound {
                "tun_authorization_unavailable".into()
            } else {
                format!("core_launch: {e}")
            }
        })?;
        let mut log_tasks = Vec::new();
        if let Some(logs) = logs {
            logs.event("info", "core_started", None);
            if let Some(stdout) = child.stdout.take() {
                let sink = logs.clone();
                log_tasks.push(tokio::spawn(async move {
                    crate::logs::capture(stdout, sink, "stdout").await
                }));
            }
            if let Some(stderr) = child.stderr.take() {
                log_tasks.push(tokio::spawn(async move {
                    crate::logs::capture(stderr, logs, "stderr").await
                }));
            }
        }
        #[cfg(windows)]
        let job = super::job::contain_child(&child);
        let expected_pid = child.id().ok_or("core_exited")?;
        let owned_process = owned_process(expected_pid);
        let accept = async {
            #[cfg(unix)]
            let stream = {
                let (stream, _) = listener.accept().await.map_err(|_| "core_disconnected")?;
                let credentials = stream.peer_cred().map_err(|_| "core_peer_mismatch")?;
                #[cfg(not(target_os = "macos"))]
                let peer_pid = credentials.pid().map(|p| p as u32);
                #[cfg(target_os = "macos")]
                let peer_pid = {
                    use std::os::fd::AsRawFd;
                    let mut pid: libc::pid_t = 0;
                    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
                    // LOCAL_PEERPID returns the process that connected this Unix socket.
                    let result = unsafe {
                        libc::getsockopt(
                            stream.as_raw_fd(),
                            0,
                            2,
                            &mut pid as *mut _ as *mut _,
                            &mut size,
                        )
                    };
                    if result == 0 {
                        Some(pid as u32)
                    } else {
                        None
                    }
                };
                if peer_pid != Some(expected_pid) {
                    return Err("core_peer_mismatch".into());
                }
                let _ = credentials;
                Box::new(stream) as Box<dyn Stream>
            };
            #[cfg(windows)]
            let stream = {
                use std::os::windows::io::AsRawHandle;
                listener.connect().await.map_err(|_| "core_disconnected")?;
                let mut pid = 0;
                let ok = unsafe {
                    windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
                        listener.as_raw_handle(),
                        &mut pid,
                    )
                };
                if ok == 0 || pid != expected_pid {
                    return Err("core_peer_mismatch".into());
                }
                Box::new(listener) as Box<dyn Stream>
            };
            Ok::<_, String>(stream)
        };
        *slot = Some(Self {
            stream: None,
            stream_loss: StreamLoss::Local,
            child: process::CoreProcess::Local(child),
            next_id: 0,
            _socket_dir: socket_dir,
            log_tasks,
            tun_lease: None,
            managed,
            owned_process,
            #[cfg(windows)]
            _job: job,
        });
        let rpc = slot.as_mut().expect("owned spawn slot");
        let handshake = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(if managed {120} else {8}), accept) => result,
            status = rpc.child.wait() => Ok(Err(if managed {match status.ok().and_then(|s| s.code()) {Some(126)=>"tun_authorization_cancelled",Some(127)=>"tun_authorization_failed",_=>"tun_helper_failed"}.into()} else {"core_exited".into()})),
        };
        let stream = match handshake {
            Ok(Ok(stream)) => stream,
            result => {
                if retain_failed_child {
                    // The owning Engine must regain control to restore its
                    // proxy and perform bounded reap. Keep the Child in slot.
                    let _ = rpc.child.start_kill();
                } else {
                    let _ = rpc.child.kill().await;
                }
                return Err(match result {
                    Ok(Err(e)) => e,
                    _ => "core_handshake_timeout".into(),
                });
            }
        };
        rpc.stream = Some(stream);
        rpc.stream_loss = StreamLoss::None;
        Ok(())
    }
}
