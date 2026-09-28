//! A headless child of the same executable, armed before any GSettings write.
use super::*;
use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ERROR: &str = "system_proxy_guardian_failed";
const MAGIC: &[u8; 4] = b"TPG1";
const DEADLINE: Duration = Duration::from_secs(10);

pub(super) struct Guardian {
    child: Child,
    channel: Option<UnixStream>,
}
impl Guardian {
    pub fn spawn(token: &str) -> Result<Self, String> {
        Self::spawn_inner(token).map_err(|_| ERROR.into())
    }
    fn spawn_inner(token: &str) -> io::Result<Self> {
        let (mut parent, child_socket) = UnixStream::pair()?;
        parent.set_read_timeout(Some(Duration::from_secs(5)))?;
        parent.set_write_timeout(Some(Duration::from_secs(1)))?;
        let fd = child_socket.as_raw_fd();
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--thronium-proxy-guardian", &fd.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // No inherited lock, listener, RPC socket, or other application FD is
        // deliberately passed. Only this socket loses CLOEXEC in the fork child.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        drop(child_socket);
        let mut guardian = Self {
            child,
            channel: None,
        };
        let result: io::Result<()> = (|| {
            parent.write_all(MAGIC)?;
            parent.write_all(token.as_bytes())?;
            let mut ready = [0];
            parent.read_exact(&mut ready)?;
            if ready != *b"R" || !guardian.alive() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })();
        guardian.channel = Some(parent);
        result?;
        Ok(guardian)
    }
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    fn reap(&mut self, timeout: Duration) {
        let end = Instant::now() + timeout;
        while self.alive() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.alive() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
    pub fn disarm(&mut self) {
        if let Some(mut channel) = self.channel.take() {
            let _ = channel.write_all(b"D");
        }
        self.reap(Duration::from_secs(2));
    }
    pub fn recover_after_drop(&mut self) {
        self.channel = None;
        self.reap(DEADLINE + Duration::from_secs(1));
    }
}
impl Drop for Guardian {
    fn drop(&mut self) {
        self.disarm();
    }
}

// GSettings::sync has no deadline API. A separate watchdog bounds the entire
// recovery process even if the desktop settings service stops responding.
struct Deadline(std::sync::mpsc::Sender<()>);
impl Deadline {
    fn start() -> Self {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if receive.recv_timeout(DEADLINE) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
                unsafe {
                    libc::_exit(3);
                }
            }
        });
        Self(send)
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn socket_option<T: Copy>(fd: i32, option: i32, mut value: T) -> io::Result<T> {
    let mut size = std::mem::size_of::<T>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut T).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<T>() {
        return Err(invalid());
    }
    Ok(value)
}
fn authenticated_channel(fd: i32) -> io::Result<(UnixStream, OwnedFd)> {
    if fd < 3
        || socket_option(fd, libc::SO_DOMAIN, 0i32)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE, 0i32)? != libc::SOCK_STREAM
    {
        return Err(invalid());
    }
    let peer = socket_option(
        fd,
        libc::SO_PEERCRED,
        libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        },
    )?;
    if peer.uid != unsafe { libc::geteuid() }
        || peer.pid <= 1
        || peer.pid != unsafe { libc::getppid() }
    {
        return Err(invalid());
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid, 0) as i32 };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    let parent = std::fs::metadata(format!("/proc/{}/exe", peer.pid))?;
    let this = std::fs::metadata("/proc/self/exe")?;
    if (parent.dev(), parent.ino()) != (this.dev(), this.ino()) {
        return Err(invalid());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((unsafe { UnixStream::from_raw_fd(fd) }, pidfd))
}
fn token(channel: &mut UnixStream) -> io::Result<String> {
    let mut packet = [0u8; 36];
    channel.read_exact(&mut packet)?;
    if &packet[..4] != MAGIC
        || !packet[4..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid());
    }
    String::from_utf8(packet[4..].to_vec()).map_err(|_| invalid())
}
fn wait_owner(channel: &mut UnixStream, pidfd: &OwnedFd) -> io::Result<bool> {
    let mut fds = [
        libc::pollfd {
            fd: channel.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds[0].revents != 0 {
            let mut byte = [0];
            return match channel.read(&mut byte)? {
                0 => Ok(true),
                1 if byte == *b"D" => Ok(false),
                _ => Err(invalid()),
            };
        }
        // pidfd also handles a forked child temporarily retaining the channel.
        if fds[1].revents != 0 {
            return Ok(true);
        }
    }
}
pub(super) fn run() -> Result<(), String> {
    let deadline = Deadline::start();
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(ERROR.into());
    }
    let fd = args[2]
        .to_str()
        .and_then(|s| s.parse::<i32>().ok())
        .ok_or(ERROR)?;
    let (mut channel, pidfd) = authenticated_channel(fd).map_err(|_| ERROR)?;
    channel
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| ERROR)?;
    channel
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| ERROR)?;
    let token = token(&mut channel).map_err(|_| ERROR)?;
    let mut manager = Manager::platform_unrecovered();
    if manager.backend.is_none() {
        return Err(ERROR.into());
    }
    let journal = manager.read_journal()?.ok_or(ERROR)?;
    if journal.token.as_deref() != Some(&token) {
        return Err(ERROR.into());
    }
    // Do not construct GSettings before owner death: a headless process has no
    // GTK loop delivering backend notifications. Its first recovery read must
    // load current values, including changes made outside the application.
    // The parent has already checked writability before creating this journal.
    channel.write_all(b"R").map_err(|_| ERROR)?;
    drop(deadline);
    if wait_owner(&mut channel, &pidfd).map_err(|_| ERROR)? {
        let _deadline = Deadline::start();
        recover_owned(&mut manager, &token)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
