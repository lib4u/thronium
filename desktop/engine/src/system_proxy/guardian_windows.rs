//! Windows: the same headless guardian as on Linux, a child of this executable
//! that restores the system proxy from the journal when its owner dies.
//!
//! The channel is the child's stdin and stdout, which nobody else holds. The
//! guardian names its parent on the command line and believes it only when
//! that process really is its parent and runs this very executable; it then
//! waits on the parent's process handle, which also covers a crash.
use super::*;
use std::io::{self, Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

const ERROR: &str = "system_proxy_guardian_failed";
const MAGIC: &[u8; 4] = b"TPG1";
const DEADLINE: Duration = Duration::from_secs(10);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

pub(super) struct Guardian {
    child: Child,
    channel: Option<ChildStdin>,
}
impl Guardian {
    pub fn spawn(token: &str) -> Result<Self, String> {
        Self::spawn_inner(token).map_err(|_| ERROR.into())
    }
    fn spawn_inner(token: &str) -> io::Result<Self> {
        let command = |flags: u32| {
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args(["--thronium-proxy-guardian", &std::process::id().to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .creation_flags(flags);
            command.spawn()
        };
        // Outside a job the window may belong to, so the window's end is not
        // the guardian's; a job that forbids leaving keeps it inside.
        let mut child = command(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB)
            .or_else(|_| command(CREATE_NO_WINDOW))?;
        let mut stdin = child.stdin.take().ok_or_else(invalid)?;
        let mut stdout = child.stdout.take().ok_or_else(invalid)?;
        let mut guardian = Self {
            child,
            channel: None,
        };
        let result: io::Result<()> = (|| {
            stdin.write_all(MAGIC)?;
            stdin.write_all(token.as_bytes())?;
            stdin.flush()?;
            let (send, receive) = mpsc::channel();
            std::thread::spawn(move || {
                let mut ready = [0];
                let _ = send.send(stdout.read_exact(&mut ready).map(|()| ready));
            });
            let ready = receive
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            if ready != *b"R" || !guardian.alive() {
                return Err(invalid());
            }
            Ok(())
        })();
        guardian.channel = Some(stdin);
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

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// The process that started this one, from the system's own record.
fn parent_of(pid: u32) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return None;
    }
    let snapshot = Handle(snapshot);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
    while more {
        if entry.th32ProcessID == pid {
            return Some(entry.th32ParentProcessID);
        }
        more = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
    }
    None
}

fn image(process: HANDLE) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
    };
    (ok != 0).then(|| std::ffi::OsString::from_wide(&buffer[..size as usize]).into())
}

/// The named owner must be this process's parent and run this executable; the
/// handle kept for waiting is the one that was checked.
fn authenticated_owner(named: &str) -> io::Result<Handle> {
    let pid: u32 = named.parse().map_err(|_| invalid())?;
    if pid == 0 || parent_of(std::process::id()) != Some(pid) {
        return Err(invalid());
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Handle(process);
    let this = std::env::current_exe()?;
    let owner = image(process.0).ok_or_else(invalid)?;
    let same = |path: &std::path::Path| std::fs::canonicalize(path).ok();
    if same(&owner).is_none() || same(&owner) != same(&this) {
        return Err(invalid());
    }
    Ok(process)
}

fn token(channel: &mut impl Read) -> io::Result<String> {
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

/// `true` when the owner is gone (dead, or its end of the channel closed),
/// `false` when it disarmed the guardian.
fn wait_owner(mut channel: impl Read + Send + 'static, owner: &Handle) -> io::Result<bool> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = send.send(channel.read(&mut byte).map(|n| (n, byte[0])));
    });
    loop {
        match receive.try_recv() {
            Ok(Ok((0, _))) => return Ok(true),
            Ok(Ok((_, b'D'))) => return Ok(false),
            Ok(_) => return Err(invalid()),
            Err(mpsc::TryRecvError::Disconnected) => return Err(invalid()),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if unsafe { WaitForSingleObject(owner.0, 100) } == WAIT_OBJECT_0 {
            return Ok(true);
        }
    }
}

/// Recovery has no deadline of its own in WinINet; the whole process has one.
fn deadline() -> mpsc::Sender<()> {
    let (send, receive) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        if receive.recv_timeout(DEADLINE) == Err(mpsc::RecvTimeoutError::Timeout) {
            std::process::exit(3);
        }
    });
    send
}

pub(super) fn run() -> Result<(), String> {
    let armed = deadline();
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(ERROR.into());
    }
    let owner = authenticated_owner(&args[2]).map_err(|_| ERROR)?;
    let mut input = io::stdin().lock();
    let token = token(&mut input).map_err(|_| ERROR)?;
    drop(input);
    let mut manager = Manager::platform_unrecovered();
    if manager.backend.is_none() {
        return Err(ERROR.into());
    }
    let journal = manager.read_journal()?.ok_or(ERROR)?;
    if journal.token.as_deref() != Some(&token) {
        return Err(ERROR.into());
    }
    let mut output = io::stdout();
    output
        .write_all(b"R")
        .and_then(|()| output.flush())
        .map_err(|_| ERROR)?;
    drop(armed);
    if wait_owner(io::stdin(), &owner).map_err(|_| ERROR)? {
        let _armed = deadline();
        recover_owned(&mut manager, &token)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshake_is_versioned_fixed_length_and_rejects_malformed_tokens() {
        for data in [
            b"TPG1"
                .iter()
                .copied()
                .chain([b'a'; 32])
                .collect::<Vec<_>>(),
            vec![0; 36],
            b"TPG1abcdef".to_vec(),
            b"TPG1".iter().copied().chain([b'A'; 32]).collect(),
        ] {
            assert_eq!(
                token(&mut data.as_slice()).is_ok(),
                data.len() == 36 && data[4..] == [b'a'; 32]
            );
        }
    }
    #[test]
    fn a_process_that_is_not_the_parent_is_never_trusted() {
        assert!(authenticated_owner("0").is_err());
        assert!(authenticated_owner("not a pid").is_err());
        // This process is not its own parent.
        assert!(authenticated_owner(&std::process::id().to_string()).is_err());
    }
    #[test]
    fn the_channel_tells_disarm_from_a_closed_owner_and_rejects_noise() {
        let this = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, std::process::id()) };
        let this = Handle(this);
        assert!(!wait_owner(&b"D"[..], &this).unwrap());
        assert!(wait_owner(&b""[..], &this).unwrap());
        assert!(wait_owner(&b"X"[..], &this).is_err());
    }
}
