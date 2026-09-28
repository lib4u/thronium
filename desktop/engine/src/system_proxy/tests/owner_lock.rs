//! Deterministic fork inheritance checks. Private fake settings only.
use super::*;
use std::os::fd::AsRawFd;

struct Inherited {
    pid: libc::pid_t,
    release: i32,
}
impl Inherited {
    fn spawn(drop_guard: Option<*const ProxyLock>, unlock_old_fd: Option<i32>) -> Self {
        let mut ready = [0; 2];
        let mut release = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let parent = unsafe { libc::getpid() };
        let pid = unsafe { libc::syscall(libc::SYS_fork) } as libc::pid_t;
        assert!(pid >= 0);
        if pid == 0 {
            // Never drop Manager/Backend or use allocator/runtime locks after
            // raw fork. Only the tiny file ownership guard may be dropped.
            let mut byte = [0u8];
            unsafe {
                libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if libc::syscall(libc::SYS_getppid) != parent as libc::c_long {
                    libc::syscall(libc::SYS_exit, 1);
                }
                if let Some(guard) = drop_guard {
                    drop(std::ptr::read(guard));
                }
                libc::syscall(libc::SYS_close, ready[0]);
                libc::syscall(libc::SYS_close, release[1]);
                if libc::syscall(libc::SYS_write, ready[1], [1u8].as_ptr(), 1usize) != 1 {
                    libc::syscall(libc::SYS_exit, 2);
                }
                if libc::syscall(libc::SYS_read, release[0], byte.as_mut_ptr(), 1usize) != 1 {
                    libc::syscall(libc::SYS_exit, 3);
                }
                if let Some(fd) = unlock_old_fd {
                    if libc::syscall(libc::SYS_flock, fd, libc::LOCK_UN) != 0 {
                        libc::syscall(libc::SYS_exit, 4);
                    }
                }
                libc::syscall(libc::SYS_exit, 0);
            }
            unreachable!();
        }
        unsafe {
            libc::close(ready[1]);
            libc::close(release[0]);
        }
        let child = Self {
            pid,
            release: release[1],
        };
        let mut poll = libc::pollfd {
            fd: ready[0],
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
        let mut byte = [0u8];
        assert_eq!(
            unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 1) },
            1
        );
        unsafe {
            libc::close(ready[0]);
        }
        child
    }
}
impl Drop for Inherited {
    fn drop(&mut self) {
        unsafe {
            let sent = loop {
                let result = libc::write(self.release, [1u8].as_ptr().cast(), 1);
                if result >= 0 || *libc::__errno_location() != libc::EINTR {
                    break result;
                }
            };
            let mut status = 0;
            let waited = loop {
                let result = libc::waitpid(self.pid, &mut status, 0);
                if result >= 0 || *libc::__errno_location() != libc::EINTR {
                    break result;
                }
            };
            libc::close(self.release);
            // Preserve the original assertion if unwinding, but on the normal
            // path prove that every child operation, including LOCK_UN, ran.
            if !std::thread::panicking() {
                assert_eq!(sent, 1, "failed to release the fork barrier");
                assert_eq!(waited, self.pid, "failed to reap the exact fork child");
                assert!(libc::WIFEXITED(status), "fork child did not exit normally");
                assert_eq!(libc::WEXITSTATUS(status), 0, "fork child syscall failed");
            }
        }
    }
}

#[test]
fn parent_release_recovers_with_inherited_fd_and_old_child_cannot_unlock_new_owner() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let original = shared.lock().unwrap().values.clone();
    let mut first = open(dir.path(), &shared);
    first.enable(2080).unwrap();
    let fd = first.lease.as_ref().unwrap()._file.file.as_raw_fd();
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let child = Inherited::spawn(None, Some(fd));
    crash(first);
    let mut next = open(dir.path(), &shared);
    assert!(!next.status().active);
    assert!(next.status().error.is_none());
    assert_eq!(shared.lock().unwrap().values, original);
    assert!(!next.path().exists());
    next.enable(3000).unwrap();
    let competitor = open(dir.path(), &shared);
    assert_eq!(competitor.preflight().unwrap_err(), "system_proxy_busy");
    // LOCK_UN via the retired open description cannot release the new lease.
    drop(child);
    assert_eq!(competitor.preflight().unwrap_err(), "system_proxy_busy");
    next.restore().unwrap();
    assert_eq!(shared.lock().unwrap().values, original);
}

#[test]
fn child_guard_drop_does_not_unlock_live_parent_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let original = shared.lock().unwrap().values.clone();
    let mut first = open(dir.path(), &shared);
    first.enable(2080).unwrap();
    let child = Inherited::spawn(Some(&first.lease.as_ref().unwrap()._file), None);
    let competitor = open(dir.path(), &shared);
    assert_eq!(competitor.preflight().unwrap_err(), "system_proxy_busy");
    drop(child);
    assert_eq!(competitor.preflight().unwrap_err(), "system_proxy_busy");
    assert!(first.status().active);
    first.restore().unwrap();
    assert_eq!(shared.lock().unwrap().values, original);
}

struct FailAfterFork(Arc<Mutex<Option<Inherited>>>);
impl Backend for FailAfterFork {
    fn writable(&self) -> Result<(), String> {
        Ok(())
    }
    fn read(&self) -> Result<Vec<Value>, String> {
        *self.0.lock().unwrap() = Some(Inherited::spawn(None, None));
        Err("system_proxy_read_failed".into())
    }
    fn write(&self, _: usize, _: Option<&str>) -> Result<(), String> {
        panic!("failed initial read must not write settings")
    }
}

#[test]
fn failed_enable_releases_inherited_lock_before_lease_is_constructed() {
    let dir = tempfile::tempdir().unwrap();
    let held = Arc::new(Mutex::new(None));
    let mut failed = Manager::open(dir.path().into(), Box::new(FailAfterFork(held.clone())));
    assert_eq!(failed.enable(2080).unwrap_err(), "system_proxy_read_failed");
    assert!(failed.lease.is_none());
    assert!(!failed.path().exists());
    let shared = state();
    let original = shared.lock().unwrap().values.clone();
    let mut next = open(dir.path(), &shared);
    next.enable(3000)
        .expect("early-return lock guard must release while fork child is alive");
    drop(held.lock().unwrap().take());
    let competitor = open(dir.path(), &shared);
    assert_eq!(competitor.preflight().unwrap_err(), "system_proxy_busy");
    next.restore().unwrap();
    assert_eq!(shared.lock().unwrap().values, original);
}
