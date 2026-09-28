use super::*;
use crate::store::Store;
use std::{io::Write, os::fd::AsRawFd};

struct Inherited {
    pid: libc::pid_t,
    release: i32,
    ready: i32,
}
impl Inherited {
    fn spawn(fd: i32, drop_guard: Option<*const LibraryLock>, close_fd: Option<i32>) -> Self {
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
        let pid = unsafe { libc::syscall(libc::SYS_fork) } as libc::pid_t;
        assert!(pid >= 0);
        if pid == 0 {
            // No allocator, IO formatting or runtime locks after raw fork.
            // Only the tiny ownership guard is dropped, never the Store graph.
            if let Some(guard) = drop_guard {
                unsafe {
                    drop(std::ptr::read(guard));
                }
            }
            let ready_byte = [if drop_guard.is_some() { 2u8 } else { 1u8 }];
            let mut done = [0u8];
            unsafe {
                libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if let Some(extra) = close_fd {
                    libc::syscall(libc::SYS_close, extra);
                }
                libc::syscall(libc::SYS_close, ready[0]);
                libc::syscall(libc::SYS_close, release[1]);
                libc::syscall(libc::SYS_write, ready[1], ready_byte.as_ptr(), 1usize);
                libc::syscall(libc::SYS_read, release[0], done.as_mut_ptr(), 1usize);
                if drop_guard.is_none() {
                    libc::syscall(libc::SYS_flock, fd, libc::LOCK_UN);
                }
                libc::syscall(libc::SYS_exit, 0);
            }
            unreachable!();
        }
        unsafe {
            libc::close(ready[1]);
            libc::close(release[0]);
        }
        let owned = Self {
            pid,
            release: release[1],
            ready: ready[0],
        };
        let mut poll = libc::pollfd {
            fd: owned.ready,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut poll, 1, 5000) },
            1,
            "fork child did not confirm readiness"
        );
        let mut byte = [0u8];
        assert_eq!(
            unsafe { libc::read(owned.ready, byte.as_mut_ptr().cast(), 1) },
            1
        );
        assert_eq!(byte[0], if drop_guard.is_some() { 2 } else { 1 });
        owned
    }
}
impl Drop for Inherited {
    fn drop(&mut self) {
        unsafe {
            libc::write(self.release, [1u8].as_ptr().cast(), 1);
            let mut status = 0;
            libc::waitpid(self.pid, &mut status, 0);
            libc::close(self.release);
            libc::close(self.ready);
        }
    }
}

#[test]
fn parent_drop_releases_inherited_description_and_new_owner_remains_protected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let fd = store._lock.file.as_raw_fd();
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let child = Inherited::spawn(fd, None, None);
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(store);
    let reopened = Store::open(dir.path())
        .expect("child has not exec'ed or exited, but parent released its ownership");
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    // This child's LOCK_UN affects the old open file description only.
    drop(child);
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(reopened);
    assert!(Store::open(dir.path()).is_ok());
}

#[test]
fn child_guard_drop_cannot_unlock_the_live_parent_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let child = Inherited::spawn(store._lock.file.as_raw_fd(), Some(&store._lock), None);
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(child);
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(store);
    assert!(Store::open(dir.path()).is_ok());
}

#[test]
fn failed_store_parse_releases_lock_even_when_another_fork_holds_its_fd() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let directory = dir.path().to_owned();
    let reader = std::thread::spawn(move || Store::open(&directory));
    // Opening the private FIFO writer rendezvous with Store::open's read. Its
    // library lock is acquired and held until we publish the malformed bytes.
    let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
    let lock = dir.path().join("library.lock");
    let fd = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&lock))
        .unwrap()
        .file_name()
        .to_string_lossy()
        .parse()
        .unwrap();
    let child = Inherited::spawn(fd, None, Some(writer.as_raw_fd()));
    writer.write_all(b"{invalid").unwrap();
    drop(writer);
    // The child closed its inherited FIFO writer before signalling readiness,
    // so malformed input now reaches EOF while its lock FD remains open.
    assert_eq!(
        reader.join().unwrap().err().as_deref(),
        Some("library_corrupt")
    );
    std::fs::remove_file(&path).unwrap();
    let reopened = Store::open(dir.path()).expect("failed open must also release its lock");
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(child);
    assert_eq!(
        Store::open(dir.path()).err().as_deref(),
        Some("library_in_use")
    );
    drop(reopened);
}
