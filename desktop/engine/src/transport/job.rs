//! Windows: the core and every process it starts belong to a job object that
//! only this process holds and that kills its members when closed. A crashed
//! window therefore never leaves a core running; what a TUN session changed
//! is restored by the service from its journal, not by the core on the way out.
use std::os::windows::io::RawHandle;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub(crate) struct Job(HANDLE);
// The handle is owned and only passed to the kernel.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}
impl Drop for Job {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Puts the process into a new killing job. A process that is already in a
/// job that forbids nesting cannot be moved; it keeps kill_on_drop only.
pub(crate) fn contain(process: RawHandle) -> Option<Job> {
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return None;
    }
    let job = Job(job);
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let limited = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    (limited != 0 && unsafe { AssignProcessToJobObject(job.0, process as HANDLE) } != 0)
        .then_some(job)
}

pub(crate) fn contain_child(child: &tokio::process::Child) -> Option<Job> {
    child.raw_handle().and_then(contain)
}

pub(crate) fn start_time(pid: u32) -> Option<u64> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    let ok = unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
    unsafe { CloseHandle(process) };
    (ok != 0).then(|| u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle;
    #[test]
    fn closing_the_job_ends_the_process_and_start_time_names_it() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 60 127.0.0.1 >NUL"])
            .spawn()
            .unwrap();
        let started = super::start_time(child.id()).expect("creation time");
        assert_eq!(super::start_time(child.id()), Some(started));
        let job = super::contain(child.as_raw_handle()).expect("job");
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "process outlived its job"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
