//! Windows process metrics: a Toolhelp snapshot gives the tree, process handles
//! give the numbers.
//!
//! The shared scan works in ticks and memory units, so this platform declares
//! its own: CPU time arrives in 100-nanosecond intervals (ten million to the
//! second) and memory in plain bytes. Identity is the process creation time,
//! which is what makes a reused PID recognisable. No process is ever stopped,
//! opened for writing, or named: only counters are read.

/// The two halves of a FILETIME as the single counter the scan compares.
#[cfg(any(windows, test))]
fn units(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// Stable reasons, the same ones /proc failures map to: 5 missing process,
/// 6 permission denied, 9 the backend itself is unavailable.
#[cfg(any(windows, test))]
fn reason(code: u32) -> u16 {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_INVALID_PARAMETER => 5,
        ERROR_ACCESS_DENIED => 6,
        _ => 9,
    }
}

#[cfg(windows)]
pub(super) use api::Sampler;

#[cfg(windows)]
mod api {
    use super::super::shared::*;
    use super::super::*;
    use super::{reason, units};
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Ten million 100-nanosecond intervals make a second; memory is already
    /// counted in bytes, so one unit is one byte.
    impl System {
        pub(in super::super) fn read() -> Option<Self> {
            let mut info = SYSTEM_INFO::default();
            unsafe { GetSystemInfo(&mut info) };
            let cpus = info.dwNumberOfProcessors;
            (cpus > 0).then_some(Self {
                hz: 10_000_000,
                page: 1,
                cpus,
            })
        }
    }

    /// A handle that closes itself, so no scan can leak one.
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: u32) -> Result<Owned, u16> {
        // Query-limited access is enough for times and memory, and it is the
        // access a plain user has to its own processes.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(reason(unsafe { GetLastError() }));
        }
        Ok(Owned(handle))
    }

    /// One walk over the process list, bounded like every other scan step.
    fn snapshot(budget: &mut Budget) -> Result<Vec<(u32, u32)>, u16> {
        budget.available()?;
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(reason(unsafe { GetLastError() }));
        }
        let handle = Owned(handle);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut processes = Vec::new();
        let mut more = unsafe { Process32FirstW(handle.0, &mut entry) };
        while more != 0 {
            budget.thread()?;
            processes.push((entry.th32ProcessID, entry.th32ParentProcessID));
            if processes.len() > MAX_PROCESSES * 4 {
                return Err(8);
            }
            more = unsafe { Process32NextW(handle.0, &mut entry) };
        }
        if processes.is_empty() {
            return Err(9);
        }
        Ok(processes)
    }

    pub(in super::super) struct Win32;

    impl ProcSource for Win32 {
        fn stat(&self, pid: u32, budget: &mut Budget) -> Result<Stat, u16> {
            budget.available()?;
            let parent = snapshot(budget)?
                .into_iter()
                .find_map(|(id, parent)| (id == pid).then_some(parent))
                .ok_or(5u16)?;
            let process = open(pid)?;
            let (mut created, mut exited, mut kernel, mut user) = Default::default();
            let ok = unsafe {
                GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user)
            };
            if ok == 0 {
                return Err(reason(unsafe { GetLastError() }));
            }
            let mut memory = PROCESS_MEMORY_COUNTERS::default();
            let ok = unsafe {
                K32GetProcessMemoryInfo(
                    process.0,
                    &mut memory,
                    std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                )
            };
            if ok == 0 {
                return Err(reason(unsafe { GetLastError() }));
            }
            let start = units(created.dwHighDateTime, created.dwLowDateTime);
            if start == 0 {
                return Err(7);
            }
            let ticks = units(kernel.dwHighDateTime, kernel.dwLowDateTime)
                .checked_add(units(user.dwHighDateTime, user.dwLowDateTime))
                .ok_or(7u16)?;
            Ok(Stat {
                identity: Identity { pid, start },
                parent,
                ticks,
                rss_pages: memory.WorkingSetSize as u64,
            })
        }
        fn children(&self, pid: u32, budget: &mut Budget) -> Result<Vec<u32>, u16> {
            let mut children: Vec<u32> = snapshot(budget)?
                .into_iter()
                .filter(|(id, parent)| *parent == pid && *id != pid && *id != 0)
                .map(|(id, _)| id)
                .collect();
            children.sort_unstable();
            children.dedup();
            if children.len() > MAX_PROCESSES {
                return Err(8);
            }
            Ok(children)
        }
    }

    #[derive(Default)]
    pub(in super::super) struct Sampler(Sampler0);
    type Sampler0 = super::super::shared::Sampler;
    impl Sampler {
        pub(in super::super) fn sample(
            &mut self,
            core: Option<OwnedProcess>,
            reset: bool,
        ) -> Snapshot {
            self.0.sample_from(
                &Win32,
                std::process::id(),
                core,
                reset,
                Instant::now(),
                System::read(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_creation_time_becomes_one_counter_and_survives_the_high_half() {
        assert_eq!(super::units(0, 0), 0);
        assert_eq!(super::units(0, 7), 7);
        assert_eq!(super::units(1, 0), 1 << 32);
        assert_eq!(super::units(u32::MAX, u32::MAX), u64::MAX);
        // Two processes started in the same second differ in the low half.
        assert!(super::units(31, 100) < super::units(31, 200));
    }

    #[test]
    fn windows_failures_map_to_the_same_reasons_as_proc_failures() {
        assert_eq!(super::reason(2), 5);
        assert_eq!(super::reason(87), 5);
        assert_eq!(super::reason(5), 6);
        assert_eq!(super::reason(1450), 9);
    }
}
