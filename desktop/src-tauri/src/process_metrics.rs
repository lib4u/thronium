//! Read-only, bounded process-tree estimates for this app and its owned core.
//!
//! Linux /proc fields and limitations:
//! https://www.kernel.org/doc/html/latest/filesystems/proc.html
//! CPU uses utime+stime (not waited-child times) and monotonic elapsed time,
//! normalized by online logical CPUs. RSS sums process resident pages: shared
//! pages may be counted repeatedly and the kernel RSS counters are approximate.
//! The children interface can miss processes during concurrent exit; detected
//! races are partial, and membership changes reset the rate baseline. Processes
//! are never stopped to take a snapshot. No names, command lines, or arbitrary
//! frontend PIDs are used, returned, or logged.
use serde::Serialize;
use thronium_engine::transport::OwnedProcess;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Partial,
    Unavailable,
    Inactive,
}

/// Stable, non-sensitive reason codes: 1 first sample, 2 reset, 3 gap,
/// 4 identity changed, 5 missing process, 6 permission denied, 7 malformed data,
/// 8 scan bound, 9 unavailable system backend, 10 uncaptured owned identity,
/// 11 counter reset, 12 interval below 100 ms, 13 changed process membership.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub status: Status,
    pub cpu_percent: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub processes: u32,
    pub reason: Option<u16>,
}
impl Usage {
    fn inactive() -> Self {
        Self {
            status: Status::Inactive,
            cpu_percent: None,
            rss_bytes: None,
            processes: 0,
            reason: None,
        }
    }
    fn unavailable(reason: u16) -> Self {
        Self {
            status: Status::Unavailable,
            cpu_percent: None,
            rss_bytes: None,
            processes: 0,
            reason: Some(reason),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub supported: bool,
    pub logical_cpus: Option<u32>,
    pub interval_ms: Option<u64>,
    pub core_instance: Option<String>,
    pub app: Usage,
    pub core: Usage,
}

#[derive(Default)]
pub struct Sampler {
    #[cfg(target_os = "linux")]
    inner: linux::Sampler,
    #[cfg(target_os = "windows")]
    inner: windows::Sampler,
}
impl Sampler {
    /// Call outside the engine lock, preferably on a blocking worker. Sampling
    /// state should be protected by its own mutex; this never mutates Engine.
    pub fn sample(&mut self, core: Option<OwnedProcess>, reset: bool) -> Snapshot {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            self.inner.sample(core, reset)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = reset;
            Snapshot {
                supported: false,
                logical_cpus: None,
                interval_ms: None,
                core_instance: core.map(|p| p.instance.to_string()),
                app: Usage::unavailable(9),
                core: if core.is_some() {
                    Usage::unavailable(9)
                } else {
                    Usage::inactive()
                },
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux;
mod shared;
#[cfg(any(target_os = "windows", test))]
mod windows;
