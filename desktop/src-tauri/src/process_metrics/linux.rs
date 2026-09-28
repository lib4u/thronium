//! Linux reads /proc: CPU in clock ticks, memory in resident pages.
use super::shared::*;
use super::*;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Instant,
};

fn parse_stat(data: &[u8], expected_pid: u32) -> Result<Stat, u16> {
    // comm may contain whitespace, non-UTF8 bytes, newlines and parentheses.
    // Only the numeric prefix and suffix are decoded, never the process name.
    let open = data.iter().position(|b| *b == b'(').ok_or(7u16)?;
    let close = data.iter().rposition(|b| *b == b')').ok_or(7u16)?;
    if open >= close {
        return Err(7);
    }
    let pid: u32 = std::str::from_utf8(&data[..open])
        .map_err(|_| 7u16)?
        .trim()
        .parse()
        .map_err(|_| 7u16)?;
    if pid != expected_pid || pid == 0 {
        return Err(7);
    }
    let text = std::str::from_utf8(&data[close + 1..]).map_err(|_| 7u16)?;
    let fields: Vec<_> = text.split_ascii_whitespace().take(22).collect();
    if fields.len() != 22 || fields[0].len() != 1 || !fields[0].as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(7);
    }
    if matches!(fields[0], "Z" | "X" | "x") {
        return Err(5);
    }
    let number = |index: usize| fields[index].parse::<u64>().map_err(|_| 7u16);
    let parent = u32::try_from(number(1)?).map_err(|_| 7u16)?;
    let ticks = number(11)?.checked_add(number(12)?).ok_or(7u16)?;
    let start = number(19)?;
    // rss is signed in the kernel ABI; negative values are not a valid size.
    let rss_pages = fields[21]
        .parse::<i64>()
        .ok()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(7u16)?;
    Ok(Stat {
        identity: Identity { pid, start },
        parent,
        ticks,
        rss_pages,
    })
}
/// One /proc file is never larger than this.
pub(super) const MAX_FILE_BYTES: usize = 64 * 1024;
fn io_reason(error: io::Error) -> u16 {
    match error.kind() {
        io::ErrorKind::NotFound => 5,
        io::ErrorKind::PermissionDenied => 6,
        _ if error.raw_os_error() == Some(libc::ESRCH) => 5,
        _ => 9,
    }
}
struct Proc {
    root: PathBuf,
}
impl Proc {
    fn read(&self, path: &Path, budget: &mut Budget) -> Result<Vec<u8>, u16> {
        budget.available()?;
        budget.files += 1;
        let mut data = Vec::new();
        File::open(path)
            .map_err(io_reason)?
            .take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(io_reason)?;
        budget.bytes = budget.bytes.checked_add(data.len()).ok_or(8u16)?;
        if data.len() > MAX_FILE_BYTES || budget.bytes > MAX_BYTES {
            return Err(8);
        }
        budget.available()?;
        Ok(data)
    }
}
impl ProcSource for Proc {
    fn stat(&self, pid: u32, budget: &mut Budget) -> Result<Stat, u16> {
        parse_stat(
            &self.read(&self.root.join(pid.to_string()).join("stat"), budget)?,
            pid,
        )
    }
    fn children(&self, pid: u32, budget: &mut Budget) -> Result<Vec<u32>, u16> {
        budget.available()?;
        let task = self.root.join(pid.to_string()).join("task");
        let entries = std::fs::read_dir(&task).map_err(io_reason)?;
        let mut children = BTreeSet::new();
        let mut threads = 0;
        for entry in entries {
            budget.thread()?;
            let entry = entry.map_err(io_reason)?;
            let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if tid == 0 {
                return Err(7);
            }
            threads += 1;
            let bytes = self.read(&task.join(tid.to_string()).join("children"), budget)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| 7u16)?;
            for token in text.split_ascii_whitespace() {
                let child = token.parse::<u32>().map_err(|_| 7u16)?;
                if child == 0 || child == pid {
                    return Err(7);
                }
                children.insert(child);
                if children.len() > MAX_PROCESSES {
                    return Err(8);
                }
            }
        }
        if threads == 0 {
            return Err(5);
        }
        Ok(children.into_iter().collect())
    }
}
impl System {
    fn read() -> Option<Self> {
        // sysconf has no side effects; online CPUs deliberately differs from
        // available_parallelism(), which can reflect this process's affinity.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if hz <= 0 || page <= 0 || cpus <= 0 {
            return None;
        }
        Some(Self {
            hz: hz as u64,
            page: page as u64,
            cpus: u32::try_from(cpus).ok()?,
        })
    }
}
#[derive(Default)]
pub(super) struct Sampler(super::shared::Sampler);
impl Sampler {
    /// Call outside the engine lock, preferably on a blocking worker.
    pub(super) fn sample(&mut self, core: Option<OwnedProcess>, reset: bool) -> Snapshot {
        let proc = Proc {
            root: PathBuf::from("/proc"),
        };
        self.0.sample_from(
            &proc,
            std::process::id(),
            core,
            reset,
            Instant::now(),
            System::read(),
        )
    }
    #[cfg(test)]
    fn sample_from(
        &mut self,
        source: &impl ProcSource,
        app_pid: u32,
        core: Option<OwnedProcess>,
        reset: bool,
        now: Instant,
        system: Option<System>,
    ) -> Snapshot {
        self.0
            .sample_from(source, app_pid, core, reset, now, system)
    }
}

#[cfg(test)]
mod tests;
