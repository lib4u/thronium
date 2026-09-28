//! What every platform's process metrics share: the bounded scan, the process
//! tree it walks, and the rate it reports.
//!
//! A platform supplies only a source of per-process samples. Its units are
//! declared in `System`: `hz` is how many CPU ticks make a second and `page`
//! how many bytes one memory unit holds, so Linux passes clock ticks and pages
//! while Windows passes 100-nanosecond intervals and plain bytes.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

pub(super) const MAX_PROCESSES: usize = 1024;
pub(super) const MAX_THREADS: usize = 8192;
pub(super) const MAX_FILES: usize = 20_000;
pub(super) const MAX_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_SCAN: Duration = Duration::from_millis(200);
pub(super) const MAX_GAP: Duration = Duration::from_secs(3);
pub(super) const MIN_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) start: u64,
}
#[derive(Clone, Debug)]
pub(super) struct Stat {
    pub(super) identity: Identity,
    pub(super) parent: u32,
    pub(super) ticks: u64,
    pub(super) rss_pages: u64,
}

pub(super) struct Budget {
    pub(super) started: Instant,
    pub(super) files: usize,
    pub(super) threads: usize,
    pub(super) processes: usize,
    pub(super) bytes: usize,
}
impl Budget {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            files: 0,
            threads: 0,
            processes: 0,
            bytes: 0,
        }
    }
    pub(super) fn available(&self) -> Result<(), u16> {
        if self.started.elapsed() > MAX_SCAN || self.files >= MAX_FILES || self.bytes > MAX_BYTES {
            Err(8)
        } else {
            Ok(())
        }
    }
    pub(super) fn process(&mut self) -> Result<(), u16> {
        self.available()?;
        if self.processes >= MAX_PROCESSES {
            return Err(8);
        }
        self.processes += 1;
        Ok(())
    }
    pub(super) fn thread(&mut self) -> Result<(), u16> {
        self.available()?;
        if self.threads >= MAX_THREADS {
            return Err(8);
        }
        self.threads += 1;
        Ok(())
    }
}
pub(super) trait ProcSource {
    fn stat(&self, pid: u32, budget: &mut Budget) -> Result<Stat, u16>;
    fn children(&self, pid: u32, budget: &mut Budget) -> Result<Vec<u32>, u16>;
}
#[derive(Default)]
pub(super) struct Tree {
    pub(super) entries: BTreeMap<Identity, Stat>,
    pub(super) root_valid: bool,
    pub(super) reason: Option<u16>,
}
impl Tree {
    pub(super) fn fail(&mut self, reason: u16) {
        // Preserve the first concrete cause; scan bounds override lesser races.
        if self.reason.is_none() || reason == 8 {
            self.reason = Some(reason);
        }
    }
}
pub(super) fn collect(
    source: &impl ProcSource,
    root: u32,
    expected_start: Option<u64>,
    excluded: Option<u32>,
) -> Tree {
    let mut tree = Tree::default();
    let mut budget = Budget::new();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([(root, expected_start, None::<Identity>)]);
    while let Some((pid, start, parent)) = queue.pop_front() {
        if Some(pid) == excluded || !seen.insert(pid) {
            continue;
        }
        if let Err(reason) = budget.process() {
            tree.fail(reason);
            break;
        }
        let before = match source.stat(pid, &mut budget) {
            Ok(value) => value,
            Err(reason) => {
                tree.fail(reason);
                continue;
            }
        };
        if start.is_some_and(|s| s != before.identity.start)
            || parent.is_some_and(|p| before.parent != p.pid || before.identity.start < p.start)
        {
            tree.fail(4);
            continue;
        }
        let children = source.children(pid, &mut budget);
        // Verify identity and parent again after reading the thread children
        // lists; a reused/reparented PID must not lend us its descendants.
        let after = match source.stat(pid, &mut budget) {
            Ok(value) => value,
            Err(reason) => {
                tree.fail(reason);
                continue;
            }
        };
        if before.identity != after.identity || before.parent != after.parent {
            tree.fail(4);
            continue;
        }
        if pid == root {
            tree.root_valid = true;
        }
        let identity = after.identity;
        tree.entries.insert(identity, after);
        match children {
            Ok(children) => {
                for child in children {
                    if queue.len() + seen.len() >= MAX_PROCESSES {
                        tree.fail(8);
                        break;
                    }
                    if !seen.contains(&child) && Some(child) != excluded {
                        queue.push_back((child, None, Some(identity)));
                    }
                }
            }
            Err(reason) => tree.fail(reason),
        }
        if tree.reason == Some(8) {
            break;
        }
    }
    // Descendant traversal can outlive the root. Recheck ownership at its
    // end, so an exited or reused root cannot leave an apparently valid sum.
    if tree.root_valid {
        let original = tree
            .entries
            .values()
            .find(|stat| stat.identity.pid == root)
            .cloned();
        match (original, source.stat(root, &mut budget)) {
            (Some(before), Ok(after))
                if before.identity == after.identity && before.parent == after.parent => {}
            (_, Err(reason)) => {
                tree.root_valid = false;
                tree.fail(reason);
            }
            _ => {
                tree.root_valid = false;
                tree.fail(4);
            }
        }
    }
    tree
}
#[derive(Clone, Copy)]
pub(super) struct System {
    pub(super) hz: u64,
    pub(super) page: u64,
    pub(super) cpus: u32,
}
pub(super) struct Baseline {
    pub(super) at: Instant,
    pub(super) cpus: u32,
    pub(super) ticks: BTreeMap<Identity, u64>,
}
pub(super) fn usage(
    tree: Tree,
    baseline: &mut Option<Baseline>,
    now: Instant,
    system: System,
    reset_reason: Option<u16>,
) -> Usage {
    if !tree.root_valid {
        *baseline = None;
        return Usage::unavailable(tree.reason.unwrap_or(5));
    }
    let Some(rss) = tree.entries.values().try_fold(0u64, |sum, p| {
        sum.checked_add(p.rss_pages.checked_mul(system.page)?)
    }) else {
        *baseline = None;
        return Usage::unavailable(7);
    };
    let ticks: BTreeMap<_, _> = tree.entries.iter().map(|(id, p)| (*id, p.ticks)).collect();
    let mut reason = tree.reason.or(reset_reason);
    let mut cpu = None;
    if reason.is_none() {
        if let Some(previous) = baseline.as_ref() {
            let elapsed = now.saturating_duration_since(previous.at);
            if previous.cpus != system.cpus {
                reason = Some(4);
            } else if elapsed > MAX_GAP {
                reason = Some(3);
            } else if elapsed < MIN_INTERVAL {
                reason = Some(12);
            } else if !previous.ticks.keys().eq(ticks.keys()) {
                reason = Some(13);
            } else if let Some(delta) = ticks.iter().try_fold(0u64, |sum, (id, value)| {
                sum.checked_add(value.checked_sub(previous.ticks[id])?)
            }) {
                let percent = 100.0 * delta as f64
                    / system.hz as f64
                    / elapsed.as_secs_f64()
                    / system.cpus as f64;
                if percent.is_finite() {
                    cpu = Some(percent.clamp(0.0, 100.0));
                } else {
                    reason = Some(7);
                }
            } else {
                reason = Some(11);
            }
        } else {
            reason = Some(1);
        }
    }
    *baseline = if tree.reason.is_none() {
        Some(Baseline {
            at: now,
            cpus: system.cpus,
            ticks,
        })
    } else {
        None
    };
    Usage {
        status: if tree.reason.is_some() {
            Status::Partial
        } else {
            Status::Ok
        },
        cpu_percent: cpu,
        rss_bytes: Some(rss),
        processes: tree.entries.len() as u32,
        reason,
    }
}
#[derive(Default)]
pub(super) struct Sampler {
    pub(super) app: Option<Baseline>,
    pub(super) core: Option<Baseline>,
    pub(super) last: Option<Instant>,
    pub(super) core_identity: Option<OwnedProcess>,
}
impl Sampler {
    pub(super) fn sample_from(
        &mut self,
        source: &impl ProcSource,
        app_pid: u32,
        core: Option<OwnedProcess>,
        reset: bool,
        now: Instant,
        system: Option<System>,
    ) -> Snapshot {
        let interval = self.last.map(|old| now.saturating_duration_since(old));
        self.last = Some(now);
        let mut snapshot = Snapshot {
            supported: true,
            logical_cpus: system.map(|s| s.cpus),
            interval_ms: interval.map(|d| d.as_millis().min(u64::MAX as u128) as u64),
            core_instance: core.map(|p| p.instance.to_string()),
            app: Usage::unavailable(9),
            core: Usage::inactive(),
        };
        let changed = self.core_identity != core;
        self.core_identity = core;
        let Some(system) = system else {
            self.app = None;
            self.core = None;
            if core.is_some() {
                snapshot.core = Usage::unavailable(9);
            }
            return snapshot;
        };
        let reset_reason = if reset {
            Some(2)
        } else if interval.is_some_and(|d| d > MAX_GAP) {
            Some(3)
        } else {
            None
        };
        if reset_reason.is_some() {
            self.app = None;
            self.core = None;
        }
        // Exclude the owned numeric root before reading it. Even if privilege
        // or PID reuse prevents attribution, its subtree never becomes app RAM.
        let app = collect(source, app_pid, None, core.map(|p| p.pid));
        snapshot.app = usage(app, &mut self.app, now, system, reset_reason);
        if changed {
            self.core = None;
        }
        snapshot.core = match core {
            None => {
                self.core = None;
                Usage::inactive()
            }
            Some(owned) => match owned.start_time {
                None => {
                    self.core = None;
                    Usage::unavailable(10)
                }
                Some(start) if owned.pid != app_pid => usage(
                    collect(source, owned.pid, Some(start), None),
                    &mut self.core,
                    now,
                    system,
                    reset_reason.or(if changed { Some(4) } else { None }),
                ),
                Some(_) => {
                    self.core = None;
                    Usage::unavailable(10)
                }
            },
        };
        snapshot
    }
}
