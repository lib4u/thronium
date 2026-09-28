//! Opt-in periodic checks of favourite servers: one bounded batch per interval
//! through the shared queue, never beside a manual measurement, stopped the
//! moment the option is switched off. Nothing runs until the user enables it.
use super::{Kind, Run, Source};
use crate::{settings, Engine};

pub const ENABLED: &str = "periodic_tests_enabled";
pub const INTERVAL_MINUTES: &str = "periodic_tests_interval_min";
pub const KIND: &str = "periodic_tests_kind";

pub(crate) fn settings_changed(
    before: &crate::store::Library,
    after: &crate::store::Library,
) -> bool {
    [ENABLED, INTERVAL_MINUTES, KIND]
        .iter()
        .any(|key| settings::value(before, key) != settings::value(after, key))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Options {
    interval: u64,
    kind: Kind,
}

#[derive(Default)]
pub struct Schedule {
    options: Option<Options>,
    /// Seconds since the epoch when the schedule was armed or a batch started.
    armed_at: Option<u64>,
    /// Where the next batch starts in the favorites list when it exceeds one batch.
    next: usize,
}

impl Engine {
    /// Called by the host on its slow tick with the current time in seconds.
    /// Returns the run to drive when a periodic batch is due and the queue is
    /// free; a busy queue simply defers to the next tick.
    pub fn periodic_probe_tick(&mut self, now: u64) -> Option<Run> {
        let library = &self.store.library;
        if !settings::boolean(library, ENABLED) {
            self.cancel_periodic_probes();
            self.probes.periodic = Schedule::default();
            return None;
        }
        let interval = u64::try_from(settings::integer(library, INTERVAL_MINUTES))
            .unwrap_or(0)
            .max(1)
            * 60;
        let kind = match settings::string(library, KIND).as_str() {
            "ip" => Kind::Ip,
            "speed" => Kind::Speed,
            _ => Kind::Latency,
        };
        let options = Options { interval, kind };
        if self.probes.periodic.options != Some(options) {
            // Consent to one measurement must not continue a previously selected
            // speed batch. Re-arm only for schedule edits, not other settings.
            self.cancel_periodic_probes();
            self.probes.periodic = Schedule {
                options: Some(options),
                armed_at: Some(now),
                next: 0,
            };
            return None;
        }
        // The first check runs one interval after enabling: no burst at start.
        let armed = *self.probes.periodic.armed_at.get_or_insert(now);
        if now < armed {
            self.probes.periodic.armed_at = Some(now);
            return None;
        }
        if now < armed.saturating_add(interval) {
            return None;
        }
        if !self.probe_queue_free() {
            return None;
        }
        let favorites: Vec<&String> = self
            .store
            .library
            .profiles
            .iter()
            .filter(|p| p.favorite)
            .map(|p| &p.id)
            .collect();
        self.probes.periodic.armed_at = Some(now);
        if favorites.is_empty() {
            return None;
        }
        // One batch holds at most MAX_BATCH servers: a longer favorites list is
        // checked in turn, one slice per interval, so every favorite is measured.
        let start = self.probes.periodic.next % favorites.len();
        let ids: Vec<String> = favorites
            .iter()
            .cycle()
            .skip(start)
            .take(favorites.len().min(super::MAX_BATCH))
            .map(|id| (*id).clone())
            .collect();
        self.probes.periodic.next = start + ids.len();
        match self.start_profile_tests_from(ids, kind, Source::Periodic) {
            Ok(run) => Some(run),
            Err(error) => {
                self.logs.event("warn", &error, None);
                None
            }
        }
    }

    /// Called after a successful settings commit, so Stop takes effect without
    /// waiting for the host's slow scheduler tick. Never cancel a manual batch.
    pub(crate) fn reset_periodic_probes(&mut self) {
        self.cancel_periodic_probes();
        self.probes.periodic = Schedule::default();
    }

    pub(crate) fn cancel_periodic_probes(&mut self) {
        let periodic_running = self.probes.batch.as_ref().is_some_and(|batch| {
            batch.source == Source::Periodic
                && batch.entries.iter().any(|entry| entry.status.active())
        });
        if periodic_running {
            self.cancel_url_tests();
        }
    }
}
