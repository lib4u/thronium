//! One owner of diagnostic capacity. A batch in flight and a single test never
//! run together: both spawn disposable cores, and a speed sample saturates the
//! link. The host registry only tracks cancellation; the queue decides admission.
use super::*;

#[derive(Default)]
pub(crate) struct Singles {
    active: Vec<String>,
}

impl Engine {
    pub(crate) fn batch_active(&self) -> bool {
        self.probes
            .batch
            .as_ref()
            .is_some_and(|b| b.entries.iter().any(|e| e.status.active()))
    }
    pub(crate) fn singles_active(&self) -> bool {
        !self.probes.singles.active.is_empty()
    }
    /// Background work (periodic checks, pool rebuilds) starts only when no
    /// batch, single diagnostic or VPN probe holds the queue, so it never spends
    /// an attempt on a certain `probe_busy`.
    pub(crate) fn probe_queue_free(&self) -> bool {
        !self.batch_active() && !self.singles_active() && self.vpn_probe_guard().is_ok()
    }
    /// A single diagnostic (exit IP or speed) takes the queue for its run.
    pub fn reserve_probe(&mut self, id: &str) -> Result<(), String> {
        if self.batch_active() || self.singles_active() {
            return Err("probe_busy".into());
        }
        self.probes.singles.active.push(id.to_owned());
        Ok(())
    }
    pub fn release_probe(&mut self, id: &str) {
        self.probes.singles.active.retain(|active| active != id);
    }
}
