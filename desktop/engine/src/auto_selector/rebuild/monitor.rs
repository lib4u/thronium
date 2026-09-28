//! Pure monotonic exhaustion gate; RPC failures and missing samples break grace.
/// How long a pool stays exhausted before its failed servers are rechecked.
pub const GRACE_MS: u64 = 20_000;
const MAX_SAMPLE_GAP_MS: u64 = 15_000;
pub const MAX_ATTEMPTS: u8 = 3;
/// Pause after the first automatic attempt; it doubles after each later one.
pub const FIRST_RETRY_MS: u64 = 60_000;
pub(super) fn retry_delay_ms(attempts: u8) -> u64 {
    FIRST_RETRY_MS << attempts.saturating_sub(1)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Observation {
    Healthy,
    Unknown,
    Exhausted,
}
#[derive(Clone, Debug, Default)]
pub(super) struct Monitor {
    since: Option<u64>,
    last_sample: Option<u64>,
    last_attempt: Option<u64>,
    pub attempts: u8,
    pub cancelled: bool,
}
impl Monitor {
    pub fn observe(&mut self, now: u64, observation: Observation) -> bool {
        if self
            .last_sample
            .is_some_and(|last| now < last || now - last > MAX_SAMPLE_GAP_MS)
        {
            self.since = None;
        }
        self.last_sample = Some(now);
        match observation {
            Observation::Healthy => {
                self.since = None;
                self.attempts = 0;
                self.last_attempt = None;
                false
            }
            Observation::Unknown => {
                self.since = None;
                false
            }
            Observation::Exhausted => {
                let since = *self.since.get_or_insert(now);
                !self.cancelled
                    && self.attempts < MAX_ATTEMPTS
                    && now.saturating_sub(since) >= GRACE_MS
                    && self.last_attempt.is_none_or(|last| {
                        now.saturating_sub(last) >= retry_delay_ms(self.attempts)
                    })
            }
        }
    }
    pub fn attempted(&mut self, now: u64) {
        self.last_attempt = Some(now);
        self.attempts = self.attempts.saturating_add(1).min(MAX_ATTEMPTS);
        self.since = None;
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.since = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tick(m: &mut Monitor, from: u64, to: u64, obs: Observation) -> Vec<u64> {
        (from..=to)
            .step_by(5_000)
            .filter(|now| m.observe(*now, obs))
            .collect()
    }
    #[test]
    fn waits_twenty_continuous_seconds_before_first_attempt() {
        let mut m = Monitor::default();
        assert_eq!(
            tick(&mut m, 0, 20_000, Observation::Exhausted),
            vec![20_000]
        );
        assert_eq!(m.attempts, 0); // Observation alone never consumes a retry.
        m.attempted(20_000);
        assert_eq!(m.attempts, 1);
    }
    #[test]
    fn unknown_suspended_and_network_failures_break_grace_without_consuming_retry() {
        let mut m = Monitor::default();
        assert!(tick(&mut m, 0, 15_000, Observation::Exhausted).is_empty());
        assert!(!m.observe(20_000, Observation::Unknown));
        assert_eq!(
            tick(&mut m, 25_000, 45_000, Observation::Exhausted),
            vec![45_000]
        );
        assert_eq!(m.attempts, 0);
    }
    #[test]
    fn scheduling_gap_and_clock_reversal_require_new_continuous_grace() {
        let mut m = Monitor::default();
        tick(&mut m, 0, 15_000, Observation::Exhausted);
        assert!(!m.observe(40_000, Observation::Exhausted));
        assert_eq!(
            tick(&mut m, 45_000, 60_000, Observation::Exhausted),
            vec![60_000]
        );
        assert!(!m.observe(1_000, Observation::Exhausted));
        assert_eq!(
            tick(&mut m, 6_000, 21_000, Observation::Exhausted),
            vec![21_000]
        );
    }
    #[test]
    fn three_attempts_are_spaced_and_then_pause_until_recovery() {
        let mut m = Monitor::default();
        tick(&mut m, 0, 20_000, Observation::Exhausted);
        m.attempted(20_000);
        assert_eq!(
            tick(&mut m, 25_000, 80_000, Observation::Exhausted),
            vec![80_000]
        );
        m.attempted(80_000);
        assert_eq!(
            tick(&mut m, 85_000, 200_000, Observation::Exhausted),
            vec![200_000]
        );
        m.attempted(200_000);
        assert!(tick(&mut m, 205_000, 1_000_000, Observation::Exhausted).is_empty());
        assert_eq!(m.attempts, 3);
        assert!(!m.observe(1_005_000, Observation::Healthy));
        assert_eq!(m.attempts, 0);
        assert_eq!(
            tick(&mut m, 1_010_000, 1_030_000, Observation::Exhausted),
            vec![1_030_000]
        );
    }
    #[test]
    fn cancellation_survives_health_changes_until_a_new_monitor_is_created() {
        let mut m = Monitor::default();
        m.cancel();
        assert!(tick(&mut m, 0, 30_000, Observation::Exhausted).is_empty());
        m.observe(35_000, Observation::Healthy);
        assert!(tick(&mut m, 40_000, 80_000, Observation::Exhausted).is_empty());
        assert!(m.cancelled);
    }
    #[test]
    fn cloned_monitor_retains_backoff_across_an_automatic_connection() {
        let mut m = Monitor::default();
        tick(&mut m, 0, 20_000, Observation::Exhausted);
        m.attempted(20_000);
        let mut successor = m.clone();
        assert_eq!(
            tick(&mut successor, 25_000, 80_000, Observation::Exhausted),
            vec![80_000]
        );
        assert_eq!(successor.attempts, 1);
    }
}
