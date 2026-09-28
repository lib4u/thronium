//! Loopback ports for the generated inbounds of this process's cores. A port
//! is found by binding port 0, and the caller releases it before the core
//! binds it. Ports handed out recently are remembered, so concurrent builds —
//! a probe batch starts many one-shot cores — never receive the same port
//! while an earlier one is still waiting for its core to start.
use std::{
    collections::HashSet,
    net::TcpListener,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Longer than preparing and starting a one-shot core takes.
const HOLD: Duration = Duration::from_secs(60);
static RECENT: Mutex<Vec<(u16, Instant)>> = Mutex::new(Vec::new());

/// A free port outside `used` and outside recently claimed ports, with the
/// listener that keeps it bound until the caller drops it.
pub(crate) fn claim(used: &HashSet<u16>) -> Option<(u16, TcpListener)> {
    let mut recent = RECENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    recent.retain(|(_, at)| now.duration_since(*at) < HOLD);
    // Rejected ports stay bound until a free one is found, so the OS offers
    // a different port on every attempt.
    let mut rejected = Vec::new();
    for _ in 0..100 {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        if used.contains(&port) || recent.iter().any(|(p, _)| *p == port) {
            rejected.push(listener);
            continue;
        }
        recent.push((port, now));
        return Some((port, listener));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_released_at_once_are_not_handed_out_again() {
        let mut seen = HashSet::new();
        for _ in 0..300 {
            let (port, listener) = claim(&HashSet::new()).unwrap();
            drop(listener);
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
        let (taken, _guard) = claim(&HashSet::new()).unwrap();
        let used = HashSet::from([taken]);
        assert_ne!(claim(&used).unwrap().0, taken);
    }
}
