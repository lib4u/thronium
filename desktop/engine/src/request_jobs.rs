//! A feature runs one cancellable request at a time. Request ids are bounded
//! and single-use: a finished or cancelled id never starts again, so a late
//! Start cannot bring back work the window already cancelled.
use std::{collections::VecDeque, marker::PhantomData};
use tokio::sync::watch;

/// The error codes one feature reports for its requests.
pub trait Codes {
    const INVALID: &'static str;
    const FINISHED: &'static str;
    const BUSY: &'static str;
}

/// Finished ids kept to refuse late starts; older ids are forgotten.
const REMEMBERED: usize = 128;

pub struct Jobs<C: Codes> {
    active: Option<(String, watch::Sender<bool>)>,
    consumed: VecDeque<String>,
    codes: PhantomData<C>,
}
impl<C: Codes> Default for Jobs<C> {
    fn default() -> Self {
        Self {
            active: None,
            consumed: VecDeque::new(),
            codes: PhantomData,
        }
    }
}
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
impl<C: Codes> Jobs<C> {
    pub fn begin(&mut self, id: &str) -> Result<watch::Receiver<bool>, String> {
        if !valid_id(id) {
            return Err(C::INVALID.into());
        }
        if self.consumed.iter().any(|old| old == id) {
            return Err(C::FINISHED.into());
        }
        if self.active.is_some() {
            return Err(C::BUSY.into());
        }
        let (send, receive) = watch::channel(false);
        self.active = Some((id.into(), send));
        Ok(receive)
    }
    fn remember(&mut self, id: &str) {
        if !self.consumed.iter().any(|old| old == id) {
            self.consumed.push_back(id.into());
            if self.consumed.len() > REMEMBERED {
                self.consumed.pop_front();
            }
        }
    }
    /// A cancellation can arrive before its Start; that Start is then refused.
    pub fn cancel(&mut self, id: &str) -> Result<(), String> {
        if !valid_id(id) {
            return Err(C::INVALID.into());
        }
        if let Some((active, send)) = &self.active {
            if active == id {
                let _ = send.send(true);
            }
        }
        self.remember(id);
        Ok(())
    }
    /// Application exit: cancel the current request without allowing its id again.
    pub fn cancel_all(&mut self) {
        if let Some((id, send)) = &self.active {
            let id = id.clone();
            let _ = send.send(true);
            self.remember(&id);
        }
    }
    pub fn finish(&mut self, id: &str) {
        if self.active.as_ref().is_some_and(|(active, _)| active == id) {
            self.active.take();
            self.remember(id);
        }
    }
    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Test;
    impl Codes for Test {
        const INVALID: &'static str = "test_invalid_request";
        const FINISHED: &'static str = "test_request_finished";
        const BUSY: &'static str = "test_busy";
    }
    #[test]
    fn cancelled_before_dispatch_duplicate_busy_and_completed_requests_are_bounded() {
        let mut jobs = Jobs::<Test>::default();
        jobs.cancel("before").unwrap();
        assert_eq!(
            jobs.begin("before").err().as_deref(),
            Some("test_request_finished")
        );
        let rx = jobs.begin("active").unwrap();
        assert_eq!(jobs.begin("second").err().as_deref(), Some("test_busy"));
        jobs.cancel("unrelated").unwrap();
        assert!(!*rx.borrow());
        jobs.cancel("active").unwrap();
        assert!(*rx.borrow());
        jobs.finish("wrong");
        assert!(jobs.begin("second").is_err());
        jobs.finish("active");
        assert!(jobs.begin("active").is_err());
        jobs.begin("second").unwrap();
        jobs.finish("second");
        for n in 0..300 {
            jobs.cancel(&format!("done-{n}")).unwrap();
        }
        assert_eq!(jobs.consumed.len(), REMEMBERED);
        for bad in ["", "bad/id", "spaces not accepted", "ключ"] {
            assert_eq!(
                jobs.begin(bad).err().as_deref(),
                Some("test_invalid_request")
            );
            assert!(jobs.cancel(bad).is_err());
        }
    }
    #[test]
    fn exit_cancels_the_running_request_and_refuses_its_late_restart() {
        let mut jobs = Jobs::<Test>::default();
        jobs.cancel_all();
        let rx = jobs.begin("running").unwrap();
        jobs.cancel_all();
        assert!(*rx.borrow());
        jobs.finish("running");
        assert!(!jobs.is_active());
        assert_eq!(
            jobs.begin("running").err().as_deref(),
            Some("test_request_finished")
        );
    }
}
