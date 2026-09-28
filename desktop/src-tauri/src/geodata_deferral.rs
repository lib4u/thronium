//! Engine commands whose asset downloads must not hold the Engine lock (S6).
//! Under the lock a command only reads the asset cache; a needed download is
//! reported, runs here unlocked and cancellable, and the command is repeated:
//!
//! ```ignore
//! let mut deferred = Deferred::new(&shared);
//! loop {
//!     let mut guard = deferred.lock().await?;
//!     let result = command(guard.as_mut()?).await;
//!     if let Some(result) = deferred.finish(guard, result).await {
//!         return result;
//!     }
//! }
//! ```
use crate::Shared;
use std::sync::atomic::Ordering;
use thronium_engine::{
    geodata_deferral::{DOWNLOAD_REQUIRED, MAX_DOWNLOADS},
    Engine,
};
use tokio::sync::{watch, MutexGuard};

type Guard<'s> = MutexGuard<'s, Result<Engine, String>>;

pub(crate) struct Deferred<'s> {
    shared: &'s Shared,
    downloads: usize,
    cancelled: Option<watch::Receiver<bool>>,
    downloading: Box<dyn FnMut(bool) + Send + Sync + 's>,
}

impl<'s> Deferred<'s> {
    pub(crate) fn new(shared: &'s Shared) -> Self {
        Self {
            shared,
            downloads: 0,
            cancelled: None,
            downloading: Box::new(|_| {}),
        }
    }
    /// A download stops when `cancelled` becomes true; `downloading` is told
    /// when one starts (`true`) and ends (`false`), so a job can be cancellable
    /// only while nothing is committed.
    pub(crate) fn cancellable(
        mut self,
        cancelled: watch::Receiver<bool>,
        downloading: impl FnMut(bool) + Send + Sync + 's,
    ) -> Self {
        self.cancelled = Some(cancelled);
        self.downloading = Box::new(downloading);
        self
    }
    pub(crate) async fn lock(&self) -> Result<Guard<'s>, String> {
        let mut guard = self.shared.engine.lock().await;
        // A command may have waited behind the shutdown task.
        if self.shared.quitting.load(Ordering::SeqCst) {
            return Err("app_quitting".into());
        }
        if let Ok(engine) = guard.as_mut() {
            engine.defer_geodata(self.downloads > 0);
        }
        Ok(guard)
    }
    /// The command's result, or `None` after running its download: then the
    /// command must be repeated under a new [`Deferred::lock`].
    pub(crate) async fn finish<T>(
        &mut self,
        mut guard: Guard<'s>,
        result: Result<T, String>,
    ) -> Option<Result<T, String>> {
        let Ok(engine) = guard.as_mut() else {
            return Some(result);
        };
        let work = engine.take_geodata_work();
        engine.inline_geodata();
        let work = match (&result, work) {
            (Err(error), Some(work))
                if error == DOWNLOAD_REQUIRED && self.downloads < MAX_DOWNLOADS =>
            {
                work
            }
            _ => return Some(result),
        };
        drop(guard);
        (self.downloading)(true);
        let downloaded = work.run(self.cancelled.clone()).await;
        (self.downloading)(false);
        if let Err(error) = downloaded {
            return Some(Err(error));
        }
        self.downloads += 1;
        None
    }
}
