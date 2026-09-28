//! The job owns the exact test Child and its directory through cancellation.
//! Dropping execute's future closes a private channel; it never detaches an
//! untracked child or releases the admission permit before waitpid succeeds.
use super::{Outcome, Probe, Request};
use crate::{proto, transport::Rpc};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{oneshot, watch};

pub(super) struct Permit {
    owners: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
    armed: bool,
}
impl Permit {
    pub(super) fn new(owners: Arc<AtomicUsize>, blocked: Arc<AtomicBool>) -> Self {
        owners.fetch_add(1, Ordering::AcqRel);
        Self {
            owners,
            blocked,
            armed: false,
        }
    }
    fn release(mut self) {
        self.armed = false;
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        // Unexpected unwinding after spawn is uncertainty, never permission to
        // start TUN or another disposable VPN. Normal completion releases below.
        if !self.armed {
            self.owners.fetch_sub(1, Ordering::AcqRel);
        } else {
            self.blocked.store(true, Ordering::Release);
        }
    }
}

pub(super) async fn execute(
    probe: Probe,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<Outcome, String> {
    if *cancelled.borrow() {
        return Err("probe_cancelled".into());
    }
    let (dispose, disposed) = oneshot::channel::<()>();
    let (send, receive) = oneshot::channel();
    tokio::spawn(run(probe, cancelled.clone(), disposed, send));
    // Keep the sender alive while awaiting; dropping this future signals run.
    let result = receive
        .await
        .unwrap_or_else(|_| Err("probe_cleanup_failed".into()));
    drop(dispose);
    result
}

async fn run(
    probe: Probe,
    mut cancelled: watch::Receiver<bool>,
    mut disposed: oneshot::Receiver<()>,
    send: oneshot::Sender<Result<Outcome, String>>,
) {
    let Probe {
        core,
        request,
        timeout_ms,
        vpn_permit: mut permit,
        logs,
        ..
    } = probe;
    let directory = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => {
            let _ = send.send(Err("probe_core_failed".into()));
            return;
        }
    };
    let mut slot = None;
    if let Some(permit) = permit.as_mut() {
        permit.armed = true;
    }
    // Two HTTP attempts, the explicit VPN status wait, and the private core's
    // 8 s handshake. Cleanup has its own budget and is never called success
    // merely because this operation deadline elapsed.
    let exchange_budget = Duration::from_millis(timeout_ms as u64 * 2 + 12_000);
    let already_cancelled = *cancelled.borrow();
    let result = tokio::select! {
        biased;
        _=&mut disposed=>Err("probe_cancelled".into()),
        _=cancelled.changed()=>Err("probe_cancelled".into()),
        result=tokio::time::timeout(exchange_budget+Duration::from_secs(8),async {
            if already_cancelled {return Err("probe_cancelled".into());}
            Rpc::spawn_local_retained(&core,directory.path(),logs,&mut slot).await.map_err(|_|"probe_core_failed")?;
            let Request::Http(request)=request else {return Err("probe_failed".into());};
            let tags=request.vpn_endpoint_tags.clone();
            let outbound=request.outbound_tags.first().cloned().ok_or("probe_failed")?;
            let reply:proto::TestResp=slot.as_mut().ok_or("probe_core_failed")?
                .call_with_timeout("Test",request,exchange_budget).await.map_err(|_|"probe_configuration_failed")?;
            super::vpn::decode(reply,&tags,&outbound)
        })=>result.unwrap_or_else(|_|Err("probe_timeout".into())),
    };
    if let Some(rpc) = slot.as_mut() {
        if rpc.reap_local().await.is_err() {
            if let Some(permit) = &permit {
                permit.blocked.store(true, Ordering::Release);
            }
            let _ = send.send(Err("probe_cleanup_failed".into()));
            // Keep the exact owner, working directory and permit. Nothing starts
            // again while exit/reap is uncertain; this loop only observes exit.
            loop {
                if matches!(rpc.exit_success(), Ok(Some(_))) {
                    break;
                }
                let _ = rpc.request_kill();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            drop(slot);
            drop(directory);
            if let Some(permit) = permit {
                permit.release();
            }
            return;
        }
    }
    drop(slot);
    drop(directory);
    if let Some(permit) = permit {
        permit.release();
    }
    let _ = send.send(result);
}
