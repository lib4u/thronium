//! Qt's "resolve domain to IP" for library servers. The system resolver runs
//! without the Engine lock, as Qt's `QHostInfo::lookupHost` runs off its UI
//! thread, and only addresses that came back are written into the library.
use crate::Shared;
use serde_json::{json, Value};
use std::time::Duration;
use tauri::{AppHandle, Manager};

/// Names resolved at once; the rest follow in the next round.
const PARALLEL: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(10);

pub async fn resolve(app: &AppHandle, payload: &Value) -> Result<Value, String> {
    let ids: Vec<String> =
        serde_json::from_value(payload["ids"].clone()).map_err(|_| "invalid_profile_selection")?;
    if ids.is_empty() || ids.len() > thronium_engine::store::MAX_BATCH_PROFILES {
        return Err("invalid_profile_selection".into());
    }
    let shared = app.state::<Shared>();
    let named = {
        let guard = shared.engine.lock().await;
        guard
            .as_ref()
            .map_err(|e| e.clone())?
            .resolvable_hosts(&ids)
    };
    let mut answers = Vec::new();
    for group in named.chunks(PARALLEL) {
        let mut running = Vec::new();
        for (id, host) in group {
            let (id, host) = (id.clone(), host.clone());
            running.push(tokio::spawn(async move {
                let lookup = tokio::time::timeout(TIMEOUT, tokio::net::lookup_host((&*host, 0)))
                    .await
                    .ok()
                    .and_then(Result::ok);
                // Qt keeps the first address the resolver returned.
                lookup
                    .and_then(|mut found| found.next())
                    .map(|address| (id, address.ip().to_string()))
            }));
        }
        for task in running {
            if let Ok(Some(answer)) = task.await {
                answers.push(answer);
            }
        }
    }
    let mut guard = shared.engine.lock().await;
    let resolved = guard
        .as_mut()
        .map_err(|e| e.clone())?
        .apply_resolved_hosts(&answers)?;
    Ok(json!({"resolved": resolved, "named": named.len()}))
}
