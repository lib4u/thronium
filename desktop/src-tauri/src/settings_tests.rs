use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tokio::sync::{watch, Mutex};

#[derive(Default)]
pub struct State(Mutex<Registry>);
impl State {
    /// Application exit: the running measurement returns `probe_cancelled` and
    /// its disposable core is terminated before the process exits.
    pub async fn cancel_all(&self) {
        self.0.lock().await.cancel(None);
    }
}

#[derive(Default)]
struct Registry {
    active: Option<(String, watch::Sender<bool>)>,
    cancelled: std::collections::VecDeque<String>,
}
impl Registry {
    fn begin(&mut self, id: String) -> Result<watch::Receiver<bool>, String> {
        if let Some(index) = self.cancelled.iter().position(|token| token == &id) {
            self.cancelled.remove(index);
            return Err("probe_cancelled".into());
        }
        if self.active.is_some() {
            return Err("probe_busy".into());
        }
        let (sender, receiver) = watch::channel(false);
        self.active = Some((id, sender));
        Ok(receiver)
    }
    fn cancel(&mut self, id: Option<&str>) {
        if let Some((active, sender)) = &self.active {
            if id.is_none() || id == Some(active.as_str()) {
                let _ = sender.send(true);
            }
        }
        // Closing a view can arrive before its start command is scheduled.
        // Keep a bounded set of explicit cancellations so that test never starts.
        if let Some(id) = id {
            if !self.cancelled.iter().any(|token| token == id) {
                self.cancelled.push_back(id.to_owned());
                if self.cancelled.len() > 128 {
                    self.cancelled.pop_front();
                }
            }
        }
    }
    fn finish(&mut self, id: &str) {
        if self.active.as_ref().is_some_and(|(active, _)| active == id) {
            self.active.take();
        }
    }
}
fn request_id(payload: &Value) -> Result<Option<&str>, String> {
    payload
        .get("requestId")
        .map(|id| {
            id.as_str()
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 128
                        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
                .ok_or_else(|| "probe_invalid_options".to_string())
        })
        .transpose()
}

pub async fn run(app: &AppHandle, name: &str, payload: &Value) -> Result<Value, String> {
    let state = app.state::<State>();
    if name == "cancelSettingsTest" {
        state.0.lock().await.cancel(request_id(payload)?);
        return Ok(Value::Null);
    }
    if !matches!(name, "testSpeed" | "testIp" | "testInternet") {
        return Err("probe_invalid_options".into());
    }
    let id = if let Some(id) = request_id(payload)? {
        id.to_owned()
    } else {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "settings-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    };
    let mut cancelled = state.0.lock().await.begin(id.clone())?;
    let result = async {
        let shared = app.state::<crate::Shared>();
        if matches!(name, "testSpeed" | "testIp") {
            let profile_id = payload["id"].as_str().ok_or("profile_not_found")?;
            let (test, profile_name) = {
                let mut guard = shared.engine.lock().await;
                let engine = guard.as_mut().map_err(|e| e.clone())?;
                // The slot is reserved before a bound profile spends its code.
                let test = if name == "testIp" {
                    engine.reserved_ip_test(&id, profile_id)?
                } else {
                    engine.reserved_speed_test(&id, profile_id)?
                };
                match engine.profile(profile_id) {
                    Ok(profile) => (test, profile.name),
                    Err(error) => {
                        engine.release_probe(&id);
                        return Err(error);
                    }
                }
            };
            let executed = test.execute(&mut cancelled).await;
            let mut guard = shared.engine.lock().await;
            if let Ok(engine) = guard.as_mut() {
                engine.release_probe(&id);
            }
            let mut result = executed?;
            if *cancelled.borrow() {
                return Err("probe_cancelled".into());
            }
            if !guard.as_ref().map_err(|e| e.clone())?.test_matches(&test) {
                return Err("probe_stale".into());
            }
            if name == "testIp" {
                guard
                    .as_mut()
                    .map_err(|e| e.clone())?
                    .remember_ip_country(&test, &result)?;
            }
            result["profileId"] = json!(profile_id);
            result["profileName"] = json!(profile_name);
            result["kind"] = json!(test.kind_name());
            result["transport"] = json!(test.transport());
            if let Some((member_id, member_name)) = test.member() {
                result["memberId"] = json!(member_id);
                result["memberName"] = json!(member_name);
                result["memberOrigin"] = json!(test.member_origin());
            }
            result["testedAt"] = json!(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs());
            Ok(result)
        } else {
            let (url, timeout) = {
                let guard = shared.engine.lock().await;
                let engine = guard.as_ref().map_err(|e| e.clone())?;
                (
                    thronium_engine::settings::string(&engine.store.library, "direct_test_url"),
                    engine.store.library.preferences.ping.timeout_ms as u64,
                )
            };
            thronium_engine::settings::tests_runtime::direct(url, timeout, &mut cancelled)
                .await
                .map(|mut value| {
                    value["kind"] = json!("internet");
                    value["transport"] = json!("direct");
                    value
                })
        }
    }
    .await;
    state.0.lock().await.finish(&id);
    journal(app, name, payload, &result).await;
    result.map(|value| json!({"result":value}))
}

/// Every single run reaches the measurement journal, including refusals and cancellations.
async fn journal(app: &AppHandle, name: &str, payload: &Value, result: &Result<Value, String>) {
    let shared = app.state::<crate::Shared>();
    let mut guard = shared.engine.lock().await;
    let Ok(engine) = guard.as_mut() else { return };
    let value = result.as_ref().ok();
    let text = |key: &str| value.and_then(|v| v[key].as_str().map(str::to_owned));
    let profile_id = payload["id"].as_str().unwrap_or("");
    let profile_name = if name == "testInternet" {
        String::new()
    } else {
        engine
            .profile(profile_id)
            .map(|p| p.name)
            .unwrap_or_default()
    };
    engine.record_measurement(thronium_engine::probes::journal::Entry {
        id: 0,
        at: 0,
        kind: text("kind").unwrap_or_else(|| {
            if name == "testInternet" {
                "internet"
            } else if name == "testIp" {
                "ip"
            } else {
                "speed"
            }
            .into()
        }),
        source: "single".into(),
        profile_id: if name == "testInternet" {
            "direct".into()
        } else {
            profile_id.into()
        },
        profile_name,
        member_id: text("memberId"),
        member_name: text("memberName"),
        member_origin: None,
        transport: text("transport"),
        status: match result {
            Ok(v) if v.get("online") == Some(&json!(false)) => "error".into(),
            Ok(_) => "ok".into(),
            Err(code) if code == "probe_cancelled" => "cancelled".into(),
            Err(code) if code == "probe_stale" => "stale".into(),
            Err(code) if code == "probe_unsupported" => "unsupported".into(),
            Err(_) => "error".into(),
        },
        latency_ms: value
            .and_then(|v| v["latencyMs"].as_i64())
            .map(|n| n as i32),
        ip: text("ip"),
        country_code: text("countryCode"),
        download: text("download"),
        upload: text("upload"),
        error: result.as_ref().err().cloned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_before_start_does_not_launch_a_late_request() {
        let mut registry = Registry::default();
        registry.cancel(Some("closed-view"));
        assert_eq!(
            registry.begin("closed-view".into()).unwrap_err(),
            "probe_cancelled"
        );
        assert!(registry.active.is_none());
        assert!(registry.begin("new-view".into()).is_ok());
    }
    #[test]
    fn cancellation_is_owned_and_late_completion_cannot_clear_a_new_test() {
        let mut registry = Registry::default();
        let first = registry.begin("one".into()).unwrap();
        registry.cancel(Some("other"));
        assert!(!*first.borrow());
        assert_eq!(registry.begin("two".into()).unwrap_err(), "probe_busy");
        registry.cancel(Some("one"));
        assert!(*first.borrow());
        registry.finish("one");
        let second = registry.begin("two".into()).unwrap();
        registry.finish("one");
        assert_eq!(registry.begin("three".into()).unwrap_err(), "probe_busy");
        assert!(!*second.borrow());
        registry.cancel(None);
        assert!(*second.borrow());
    }
    #[test]
    fn cancellation_tokens_are_validated_and_memory_is_bounded() {
        for value in [
            json!(""),
            json!("x".repeat(129)),
            json!("token / path"),
            json!(42),
        ] {
            assert_eq!(
                request_id(&json!({"requestId":value})).unwrap_err(),
                "probe_invalid_options"
            );
        }
        let mut registry = Registry::default();
        for i in 0..200 {
            registry.cancel(Some(&format!("token-{i}")));
        }
        assert_eq!(registry.cancelled.len(), 128);
    }
}
