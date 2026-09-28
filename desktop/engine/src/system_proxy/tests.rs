use super::*;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
mod credentials;
#[cfg(target_os = "linux")]
mod guardian;
#[cfg(target_os = "linux")]
mod owner_lock;
#[cfg(target_os = "linux")]
mod real_recovery;

struct State {
    kind: BackendKind,
    order: Vec<usize>,
    values: Vec<Value>,
    defaults: Vec<String>,
    writes: usize,
    fail_at: Option<usize>,
    compete_at: Option<usize>,
    writable: bool,
    reads: usize,
    read_error: bool,
    short_read: bool,
    change_at_read: Option<usize>,
}
struct Fake(Arc<Mutex<State>>);
impl Backend for Fake {
    fn kind(&self) -> BackendKind {
        self.0.lock().unwrap().kind
    }
    fn read(&self) -> Result<Vec<Value>, String> {
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        if state.read_error {
            return Err("system_proxy_read_failed".into());
        }
        if state.change_at_read == Some(state.reads) {
            state.values[0] = Value {
                effective: "'outside.proxy.test'".into(),
                user: Some("'outside.proxy.test'".into()),
            };
        }
        let mut values = state.values.clone();
        if state.short_read {
            values.pop();
        }
        Ok(values)
    }
    fn writable(&self) -> Result<(), String> {
        if self.0.lock().unwrap().writable {
            Ok(())
        } else {
            Err("system_proxy_not_writable".into())
        }
    }
    fn write(&self, index: usize, value: Option<&str>) -> Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.writes += 1;
        s.order.push(index);
        if s.fail_at == Some(s.writes) || !s.writable {
            return Err("system_proxy_apply_failed".into());
        }
        s.values[index] = Value {
            effective: value
                .map(str::to_owned)
                .unwrap_or_else(|| s.defaults[index].clone()),
            user: value.map(str::to_owned),
        };
        if s.compete_at == Some(s.writes) {
            s.values[0] = Value {
                effective: "'external.proxy.test'".into(),
                user: Some("'external.proxy.test'".into()),
            };
        }
        Ok(())
    }
}
fn state() -> Arc<Mutex<State>> {
    let defaults: Vec<String> = KEYS
        .iter()
        .map(|(_, key)| {
            match *key {
                "host" => "''",
                "port" => "0",
                "mode" => "'none'",
                _ => "false",
            }
            .into()
        })
        .collect();
    let mut values: Vec<Value> = defaults
        .iter()
        .map(|v| Value {
            effective: v.clone(),
            user: None,
        })
        .collect();
    values[0] = Value {
        effective: "'previous.proxy.test'".into(),
        user: Some("'previous.proxy.test'".into()),
    };
    values[1] = Value {
        effective: "3128".into(),
        user: Some("3128".into()),
    };
    values[11] = Value {
        effective: "'auto'".into(),
        user: Some("'auto'".into()),
    };
    Arc::new(Mutex::new(State {
        kind: BackendKind::Gnome,
        order: Vec::new(),
        values,
        defaults,
        writes: 0,
        fail_at: None,
        compete_at: None,
        writable: true,
        reads: 0,
        read_error: false,
        short_read: false,
        change_at_read: None,
    }))
}
/// A writable fake OS proxy for tests of the modules that drive the manager.
pub(crate) fn fake_manager(path: &Path) -> Manager {
    open(path, &state())
}
fn open(path: &Path, shared: &Arc<Mutex<State>>) -> Manager {
    Manager::open(path.into(), Box::new(Fake(shared.clone())))
}
fn crash(mut manager: Manager) {
    manager.lease.take();
    manager.active = false;
}

#[test]
fn restores_exact_user_values_and_defaults_and_keeps_private_journal() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let original = s.lock().unwrap().values.clone();
    let mut m = open(dir.path(), &s);
    assert_eq!(s.lock().unwrap().writes, 0);
    m.enable(2080).unwrap();
    assert!(m.status().active);
    assert!(m.path().is_file());
    assert_eq!(
        s.lock()
            .unwrap()
            .values
            .iter()
            .map(|v| v.effective.clone())
            .collect::<Vec<_>>(),
        m.lease.as_ref().unwrap().journal.desired()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(m.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    m.restore().unwrap();
    assert!(!m.status().active);
    assert!(!m.path().exists());
    assert_eq!(s.lock().unwrap().values, original);
}

#[test]
fn every_partial_apply_failure_rolls_back_before_reporting_failure() {
    for fail in 1..=KEYS.len() {
        let dir = tempfile::tempdir().unwrap();
        let s = state();
        let original = s.lock().unwrap().values.clone();
        s.lock().unwrap().fail_at = Some(fail);
        let mut m = open(dir.path(), &s);
        assert_eq!(m.enable(2080).unwrap_err(), "system_proxy_apply_failed");
        assert_eq!(s.lock().unwrap().values, original);
        assert!(!m.path().exists());
        assert!(!m.status().active);
    }
}

#[test]
fn another_library_cannot_take_over_or_restore_an_active_owner() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let mut first = open(dir.path(), &s);
    first.enable(2080).unwrap();
    let applied = s.lock().unwrap().values.clone();
    let mut second = open(dir.path(), &s);
    assert_eq!(second.enable(3000).unwrap_err(), "system_proxy_busy");
    assert_eq!(s.lock().unwrap().values, applied);
    assert!(first.status().active);
    first.restore().unwrap();
    second.enable(3000).unwrap();
    assert_eq!(s.lock().unwrap().values[1].effective, "3000");
}

#[test]
fn startup_recovers_settings_after_abrupt_exit_without_reconnecting() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let original = s.lock().unwrap().values.clone();
    let mut first = open(dir.path(), &s);
    first.enable(2080).unwrap();
    crash(first);
    let next = open(dir.path(), &s);
    assert!(!next.status().active);
    assert!(next.status().error.is_none());
    assert_eq!(s.lock().unwrap().values, original);
    assert!(!next.path().exists());
}

#[test]
fn partial_recovery_can_resume_after_a_second_crash() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let original = s.lock().unwrap().values.clone();
    let mut first = open(dir.path(), &s);
    first.enable(2080).unwrap();
    s.lock().unwrap().values[11] = original[11].clone();
    crash(first);
    let next = open(dir.path(), &s);
    assert_eq!(s.lock().unwrap().values, original);
    assert!(!next.path().exists());
}

#[test]
fn outside_changes_are_preserved_as_a_whole_on_disconnect_and_observation() {
    for observe in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let s = state();
        let mut m = open(dir.path(), &s);
        m.enable(2080).unwrap();
        s.lock().unwrap().values[0] = Value {
            effective: "'other.proxy.test'".into(),
            user: Some("'other.proxy.test'".into()),
        };
        let external = s.lock().unwrap().values.clone();
        if observe {
            m.observe();
        } else {
            m.restore().unwrap();
        }
        assert!(!m.status().active);
        assert_eq!(m.status().error.as_deref(), Some("system_proxy_changed"));
        assert_eq!(s.lock().unwrap().values, external);
        assert!(!m.path().exists());
    }
}

#[test]
fn failed_restore_keeps_ownership_and_journal_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let original = s.lock().unwrap().values.clone();
    let mut m = open(dir.path(), &s);
    m.enable(2080).unwrap();
    s.lock().unwrap().writable = false;
    assert!(m.restore().is_err());
    assert!(m.status().active);
    assert!(m.path().is_file());
    assert_eq!(
        m.status().error.as_deref(),
        Some("system_proxy_recovery_failed")
    );
    s.lock().unwrap().writable = true;
    m.retry_recovery().unwrap();
    assert_eq!(s.lock().unwrap().values, original);
    assert!(m.status().error.is_none());
}

#[test]
fn unwritable_backend_and_corrupt_journal_never_modify_system_settings() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    s.lock().unwrap().writable = false;
    let mut m = open(dir.path(), &s);
    assert_eq!(m.enable(2080).unwrap_err(), "system_proxy_not_writable");
    assert_eq!(s.lock().unwrap().writes, 0);
    s.lock().unwrap().writable = true;
    std::fs::write(dir.path().join("recovery.json"), b"invalid journal").unwrap();
    drop(m);
    let m = open(dir.path(), &s);
    assert_eq!(
        m.status().error.as_deref(),
        Some("system_proxy_recovery_failed")
    );
    assert_eq!(s.lock().unwrap().writes, 0);
    assert!(m.path().exists());
}

#[test]
fn old_preferences_default_to_local_without_rewriting_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(crate::store::Library::default()).unwrap();
    value["preferences"]
        .as_object_mut()
        .unwrap()
        .remove("connectionMode");
    let original = serde_json::to_vec(&value).unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, &original).unwrap();
    let e = crate::Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(e.store.library.preferences.connection_mode == ConnectionMode::Local);
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn competing_write_during_enable_does_not_claim_the_previous_settings_were_restored() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    s.lock().unwrap().compete_at = Some(KEYS.len());
    let mut m = open(dir.path(), &s);
    assert_eq!(m.enable(2080).unwrap_err(), "system_proxy_changed");
    assert_eq!(m.status().error.as_deref(), Some("system_proxy_changed"));
    assert_eq!(
        s.lock().unwrap().values[0].effective,
        "'external.proxy.test'"
    );
    assert_eq!(s.lock().unwrap().writes, KEYS.len());
    assert!(!m.status().active);
}

#[test]
fn missing_journal_does_not_block_restoring_a_live_owners_in_memory_copy() {
    let dir = tempfile::tempdir().unwrap();
    let s = state();
    let before = s.lock().unwrap().values.clone();
    let mut m = open(dir.path(), &s);
    m.enable(2080).unwrap();
    std::fs::remove_file(m.path()).unwrap();
    m.restore().unwrap();
    assert_eq!(s.lock().unwrap().values, before);
    assert!(!m.status().active);
}

#[test]
fn retained_checks_preserve_original_journal_lock_and_write_no_settings() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let before = shared.lock().unwrap().values.clone();
    let mut manager = open(dir.path(), &shared);
    manager.enable(2080).unwrap();
    let journal = std::fs::read(manager.path()).unwrap();
    let writes = shared.lock().unwrap().writes;
    for _ in 0..2 {
        assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Owned);
    }
    assert_eq!(std::fs::read(manager.path()).unwrap(), journal);
    assert_eq!(shared.lock().unwrap().writes, writes);
    let competitor = open(dir.path(), &shared);
    assert_eq!(
        competitor.preflight().err().as_deref(),
        Some("system_proxy_busy")
    );
    manager.restore().unwrap();
    assert_eq!(shared.lock().unwrap().values, before);
}

#[test]
fn absent_or_wrong_port_never_acquires_a_new_proxy_lease() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let mut manager = open(dir.path(), &shared);
    assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Lost);
    assert_eq!(shared.lock().unwrap().writes, 0);
    assert!(!manager.path().exists());
    manager.enable(2080).unwrap();
    let journal = std::fs::read(manager.path()).unwrap();
    let values = shared.lock().unwrap().values.clone();
    let writes = shared.lock().unwrap().writes;
    for port in [0, 2081] {
        assert_eq!(
            manager.check_retained(port).err().as_deref(),
            Some("system_proxy_incompatible")
        );
        assert_eq!(shared.lock().unwrap().values, values);
        assert_eq!(shared.lock().unwrap().writes, writes);
        assert_eq!(std::fs::read(manager.path()).unwrap(), journal);
    }
    // Existing in-memory ownership remains usable if its journal was removed;
    // this does not create or rewrite a replacement journal.
    std::fs::remove_file(manager.path()).unwrap();
    assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Owned);
    assert!(!manager.path().exists());
    assert_eq!(shared.lock().unwrap().writes, writes);
}

#[test]
fn retained_read_failures_are_errors_and_keep_the_journal_for_restore() {
    for malformed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let shared = state();
        let before = shared.lock().unwrap().values.clone();
        let mut manager = open(dir.path(), &shared);
        manager.enable(2080).unwrap();
        let journal = std::fs::read(manager.path()).unwrap();
        let writes = shared.lock().unwrap().writes;
        {
            let mut s = shared.lock().unwrap();
            s.read_error = !malformed;
            s.short_read = malformed;
        }
        assert!(manager.check_retained(2080).is_err());
        assert!(manager.status().active);
        assert_eq!(
            manager.status().error.as_deref(),
            Some("system_proxy_recovery_failed")
        );
        assert_eq!(shared.lock().unwrap().writes, writes);
        assert_eq!(std::fs::read(manager.path()).unwrap(), journal);
        assert!(manager.restore().is_err());
        assert_eq!(std::fs::read(manager.path()).unwrap(), journal);
        {
            let mut s = shared.lock().unwrap();
            s.read_error = false;
            s.short_read = false;
        }
        manager.retry_recovery().unwrap();
        assert_eq!(shared.lock().unwrap().values, before);
    }
}

#[test]
fn retaining_a_readable_lease_does_not_require_writing_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let mut manager = open(dir.path(), &shared);
    manager.enable(2080).unwrap();
    let writes = shared.lock().unwrap().writes;
    shared.lock().unwrap().writable = false;
    assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Owned);
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(manager.restore().is_err());
    assert!(manager.path().is_file());
    shared.lock().unwrap().writable = true;
    manager.restore().unwrap();
}

#[test]
fn retained_check_relinquishes_external_values_and_reports_failed_release() {
    for release_failure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let shared = state();
        let mut manager = open(dir.path(), &shared);
        manager.enable(2080).unwrap();
        let writes = shared.lock().unwrap().writes;
        assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Owned);
        shared.lock().unwrap().values[0] = Value {
            effective: "'external.proxy.test'".into(),
            user: Some("'external.proxy.test'".into()),
        };
        let outside = shared.lock().unwrap().values.clone();
        if release_failure {
            std::fs::remove_file(manager.path()).unwrap();
            std::fs::create_dir(manager.path()).unwrap();
            assert_eq!(
                manager.check_retained(2080).err().as_deref(),
                Some("system_proxy_journal_failed")
            );
            assert!(manager.status().active);
            assert!(manager.lease.is_some());
            assert_eq!(
                manager.status().error.as_deref(),
                Some("system_proxy_recovery_failed")
            );
            std::fs::remove_dir(manager.path()).unwrap();
        }
        assert_eq!(manager.check_retained(2080).unwrap(), RetainedProxy::Lost);
        assert!(!manager.status().active);
        assert_eq!(
            manager.status().error.as_deref(),
            Some("system_proxy_changed")
        );
        assert_eq!(shared.lock().unwrap().values, outside);
        assert_eq!(shared.lock().unwrap().writes, writes);
        manager.restore().unwrap();
        assert_eq!(shared.lock().unwrap().values, outside);
    }
}

#[cfg(target_os = "linux")]
async fn pending_system_proxy() -> (
    tempfile::TempDir,
    crate::Engine,
    Arc<Mutex<State>>,
    Vec<Value>,
) {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let original = shared.lock().unwrap().values.clone();
    let mut engine = crate::Engine::open(
        &dir.path().join("library"),
        &dir.path().join("must-not-spawn"),
    )
    .unwrap();
    engine.system_proxy = open(&dir.path().join("proxy"), &shared);
    engine.system_proxy.enable(2080).unwrap();
    engine.store.library.preferences.connection_mode = ConnectionMode::SystemProxy;
    engine.active_connection = Some(crate::connection::ActiveConnection {
        id: "proxy-session".into(),
        profiles: Default::default(),
        groups: Default::default(),
        request: crate::proto::LoadConfigReq {
            core_config: Some("{\"inbounds\":[]}".into()),
            ..Default::default()
        },
        routing_revision: 1,
        system_port: Some(2080),
        tun: false,
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    engine.running = Some("proxy-session".into());
    engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(true));
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    assert_eq!(engine.snapshot().phase, "reconnecting");
    (dir, engine, shared, original)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pending_cancel_restores_before_invalid_connect_and_retains_failed_restore_journal() {
    for fail in [false, true] {
        let (_dir, mut engine, shared, original) = pending_system_proxy().await;
        let journal = std::fs::read(engine.system_proxy.path()).unwrap();
        let writes = shared.lock().unwrap().writes;
        shared.lock().unwrap().writable = !fail;
        let error = engine.connect("missing-profile").await.err();
        assert_eq!(
            error.as_deref(),
            Some(if fail {
                "system_proxy_not_writable"
            } else {
                "profile_not_found"
            })
        );
        assert!(engine.running.is_none());
        assert!(engine.rpc.is_none());
        assert!(!engine.recovery.pending());
        if fail {
            assert_eq!(shared.lock().unwrap().writes, writes);
            assert_eq!(std::fs::read(engine.system_proxy.path()).unwrap(), journal);
            assert_eq!(
                engine.system_proxy.status().error.as_deref(),
                Some("system_proxy_recovery_failed")
            );
            shared.lock().unwrap().writable = true;
            engine.retry_system_proxy_recovery().unwrap();
        }
        assert_eq!(shared.lock().unwrap().values, original);
        assert!(!engine.system_proxy.path().exists());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn hidden_rapid_exit_tick_restores_proxy_without_a_following_snapshot() {
    let (_dir, mut engine, shared, original) = pending_system_proxy().await;
    engine.recovery.clear_pending();
    engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(true));
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    engine.recovery_tick().await;
    assert_eq!(engine.error.as_deref(), Some("core_restart_limited"));
    assert!(engine.running.is_none());
    assert_eq!(shared.lock().unwrap().values, original);
    assert!(!engine.system_proxy.path().exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_retained_precheck_keeps_journal_if_terminal_restore_also_fails() {
    let (_dir, mut engine, shared, original) = pending_system_proxy().await;
    let journal = std::fs::read(engine.system_proxy.path()).unwrap();
    let writes = shared.lock().unwrap().writes;
    shared.lock().unwrap().read_error = true;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    engine.recovery_tick().await;
    assert_eq!(engine.error.as_deref(), Some("core_reconnect_failed"));
    assert!(engine.rpc.is_none());
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert_eq!(std::fs::read(engine.system_proxy.path()).unwrap(), journal);
    shared.lock().unwrap().read_error = false;
    // Hidden backend tick resumes the existing recovery journal, not the core.
    engine.recovery_tick().await;
    assert!(engine.rpc.is_none());
    assert_eq!(shared.lock().unwrap().values, original);
    assert!(!engine.system_proxy.path().exists());
}

/// The Windows backend owns two values, so the manager's own behaviour around
/// them can be proven here: what it publishes, in which order, and what it
/// gives back. Only the WinINet calls themselves need that machine.
fn windows_state(before: [&str; 2]) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        kind: BackendKind::WinInet,
        order: Vec::new(),
        values: before
            .iter()
            .map(|v| Value {
                effective: (*v).to_owned(),
                user: Some((*v).to_owned()),
            })
            .collect(),
        defaults: vec![String::new(), "1".into()],
        writes: 0,
        fail_at: None,
        compete_at: None,
        writable: true,
        reads: 0,
        read_error: false,
        short_read: false,
        change_at_read: None,
    }))
}
fn effective(shared: &Arc<Mutex<State>>) -> Vec<String> {
    shared
        .lock()
        .unwrap()
        .values
        .iter()
        .map(|v| v.effective.clone())
        .collect()
}

#[test]
fn windows_publishes_the_address_before_the_flags_and_restores_the_previous_source() {
    let directory = tempfile::tempdir().unwrap();
    // PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT: this machine was autodetecting.
    let shared = windows_state(["proxy.fixture.invalid:8080", "9"]);
    let mut manager = open(directory.path(), &shared);
    manager.set_scheme("http://{ip}:{port}".into());
    manager.enable(2080).unwrap();
    assert_eq!(
        effective(&shared),
        ["http://127.0.0.1:2080".to_owned(), "3".to_owned()]
    );
    assert_eq!(shared.lock().unwrap().order, [0, 1]);
    manager.restore().unwrap();
    assert_eq!(
        effective(&shared),
        ["proxy.fixture.invalid:8080".to_owned(), "9".to_owned()]
    );
}

#[test]
fn windows_without_a_scheme_publishes_the_plain_address() {
    let directory = tempfile::tempdir().unwrap();
    let shared = windows_state(["", "1"]);
    let mut manager = open(directory.path(), &shared);
    manager.enable(1080).unwrap();
    assert_eq!(
        effective(&shared),
        ["127.0.0.1:1080".to_owned(), "3".to_owned()]
    );
}

#[test]
fn windows_gives_the_previous_source_back_after_a_crash() {
    let directory = tempfile::tempdir().unwrap();
    let shared = windows_state(["socks=proxy.fixture.invalid:1080", "2"]);
    let mut manager = open(directory.path(), &shared);
    manager.set_scheme("socks={ip}:{port}".into());
    manager.enable(2080).unwrap();
    assert_eq!(
        effective(&shared),
        ["socks=127.0.0.1:2080".to_owned(), "3".to_owned()]
    );
    crash(manager);
    let recovered = open(directory.path(), &shared);
    assert!(!recovered.status().active);
    assert_eq!(
        effective(&shared),
        [
            "socks=proxy.fixture.invalid:1080".to_owned(),
            "2".to_owned()
        ]
    );
}
