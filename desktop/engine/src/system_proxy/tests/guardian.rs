use super::*;
use crate::system_proxy::recover_owned;
use std::os::unix::fs::{symlink, PermissionsExt};

fn unrecovered(path: &Path, shared: &Arc<Mutex<State>>) -> Manager {
    let mut manager = Manager::default();
    manager.directory = Some(path.into());
    manager.backend = Some(Box::new(Fake(shared.clone())));
    manager
}
#[test]
fn only_matching_guardian_restores_exact_defaults_and_explicit_values() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let before = shared.lock().unwrap().values.clone();
    let mut owner = open(dir.path(), &shared);
    owner.enable(2080).unwrap();
    let token = owner.lease.as_ref().unwrap().journal.token.clone().unwrap();
    crash(owner);
    let mut guardian = unrecovered(dir.path(), &shared);
    let writes = shared.lock().unwrap().writes;
    recover_owned(&mut guardian, &"f".repeat(32)).unwrap();
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(guardian.path().exists());
    recover_owned(&mut guardian, &token).unwrap();
    assert_eq!(shared.lock().unwrap().values, before);
    assert!(!guardian.path().exists());
    recover_owned(&mut guardian, &token).unwrap();
}
#[test]
fn guardian_never_overwrites_another_live_owner() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let mut owner = open(dir.path(), &shared);
    owner.enable(2080).unwrap();
    let writes = shared.lock().unwrap().writes;
    let mut guardian = unrecovered(dir.path(), &shared);
    recover_owned(
        &mut guardian,
        owner
            .lease
            .as_ref()
            .unwrap()
            .journal
            .token
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(shared.lock().unwrap().writes, writes);
    assert!(owner.status().active);
}
#[test]
fn guardian_preserves_external_changes_and_failed_recovery_journal() {
    for external in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let shared = state();
        let mut owner = open(dir.path(), &shared);
        owner.enable(2080).unwrap();
        let token = owner.lease.as_ref().unwrap().journal.token.clone().unwrap();
        crash(owner);
        if external {
            shared.lock().unwrap().values[0].effective = "'other.example'".into();
        } else {
            shared.lock().unwrap().writable = false;
        }
        let writes = shared.lock().unwrap().writes;
        let mut guardian = unrecovered(dir.path(), &shared);
        assert_eq!(recover_owned(&mut guardian, &token).is_ok(), external);
        assert!(guardian.lease.is_none());
        assert_eq!(guardian.path().exists(), !external);
        drop(guardian);
        assert_eq!(shared.lock().unwrap().writes, writes);
    }
}
#[test]
fn legacy_journal_recovers_on_startup_but_is_not_claimed_by_guardian() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let before = shared.lock().unwrap().values.clone();
    let mut owner = open(dir.path(), &shared);
    owner.enable(2080).unwrap();
    let path = owner.path();
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("token");
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    crash(owner);
    let mut guardian = unrecovered(dir.path(), &shared);
    let writes = shared.lock().unwrap().writes;
    recover_owned(&mut guardian, &"a".repeat(32)).unwrap();
    assert_eq!(shared.lock().unwrap().writes, writes);
    let manager = open(dir.path(), &shared);
    assert!(manager.error.is_none());
    assert_eq!(shared.lock().unwrap().values, before);
}
#[test]
fn invalid_tokens_permissions_symlinks_and_oversized_journals_are_not_followed() {
    for case in [
        "token",
        "permissions",
        "symlink",
        "hardlink",
        "oversized",
        "directory",
        "lock",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let shared = state();
        let mut owner = open(dir.path(), &shared);
        owner.enable(2080).unwrap();
        let path = owner.path();
        let token = owner.lease.as_ref().unwrap().journal.token.clone().unwrap();
        crash(owner);
        let writes = shared.lock().unwrap().writes;
        match case {
            "token" => {
                let mut json: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                json["token"] = serde_json::json!("G".repeat(32));
                std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
            }
            "permissions" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "symlink" => {
                std::fs::rename(&path, other.path().join("journal")).unwrap();
                symlink(other.path().join("journal"), &path).unwrap();
            }
            "hardlink" => std::fs::hard_link(&path, other.path().join("journal")).unwrap(),
            "oversized" => std::fs::write(&path, vec![b' '; 65537]).unwrap(),
            "directory" => {
                std::fs::remove_file(&path).unwrap();
                std::fs::create_dir(&path).unwrap();
            }
            "lock" => {
                std::fs::remove_file(path.with_file_name("owner.lock")).unwrap();
                std::fs::write(other.path().join("lock"), b"untouched").unwrap();
                symlink(other.path().join("lock"), path.with_file_name("owner.lock")).unwrap();
            }
            _ => unreachable!(),
        }
        let mut guardian = unrecovered(dir.path(), &shared);
        assert!(recover_owned(&mut guardian, &token).is_err(), "{case}");
        assert_eq!(shared.lock().unwrap().writes, writes, "{case}");
        assert!(path.symlink_metadata().is_ok());
    }
}
#[test]
fn unavailable_guardian_fails_before_writing_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let mut manager = open(dir.path(), &shared);
    // The test executable has no early guardian entry point; its argument parser
    // exits. A missing/old packaged app must fail before any OS setting changes.
    manager.guardian_required = true;
    assert_eq!(
        manager.enable(2080).unwrap_err(),
        "system_proxy_guardian_failed"
    );
    assert_eq!(shared.lock().unwrap().writes, 0);
    assert!(!manager.path().exists());
    assert!(!manager.status().active);
}
#[test]
fn guardian_loss_restores_proxy_or_preserves_foreign_values() {
    for external in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let shared = state();
        let before = shared.lock().unwrap().values.clone();
        let mut manager = open(dir.path(), &shared);
        manager.enable(2080).unwrap();
        manager.guardian_required = true; // an absent/dead child is not protection
        if external {
            shared.lock().unwrap().values[0].effective = "'other.example'".into();
        }
        manager.observe();
        assert!(!manager.status().active);
        assert_eq!(
            manager.status().error.as_deref(),
            Some(if external {
                "system_proxy_changed"
            } else {
                "system_proxy_guardian_failed"
            })
        );
        if !external {
            assert_eq!(shared.lock().unwrap().values, before);
        } else {
            assert_eq!(
                shared.lock().unwrap().values[0].effective,
                "'other.example'"
            );
        }
    }
}
#[test]
fn guardian_loss_cannot_retain_unverified_proxy_when_restore_fails() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let mut manager = open(dir.path(), &shared);
    manager.enable(2080).unwrap();
    manager.guardian_required = true;
    shared.lock().unwrap().writable = false;
    assert!(manager.check_retained(2080).is_err());
    assert_eq!(
        manager.status().error.as_deref(),
        Some("system_proxy_recovery_failed")
    );
    assert!(manager.path().is_file());
    shared.lock().unwrap().writable = true;
    manager.retry_recovery().unwrap();
    assert!(!manager.path().exists());
}

#[tokio::test]
async fn backend_tick_handles_guardian_failure_without_webview_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let shared = state();
    let before = shared.lock().unwrap().values.clone();
    let mut engine =
        crate::Engine::open(&dir.path().join("library"), &dir.path().join("unused-core")).unwrap();
    engine.system_proxy = open(&dir.path().join("proxy"), &shared);
    engine.system_proxy.enable(2080).unwrap();
    engine.system_proxy.guardian_required = true;
    engine.running = Some("owned-local-listener".into());
    engine.rpc = Some(crate::transport::Rpc::sleeping_recovery_test_child(true));
    engine.recovery_tick().await;
    assert_eq!(engine.running.as_deref(), Some("owned-local-listener"));
    assert_eq!(shared.lock().unwrap().values, before);
    assert!(!engine.system_proxy.status().active);
    assert_eq!(
        engine.system_proxy.status().error.as_deref(),
        Some("system_proxy_guardian_failed")
    );
    assert!(!engine.system_proxy.path().exists());
    let owner = engine.owned_core_process().unwrap();
    // This fixture intentionally closes its fake RPC stream on the first
    // request. Disconnect still has to reap the independent sleeping child.
    assert_eq!(
        engine.disconnect().await.err().as_deref(),
        Some("core_disconnected")
    );
    assert!(engine.rpc.is_none());
    assert!(!Path::new(&format!("/proc/{}", owner.pid)).exists());
}
