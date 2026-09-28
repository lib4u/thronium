use super::*;
use crate::{
    store::ProfileKind,
    subscriptions::{GroupDraft, Settings},
    ProfileDraft,
};
fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("missing")).unwrap();
    let group = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: None,
            name: "Provider".into(),
            subscription: Some(Settings {
                name_rules: Default::default(),
                inherit_defaults: Some(false),
                allow_insecure: false,
                timeout_seconds: 30,
                url: "https://example.test/backup-secret".into(),
                headers: Default::default(),
                user_agent: "fixture".into(),
                via_proxy: false,
                use_provider_routing: false,
                interval_minutes: 0,
            }),
        })
        .unwrap();
    let leaf=e.save_profile(ProfileDraft{ vpn_policy: Default::default(),id:None,name:"Сервер 🦊".into(),group_id:group.clone(),kind:ProfileKind::SingBoxOutbound,config:json!({"type":"socks","server":"localhost","server_port":1080,"password":"private-backup-password","future":{"preserve":true}})}).unwrap();
    e.store
        .library
        .groups
        .iter_mut()
        .find(|g| g.id == group)
        .unwrap()
        .subscription
        .as_mut()
        .unwrap()
        .managed_ids = vec![leaf.clone()];
    e.favorite(&leaf).unwrap();
    let chain = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Chain".into(),
            group_id: "personal".into(),
            kind: ProfileKind::Chain,
            config: json!({"type":"chain","hops":[leaf]}),
        })
        .unwrap();
    let pool = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Pool".into(),
            group_id: "personal".into(),
            kind: ProfileKind::AutoSelector,
            config: json!({"type":"auto-selector","members":[leaf],"pinned_profile":leaf}),
        })
        .unwrap();
    let mut routing = e.routing();
    routing.profiles[0].route["final"] = json!(format!("profile:{pool}"));
    e.save_routing(routing).unwrap();
    e.select(&chain).unwrap();
    (dir, e)
}
fn fresh() -> (tempfile::TempDir, Engine) {
    let d = tempfile::tempdir().unwrap();
    let e = Engine::open(d.path(), Path::new("missing")).unwrap();
    (d, e)
}
#[test]
fn export_restore_and_undo_keep_exact_ids_secrets_subscriptions_links_routing_and_preferences() {
    let (_source_dir, source) = setup();
    let (target_dir, mut target) = fresh();
    let original = json!(target.store.library);
    let text = source.export_backup().unwrap();
    assert!(text.contains("private-backup-password"));
    let preview = target.preview_backup(&text).unwrap();
    assert_eq!(preview.incoming.profiles, 3);
    assert_eq!(preview.incoming.subscriptions, 1);
    assert!(!json!(preview).to_string().contains("backup-secret"));
    assert_eq!(json!(target.store.library), original);
    target.restore_backup(&preview.token).unwrap();
    assert_eq!(json!(target.store.library), json!(source.store.library));
    assert_eq!(target.backup_status()["canUndo"], true);
    let snapshot = target.snapshot();
    assert!(snapshot.running.is_none());
    assert!(snapshot.url_tests.is_none());
    assert!(snapshot.subscription_jobs.is_empty());
    let undo = target.preview_previous_backup().unwrap();
    target.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(target.store.library), original);
    let redo = target.preview_previous_backup().unwrap();
    target.restore_backup(&redo.token).unwrap();
    assert_eq!(json!(target.store.library), json!(source.store.library));
    drop(target);
    let reopened = Engine::open(target_dir.path(), Path::new("missing")).unwrap();
    assert_eq!(json!(reopened.store.library), json!(source.store.library));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(target_dir.path().join("backup-before-restore.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
/// Restoring an older copy must not lower a spent HOTP counter, or the next
/// connect would send a code the server has already seen.
#[test]
fn restoring_an_older_backup_keeps_spent_hotp_counters() {
    let (_dir, mut e) = fresh();
    let saved = e
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                secret: "JBSWY3DPEHPK3PXP".into(),
                kind: crate::otp::Kind::Hotp,
                counter: "5".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let id = saved["id"].as_str().unwrap().to_owned();
    let older = e.export_backup().unwrap();
    let mut spent = e.store.library.clone();
    spent
        .otp
        .iter_mut()
        .find(|o| o.id == id)
        .unwrap()
        .value
        .counter = "9".into();
    e.store.commit(spent).unwrap();
    let preview = e.preview_backup(&older).unwrap();
    e.restore_backup(&preview.token).unwrap();
    let restored = e.store.library.otp.iter().find(|o| o.id == id).unwrap();
    assert_eq!(restored.value.counter, "9");
    // A re-created entry with the same secret keeps the mark as well.
    let mut current = e.store.library.otp.clone();
    let mut incoming = current.clone();
    incoming[0].id = "re-created".into();
    incoming[0].value.counter = "1".into();
    current[0].value.counter = "12".into();
    crate::otp::keep_spent_counters(&current, &mut incoming);
    assert_eq!(incoming[0].value.counter, "12");
}

#[test]
fn malformed_future_and_broken_reference_backups_never_change_the_library_or_echo_secrets() {
    let (_d, source) = setup();
    let (_t, mut target) = fresh();
    let text = source.export_backup().unwrap();
    let valid: Value = serde_json::from_str(&text).unwrap();
    let before = json!(target.store.library);
    let mut cases = vec![
        json!({"format":"other","secret":"fixture-secret"}),
        json!({"format":"thronium-backup","version":2}),
    ];
    let mut broken = valid.clone();
    broken["library"]["profiles"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    cases.push(broken);
    let mut broken = valid.clone();
    broken["library"]["routing"]["profiles"][0]["route"]["final"] = json!("profile:missing");
    cases.push(broken);
    let mut broken = valid.clone();
    broken["library"]["groups"][1]["subscription"]["managedIds"] = json!(["missing"]);
    cases.push(broken);
    let mut future = valid.clone();
    future["library"]["version"] = json!(9);
    cases.push(future);
    for value in cases {
        let error = target.preview_backup(&value.to_string()).err().unwrap();
        assert!(!error.contains("secret"));
        assert_eq!(json!(target.store.library), before);
    }
    for text in ["{bad", "[]", ""] {
        assert!(target.preview_backup(text).is_err());
    }
}
#[test]
fn stale_cancelled_superseded_and_expired_previews_require_review_again() {
    let (_d, source) = setup();
    let (_t, mut target) = fresh();
    let text = source.export_backup().unwrap();
    let a = target.preview_backup(&text).unwrap();
    let b = target.preview_backup(&text).unwrap();
    assert!(target.restore_backup(&a.token).is_err());
    target.discard_backup_preview(&a.token);
    let mut prefs = target.store.library.preferences.clone();
    prefs.language = "en".into();
    target.preferences(prefs).unwrap();
    assert_eq!(
        target.restore_backup(&b.token).unwrap_err(),
        "backup_preview_stale"
    );
    let c = target.refresh_backup_preview(&b.token).unwrap();
    target.restore.as_mut().unwrap().created -= Duration::from_secs(901);
    assert!(target.restore_backup(&c.token).is_err());
    let d = target.refresh_backup_preview(&c.token).unwrap();
    target.discard_backup_preview(&d.token);
    assert!(target.restore_backup(&d.token).is_err());
    assert!(target.store.library.profiles.is_empty());
}
#[test]
fn connection_and_background_work_protect_restore_without_cancelling_them() {
    let (_d, mut e) = setup();
    let text = e.export_backup().unwrap();
    let p = e.preview_backup(&text).unwrap();
    let selected = e.store.library.selected.clone();
    e.running = selected.clone();
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_disconnect_first"
    );
    assert_eq!(e.running, selected);
    e.running = None;
    e.enqueue_subscription_updates().unwrap();
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_background_busy"
    );
    e.cancel_subscription_jobs().unwrap();
    let p = e.refresh_backup_preview(&p.token).unwrap();
    let group = e.store.library.groups[1].id.clone();
    e.begin_manual_subscription(&group, "fixture").unwrap();
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_background_busy"
    );
    e.end_manual_subscription(&group, "fixture");
    let run = e
        .start_url_tests(crate::probes::Options {
            ids: vec![e.store.library.profiles[0].id.clone()],
            url: "http://localhost/test".into(),
            timeout_ms: 100,
            concurrency: None,
        })
        .unwrap();
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_background_busy"
    );
    e.cancel_url_tests();
    assert!(*run.cancelled.borrow());
    e.restore_backup(&p.token).unwrap();
}
#[test]
fn recovery_and_library_write_failures_are_non_destructive_and_can_be_retried() {
    let (_s, source) = setup();
    let (dir, mut target) = fresh();
    let before = json!(target.store.library);
    let preview = target
        .preview_backup(&source.export_backup().unwrap())
        .unwrap();
    let recovery = dir.path().join("backup-before-restore.json");
    std::fs::create_dir(&recovery).unwrap();
    assert_eq!(
        target.restore_backup(&preview.token).unwrap_err(),
        "backup_recovery_write_failed"
    );
    assert_eq!(json!(target.store.library), before);
    std::fs::remove_dir(&recovery).unwrap();
    let library = dir.path().join("library.json");
    std::fs::create_dir(&library).unwrap();
    assert_eq!(
        target.restore_backup(&preview.token).unwrap_err(),
        "backup_restore_failed"
    );
    assert_eq!(json!(target.store.library), before);
    assert!(
        !recovery.exists(),
        "an unwritten restore does not create or replace the recovery point"
    );
    std::fs::remove_dir(&library).unwrap();
    target.restore_backup(&preview.token).unwrap();
    assert_eq!(json!(target.store.library), json!(source.store.library));
    let saved: Value = serde_json::from_str(&read(&recovery).unwrap()).unwrap();
    assert_eq!(saved["library"], before);
    // A later failed restore keeps the undo of this one.
    let restored = json!(target.store.library);
    let again = target
        .preview_backup(&source.export_backup().unwrap())
        .unwrap();
    target
        .store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert_eq!(
        target.restore_backup(&again.token).unwrap_err(),
        "backup_restore_failed"
    );
    assert_eq!(json!(target.store.library), restored);
    let kept: Value = serde_json::from_str(&read(&recovery).unwrap()).unwrap();
    assert_eq!(kept["library"], before);
    assert!(!dir.path().join("backup-before-restore.json.next").exists());
}
#[test]
fn file_reads_are_bounded_reject_non_files_and_preserve_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.json");
    assert!(read(dir.path()).is_err());
    assert!(read(&path).is_err());
    std::fs::write(&path, "Тест 🦊").unwrap();
    assert_eq!(read(&path).unwrap(), "Тест 🦊");
    std::fs::write(&path, [255, 254]).unwrap();
    assert_eq!(read(&path).unwrap_err(), "backup_invalid");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len((MAX_BYTES + 1) as u64).unwrap();
    assert_eq!(read(&path).unwrap_err(), "backup_too_large");
}

#[test]
fn chosen_backup_files_are_recognised_by_content() {
    assert!(matches!(
        read_file(b"{\"format\":\"thronium-backup\"}".to_vec()),
        Ok(File::Thronium(text)) if text.starts_with('{')
    ));
    assert_eq!(
        read_file(vec![0xff, 0xfe]).err().as_deref(),
        Some("backup_invalid")
    );
    // The Throne signature routes the bytes to the Throne reader and its errors.
    let error = read_file(b"THRN\x00".to_vec()).err().unwrap();
    assert!(error.starts_with("legacy_backup_"), "{error}");
}

#[tokio::test]
async fn a_checked_draft_keeps_the_saved_policy_and_refuses_it_for_other_protocols() {
    let (_dir, mut engine) = setup();
    let policy = crate::vpn_policy::Policy {
        only_advertised_routes: true,
        use_tunnel_dns: true,
        block_outside_dns: false,
    };
    let draft = ProfileDraft {
        vpn_policy: crate::vpn_policy::Edit::Set(Some(policy)),
        id: None,
        name: "Plain".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: serde_json::json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    };
    assert_eq!(
        engine
            .check_profile_draft(draft, None)
            .await
            .err()
            .as_deref(),
        Some("vpn_policy_profile_unsupported")
    );
}

#[test]
fn exported_configurations_are_bounded_and_named_by_format() {
    let (_dir, engine) = setup();
    assert_eq!(
        engine
            .configuration_export(None, &serde_json::json!([1]))
            .err()
            .as_deref(),
        Some("invalid_profile")
    );
    let big = serde_json::json!({"text": "x".repeat(crate::exports::MAX_BYTES)});
    assert_eq!(
        engine.configuration_export(None, &big).err().as_deref(),
        Some("export_too_large")
    );
    assert!(engine
        .configuration_export(None, &serde_json::json!({"type":"direct"}))
        .unwrap()
        .contains("direct"));
    assert_eq!(
        crate::exports::shared_text_file_name("otp-links").unwrap(),
        "thronium-otp.txt"
    );
    assert!(crate::exports::shared_text_file_name("../x").is_err());
}
