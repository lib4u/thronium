use super::*;
use crate::store::ProfileKind;
use crate::{
    otp::{Draft, Kind},
    store::{CommitFault, Store},
    ProfileDraft,
};
use serde_json::{json, Value};

fn setup() -> (tempfile::TempDir, Engine, String, Entry) {
    let directory = tempfile::tempdir().unwrap();
    let mut engine =
        Engine::open(directory.path(), &directory.path().join("nonexistent-core")).unwrap();
    let id = engine.save_profile(ProfileDraft { vpn_policy: Default::default(), id: None, name: "Local VPN".into(), group_id: "personal".into(), kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"openconnect","server":"127.0.0.1","server_port":443,"username":"fixture-user","password":"fixture-password"}) }).unwrap();
    let metadata = engine
        .otp_save(
            "",
            "",
            Draft {
                name: "Public RFC".into(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                kind: Kind::Hotp,
                ..Draft::default()
            },
        )
        .unwrap();
    let entry = engine
        .store
        .library
        .otp
        .iter()
        .find(|entry| entry.id == metadata["id"])
        .unwrap()
        .clone();
    (directory, engine, id, entry)
}
fn save(engine: &mut Engine, profile_id: &str, entry: &Entry) -> BindingView {
    let view = engine.get_vpn_otp_binding(profile_id).unwrap();
    engine
        .save_vpn_otp_binding(SaveRequest {
            profile_id: profile_id.into(),
            edit_token: view.edit_token,
            otp_id: Some(entry.id.clone()),
            otp_revision: Some(entry.revision.clone()),
            mode: None,
        })
        .unwrap()
}
fn bytes(directory: &std::path::Path) -> Vec<u8> {
    std::fs::read(directory.join("library.json")).unwrap()
}
fn wire(engine: &Engine) -> Value {
    json!(engine.store.library)
}

#[test]
fn explicit_crud_metadata_privacy_revisions_and_no_core() {
    let (directory, mut engine, profile, entry) = setup();
    let before = bytes(directory.path());
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    assert!(view.supported && view.binding.is_none());
    assert!(view.hotp_supported);
    let text = serde_json::to_string(&view).unwrap();
    for secret in [
        &entry.value.secret,
        "fixture-password",
        "fixture-user",
        &entry.id,
    ] {
        assert!(!text.contains(secret));
    }
    assert_eq!(bytes(directory.path()), before);
    assert!(engine.owned_core_process().is_none());
    let bound = save(&mut engine, &profile, &entry);
    assert!(bound.binding.is_some());
    assert_eq!(engine.store.library.version, 3);
    assert_eq!(engine.store.library.otp[0].value.counter, "0");
    assert_eq!(
        engine.otp_remove(&entry.id, &entry.revision).unwrap_err(),
        "otp_in_use"
    );
    let token = bound.edit_token;
    let removed = engine
        .save_vpn_otp_binding(SaveRequest {
            profile_id: profile.clone(),
            edit_token: token.clone(),
            otp_id: None,
            otp_revision: None,
            mode: None,
        })
        .unwrap();
    assert!(removed.binding.is_none());
    assert_eq!(engine.store.library.version, 3);
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile.clone(),
                edit_token: token,
                otp_id: None,
                otp_revision: None,
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_binding_changed"
    );
    engine.otp_remove(&entry.id, &entry.revision).unwrap();
    assert_eq!(engine.store.library.version, 3);
    assert!(engine.owned_core_process().is_none());
}
#[test]
fn tokens_guard_exact_profile_and_binding_but_not_unrelated_otp_edits() {
    let (_directory, mut engine, profile, entry) = setup();
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    engine
        .otp_save(
            "",
            "",
            Draft {
                name: "Unrelated".into(),
                secret: entry.value.secret.clone(),
                ..Draft::default()
            },
        )
        .unwrap();
    let bound = engine
        .save_vpn_otp_binding(SaveRequest {
            profile_id: profile.clone(),
            edit_token: view.edit_token,
            otp_id: Some(entry.id.clone()),
            otp_revision: Some(entry.revision.clone()),
            mode: None,
        })
        .unwrap();
    let mut changed = entry.value.clone();
    changed.name = "renamed".into();
    engine
        .otp_save(&entry.id, &entry.revision, changed)
        .unwrap();
    let before = wire(&engine);
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile.clone(),
                edit_token: bound.edit_token,
                otp_id: Some(entry.id.clone()),
                otp_revision: Some(entry.revision.clone()),
                mode: None,
            })
            .err()
            .unwrap(),
        "otp_changed"
    );
    assert_eq!(wire(&engine), before);
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    let mut config = engine.store.library.profiles[0].config.clone();
    config["password"] = json!("updated-password");
    engine
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: Some(profile.clone()),
            name: "Updated".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config,
        })
        .unwrap();
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile,
                edit_token: view.edit_token,
                otp_id: None,
                otp_revision: None,
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_binding_changed"
    );
}
#[test]
fn bounded_expiring_tokens_and_unsupported_live_source_never_write() {
    let (directory, mut engine, profile, entry) = setup();
    let old = engine.get_vpn_otp_binding(&profile).unwrap();
    for _ in 0..MAX_EDITS {
        engine.get_vpn_otp_binding(&profile).unwrap();
    }
    assert_eq!(engine.vpn_otp_binding_edits.0.len(), MAX_EDITS);
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile.clone(),
                edit_token: old.edit_token,
                otp_id: None,
                otp_revision: None,
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_binding_changed"
    );
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    engine.vpn_otp_binding_edits.0.back_mut().unwrap().created =
        Instant::now() - EDIT_TTL - Duration::from_secs(1);
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile.clone(),
                edit_token: view.edit_token,
                otp_id: None,
                otp_revision: None,
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_binding_changed"
    );
    engine
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: Some(profile.clone()),
            name: "Unsupported Start placeholder".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"openconnect","password":"{otp}"}),
        })
        .unwrap();
    let before = bytes(directory.path());
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    assert!(!view.supported);
    assert_eq!(
        view.reason.as_deref(),
        Some("vpn_otp_start_placeholder_unsupported")
    );
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile,
                edit_token: view.edit_token,
                otp_id: Some(entry.id),
                otp_revision: Some(entry.revision),
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_start_placeholder_unsupported"
    );
    assert_eq!(before, bytes(directory.path()));
    assert!(engine.owned_core_process().is_none());
}
#[test]
fn library_v3_backup_restore_and_removal_are_monotonic() {
    let (directory, mut engine, profile, entry) = setup();
    let old = engine.export_backup().unwrap();
    save(&mut engine, &profile, &entry);
    let backup = engine.export_backup().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&backup).unwrap()["library"]["vpnOtpBindings"][&profile]
            ["otpId"],
        entry.id
    );
    engine.delete_profiles(vec![profile.clone()]).unwrap();
    assert!(engine.store.library.vpn_otp_bindings.is_empty());
    assert_eq!(engine.store.library.version, 3);
    let preview = engine.preview_backup(&backup).unwrap();
    engine.restore_backup(&preview.token).unwrap();
    assert_eq!(
        engine.store.library.vpn_otp_bindings[&profile].otp_id,
        entry.id
    );
    let preview = engine.preview_backup(&old).unwrap();
    engine.restore_backup(&preview.token).unwrap();
    assert!(engine.store.library.vpn_otp_bindings.is_empty());
    assert_eq!(engine.store.library.version, 3);
    engine.otp_import("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(engine.store.library.version, 3);
    let current = engine.store.library.otp[0].clone();
    engine
        .otp_save(&current.id, &current.revision, current.value)
        .unwrap();
    drop(engine);
    let reopened = Store::open(directory.path()).unwrap();
    assert_eq!(reopened.library.version, 3);
}
#[test]
fn malformed_binding_maps_reject_before_value_migration_or_write() {
    let (directory, mut engine, profile, entry) = setup();
    save(&mut engine, &profile, &entry);
    let valid = wire(&engine);
    for change in [
        json!({"revision":uuid::Uuid::new_v4().to_string(),"otpId":entry.id,"mode":"future"}),
        json!({"revision":uuid::Uuid::new_v4().to_string(),"otpId":"missing","mode":"auto-live"}),
        json!({"revision":"not-uuid","otpId":entry.id,"mode":"auto-live"}),
        json!({"revision":uuid::Uuid::new_v4().to_string(),"otpId":entry.id,"mode":"auto-live","secret":"foreign"}),
    ] {
        let mut invalid = valid.clone();
        invalid["vpnOtpBindings"][&profile] = change;
        let backup =
            json!({"format":"thronium-backup","version":1,"createdAt":1,"library":invalid});
        assert!(engine.preview_backup(&backup.to_string()).is_err());
        assert_eq!(wire(&engine), valid);
    }
    let binding = valid["vpnOtpBindings"][&profile].to_string();
    let body = serde_json::to_string(&valid).unwrap();
    let once = format!("\"vpnOtpBindings\":{{\"{profile}\":{binding}}}");
    assert!(body.contains(&once));
    let duplicate = body.replace(
        &once,
        &format!("\"vpnOtpBindings\":{{\"{profile}\":{binding},\"{profile}\":{binding}}}"),
    );
    assert!(serde_json::from_str::<Library>(&duplicate).is_err());
    assert!(engine.preview_backup(&format!("{{\"format\":\"thronium-backup\",\"version\":1,\"createdAt\":1,\"library\":{duplicate}}}")).is_err());
    drop(engine);
    std::fs::write(directory.path().join("library.json"), duplicate).unwrap();
    assert_eq!(
        Store::open(directory.path()).err().unwrap(),
        "library_corrupt"
    );
}
#[test]
fn duplicate_fields_and_dangling_profile_cannot_be_smuggled_through_json() {
    let (_directory, mut engine, profile, entry) = setup();
    save(&mut engine, &profile, &entry);
    let valid = engine.export_backup().unwrap();
    let duplicate = valid.replace(
        &format!("\"otpId\": \"{}\"", entry.id),
        &format!("\"otpId\": \"{}\", \"otpId\": \"{}\"", entry.id, entry.id),
    );
    assert_ne!(valid, duplicate);
    assert!(engine.preview_backup(&duplicate).is_err());
    let body = wire(&engine);
    let mut bad = body.clone();
    bad["profiles"] = json!([]);
    bad["selected"] = Value::Null;
    assert!(engine
        .preview_backup(
            &json!({"format":"thronium-backup","version":1,"createdAt":1,"library":bad})
                .to_string()
        )
        .is_err());
    let mut bad = body.clone();
    bad["version"] = json!(2);
    assert!(engine
        .preview_backup(
            &json!({"format":"thronium-backup","version":1,"createdAt":1,"library":bad})
                .to_string()
        )
        .is_err());
    assert_eq!(wire(&engine), body);
}
#[test]
fn imported_profile_json_cannot_claim_a_local_otp_binding() {
    let (_directory, mut engine, _profile, entry) = setup();
    let imported=engine.save_profile(ProfileDraft { vpn_policy: Default::default(),id:None,name:"Foreign JSON".into(),group_id:"personal".into(),kind:ProfileKind::SingBoxOutbound,
        config:json!({"type":"openconnect","otpId":entry.id,"vpnOtpBindings":{"fake":{"otpId":entry.id,"mode":"auto-live"}}})}).unwrap();
    assert!(engine
        .get_vpn_otp_binding(&imported)
        .unwrap()
        .binding
        .is_none());
    assert!(engine.store.library.vpn_otp_bindings.is_empty());
}
#[test]
fn identity_changes_ignore_labels_but_cover_each_cryptographic_parameter() {
    let (_directory, _engine, _profile, entry) = setup();
    let mut edited = entry.clone();
    edited.value.name = "Renamed".into();
    edited.value.issuer = "Metadata".into();
    edited.value.counter = "1".into();
    edited.revision = uuid::Uuid::new_v4().to_string();
    assert!(same_identity(&entry, &edited));
    edited.value.secret = entry.value.secret.to_lowercase();
    assert!(same_identity(&entry, &edited));
    for changed in ["id", "secret", "algorithm", "kind", "digits", "period"] {
        let mut other = entry.clone();
        match changed {
            "id" => other.id = uuid::Uuid::new_v4().to_string(),
            "secret" => other.value.secret = "JBSWY3DPEHPK3PXP".into(),
            "algorithm" => other.value.algorithm = crate::otp::Algorithm::SHA256,
            "kind" => other.value.kind = Kind::Totp,
            "digits" => other.value.digits = 8,
            "period" => other.value.period = 60,
            _ => unreachable!(),
        };
        assert!(!same_identity(&entry, &other), "{changed}");
    }
}
#[test]
fn durable_hotp_uses_next_counter_and_refuses_stale_editor_or_repeated_reservation() {
    let (directory, mut engine, profile, entry) = setup();
    save(&mut engine, &profile, &entry);
    assert_eq!(entry.value.code_at(0).unwrap().code, "755224");
    let updated = engine.reserve_vpn_hotp(&entry).unwrap();
    assert_eq!(updated.value.counter, "1");
    assert_eq!(updated.value.code_at(0).unwrap().code, "287082");
    assert_ne!(updated.revision, entry.revision);
    assert!(!engine.store.durability_uncertain());
    let stored: Library = serde_json::from_slice(&bytes(directory.path())).unwrap();
    assert!(stored.otp[0] == updated);
    assert_eq!(
        engine.reserve_vpn_hotp(&entry).err().unwrap(),
        "otp_changed"
    );
    assert_eq!(
        engine
            .otp_save(&entry.id, &entry.revision, entry.value.clone())
            .err()
            .unwrap(),
        "otp_changed"
    );
    let codes = engine.otp_codes(std::slice::from_ref(&entry.id)).unwrap();
    assert_eq!(codes[0]["code"], "287082");
    assert_eq!(codes[0]["counter"], "1");
    assert!(codes[0].get("revision").is_none());
    assert_eq!(engine.store.library.otp[0].value.counter, "1");
    drop(engine);
    assert_eq!(
        Store::open(directory.path()).unwrap().library.otp[0]
            .value
            .counter,
        "1"
    );
}
#[test]
fn counter_boundaries_preserve_exact_large_decimal_and_never_wrap() {
    for initial in [
        "9007199254740993",
        "9223372036854775806",
        "9223372036854775807",
    ] {
        let (directory, mut engine, _profile, entry) = setup();
        let mut draft = entry.value.clone();
        draft.counter = initial.into();
        engine.otp_save(&entry.id, &entry.revision, draft).unwrap();
        let entry = engine.store.library.otp[0].clone();
        let before = bytes(directory.path());
        if initial == "9223372036854775807" {
            assert_eq!(
                engine.reserve_vpn_hotp(&entry).err().unwrap(),
                "vpn_otp_counter_exhausted"
            );
            assert_eq!(bytes(directory.path()), before);
        } else {
            assert_eq!(
                engine.reserve_vpn_hotp(&entry).unwrap().value.counter,
                (initial.parse::<u64>().unwrap() + 1).to_string()
            );
        }
    }
}
#[test]
fn failure_before_rename_spends_nothing_and_allows_exact_retry() {
    let (directory, mut engine, _profile, entry) = setup();
    let before = bytes(directory.path());
    engine.store.fail_next_commit(CommitFault::BeforeRename);
    assert_eq!(
        engine.reserve_vpn_hotp(&entry).err().unwrap(),
        "vpn_otp_save_failed"
    );
    assert_eq!(bytes(directory.path()), before);
    assert!(engine.store.library.otp[0] == entry);
    assert!(!engine.store.durability_uncertain());
    assert_eq!(engine.reserve_vpn_hotp(&entry).unwrap().value.counter, "1");
}
#[test]
fn failures_after_rename_keep_replaced_state_and_block_until_explicit_reopen() {
    for point in [CommitFault::AfterRename, CommitFault::DirectorySync] {
        let (directory, mut engine, _profile, entry) = setup();
        engine.store.fail_next_commit(point);
        assert_eq!(
            engine.reserve_vpn_hotp(&entry).err().unwrap(),
            "vpn_otp_save_failed"
        );
        let stored: Library = serde_json::from_slice(&bytes(directory.path())).unwrap();
        assert_eq!(stored.otp[0].value.counter, "1");
        assert!(stored.otp[0] == engine.store.library.otp[0]);
        assert!(engine.store.durability_uncertain());
        let current = engine.store.library.otp[0].clone();
        assert_eq!(
            engine.reserve_vpn_hotp(&current).err().unwrap(),
            "vpn_otp_save_failed"
        );
        // An unrelated successful commit is not an explicit durability reconciliation.
        engine
            .otp_save(
                "",
                "",
                Draft {
                    secret: entry.value.secret.clone(),
                    ..Draft::default()
                },
            )
            .unwrap();
        assert!(engine.store.durability_uncertain());
        assert_eq!(
            engine.reserve_vpn_hotp(&current).err().unwrap(),
            "vpn_otp_save_failed"
        );
        drop(engine);
        let mut reopened =
            Engine::open(directory.path(), &directory.path().join("nonexistent-core")).unwrap();
        assert!(!reopened.store.durability_uncertain());
        let current = reopened.store.library.otp[0].clone();
        assert_eq!(
            reopened.reserve_vpn_hotp(&current).unwrap().value.counter,
            "2"
        );
    }
}
#[test]
fn binding_commit_failure_is_distinct_and_does_not_advance_hotp() {
    let (_directory, mut engine, profile, entry) = setup();
    let view = engine.get_vpn_otp_binding(&profile).unwrap();
    engine.store.fail_next_commit(CommitFault::AfterRename);
    assert_eq!(
        engine
            .save_vpn_otp_binding(SaveRequest {
                profile_id: profile.clone(),
                edit_token: view.edit_token,
                otp_id: Some(entry.id.clone()),
                otp_revision: Some(entry.revision.clone()),
                mode: None,
            })
            .err()
            .unwrap(),
        "vpn_otp_binding_save_failed"
    );
    assert!(engine.store.library.vpn_otp_bindings.contains_key(&profile));
    assert_eq!(engine.store.library.otp[0].value.counter, "0");
    assert!(engine.store.durability_uncertain());
}
#[test]
fn deleting_a_group_removes_only_its_binding_and_preserves_move_only_bindings() {
    let (_directory, mut engine, profile, entry) = setup();
    save(&mut engine, &profile, &entry);
    let group = engine
        .save_group(crate::subscriptions::GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Temporary group".into(),
            subscription: None,
            proxy_chain: None,
        })
        .unwrap();
    engine.move_profiles(vec![profile.clone()], &group).unwrap();
    engine.delete_group(&group, false).unwrap();
    assert!(engine.store.library.vpn_otp_bindings.contains_key(&profile));
    let group = engine
        .save_group(crate::subscriptions::GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Delete with profile".into(),
            subscription: None,
            proxy_chain: None,
        })
        .unwrap();
    engine.move_profiles(vec![profile.clone()], &group).unwrap();
    engine.delete_group(&group, true).unwrap();
    assert!(!engine.store.library.vpn_otp_bindings.contains_key(&profile));
    assert_eq!(engine.store.library.otp[0].id, entry.id);
    assert_eq!(engine.store.library.version, 3);
}
#[test]
fn subscription_replacement_removes_deleted_binding_without_importing_foreign_reference() {
    let (_directory, mut engine, _profile, entry) = setup();
    let settings=serde_json::from_value(json!({"url":"http://127.0.0.1:9/synthetic-not-requested","inheritDefaults":false,"headers":{"x-hwid":"synthetic-id","x-device-os":"synthetic-os","x-ver-os":"synthetic-version","x-device-model":"synthetic-model"}})).unwrap();
    let group = engine
        .save_group(crate::subscriptions::GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Synthetic subscription".into(),
            subscription: Some(settings),
            proxy_chain: None,
        })
        .unwrap();
    let draft = |kind: &str| ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: kind.into(),
        group_id: group.clone(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":kind,"server":"127.0.0.1","server_port":443}),
    };
    let request = engine.subscription_request(&group).unwrap();
    let token = engine
        .subscription_downloaded(
            request,
            crate::subscriptions::Download {
                metadata: Default::default(),
                body: String::new(),
                usage: None,
            },
        )
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_string();
    engine
        .preview_subscription(&token, vec![draft("openconnect"), draft("direct")])
        .unwrap();
    engine.apply_subscription(&token).unwrap();
    let profile = engine
        .store
        .library
        .profiles
        .iter()
        .find(|profile| profile.group_id == group && profile.config["type"] == "openconnect")
        .unwrap()
        .id
        .clone();
    save(&mut engine, &profile, &entry);
    let request = engine.subscription_request(&group).unwrap();
    let token = engine
        .subscription_downloaded(
            request,
            crate::subscriptions::Download {
                metadata: Default::default(),
                body: String::new(),
                usage: None,
            },
        )
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_string();
    engine
        .preview_subscription(&token, vec![draft("direct")])
        .unwrap();
    engine.apply_subscription(&token).unwrap();
    assert!(!engine
        .store
        .library
        .profiles
        .iter()
        .any(|p| p.id == profile));
    assert!(engine.store.library.vpn_otp_bindings.is_empty());
    assert_eq!(engine.store.library.otp[0].id, entry.id);
    assert_eq!(engine.store.library.version, 3);
    assert!(engine.owned_core_process().is_none());
}
#[tokio::test]
async fn old_settings_form_and_selection_failures_never_restore_a_consumed_counter() {
    let (directory, mut engine, profile, entry) = setup();
    let previous = crate::settings::section(&engine.store.library, "appearance");
    let mut changed = previous.clone();
    changed["theme"] = json!("dark");
    let used = engine.reserve_vpn_hotp(&entry).unwrap();
    engine.store.fail_next_commit(CommitFault::AfterRename);
    assert!(engine
        .save_settings("appearance", previous.clone(), changed.clone())
        .await
        .is_err());
    assert!(engine.store.library.otp[0] == used);
    let persisted: Library = serde_json::from_slice(&bytes(directory.path())).unwrap();
    assert!(persisted.otp[0] == used);
    engine
        .save_settings("appearance", previous, changed)
        .await
        .unwrap();
    engine.store.fail_next_commit(CommitFault::DirectorySync);
    assert!(engine.select(&profile).is_err());
    assert!(engine.store.library.otp[0] == used);
    assert_eq!(
        engine.store.library.selected.as_deref(),
        Some(profile.as_str())
    );
    let persisted: Library = serde_json::from_slice(&bytes(directory.path())).unwrap();
    assert!(persisted.otp[0] == used);
    assert!(engine.store.durability_uncertain());
    assert!(engine.owned_core_process().is_none());
}
#[test]
fn future_library_and_binding_schema_report_unsupported_before_typed_decode() {
    let (directory, mut engine, profile, entry) = setup();
    save(&mut engine, &profile, &entry);
    let mut future = wire(&engine);
    future["version"] = json!(9);
    future["vpnOtpBindings"][&profile]["mode"] = json!("future-policy");
    assert_eq!(
        engine
            .preview_backup(
                &json!({"format":"thronium-backup","version":1,"createdAt":1,"library":future})
                    .to_string()
            )
            .err()
            .unwrap(),
        "backup_version_unsupported"
    );
    drop(engine);
    std::fs::write(directory.path().join("library.json"), future.to_string()).unwrap();
    assert_eq!(
        Store::open(directory.path()).err().unwrap(),
        "library_version_unsupported"
    );
    future["version"] = json!(3);
    std::fs::write(directory.path().join("library.json"), future.to_string()).unwrap();
    assert_eq!(
        Store::open(directory.path()).err().unwrap(),
        "library_corrupt"
    );
}
#[test]
fn remote_update_retaining_uuid_cannot_redirect_a_local_binding() {
    let (_directory, mut engine, _profile, entry) = setup();
    let settings=serde_json::from_value(json!({"url":"http://127.0.0.1:9/not-requested","inheritDefaults":false,"headers":{"x-hwid":"synthetic-id","x-device-os":"synthetic-os","x-ver-os":"synthetic-version","x-device-model":"synthetic-model"}})).unwrap();
    let group = engine
        .save_group(crate::subscriptions::GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Remote profile".into(),
            subscription: Some(settings),
            proxy_chain: None,
        })
        .unwrap();
    let apply = |engine: &mut Engine, password: &str, name: &str| {
        let request = engine.subscription_request(&group).unwrap();
        let token = engine
            .subscription_downloaded(
                request,
                crate::subscriptions::Download {
                    metadata: Default::default(),
                    body: String::new(),
                    usage: None,
                },
            )
            .unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_string();
        engine.preview_subscription(&token,vec![ProfileDraft { vpn_policy: Default::default(),id:None,name:name.into(),group_id:group.clone(),kind:ProfileKind::SingBoxOutbound,config:json!({"type":"openconnect","server":"127.0.0.1","server_port":443,"password":password})}]).unwrap();
        engine.apply_subscription(&token).unwrap();
    };
    apply(&mut engine, "initial-password", "Original name");
    let profile = engine
        .store
        .library
        .profiles
        .iter()
        .find(|profile| profile.group_id == group)
        .unwrap()
        .id
        .clone();
    let binding = save(&mut engine, &profile, &entry).binding.unwrap();
    apply(&mut engine, "initial-password", "Renamed only");
    assert!(engine.store.library.vpn_otp_bindings[&profile] == binding);
    apply(&mut engine, "remote-changed-password", "Renamed only");
    assert_eq!(
        engine
            .store
            .library
            .profiles
            .iter()
            .find(|profile| profile.group_id == group)
            .unwrap()
            .id,
        profile
    );
    assert!(!engine.store.library.vpn_otp_bindings.contains_key(&profile));
    assert_eq!(engine.store.library.otp[0].value.counter, "0");
    assert!(engine.owned_core_process().is_none());
}
