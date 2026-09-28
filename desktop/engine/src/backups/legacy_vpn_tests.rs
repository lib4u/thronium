use super::legacy::{self, Prepared, Scopes, VpnBindings};
use crate::{
    legacy_backup::{self as source, SourceArchive},
    otp::{Draft, Kind},
    store::CommitFault,
    Engine,
};
use serde_json::{json, Value};
use std::path::Path;
fn archive(name: &str) -> SourceArchive {
    source::read(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/legacy_backup/vpn/fixtures/archives")
            .join(name),
    )
    .unwrap()
}
fn prepared() -> Prepared {
    legacy::prepare(&archive("default-policy-parts-09.thrbackup"))
}
fn setup() -> (tempfile::TempDir, Engine) {
    let d = tempfile::tempdir().unwrap();
    let e = Engine::open(d.path(), Path::new("missing-core")).unwrap();
    (d, e)
}
fn auto() -> Scopes {
    Scopes {
        profiles: true,
        otp: true,
        vpn_bindings: VpnBindings::AutoLive,
        ..Default::default()
    }
}
fn review(p: &super::Preview) -> &Value {
    p.legacy.as_ref().unwrap()
}
fn wire(e: &Engine) -> Value {
    json!(e.store.library)
}
fn bytes(d: &Path) -> Vec<u8> {
    std::fs::read(d.join("library.json")).unwrap_or_default()
}
#[test]
fn legacy_vpn_auto_choice_freezes_cross_maps_revisions_and_emits_only_live_sources() {
    let (directory, mut e) = setup();
    let local = e
        .otp_save(
            "",
            "",
            Draft {
                name: "Same name".into(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                kind: Kind::Hotp,
                counter: "77".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let before = wire(&e);
    let disk = bytes(directory.path());
    let prepared = prepared();
    let plan = prepared.plan.as_ref().unwrap().clone();
    let otp = prepared.otp.as_ref().unwrap().clone();
    let first = e.preview_legacy_import(prepared.clone()).unwrap();
    assert_eq!(review(&first)["canApply"], false);
    assert_eq!(review(&first)["vpnBindingCount"], 2);
    assert_eq!(review(&first)["vpnBindingsPlanned"], 0);
    let no_otp = e
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                vpn_bindings: VpnBindings::AutoLive,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&no_otp)["canApply"], false);
    assert!(review(&no_otp)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["code"] == "legacy_vpn_bindings_require_otp"));
    let manual = e
        .legacy_backup_scopes(
            &no_otp.token,
            Scopes {
                vpn_bindings: VpnBindings::Manual,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&manual)["canApply"], false);
    let accepted = e.legacy_backup_scopes(&manual.token, auto()).unwrap();
    assert_eq!(review(&accepted)["canApply"], true, "{}", review(&accepted));
    assert_eq!(review(&accepted)["vpnBindingsPlanned"], 2);
    assert!(!review(&accepted)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["code"] == "legacy_otp_bindings_deferred"));
    let public = serde_json::to_string(&accepted).unwrap();
    for p in &plan.profiles {
        for k in ["username", "password"] {
            let value = p.config[k].as_str().unwrap();
            assert!(!public.contains(value));
        }
    }
    for entry in &otp.entries {
        assert!(!public.contains(&entry.value.secret));
    }
    assert_eq!(wire(&e), before);
    assert_eq!(bytes(directory.path()), disk);
    assert!(e.owned_core_process().is_none());
    // Refresh retains the prepared import identity, even across a legitimate local change.
    e.otp_save(
        "",
        "",
        Draft {
            name: "Unrelated".into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        e.restore_backup(&accepted.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = e.refresh_backup_preview(&accepted.token).unwrap();
    e.restore_backup(&refreshed.token).unwrap();
    assert_eq!(e.store.library.version, 4);
    for (profile_id, source) in &plan.vpn_bindings {
        let binding = &e.store.library.vpn_otp_bindings[profile_id];
        assert_eq!(binding.revision, source.revision);
        assert_eq!(binding.otp_id, otp.otp_ids[&source.otp_source_id]);
        assert_ne!(binding.otp_id, local["id"].as_str().unwrap());
        let profile = e.profile(profile_id).unwrap();
        assert_eq!(
            profile.vpn_policy,
            plan.profiles
                .iter()
                .find(|p| p.id == *profile_id)
                .unwrap()
                .vpn_policy
        );
        let request =
            Engine::build_with_library(&profile, &e.store.library, directory.path()).unwrap();
        let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
        if profile.config["type"] == "openconnect" {
            assert!(profile.config["form_entries"].to_string().contains("{otp}"));
            assert!(!core["endpoints"][0]["form_entries"]
                .to_string()
                .contains("{otp}"));
            assert!(core["endpoints"][0]["form_entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["name"] == "realm"));
        }
    }
    for entry in &otp.entries {
        assert!(e.store.library.otp.iter().any(|current| current == entry));
    }
    assert_eq!(
        e.store
            .library
            .otp
            .iter()
            .find(|entry| entry.id == local["id"])
            .unwrap()
            .value
            .counter,
        "77"
    );
    assert!(e.owned_core_process().is_none());
    let saved = e.export_backup().unwrap();
    drop(e);
    let mut reopened = Engine::open(directory.path(), Path::new("missing-core")).unwrap();
    let p = reopened.preview_backup(&saved).unwrap();
    reopened.restore_backup(&p.token).unwrap();
    assert_eq!(reopened.store.library.vpn_otp_bindings.len(), 2);
    assert_eq!(reopened.store.library.version, 4);
}
#[test]
fn legacy_vpn_eight_actual_archives_enforce_parts_schema_and_missing_invalid_otp_atomically() {
    for name in [
        "default-policy-parts-01.thrbackup",
        "default-policy-parts-08.thrbackup",
        "default-policy-parts-09.thrbackup",
        "default-policy-parts-31.thrbackup",
        "complete-schema-default-policy-parts-31.thrbackup",
        "policy-off-parts-09.thrbackup",
        "missing-otp-parts-09.thrbackup",
        "invalid-otp-parts-09.thrbackup",
    ] {
        let (_d, mut e) = setup();
        if name == "default-policy-parts-31.thrbackup" {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/legacy_backup/vpn/fixtures/archives")
                .join(name);
            assert_eq!(
                source::read(&path).err().as_deref(),
                Some("legacy_backup_invalid_schema")
            );
            continue;
        }
        let source = archive(name);
        let mut prepared = legacy::prepare(&source);
        prepared.scopes = auto();
        let before = wire(&e);
        let p = e.preview_legacy_import(prepared).unwrap();
        let expected = matches!(
            name,
            "default-policy-parts-09.thrbackup"
                | "complete-schema-default-policy-parts-31.thrbackup"
                | "policy-off-parts-09.thrbackup"
        );
        assert_eq!(review(&p)["canApply"], expected, "{name}: {}", review(&p));
        assert_eq!(wire(&e), before);
        if expected {
            e.restore_backup(&p.token).unwrap();
            assert_eq!(e.store.library.profiles.len(), 2);
            assert_eq!(e.store.library.vpn_otp_bindings.len(), 2);
            assert!(e
                .store
                .library
                .otp
                .iter()
                .any(|entry| entry.value.counter == "9007199254740993"));
        } else {
            assert_eq!(
                e.restore_backup(&p.token).unwrap_err(),
                "legacy_import_blocked"
            );
            assert_eq!(wire(&e), before);
        }
        assert!(e.owned_core_process().is_none());
    }
    let (_d, mut e) = setup();
    let p = e
        .preview_legacy_import(legacy::prepare(&archive(
            "default-policy-parts-08.thrbackup",
        )))
        .unwrap();
    let p = e
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                profiles: false,
                otp: true,
                vpn_bindings: VpnBindings::RequireChoice,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&p)["canApply"], true);
    e.restore_backup(&p.token).unwrap();
    assert!(e.store.library.profiles.is_empty());
    assert!(e.store.library.vpn_otp_bindings.is_empty());
    assert_eq!(e.store.library.otp.len(), 2);
}
#[test]
fn legacy_vpn_manual_static_challenge_and_unbound_literal_boundaries_are_explicit() {
    let mut source = archive("default-policy-parts-09.thrbackup");
    let db = source.database.as_mut().unwrap();
    let ovpn = db.profiles.iter().find(|p| p.kind == "openvpn").unwrap().id;
    db.profiles.retain(|p| p.id == ovpn);
    for group in &mut db.groups {
        group.columns.insert(
            "profiles_json".into(),
            source::SourceValue::Text(json!([ovpn]).to_string()),
        );
    }
    let (_d, mut e) = setup();
    let p = e.preview_legacy_import(legacy::prepare(&source)).unwrap();
    let p = e
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                vpn_bindings: VpnBindings::Manual,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(review(&p)["canApply"], true, "{}", review(&p));
    assert_eq!(review(&p)["vpnBindingsPlanned"], 0);
    e.restore_backup(&p.token).unwrap();
    assert_eq!(e.store.library.profiles.len(), 1);
    assert!(e.store.library.vpn_otp_bindings.is_empty());
    assert!(e.store.library.otp.is_empty());
    assert!(e.store.library.profiles[0].config["static_challenge"].is_string());
    let mut source = archive("default-policy-parts-09.thrbackup");
    source
        .database
        .as_mut()
        .unwrap()
        .profiles
        .iter_mut()
        .find(|p| p.kind == "openconnect")
        .unwrap()
        .outbound
        .as_object_mut()
        .unwrap()
        .remove("otp_profile_id");
    let p = e.preview_legacy_import(legacy::prepare(&source)).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    assert!(review(&p)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_vpn_binding_required"));
}
#[test]
fn legacy_vpn_commit_faults_preserve_complete_aggregate_and_undo_reader_boundary() {
    for fault in [
        CommitFault::BeforeRename,
        CommitFault::AfterRename,
        CommitFault::DirectorySync,
    ] {
        let (d, mut e) = setup();
        e.otp_save(
            "",
            "",
            Draft {
                name: "Original".into(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let old = wire(&e);
        let bytes_before = bytes(d.path());
        let mut prepared = prepared();
        prepared.scopes = auto();
        let p = e.preview_legacy_import(prepared).unwrap();
        assert_eq!(review(&p)["canApply"], true);
        let expected = json!(e.restore.as_ref().unwrap().library);
        e.store.fail_next_commit(fault);
        assert_eq!(
            e.restore_backup(&p.token).unwrap_err(),
            if fault == CommitFault::BeforeRename {
                "backup_restore_failed"
            } else {
                crate::store::Store::WRITTEN_UNCERTAIN
            }
        );
        let current = wire(&e);
        let disk: Value = serde_json::from_slice(&bytes(d.path())).unwrap();
        if fault == CommitFault::BeforeRename {
            assert_eq!(current, old);
            assert_eq!(bytes(d.path()), bytes_before);
        } else {
            assert_eq!(current, expected);
            assert_eq!(disk, expected);
            assert!(e.store.durability_uncertain());
        }
        assert!(e.owned_core_process().is_none());
    }
    let (_d, mut e) = setup();
    let original = wire(&e);
    let mut prepared = prepared();
    prepared.scopes = auto();
    let p = e.preview_legacy_import(prepared).unwrap();
    e.restore_backup(&p.token).unwrap();
    let undo = e.preview_previous_backup().unwrap();
    e.restore_backup(&undo.token).unwrap();
    let mut expected = original;
    expected["version"] = json!(4);
    assert_eq!(wire(&e), expected);
}
#[test]
fn legacy_vpn_source_override_graph_and_forged_cross_archive_reference_refuse() {
    let (_d, mut e) = setup();
    let mut s = archive("default-policy-parts-09.thrbackup");
    s.parts.settings = true; // Typed source variant; not the incomplete historical mask31 file.
    s.database
        .as_mut()
        .unwrap()
        .settings
        .push(source::SourceSetting {
            key: "use_dns_object".into(),
            value: "true".into(),
            columns: Default::default(),
        });
    let p = e.preview_legacy_import(legacy::prepare(&s)).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    assert!(review(&p)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_vpn_dns_override_unsupported"));
    let mut graph = archive("default-policy-parts-09.thrbackup");
    graph.database.as_mut().unwrap().groups[0]
        .columns
        .insert("front_proxy_id".into(), source::SourceValue::Integer(17));
    let p = e.preview_legacy_import(legacy::prepare(&graph)).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    assert!(review(&p)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_vpn_graph_unsupported"));
    let mut first = prepared();
    let second = prepared();
    first.otp.as_mut().unwrap().otp_ids = second.otp.unwrap().otp_ids;
    first.scopes = auto();
    let before = wire(&e);
    let p = e.preview_legacy_import(first).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    assert!(review(&p)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["code"] == "legacy_vpn_binding_missing"));
    assert_eq!(wire(&e), before);
    // An existing active session is never stopped merely to apply an import.
    let mut prepared = prepared();
    prepared.scopes = auto();
    let p = e.preview_legacy_import(prepared).unwrap();
    e.running = Some("owned-active".into());
    assert_eq!(
        e.restore_backup(&p.token).unwrap_err(),
        "backup_disconnect_first"
    );
    assert_eq!(wire(&e), before);
}

#[test]
fn legacy_vpn_automatic_choice_imports_start_and_live_without_spending_codes() {
    use crate::vpn_otp_bindings::Mode;
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/legacy-vpn-bindings/start-otp-parts-09.thrbackup");
    let source = source::read(&path).unwrap();
    let prepared = legacy::prepare(&source);
    let plan = prepared.plan.as_ref().unwrap();
    let id = plan
        .profiles
        .iter()
        .find(|p| p.config["type"] == "openvpn-client")
        .unwrap()
        .id
        .clone();
    let (_directory, mut e) = setup();
    let before = wire(&e);
    let p = e.preview_legacy_import(prepared).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    let rows = review(&p)["vpnBindings"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|row| row["mode"] == "auto-start" && row["manualAllowed"] == false));
    assert!(rows.iter().any(|row| row["mode"] == "auto-live"));
    // The previous API means live prompts only, never silently broaden it.
    let p = e.legacy_backup_scopes(&p.token, auto()).unwrap();
    assert_eq!(review(&p)["canApply"], false);
    let p = e
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                vpn_bindings: VpnBindings::Manual,
                ..auto()
            },
        )
        .unwrap();
    assert_eq!(review(&p)["canApply"], false);
    let p = e
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                otp: false,
                vpn_bindings: VpnBindings::Automatic,
                ..auto()
            },
        )
        .unwrap();
    assert_eq!(review(&p)["canApply"], false);
    let p = e
        .legacy_backup_scopes(
            &p.token,
            Scopes {
                vpn_bindings: VpnBindings::Automatic,
                ..auto()
            },
        )
        .unwrap();
    assert_eq!(review(&p)["canApply"], true, "{}", review(&p));
    assert!(review(&p)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["code"] == "legacy_vpn_bindings_auto_start"));
    assert_eq!(wire(&e), before);
    e.restore_backup(&p.token).unwrap();
    assert_eq!(e.store.library.version, 4);
    assert_eq!(e.store.library.vpn_otp_bindings[&id].mode, Mode::AutoStart);
    assert_eq!(
        e.store
            .library
            .vpn_otp_bindings
            .values()
            .filter(|b| b.mode == Mode::AutoLive)
            .count(),
        1
    );
    let profile = e.profile(&id).unwrap();
    let request =
        Engine::build_with_library(&profile, &e.store.library, _directory.path()).unwrap();
    assert!(request.core_config.unwrap().contains("prefix-{otp}"));
    assert!(e
        .store
        .library
        .otp
        .iter()
        .all(|o| o.value.counter == "9007199254740993"));
    let imported = wire(&e);
    let saved = e.export_backup().unwrap();
    drop(e);
    let mut e = Engine::open(_directory.path(), Path::new("missing-core")).unwrap();
    assert_eq!(wire(&e), imported);
    let p = e.preview_backup(&saved).unwrap();
    e.restore_backup(&p.token).unwrap();
    assert_eq!(wire(&e), imported);
    assert!(e.owned_core_process().is_none());
}
