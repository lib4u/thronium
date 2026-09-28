//! Independent positional ordering contract. No Core, sockets or OTP generation.
#![cfg(unix)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt, path::Path};
use thronium_engine::{
    subscriptions::{Download, GroupDraft},
    Engine, ProfileDraft,
};

struct App {
    dir: tempfile::TempDir,
    engine: Engine,
    ids: BTreeMap<String, String>,
}
impl App {
    fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path(), &dir.path().join("absent-core37")).unwrap();
        Self {
            dir,
            engine,
            ids: BTreeMap::new(),
        }
    }
    fn interleaved() -> Self {
        let mut app = Self::empty();
        let foreign = group(&mut app.engine, "Foreign", false);
        for name in ["A", "x", "B", "y", "C", "z", "D", "E"] {
            let gid = if name.as_bytes()[0].is_ascii_uppercase() {
                "personal"
            } else {
                &foreign
            };
            let id = save(&mut app.engine, name, gid, endpoint(name));
            app.ids.insert(name.into(), id);
        }
        app
    }
    fn id(&self, name: &str) -> String {
        self.ids[name].clone()
    }
    fn order(&self) -> Vec<String> {
        self.engine
            .store
            .library
            .profiles
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }
    fn members(&self, gid: &str) -> Vec<String> {
        self.engine
            .store
            .library
            .profiles
            .iter()
            .filter(|p| p.group_id == gid)
            .map(|p| p.name.clone())
            .collect()
    }
    fn move_to(&mut self, a: &str, b: &str, after: bool) -> Result<(), String> {
        self.engine.reorder_profile(&self.id(a), &self.id(b), after)
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("library.json")).unwrap()
    }
    fn rest(&self) -> Value {
        let mut v = json!(self.engine.store.library);
        v.as_object_mut().unwrap().remove("profiles");
        v
    }
    fn profiles(&self) -> BTreeMap<String, Value> {
        self.engine
            .store
            .library
            .profiles
            .iter()
            .map(|p| (p.id.clone(), json!(p)))
            .collect()
    }
}
fn endpoint(name: &str) -> Value {
    json!({"type":"socks","server":"127.0.0.1","server_port":20000+name.as_bytes()[0] as u16,"version":"5"})
}
fn draft(name: &str, gid: &str, config: Value) -> ProfileDraft {
    serde_json::from_value(
        json!({"name":name,"groupId":gid,"kind":"sing-box-outbound","config":config}),
    )
    .unwrap()
}
fn save(e: &mut Engine, name: &str, gid: &str, config: Value) -> String {
    e.save_profile(draft(name, gid, config)).unwrap()
}
fn group(e: &mut Engine, name: &str, subscription: bool) -> String {
    let d:GroupDraft=serde_json::from_value(json!({"name":name,"subscription":if subscription {json!({"url":"https://subscription.fixture.invalid/never-downloaded"})}else{Value::Null}})).unwrap();
    e.save_group(d).unwrap()
}
fn stamp(path: &Path) -> (Vec<u8>, u64, i64, i64) {
    let m = std::fs::metadata(path).unwrap();
    (
        std::fs::read(path).unwrap(),
        m.ino(),
        m.mtime(),
        m.mtime_nsec(),
    )
}
fn expect_order(app: &App, names: &[&str]) {
    assert_eq!(app.members("personal"), names);
}
fn unchanged(app: &App, profiles: &BTreeMap<String, Value>, rest: &Value) {
    assert!(
        app.profiles() == *profiles,
        "profile content/metadata changed"
    );
    assert!(app.rest() == *rest, "non-order library state changed");
    assert!(app.engine.owned_core_process().is_none());
}

#[test]
fn qt_after_oracle_preserves_foreign_slots_and_profile_payloads() {
    let oracle: Value =
        serde_json::from_str(include_str!("fixtures/profile-order37/qt-after-cases.json")).unwrap();
    assert_eq!(oracle["qtVersion"], "6.11.2");
    let names = ["A", "B", "C", "D", "E"];
    let mut count = 0;
    for case in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["accepted"] == true)
    {
        let mut app = App::interleaved();
        let contents = app.profiles();
        let rest = app.rest();
        let before = app.order();
        let expected: Vec<String> = case["after"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| names[(n.as_u64().unwrap() / 11 - 1) as usize].into())
            .collect();
        let file = app.dir.path().join("library.json");
        let original = stamp(&file);
        app.move_to(
            names[case["sourceIndex"].as_u64().unwrap() as usize],
            names[case["targetIndex"].as_u64().unwrap() as usize],
            true,
        )
        .unwrap();
        assert_eq!(app.members("personal"), expected);
        for index in [1, 3, 5] {
            assert_eq!(app.order()[index], before[index], "foreign slot moved");
        }
        unchanged(&app, &contents, &rest);
        if expected == names {
            assert!(stamp(&file) == original, "Qt-equivalent no-op rewrote disk");
        }
        let stored: Value = serde_json::from_slice(&app.disk()).unwrap();
        assert!(stored == json!(app.engine.store.library));
        count += 1;
    }
    assert_eq!(count, 25);
}

#[test]
fn before_anchor_has_explicit_front_back_and_adjacent_semantics() {
    for (source, target, expected) in [
        ("A", "E", vec!["B", "C", "D", "A", "E"]),
        ("E", "A", vec!["E", "A", "B", "C", "D"]),
        ("C", "B", vec!["A", "C", "B", "D", "E"]),
        ("B", "D", vec!["A", "C", "B", "D", "E"]),
        ("D", "B", vec!["A", "D", "B", "C", "E"]),
        ("A", "A", vec!["A", "B", "C", "D", "E"]),
        ("C", "C", vec!["A", "B", "C", "D", "E"]),
        ("D", "E", vec!["A", "B", "C", "D", "E"]),
        ("B", "C", vec!["A", "B", "C", "D", "E"]),
        ("E", "D", vec!["A", "B", "C", "E", "D"]),
    ] {
        let mut app = App::interleaved();
        let contents = app.profiles();
        let rest = app.rest();
        app.move_to(source, target, false).unwrap();
        expect_order(&app, &expected);
        unchanged(&app, &contents, &rest);
        assert_eq!(
            [&app.order()[1], &app.order()[3], &app.order()[5]],
            ["x", "y", "z"]
        );
    }
}

#[test]
fn noops_and_invalid_current_anchors_leave_disk_and_preview_valid() {
    let mut app = App::interleaved();
    let backup = app.engine.export_backup().unwrap();
    let preview = app.engine.preview_backup(&backup).unwrap();
    let file = app.dir.path().join("library.json");
    let before = stamp(&file);
    let memory = json!(app.engine.store.library);
    for (a, b, after) in [
        ("A", "A", true),
        ("E", "E", false),
        ("B", "A", true),
        ("D", "E", false),
    ] {
        app.move_to(a, b, after).unwrap();
    }
    assert_eq!(
        app.engine
            .reorder_profile("missing", &app.id("A"), true)
            .unwrap_err(),
        "profile_not_found"
    );
    assert_eq!(
        app.engine
            .reorder_profile(&app.id("A"), "missing", false)
            .unwrap_err(),
        "profile_not_found"
    );
    assert_eq!(
        app.move_to("A", "x", false).unwrap_err(),
        "invalid_profile_order"
    );
    assert_eq!(
        app.move_to("x", "E", true).unwrap_err(),
        "invalid_profile_order"
    );
    assert!(stamp(&file) == before);
    assert!(json!(app.engine.store.library) == memory);
    app.engine.restore_backup(&preview.token).unwrap(); // Still valid; this explicit restore may write.
    expect_order(&app, &["A", "B", "C", "D", "E"]);
}

#[test]
fn rejected_disk_commit_keeps_memory_and_noop_does_not_attempt_a_write() {
    let mut app = App::interleaved();
    let file = app.dir.path().join("library.json");
    let saved = app.dir.path().join("owned-original.json");
    let before = stamp(&file);
    let memory = json!(app.engine.store.library);
    let status = app.engine.backup_status();
    std::fs::rename(&file, &saved).unwrap();
    std::fs::create_dir(&file).unwrap();
    app.move_to("B", "A", true).unwrap();
    app.move_to("C", "C", false).unwrap();
    assert!(
        app.move_to("E", "A", false).is_err(),
        "replace of an owned directory unexpectedly succeeded"
    );
    assert!(
        json!(app.engine.store.library) == memory,
        "failed pre-rename commit published memory"
    );
    assert_eq!(app.engine.backup_status(), status);
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&saved, &file).unwrap();
    assert!(stamp(&file) == before);
    app.move_to("E", "A", false).unwrap();
    expect_order(&app, &["E", "A", "B", "C", "D"]);
}

#[test]
fn reorder_preserves_vpn_policy_otp_revision_bindings_selection_and_configs() {
    let mut app = App::interleaved();
    let id = save(
        &mut app.engine,
        "VPN",
        "personal",
        json!({"type":"openvpn-client","server":"127.0.0.1","server_port":1194,"system":false,"static_challenge":"Owned unused challenge"}),
    );
    let mut d = draft("VPN", "personal", app.engine.profile(&id).unwrap().config);
    d.id = Some(id.clone());
    d.vpn_policy =
        thronium_engine::vpn_policy::Edit::Set(Some(thronium_engine::vpn_policy::Policy {
            only_advertised_routes: true,
            use_tunnel_dns: true,
            block_outside_dns: false,
        }));
    app.engine.save_profile(d).unwrap();
    let otp = app
        .engine
        .otp_save(
            "",
            "",
            thronium_engine::otp::Draft {
                name: "Unused HOTP order37".into(),
                secret: "JBSWY3DPEHPK3PXP".into(),
                kind: thronium_engine::otp::Kind::Hotp,
                counter: "9007199254740993".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let edit = app.engine.get_vpn_otp_binding(&id).unwrap();
    app.engine
        .save_vpn_otp_binding(thronium_engine::vpn_otp_bindings::SaveRequest {
            profile_id: id.clone(),
            edit_token: edit.edit_token,
            otp_id: Some(otp["id"].as_str().unwrap().into()),
            otp_revision: Some(otp["revision"].as_str().unwrap().into()),
            mode: None,
        })
        .unwrap();
    app.engine.select(&id).unwrap();
    let profiles = app.profiles();
    let rest = app.rest();
    let otp_before = app.engine.otp_list();
    app.engine
        .reorder_profile(&id, &app.id("A"), false)
        .unwrap();
    unchanged(&app, &profiles, &rest);
    assert!(app.engine.otp_list() == otp_before);
    assert_eq!(
        app.engine.store.library.otp[0].value.counter,
        "9007199254740993"
    );
    assert_eq!(app.engine.snapshot().selected.as_deref(), Some(id.as_str()));
    assert_eq!(app.members("personal")[0], "VPN");
    let expected = json!(app.engine.store.library);
    assert_eq!(expected["version"], 4);
    let backup = app.engine.export_backup().unwrap();
    let mut restored = App::empty();
    let preview = restored.engine.preview_backup(&backup).unwrap();
    restored.engine.restore_backup(&preview.token).unwrap();
    assert!(
        json!(restored.engine.store.library) == expected,
        "full backup changed reordered Library4 policy/OTP/binding metadata"
    );
    assert!(restored.engine.otp_list() == otp_before);
}

#[test]
fn reordered_profile_vector_survives_reopen_and_full_backup_roundtrip() {
    let mut app = App::interleaved();
    app.engine.select(&app.id("D")).unwrap();
    app.move_to("E", "A", false).unwrap();
    app.move_to("C", "D", true).unwrap();
    let library = json!(app.engine.store.library);
    let backup = app.engine.export_backup().unwrap();
    let directory = app.dir.path().to_owned();
    drop(app.engine);
    let reopened = Engine::open(&directory, &directory.join("absent-core37")).unwrap();
    assert!(json!(reopened.store.library) == library);
    drop(reopened);
    let mut target = App::empty();
    let preview = target.engine.preview_backup(&backup).unwrap();
    target.engine.restore_backup(&preview.token).unwrap();
    assert!(json!(target.engine.store.library) == library);
    assert!(target.engine.owned_core_process().is_none());
}

#[test]
fn actual_move_invalidates_restore_and_undo_previews_but_fresh_undo_restores_order() {
    let mut app = App::interleaved();
    let original = app.engine.export_backup().unwrap();
    let pending = app.engine.preview_backup(&original).unwrap();
    app.move_to("E", "A", false).unwrap();
    assert_eq!(
        app.engine.restore_backup(&pending.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = app.engine.refresh_backup_preview(&pending.token).unwrap();
    assert_ne!(refreshed.token, pending.token);
    app.engine.restore_backup(&refreshed.token).unwrap();
    expect_order(&app, &["A", "B", "C", "D", "E"]);
    let undo = app.engine.preview_previous_backup().unwrap();
    app.move_to("D", "A", false).unwrap();
    assert_eq!(
        app.engine.restore_backup(&undo.token).unwrap_err(),
        "backup_preview_stale"
    );
    let fresh = app.engine.preview_previous_backup().unwrap();
    app.engine.restore_backup(&fresh.token).unwrap();
    expect_order(&app, &["E", "A", "B", "C", "D"]);
}

fn downloaded(e: &mut Engine, gid: &str) -> String {
    let request = e.subscription_request(gid).unwrap();
    e.subscription_downloaded(
        request,
        Download {
            body: "synthetic parser input; no download performed".into(),
            metadata: Default::default(),
            usage: None,
        },
    )
    .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .into()
}
fn provider(e: &mut Engine, gid: &str, names: &[&str]) -> String {
    let token = downloaded(e, gid);
    e.preview_subscription(
        &token,
        names.iter().map(|n| draft(n, gid, endpoint(n))).collect(),
    )
    .unwrap();
    token
}

#[test]
fn old_subscription_work_becomes_stale_and_fresh_provider_order_resets_manual_order() {
    let mut app = App::empty();
    let gid = group(&mut app.engine, "Owned provider order", true);
    let initial = provider(&mut app.engine, &gid, &["A", "B", "C"]);
    app.engine.apply_subscription(&initial).unwrap();
    app.ids = app
        .engine
        .store
        .library
        .profiles
        .iter()
        .map(|p| (p.name.clone(), p.id.clone()))
        .collect();
    let original_ids = app.ids.clone();
    let profiles = app.profiles();
    let request = app.engine.subscription_request(&gid).unwrap();
    let review = provider(&mut app.engine, &gid, &["A", "B", "C"]);
    app.move_to("C", "A", false).unwrap();
    assert_eq!(app.members(&gid), ["C", "A", "B"]);
    assert_eq!(
        app.engine
            .subscription_downloaded(
                request,
                Download {
                    body: String::new(),
                    metadata: Default::default(),
                    usage: None
                }
            )
            .unwrap_err(),
        "subscription_changed"
    );
    assert_eq!(
        app.engine.apply_subscription(&review).err().unwrap(),
        "subscription_changed"
    );
    let fresh = provider(&mut app.engine, &gid, &["B", "C", "A"]);
    app.move_to("C", "C", false).unwrap();
    app.engine.apply_subscription(&fresh).unwrap();
    assert_eq!(app.members(&gid), ["B", "C", "A"]);
    assert!(
        app.profiles() == profiles,
        "refresh changed identical provider profiles"
    );
    let ids: BTreeMap<_, _> = app
        .engine
        .store
        .library
        .profiles
        .iter()
        .map(|p| (p.name.clone(), p.id.clone()))
        .collect();
    assert_eq!(ids, original_ids);
    assert!(app.engine.owned_core_process().is_none());
}

fn member_ports(preview: &Value) -> Vec<u64> {
    let outbounds = preview["parts"][0]["config"]["outbounds"]
        .as_array()
        .unwrap();
    let selector = outbounds.iter().find(|v| v["tag"] == "proxy").unwrap();
    selector["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| {
            outbounds.iter().find(|v| v["tag"] == *tag).unwrap()["server_port"]
                .as_u64()
                .unwrap()
        })
        .collect()
}
#[tokio::test(flavor = "current_thread")]
async fn next_dynamic_selector_preview_uses_new_source_order_static_members_do_not() {
    let mut app = App::interleaved();
    let dynamic:ProfileDraft=serde_json::from_value(json!({"name":"Dynamic","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","member_source":{"group_id":"personal","name_regex":"^[ABCDE]$"}}})).unwrap();
    let dynamic = app.engine.save_profile(dynamic).unwrap();
    let fixed:ProfileDraft=serde_json::from_value(json!({"name":"Fixed","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","members":[app.id("B"),app.id("A"),app.id("E")]}})).unwrap();
    let fixed = app.engine.save_profile(fixed).unwrap();
    let old = app
        .engine
        .connection_configuration(&dynamic, false)
        .await
        .unwrap();
    let fixed_before = app
        .engine
        .connection_configuration(&fixed, false)
        .await
        .unwrap();
    let contents = app.profiles();
    let rest = app.rest();
    app.move_to("E", "A", false).unwrap();
    let next = app
        .engine
        .connection_configuration(&dynamic, false)
        .await
        .unwrap();
    let fixed_after = app
        .engine
        .connection_configuration(&fixed, false)
        .await
        .unwrap();
    assert_eq!(member_ports(&old), [20065, 20066, 20067, 20068, 20069]);
    assert_eq!(member_ports(&next), [20069, 20065, 20066, 20067, 20068]);
    assert_eq!(fixed_before, fixed_after);
    unchanged(&app, &contents, &rest);
    assert_eq!(
        app.engine
            .connection_configuration(&dynamic, true)
            .await
            .unwrap_err(),
        "active_configuration_unavailable"
    ); // No active connection fabricated.
}
