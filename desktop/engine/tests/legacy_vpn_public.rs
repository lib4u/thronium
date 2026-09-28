//! Independent legacy35 public contract, actual Qt37 goldens and nine archives.
//! No Core, provider, OTP generation/reservation, network or file-path access.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::path::Path;
use thronium_engine::{
    backups::{
        legacy::{prepare, Prepared, Scopes},
        Preview,
    },
    legacy_backup::{self, SourceArchive, SourceProfile, SourceSetting, SourceValue},
    Engine, ProfileDraft,
};
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/legacy-vpn35");
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const LARGE_COUNTER: &str = "9007199254740993";
fn archive(name: &str) -> SourceArchive {
    legacy_backup::read(&Path::new(FIXTURE).join("archives").join(name)).unwrap()
}
fn cases() -> Vec<Value> {
    serde_json::from_str(
        &std::fs::read_to_string(Path::new(FIXTURE).join("qt-cases.json")).unwrap(),
    )
    .unwrap()
}
fn single_source(config: Value) -> SourceArchive {
    let mut source = archive("default-policy-parts-09.thrbackup");
    let db = source.database.as_mut().unwrap();
    db.profiles = vec![SourceProfile {
        id: 17,
        group_id: 7,
        kind: config["type"].as_str().unwrap().into(),
        name: Some("Independent row".into()),
        columns: [(
            "outbound_json".into(),
            SourceValue::Text(config.to_string()),
        )]
        .into(),
        outbound: config,
    }];
    db.groups[0]
        .columns
        .insert("profiles_json".into(), SourceValue::Text("[17]".into()));
    source
}
fn choice(profiles: bool, otp: bool, mode: &str) -> Scopes {
    serde_json::from_value(json!({"profiles":profiles,"routes":false,"otp":otp,"vpnBindings":mode}))
        .unwrap()
}
fn review(v: &Preview) -> &Value {
    let r = v.legacy.as_ref().unwrap();
    let text = serde_json::to_string(v).unwrap();
    assert!(
        !text.contains(RFC_SECRET)
            && !text.contains("synthetic-password")
            && !text.contains("synthetic-token-secret")
    );
    r
}
fn codes(v: &Preview) -> Vec<&str> {
    review(v)["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["code"].as_str().unwrap())
        .collect()
}
struct App {
    engine: Engine,
    dir: tempfile::TempDir,
}
impl App {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        Self { engine, dir }
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("library.json")).unwrap_or_else(|e| {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            Vec::new()
        })
    }
    fn value(&self) -> Value {
        json!(self.engine.store.library)
    }
    fn idle(&mut self) {
        assert!(self.engine.owned_core_process().is_none());
        assert!(self.engine.snapshot().running.is_none());
    }
    fn preview(&mut self, input: Prepared) -> Preview {
        let before = self.disk();
        let p = self.engine.preview_legacy_import(input).unwrap();
        assert_eq!(self.disk(), before);
        self.idle();
        p
    }
    fn select(&mut self, p: &Preview, profiles: bool, otp: bool, mode: &str) -> Preview {
        let before = self.disk();
        let q = self
            .engine
            .legacy_backup_scopes(&p.token, choice(profiles, otp, mode))
            .unwrap();
        assert_ne!(q.token, p.token);
        assert_eq!(
            self.engine.restore_backup(&p.token).unwrap_err(),
            "backup_preview_expired"
        );
        assert_eq!(self.disk(), before);
        self.idle();
        q
    }
    fn blocked(&mut self, p: &Preview) {
        let before = self.disk();
        assert_eq!(review(p)["canApply"], false);
        assert_eq!(
            self.engine.restore_backup(&p.token).unwrap_err(),
            "legacy_import_blocked"
        );
        assert_eq!(self.disk(), before);
        self.idle();
    }
    /// F3b: the source's only profile cannot be converted, so it is left out
    /// with its reason and applying adds no profile.
    fn skipped(&mut self, p: &Preview) {
        assert!(
            codes(p).contains(&"legacy_profile_skipped"),
            "{}",
            json!(codes(p))
        );
        assert_eq!(review(p)["canApply"], true, "{}", json!(codes(p)));
        let profiles = self.engine.store.library.profiles.len();
        self.engine.restore_backup(&p.token).unwrap();
        assert_eq!(self.engine.store.library.profiles.len(), profiles);
        self.idle();
    }
    fn seed(&mut self) {
        let draft:ProfileDraft=serde_json::from_value(json!({"name":"Existing manual VPN","kind":"sing-box-outbound","groupId":"personal","config":{"type":"openvpn-client","server":"192.0.2.17","server_port":1194,"static_challenge":"OTP","username":"synthetic-user","password":"synthetic-password"}})).unwrap();
        let profile = self.engine.save_profile(draft).unwrap();
        for id in ["17", "41"] {
            let entry=self.engine.otp_save("","",serde_json::from_value(json!({"name":"Same name","secret":RFC_SECRET,"type":"hotp","counter":"19"})).unwrap()).unwrap();
            let mut next = self.engine.store.library.clone();
            next.otp
                .iter_mut()
                .find(|o| o.id == entry["id"].as_str().unwrap())
                .unwrap()
                .id = id.into();
            self.engine.store.commit(next).unwrap();
        }
        let edit = self.engine.get_vpn_otp_binding(&profile).unwrap();
        let otp = self
            .engine
            .store
            .library
            .otp
            .iter()
            .find(|o| o.id == "17")
            .unwrap();
        self.engine
            .save_vpn_otp_binding(thronium_engine::vpn_otp_bindings::SaveRequest {
                profile_id: profile,
                edit_token: edit.edit_token,
                otp_id: Some("17".into()),
                otp_revision: Some(otp.revision.clone()),
                mode: None,
            })
            .unwrap();
    }
}
#[cfg(target_os = "linux")]
struct Writes(std::fs::File);
#[cfg(target_os = "linux")]
impl Writes {
    fn new(dir: &Path) -> Self {
        use std::os::fd::{AsRawFd, FromRawFd};
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0);
        let file = unsafe { std::fs::File::from_raw_fd(raw) };
        let path = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), libc::IN_MOVED_TO) }
                > 0
        );
        Self(file)
    }
    fn count(&mut self) -> usize {
        use std::io::Read;
        let mut result = 0;
        let mut bytes = [0u8; 16384];
        loop {
            match self.0.read(&mut bytes) {
                Ok(n) if n > 0 => {
                    let mut offset = 0;
                    while offset < n {
                        let e = unsafe {
                            std::ptr::read_unaligned(
                                bytes[offset..].as_ptr().cast::<libc::inotify_event>(),
                            )
                        };
                        let begin = offset + std::mem::size_of::<libc::inotify_event>();
                        let name = &bytes[begin..begin + e.len as usize];
                        if name.split(|b| *b == 0).next() == Some(b"library.json".as_slice()) {
                            result += 1;
                        }
                        offset = begin + e.len as usize;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Ok(_) => break,
                Err(e) => panic!("owned write observer: {e}"),
            }
        }
        result
    }
}
#[test]
fn baseline34_actual_archives_inventory_and_otp_only_remain_read_only() {
    let mut app = App::new();
    let before = app.disk();
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(FIXTURE).join("archives/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["archives"].as_object().unwrap().len(), 7);
    for name in manifest["archives"].as_object().unwrap().keys() {
        if name == "default-policy-parts-31.thrbackup" {
            assert_eq!(
                legacy_backup::read(&Path::new(FIXTURE).join("archives").join(name))
                    .err()
                    .as_deref(),
                Some("legacy_backup_invalid_schema")
            );
            continue;
        }
        let s = archive(name);
        assert_eq!(s.inventory().profiles, 2);
        assert_eq!(s.inventory().otp, 2);
    }
    let full = archive("complete-schema-default-policy-parts-31.thrbackup");
    assert!(full.parts.profiles && full.parts.routes && full.parts.settings && full.parts.otp);
    let s = archive("default-policy-parts-08.thrbackup");
    let p = app.preview(prepare(&s));
    let scopes: Scopes =
        serde_json::from_value(json!({"profiles":false,"routes":false,"otp":true})).unwrap();
    let p = app.engine.legacy_backup_scopes(&p.token, scopes).unwrap();
    assert_eq!(review(&p)["canApply"], true);
    assert_eq!(app.disk(), before);
    app.engine.restore_backup(&p.token).unwrap();
    assert_eq!(app.engine.store.library.otp.len(), 2);
    assert!(app
        .engine
        .store
        .library
        .otp
        .iter()
        .all(|e| e.value.counter == LARGE_COUNTER));
    app.idle();
}
#[test]
fn v35_qt37_static_conversion_and_guarded_bound_cases() {
    let cases = cases();
    assert_eq!(cases.len(), 37);
    // What each refused case does since F3b: most leave the profile out with
    // their reason; a readable certificate path waits for the file and an
    // OpenVPN binding the live mode cannot honour refuses the choice.
    let rejected = [
        ("ovpn-wrong-type-policy", "legacy_profile_structure", false),
        (
            "ovpn-unknown-field",
            "legacy_profile_field_unsupported",
            false,
        ),
        ("oc-wrong-type-policy", "legacy_profile_structure", false),
        (
            "oc-unknown-field",
            "legacy_profile_field_unsupported",
            false,
        ),
        (
            "ovpn-paths-unread",
            "legacy_profile_resource_required",
            true,
        ),
        ("oc-paths-unread", "legacy_profile_external_resource", false),
        (
            "oc-token-precise-counter",
            "legacy_vpn_auth_unsupported",
            false,
        ),
        (
            "ovpn-bound-credential-placeholder",
            "legacy_vpn_binding_unsupported",
            true,
        ),
        (
            "oc-bound-credential-placeholder",
            "vpn_otp_start_placeholder_unsupported",
            false,
        ),
        (
            "oc-bound-cached-password",
            "vpn_otp_form_cache_unsupported",
            false,
        ),
        ("oc-bound-shadowed-form", "vpn_otp_form_shadowed", false),
    ];
    let mut accepted = 0;
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let input = single_source(row["source"].clone());
        let raw = input.database.as_ref().unwrap().profiles[0]
            .outbound
            .clone();
        let mut app = App::new();
        let p = app.preview(prepare(&input));
        let p = app.select(&p, true, true, "auto-live");
        if let Some((_, code, blocks)) = rejected.iter().find(|(n, _, _)| *n == name) {
            assert!(codes(&p).contains(code), "{name}: {}", json!(codes(&p)));
            if *blocks {
                app.blocked(&p);
            } else {
                app.skipped(&p);
            }
            continue;
        }
        assert!(
            review(&p)["canApply"] == true,
            "Qt case {name}: {}",
            json!(codes(&p))
        );
        app.engine.restore_backup(&p.token).unwrap();
        accepted += 1;
        let profile = app
            .engine
            .store
            .library
            .profiles
            .iter()
            .find(|p| p.group_id != "personal")
            .unwrap();
        if !row["qtBuild"].is_null() {
            assert!(
                profile.config == row["qtBuild"],
                "Qt static Build mismatch for {name}"
            );
        }
        let policy = json!({"onlyAdvertisedRoutes":raw["only_advertised_routes"].as_bool().unwrap_or(true),"useTunnelDns":raw["use_tunnel_dns"].as_bool().unwrap_or(true),"blockOutsideDns":raw["block_outside_dns"].as_bool().unwrap_or(false)});
        assert_eq!(json!(profile)["vpnPolicy"], policy, "policy case {name}");
        assert!(profile.config.get("otp_profile_id").is_none());
        assert!(profile.config.get("only_advertised_routes").is_none());
        assert_eq!(app.engine.store.library.version, 4);
        if name == "ovpn-static-options" {
            assert_eq!(
                profile.config["renegotiate_bytes"].as_i64(),
                Some(9007199254740993)
            );
            assert_eq!(
                profile.config["renegotiate_packets"].as_i64(),
                Some(i64::MAX)
            );
        }
        if name == "oc-ipv6-path" {
            assert_eq!(
                profile.config["server"],
                "[2001:db8::123]:8443/gateway/auth"
            );
        }
        if name == "ovpn-servers-precedence" {
            assert!(
                profile.config.get("server").is_none()
                    && profile.config.get("server_port").is_none()
            );
            assert_eq!(profile.config["servers"], row["qtBuild"]["servers"]);
        }
        assert_eq!(input.database.as_ref().unwrap().profiles[0].outbound, raw);
        assert!(app
            .engine
            .store
            .library
            .otp
            .iter()
            .all(|o| o.value.counter == LARGE_COUNTER));
        app.idle();
    }
    assert_eq!(accepted, 26);
}
#[test]
fn v35_qt19_raw_and_export_reparse_match_lists_and_ipv6() {
    for file in ["qt-cases.json", "export-reparse-cases.json"] {
        let rows: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(Path::new(FIXTURE).join("parity35").join(file)).unwrap(),
        )
        .unwrap();
        assert_eq!(rows.len(), 19);
        let mut accepted = 0;
        let mut refused = 0;
        for row in rows {
            let name = row["name"].as_str().unwrap();
            let source = single_source(row["source"].clone());
            let before = source.database.as_ref().unwrap().profiles[0]
                .outbound
                .clone();
            let mut app = App::new();
            let p = app.preview(prepare(&source));
            let p = app.select(&p, true, false, "manual");
            if ["oc-host-0", "oc-host-1", "oc-host-2"]
                .iter()
                .any(|n| name.starts_with(n))
            {
                // Qt preserves malformed bracket text; the bounded importer must
                // refuse it instead of silently changing the destination.
                app.skipped(&p);
                refused += 1;
            } else {
                assert!(
                    review(&p)["canApply"] == true,
                    "Qt parity {name}: {}",
                    json!(codes(&p))
                );
                app.engine.restore_backup(&p.token).unwrap();
                assert!(
                    app.engine.store.library.profiles[0].config == row["qtBuild"],
                    "Qt parity mismatch {name}"
                );
                assert!(app.engine.store.library.otp.is_empty());
                assert_eq!(app.engine.store.library.version, 4);
                accepted += 1;
            }
            assert_eq!(
                source.database.as_ref().unwrap().profiles[0].outbound,
                before
            );
            app.idle();
        }
        assert_eq!((accepted, refused), (16, 3));
    }
}
#[test]
fn v35_same_archive_provenance_stable_scopes_refresh_one_commit_undo_reopen() {
    let source = archive("default-policy-parts-09.thrbackup");
    let prepared = prepare(&source);
    let mut app = App::new();
    app.seed();
    let mut other = App::new();
    other.seed();
    let prior = app.value();
    let selected = app.engine.snapshot().selected;
    #[cfg(target_os = "linux")]
    let mut writes = Writes::new(app.dir.path());
    let first = app.preview(prepared.clone());
    assert_eq!(review(&first)["vpnBindingCount"], 2);
    assert!(codes(&first).contains(&"legacy_vpn_bindings_choice_required"));
    app.blocked(&first);
    let rows = review(&first)["vpnBindings"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for (profile, otp, manual) in [(17, 41, true), (41, 17, false)] {
        assert!(rows.iter().any(|r| r["sourceId"] == profile
            && r["otpSourceId"] == otp
            && r["manualAllowed"] == manual));
    }
    let nootp = app.select(&first, true, false, "auto-live");
    assert!(codes(&nootp).contains(&"legacy_vpn_bindings_require_otp"));
    app.blocked(&nootp);
    let manual = app.select(&nootp, true, true, "manual");
    app.blocked(&manual);
    let onlyotp = app.select(&manual, false, true, "require-choice");
    assert_eq!(review(&onlyotp)["canApply"], true);
    assert_eq!(review(&onlyotp)["vpnBindingsPlanned"], 0);
    let auto = app.select(&onlyotp, true, true, "auto-live");
    assert_eq!(review(&auto)["canApply"], true);
    assert_eq!(review(&auto)["vpnBindingsPlanned"], 2);
    #[cfg(target_os = "linux")]
    assert_eq!(writes.count(), 0);
    let existing = app.engine.store.library.profiles[0].id.clone();
    app.engine.favorite(&existing).unwrap();
    let changed = app.value();
    assert_eq!(
        app.engine.restore_backup(&auto.token).unwrap_err(),
        "backup_preview_stale"
    );
    let refreshed = app.engine.refresh_backup_preview(&auto.token).unwrap();
    assert_eq!(
        review(&refreshed)["vpnBindings"],
        review(&auto)["vpnBindings"]
    );
    #[cfg(target_os = "linux")]
    assert_eq!(writes.count(), 1);
    app.engine.restore_backup(&refreshed.token).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(writes.count(), 1);
    let result = app.value();
    assert_eq!(app.engine.snapshot().selected, selected);
    assert_eq!(result["routing"], prior["routing"]);
    assert_eq!(result["preferences"], changed["preferences"]);
    assert_eq!(result["profiles"][0], changed["profiles"][0]);
    assert_eq!(result["groups"][0], changed["groups"][0]);
    assert_eq!(
        result["vpnOtpBindings"][&existing],
        changed["vpnOtpBindings"][&existing]
    );
    assert_eq!(
        &result["otp"].as_array().unwrap()[..2],
        changed["otp"].as_array().unwrap()
    );
    let imported: Vec<_> = app
        .engine
        .store
        .library
        .profiles
        .iter()
        .filter(|p| p.group_id != "personal")
        .cloned()
        .collect();
    let otp = &app.engine.store.library.otp[2..];
    assert_eq!(otp.len(), 2);
    assert!(otp
        .iter()
        .all(|e| e.value.counter == LARGE_COUNTER && e.id != "17" && e.id != "41"));
    let binding_map = &result["vpnOtpBindings"];
    for p in &imported {
        let expected = if p.config["type"] == "openvpn-client" {
            &otp[1].id
        } else {
            &otp[0].id
        };
        assert_eq!(binding_map[&p.id]["otpId"], expected.as_str());
        assert_eq!(binding_map[&p.id]["mode"], "auto-live");
    }
    let p = other.preview(prepared);
    let p = other.select(&p, true, true, "auto-live");
    other.engine.restore_backup(&p.token).unwrap();
    let other_value = other.value();
    for p in &imported {
        assert_eq!(
            other_value["vpnOtpBindings"][&p.id],
            result["vpnOtpBindings"][&p.id]
        );
        assert!(other
            .engine
            .store
            .library
            .profiles
            .iter()
            .any(|o| o.id == p.id && o.config == p.config));
    }
    assert_eq!(json!(&other.engine.store.library.otp[2..]), json!(otp));
    // Release the existing Store lock before reopening the same library.
    drop(app.engine);
    app.engine = Engine::open(app.dir.path(), &app.dir.path().join("absent-core")).unwrap();
    assert_eq!(app.value(), result);
    let backup = app.engine.export_backup().unwrap();
    let mut restored = App::new();
    let p = restored.engine.preview_backup(&backup).unwrap();
    restored.engine.restore_backup(&p.token).unwrap();
    assert_eq!(restored.value(), result);
    restored.idle();
    let undo = app.engine.preview_previous_backup().unwrap();
    app.engine.restore_backup(&undo.token).unwrap();
    let mut expected = changed;
    expected["version"] = json!(4);
    // Undo never lowers a used HOTP counter of the same secret: the
    // counters may only have risen, with a new revision; all else is exact.
    let actual = app.value();
    for (want, got) in expected["otp"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(actual["otp"].as_array().unwrap())
    {
        let counter = |v: &Value| v["counter"].as_str().unwrap().parse::<u128>().unwrap();
        assert!(counter(got) >= counter(want));
        want["counter"] = got["counter"].clone();
        want["revision"] = got["revision"].clone();
    }
    assert_eq!(actual, expected);
    #[cfg(target_os = "linux")]
    assert_eq!(writes.count(), 1);
    app.idle();
    other.idle();
}
#[test]
fn v35_seven_archive_scopes_missing_otp_and_invalid_otp_are_atomic() {
    for name in [
        "default-policy-parts-01.thrbackup",
        "default-policy-parts-08.thrbackup",
        "default-policy-parts-09.thrbackup",
        "complete-schema-default-policy-parts-31.thrbackup",
        "policy-off-parts-09.thrbackup",
        "missing-otp-parts-09.thrbackup",
        "invalid-otp-parts-09.thrbackup",
    ] {
        let source = archive(name);
        let mut app = App::new();
        app.seed();
        let before = app.disk();
        let p = app.preview(prepare(&source));
        let p = app.select(&p, true, true, "auto-live");
        let valid = [
            "default-policy-parts-09.thrbackup",
            "complete-schema-default-policy-parts-31.thrbackup",
            "policy-off-parts-09.thrbackup",
        ]
        .contains(&name);
        if valid {
            assert!(
                review(&p)["canApply"] == true,
                "{name}: {}",
                json!(codes(&p))
            );
            app.engine.restore_backup(&p.token).unwrap();
            assert_eq!(app.engine.store.library.otp.len(), 4);
            if name.starts_with("policy-off") {
                for row in app
                    .engine
                    .store
                    .library
                    .profiles
                    .iter()
                    .filter(|p| p.group_id != "personal")
                {
                    assert_eq!(
                        json!(row)["vpnPolicy"],
                        json!({"onlyAdvertisedRoutes":false,"useTunnelDns":false,"blockOutsideDns":false})
                    );
                }
            }
        } else {
            app.blocked(&p);
            assert_eq!(app.disk(), before);
            let p = app.select(&p, false, true, "require-choice");
            let usable = source.parts.otp && !name.starts_with("invalid-otp");
            assert_eq!(review(&p)["canApply"], usable);
            if usable {
                app.engine.restore_backup(&p.token).unwrap();
                assert_eq!(app.engine.store.library.profiles.len(), 1);
                assert_eq!(app.engine.store.library.otp.len(), 4);
            } else {
                app.blocked(&p);
            }
        }
        app.idle();
    }
}
#[test]
fn v35_manual_static_challenge_and_unbound_templates_are_explicit() {
    let source = archive("manual-ovpn-only-parts-01.thrbackup");
    assert!(source.parts.profiles && !source.parts.otp);
    let db = source.database.as_ref().unwrap();
    assert_eq!(db.profiles.len(), 1);
    assert!(db.otp.is_empty());
    let source_name = db.profiles[0].name.as_deref().unwrap();
    assert!(source_name.chars().count() > 200);
    let mut physical = App::new();
    let p = physical.preview(prepare(&source));
    assert!(codes(&p).contains(&"legacy_vpn_bindings_choice_required"));
    physical.blocked(&p);
    let p = physical.select(&p, true, false, "auto-live");
    assert!(codes(&p).contains(&"legacy_vpn_bindings_require_otp"));
    physical.blocked(&p);
    let p = physical.select(&p, true, false, "manual");
    assert_eq!(review(&p)["canApply"], true);
    assert_eq!(review(&p)["vpnBindingsPlanned"], 0);
    physical.engine.restore_backup(&p.token).unwrap();
    assert_eq!(physical.engine.store.library.profiles.len(), 1);
    assert_eq!(physical.engine.store.library.profiles[0].name, source_name);
    assert_eq!(
        physical.engine.store.library.profiles[0].config["static_challenge"],
        "OTP code"
    );
    assert!(physical.engine.store.library.otp.is_empty());
    assert!(physical.value()["vpnOtpBindings"]
        .as_object()
        .is_none_or(|m| m.is_empty()));
    physical.idle();
    let all = cases();
    let cfg = |name: &str| all.iter().find(|r| r["name"] == name).unwrap()["source"].clone();
    let input = single_source(cfg("ovpn-bound-static-challenge"));
    let mut app = App::new();
    let p = app.preview(prepare(&input));
    let p = app.select(&p, true, false, "manual");
    assert_eq!(review(&p)["canApply"], true);
    assert_eq!(review(&p)["vpnBindingsPlanned"], 0);
    app.engine.restore_backup(&p.token).unwrap();
    let row = &app.engine.store.library.profiles[0];
    assert_eq!(row.config["static_challenge"], "OTP code");
    assert!(app.value()["vpnOtpBindings"]
        .as_object()
        .is_none_or(|m| m.is_empty()));
    assert!(app.engine.store.library.otp.is_empty());
    app.idle();
    for name in [
        "oc-bound-form",
        "ovpn-bound-credential-placeholder",
        "oc-bound-credential-placeholder",
        "oc-bound-cached-password",
        "oc-bound-shadowed-form",
    ] {
        let mut config = cfg(name);
        config.as_object_mut().unwrap().remove("otp_profile_id");
        let input = single_source(config);
        let mut app = App::new();
        for mode in ["require-choice", "manual", "auto-live"] {
            let p = app.preview(prepare(&input));
            let p = app.select(&p, true, true, mode);
            app.skipped(&p);
        }
    }
}
#[test]
fn v35_source_context_refusals_and_complete_dns_routes_stay_opaque() {
    let base = cases()
        .into_iter()
        .find(|r| r["name"] == "oc-defaults")
        .unwrap()["source"]
        .clone();
    for delta in [
        json!({"system":true}),
        json!({"name":"system0"}),
        json!({"flavor":"globalprotect"}),
        json!({"cookie":"public-cookie"}),
        json!({"token":{"mode":"hotp","counter":17,"secret":"synthetic-token-secret"}}),
        json!({"disable_password_auth":true}),
        json!({"mtu":"1370"}),
        json!({"server_port":65536}),
        json!({"tls":{"certificate_authority_path":"/nonexistent/synthetic/ca"}}),
    ] {
        let mut cfg = base.clone();
        cfg.as_object_mut()
            .unwrap()
            .extend(delta.as_object().unwrap().clone());
        let source = single_source(cfg);
        let mut app = App::new();
        let p = app.preview(prepare(&source));
        let p = app.select(&p, true, true, "auto-live");
        // A certificate path is asked for as a review resource (F3b) and
        // blocks until provided; every other refusal leaves the profile out.
        if delta.get("tls").is_some() {
            assert!(codes(&p).contains(&"legacy_profile_resource_required"));
            app.blocked(&p);
        } else {
            app.skipped(&p);
        }
    }
    let mut source = single_source(base.clone());
    source.parts.settings = true;
    source
        .database
        .as_mut()
        .unwrap()
        .settings
        .push(SourceSetting {
            key: "use_dns_object".into(),
            value: "true".into(),
            columns: Default::default(),
        });
    let mut app = App::new();
    let p = app.preview(prepare(&source));
    app.blocked(&p);
    assert!(codes(&p).contains(&"legacy_vpn_dns_override_unsupported"));
    let mut source = single_source(base.clone());
    source.database.as_mut().unwrap().groups[0]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(17));
    let mut app = App::new();
    let p = app.preview(prepare(&source));
    app.blocked(&p);
    let opaque = json!({"dns":{"servers":[{"type":"local","tag":"custom-dns"}],"rules":[{"domain":["dns.fixture.invalid"],"server":"custom-dns"}],"final":"custom-dns"},"route":{"rules":[{"ip_cidr":["192.0.2.0/24"],"action":"route","outbound":"direct"}],"final":"direct"},"endpoints":[{"type":"openvpn-client","tag":"same-source-id17","server":"192.0.2.34","server_port":1194}],"outbounds":[{"type":"direct","tag":"direct"}],"future":{"preserved":[true,9007199254740993u64]}});
    let mut input = single_source(base);
    let row = &mut input.database.as_mut().unwrap().profiles[0];
    row.kind = "custom".into();
    row.outbound = json!({"type":"custom","name":"Opaque full config","subtype":"fullconfig","config":opaque.to_string()});
    row.columns.insert(
        "outbound_json".into(),
        SourceValue::Text(row.outbound.to_string()),
    );
    let mut app = App::new();
    let p = app.preview(prepare(&input));
    assert_eq!(review(&p)["canApply"], true);
    app.engine.restore_backup(&p.token).unwrap();
    let imported = &app.engine.store.library.profiles[0];
    assert_eq!(imported.config, opaque);
    assert!(json!(imported).get("vpnPolicy").is_none());
    assert!(app.value()["vpnOtpBindings"]
        .as_object()
        .is_none_or(|m| m.is_empty()));
    app.idle();
}

#[test]
fn v35_source_path_is_not_opened_and_choice_wire_is_strict() {
    for value in [
        json!(null),
        json!(false),
        json!("requireChoice"),
        json!({"mode":"auto-live"}),
    ] {
        assert!(serde_json::from_value::<Scopes>(
            json!({"profiles":true,"routes":false,"otp":true,"vpnBindings":value})
        )
        .is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owned-readable-ca.pem");
    std::fs::write(&path, "PUBLIC SOURCE PATH CANARY").unwrap();
    #[cfg(target_os = "linux")]
    let mut watcher = {
        use std::os::fd::{AsRawFd, FromRawFd};
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0);
        let file = unsafe { std::fs::File::from_raw_fd(raw) };
        let value = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert!(
            unsafe { libc::inotify_add_watch(file.as_raw_fd(), value.as_ptr(), libc::IN_OPEN) } > 0
        );
        file
    };
    let config = json!({"type":"openvpn","server":"192.0.2.34","server_port":1194,"tls":{"certificate_path":path.to_str().unwrap()}});
    let input = single_source(config);
    let mut app = App::new();
    let p = app.preview(prepare(&input));
    app.blocked(&p);
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut buffer = [0u8; 1024];
        assert_eq!(
            watcher.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    app.idle();
    app.engine.discard_backup_preview(&p.token);
    assert_eq!(
        app.engine.restore_backup(&p.token).unwrap_err(),
        "backup_preview_expired"
    );
}
