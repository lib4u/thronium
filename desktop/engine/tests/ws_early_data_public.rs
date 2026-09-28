//! Independent path persistence and pinned CheckConfig proof. Never calls Start.
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use thronium_engine::{
    exports::{Format, ImportProfile},
    store::ProfileKind,
    Engine, ProfileDraft,
};

const PATHS: [&str; 6] = [
    "/socket?ed=0",
    "/socket?ed=1",
    "/socket?ed=8192",
    "/socket?z=x%20y&ed=1&a=%2f#kept",
    "/socket?ed=8192&x=1&x=2",
    "/socket?e%64=1&ED=2&x=a+b",
];
fn config(path: &str) -> Value {
    json!({"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.38","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000038","encryption":"none"}]}]},
        "streamSettings":{"network":"ws","security":"none","wsSettings":{"path":path,"host":"owned.invalid","headers":{"X-Owned-Case":"raw %2f + space","X-Second":"kept"},"heartbeatPeriod":7,"x-owned-unknown":{"integer":9007199254740993_u64,"values":[true,null,"opaque"]}}},
        "x-outbound-unknown":{"keep":true}})
}
fn draft(id: Option<&str>, name: &str, config: Value) -> ProfileDraft {
    ProfileDraft {
        id: id.map(str::to_owned),
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::XrayOutbound,
        config,
        vpn_policy: Default::default(),
    }
}
struct App {
    e: Engine,
    dir: tempfile::TempDir,
}
impl App {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::open(dir.path(), &dir.path().join("absent-Core38")).unwrap();
        Self { e, dir }
    }
    fn save(&mut self, path: &str) -> String {
        self.e
            .save_profile(draft(None, "Owned WS38", config(path)))
            .unwrap()
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("library.json")).unwrap()
    }
    fn pure(&mut self) {
        assert!(self.e.owned_core_process().is_none());
        assert!(self.e.snapshot().running.is_none());
    }
}
fn profile(e: &Engine, id: &str) -> Value {
    json!(e.profile(id).unwrap())
}
fn assert_ws(value: &Value, path: &str) {
    let expected = config(path);
    assert_eq!(value["streamSettings"], expected["streamSettings"]);
    let ws = value["streamSettings"]["wsSettings"].as_object().unwrap();
    assert_eq!(ws.len(), 5);
    for key in ["ed", "maxEarlyData", "earlyDataHeaderName"] {
        assert!(!ws.contains_key(key));
    }
    assert_eq!(
        ws["x-owned-unknown"]["integer"].as_u64(),
        Some(9007199254740993)
    );
}
fn import_bundle(e: &mut Engine, bundle: &Value) -> Vec<String> {
    assert_eq!(bundle["format"], "thronium-profiles");
    assert_eq!(bundle["version"], 1);
    let entries: Vec<ImportProfile> = bundle["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            entry["groupId"] = json!("personal");
            entry["id"] = Value::Null;
            serde_json::from_value(entry).unwrap()
        })
        .collect();
    e.import_referenced_profiles(entries).unwrap()
}

#[test]
fn explicit_zero_one_and_limit_survive_save_and_reopen_exactly() {
    let mut app = App::new();
    let mut ids = Vec::new();
    for path in &PATHS[..3] {
        let id = app.save(path);
        assert_ws(&app.e.profile(&id).unwrap().config, path);
        ids.push(id);
    }
    let before = json!(app.e.store.library);
    let disk = app.disk();
    let root = app.dir.path().to_owned();
    app.pure();
    drop(app.e);
    let mut reopened = Engine::open(&root, &root.join("absent-Core38")).unwrap();
    assert_eq!(json!(reopened.store.library), before);
    assert_eq!(std::fs::read(root.join("library.json")).unwrap(), disk);
    assert_eq!(reopened.store.library.version, 1);
    for (id, path) in ids.iter().zip(&PATHS) {
        assert_ws(&reopened.profile(id).unwrap().config, path);
    }
    assert!(reopened.snapshot().running.is_none());
    assert!(reopened.owned_core_process().is_none());
}

#[test]
fn explicit_path_update_preserves_complete_profile_metadata_and_rest_of_library() {
    let mut app = App::new();
    let id = app.save(PATHS[3]);
    app.e.favorite(&id).unwrap();
    app.e
        .vless_core(&id, Some(thronium_engine::vless::Core::Xray))
        .unwrap();
    let before = json!(app.e.store.library);
    let p = app.e.profile(&id).unwrap();
    let mut replacement = p.config.clone();
    let path = "/socket?z=x%20y&ed=8192&a=%2f#kept";
    replacement["streamSettings"]["wsSettings"]["path"] = json!(path);
    app.e
        .save_profile(draft(Some(&id), &p.name, replacement))
        .unwrap();
    let mut expected = before;
    expected["profiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|v| v["id"] == id)
        .unwrap()["config"]["streamSettings"]["wsSettings"]["path"] = json!(path);
    assert_eq!(json!(app.e.store.library), expected);
    assert_ws(&app.e.profile(&id).unwrap().config, path);
    app.pure();
}

#[test]
fn raw_and_profile_bundle_exports_preserve_encoded_path_and_unknown_json() {
    let mut source = App::new();
    let mut destination = App::new();
    for path in &PATHS[3..] {
        let id = source.save(path);
        let frozen = profile(&source.e, &id);
        let disk = source.disk();
        let raw = source
            .e
            .export_profiles(vec![id.clone()], Format::Configurations)
            .unwrap();
        let raw: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(raw, frozen["config"]);
        assert_ws(&raw, path);
        let bundle: Value = serde_json::from_str(
            &source
                .e
                .export_profiles(vec![id.clone()], Format::Profiles)
                .unwrap(),
        )
        .unwrap();
        let imported = import_bundle(&mut destination.e, &bundle);
        assert_eq!(imported.len(), 1);
        assert_ne!(imported[0], id);
        let imported = destination.e.profile(&imported[0]).unwrap();
        assert_eq!(imported.name, frozen["name"]);
        assert_eq!(imported.kind, ProfileKind::XrayOutbound);
        assert_eq!(imported.config, raw);
        assert!(!imported.favorite);
        assert_eq!(imported.group_id, "personal");
        assert!(imported.vpn_policy.is_none());
        let raw_ids = destination
            .e
            .import_profiles(vec![draft(None, "Raw JSON38", raw)])
            .unwrap();
        assert_ws(&destination.e.profile(&raw_ids[0]).unwrap().config, path);
        assert_eq!(profile(&source.e, &id), frozen);
        assert_eq!(source.disk(), disk);
    }
    source.pure();
    destination.pure();
}

#[test]
fn full_backup_preserves_uuid_favorite_selection_core_override_and_raw_path() {
    let mut source = App::new();
    let id = source.save(PATHS[5]);
    source.e.favorite(&id).unwrap();
    source
        .e
        .vless_core(&id, Some(thronium_engine::vless::Core::Xray))
        .unwrap();
    let before = json!(source.e.store.library);
    let disk = source.disk();
    let backup = source.e.export_backup().unwrap();
    let mut other = App::new();
    let review = other.e.preview_backup(&backup).unwrap();
    other.e.restore_backup(&review.token).unwrap();
    assert_eq!(json!(other.e.store.library), before);
    assert_eq!(profile(&other.e, &id), profile(&source.e, &id));
    assert_eq!(source.disk(), disk);
    assert_ws(&other.e.profile(&id).unwrap().config, PATHS[5]);
    source.pure();
    other.pure();
}

#[tokio::test]
async fn compiled_xray_request_keeps_path_bytes_and_has_no_early_data_pseudo_key() {
    let mut app = App::new();
    for path in PATHS.into_iter().chain(["/socket?ed=1&ed=8192"]) {
        let id = app.save(path);
        let disk = app.disk();
        let frozen = profile(&app.e, &id);
        let preview = app.e.connection_configuration(&id, false).await.unwrap();
        assert_eq!(preview["source"], "preview");
        let xray = &preview["parts"][1]["config"];
        let outbound = xray["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["tag"] == "proxy")
            .unwrap();
        let mut expected = config(path);
        expected["tag"] = json!("proxy");
        assert_eq!(*outbound, expected);
        assert_ws(outbound, path);
        assert_eq!(profile(&app.e, &id), frozen);
        assert_eq!(app.disk(), disk);
        app.pure();
    }
    // Duplicate ed remains raw passthrough here. The new UI helper refuses to edit it;
    // neither Engine storage nor the downstream Xray Build policy is changed.
}

#[cfg(target_os = "linux")]
fn owned_ipc(owner: thronium_engine::transport::OwnedProcess, core: &std::path::Path) -> PathBuf {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let proc = PathBuf::from(format!("/proc/{}", owner.pid));
    assert_eq!(
        std::fs::read_link(proc.join("exe")).unwrap(),
        core.canonicalize().unwrap()
    );
    assert_eq!(std::fs::metadata(&proc).unwrap().uid(), unsafe {
        libc::geteuid()
    });
    let stat = std::fs::read_to_string(proc.join("stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(fields[1].parse::<u32>().unwrap(), std::process::id());
    assert_eq!(Some(fields[19].parse::<u64>().unwrap()), owner.start_time);
    let env = std::fs::read(proc.join("environ")).unwrap();
    let socket = env
        .split(|b| *b == 0)
        .find_map(|s| s.strip_prefix(b"THRONE_CORE_SOCKET="))
        .unwrap();
    let socket = PathBuf::from(std::ffi::OsStr::from_bytes(socket));
    assert!(socket.is_absolute() && socket.exists());
    socket
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "immutable Core and parent Thronium required; CheckConfig only, no Start"]
async fn pinned_core_check_config_accepts_six_paths_without_start_or_store_mutation() {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(exe.file_name().unwrap(), "Thronium");
    let core = exe.parent().unwrap().join("ThroniumCore");
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &core).unwrap();
    let mut ids = Vec::new();
    for path in PATHS {
        ids.push(
            e.save_profile(draft(None, "Owned Check38", config(path)))
                .unwrap(),
        );
    }
    e.favorite(&ids[0]).unwrap();
    e.vless_core(&ids[0], Some(thronium_engine::vless::Core::Xray))
        .unwrap();
    let frozen = json!(e.store.library);
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    let mut captured = None;
    for (id, path) in ids.iter().zip(PATHS) {
        let profile = e.profile(id).unwrap();
        assert_ws(&profile.config, path);
        e.check(&profile).await.unwrap();
        let owner = e.owned_core_process().unwrap();
        if let Some(old) = captured {
            assert_eq!(owner, old)
        } else {
            captured = Some(owner)
        }
        assert!(e.snapshot().running.is_none());
        assert!(e.snapshot().since.is_none());
        assert_eq!(json!(e.store.library), frozen);
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            disk
        );
    }
    // Falsification control: the public check must reach the Xray UUID builder.
    let mut malformed = e.profile(&ids[0]).unwrap();
    malformed.config["settings"]["vnext"][0]["users"][0]["id"] =
        json!("not-a-uuid-and-too-long-for-xray-alias");
    let rejection = e
        .check(&malformed)
        .await
        .expect_err("malformed Xray UUID was accepted");
    assert!(rejection.to_ascii_lowercase().contains("uuid"));
    assert_eq!(json!(e.store.library), frozen);
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        disk
    );
    assert!(e.snapshot().running.is_none());
    assert!(e.snapshot().since.is_none());
    let owner = captured.unwrap();
    assert_eq!(e.owned_core_process().unwrap(), owner);
    let socket = owned_ipc(owner, &core);
    e.shutdown_checked().await.unwrap();
    assert!(e.owned_core_process().is_none());
    assert!(!PathBuf::from(format!("/proc/{}", owner.pid)).exists());
    assert!(!socket.exists());
    assert!(!socket.parent().unwrap().exists());
    println!(
        "WS_EARLY_DATA38_CHECK {}",
        json!({"acceptedPaths":6,"malformedUuidRejected":true,"idleAfterEveryCheck":true,"libraryBytesAndMetadataUnchanged":true,"ownedPid":owner.pid,"ownedStartTime":owner.start_time,"ownedInstance":owner.instance,"ownedParentExeUidVerified":true,"ownedCoreReaped":true,"ownedIpcRemoved":true,"scope":"CheckConfig only; no Start, endpoint connection or data-plane claim"})
    );
}
