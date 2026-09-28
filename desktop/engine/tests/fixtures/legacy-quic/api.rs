use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use thronium_engine::{
    backups::{
        legacy::{prepare, Scopes},
        Preview,
    },
    legacy_backup,
    store::{Profile, ProfileKind},
    Engine,
};
pub fn directory() -> PathBuf {
    std::env::var_os("THRONIUM_DOQ_ARCHIVES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-quic/archives")
        })
}
pub fn expected(name: &str) -> Value {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory().join("manifest.json")).unwrap()).unwrap();
    manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}
pub fn app(path: &Path, core: &Path) -> Engine {
    let mut app = Engine::open(path, core).unwrap();
    let mut library = app.store.library.clone();
    library.profiles.push(Profile {
        vpn_policy: None,
        id: "owned-direct".into(),
        name: "Own direct test".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct","udp_fragment":true}),
        favorite: false,
    });
    library.selected = Some("owned-direct".into());
    library.preferences.connection_mode = thronium_engine::system_proxy::ConnectionMode::Local;
    app.store.commit(library).unwrap();
    app
}
pub fn preview(app: &mut Engine, name: &str, profiles: bool) -> Preview {
    let path = directory().join(format!("{name}.thrbackup"));
    let original = std::fs::read(&path).unwrap();
    let archive = legacy_backup::read(&path).unwrap();
    let first = app.preview_legacy_import(prepare(&archive)).unwrap();
    let reviewed = app
        .legacy_backup_scopes(
            &first.token,
            Scopes {
                profiles,
                routes: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let public = json!(reviewed).to_string();
    for private in [
        "127.0.0.",
        "resolver.fixture.invalid",
        "inactive-fixture-secret",
        "quic://",
        "SQLite format",
        "outbound_json",
    ] {
        assert!(!public.contains(private), "source leaked in preview");
    }
    reviewed
}
pub fn install(app: &mut Engine, name: &str) -> String {
    let before = json!(app.store.library);
    let preview = preview(app, name, false);
    assert_eq!(
        preview.legacy.as_ref().unwrap()["canApply"],
        true,
        "{}",
        json!(preview)
    );
    assert!(app.owned_core_process().is_none());
    app.restore_backup(&preview.token).unwrap();
    assert_eq!(
        app.routing().active,
        before["routing"]["active"].as_str().unwrap()
    );
    for key in ["profiles", "groups", "selected", "preferences", "settings"] {
        assert_eq!(json!(app.store.library)[key], before[key], "{key}");
    }
    let route = app.routing().profiles.last().unwrap().clone();
    assert_eq!(route.dns, expected(name)["expectedDNS"], "Qt DNS differs");
    assert_eq!(
        route.legacy_constraints.as_ref().unwrap().version,
        if matches!(name, "remote-quic" | "remote-udp") {
            4
        } else {
            2
        }
    );
    route.id
}
