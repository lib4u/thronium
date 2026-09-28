use super::*;
use crate::{
    geodata::{digest, Assets, Attr, Domain, Site, SiteList},
    store::{Profile, ProfileKind},
    Engine,
};
use prost::Message;
use serde_json::json;
fn bytes(category: &str, domain: &str) -> Vec<u8> {
    SiteList {
        entry: vec![Site {
            code: category.into(),
            domain: vec![Domain {
                kind: 2,
                value: domain.into(),
                attribute: vec![Attr {
                    key: "owned".into(),
                }],
            }],
        }],
    }
    .encode_to_vec()
}
fn selection() -> Selection {
    Selection {
        kind: Kind::Geosite,
        url: String::new(),
    }
}
fn staged(root: &std::path::Path, content: &[u8]) -> files::Staged {
    files::Files::new(root, selection())
        .unwrap()
        .stage(content, || false)
        .unwrap()
}
#[test]
fn staged_content_does_not_change_runtime_until_atomic_commit() {
    let dir = tempfile::tempdir().unwrap();
    let files = files::Files::new(dir.path(), selection()).unwrap();
    assert_eq!(files.status().unwrap().state, "missing");
    assert!(!dir.path().join("xray-assets").exists());
    let first = staged(dir.path(), &bytes("test", "one.test"));
    let runtime = Assets::new(dir.path(), None);
    assert!(runtime.cached(true).is_err());
    first.commit().unwrap();
    let old_path = runtime.cached(true).unwrap();
    let mut config =
        json!({"routing":{"rules":[{"domain":["geosite:test"],"outboundTag":"direct"}]}});
    runtime.rewrite_xray(&mut config).unwrap();
    let frozen = config.clone();
    let second = staged(dir.path(), &bytes("test", "two.test"));
    assert_eq!(runtime.cached(true).unwrap(), old_path);
    second.commit().unwrap();
    assert_ne!(runtime.cached(true).unwrap(), old_path);
    assert!(old_path.is_file());
    assert_eq!(config, frozen);
    let mut future =
        json!({"routing":{"rules":[{"domain":["geosite:test"],"outboundTag":"direct"}]}});
    runtime.rewrite_xray(&mut future).unwrap();
    assert_ne!(future, frozen);
    assert_eq!(files.status().unwrap().categories, Some(1));
}
#[test]
fn invalid_cancelled_and_corrupt_assets_preserve_or_repair_the_reference() {
    let dir = tempfile::tempdir().unwrap();
    let content = bytes("test", "one.test");
    staged(dir.path(), &content).commit().unwrap();
    let files = files::Files::new(dir.path(), selection()).unwrap();
    let reference = std::fs::read(files.manifest()).unwrap();
    assert!(files::Files::new(dir.path(), selection())
        .unwrap()
        .stage(b"broken", || false)
        .is_err());
    assert!(files::Files::new(dir.path(), selection())
        .unwrap()
        .stage(&bytes("test", "two.test"), || true)
        .is_err());
    assert_eq!(std::fs::read(files.manifest()).unwrap(), reference);
    let path = dir
        .path()
        .join("xray-assets")
        .join(format!("{}.dat", digest(&content)));
    std::fs::write(&path, b"corrupted owned data").unwrap();
    assert_eq!(files.status().unwrap().state, "invalid");
    staged(dir.path(), &content).commit().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);
    assert_eq!(files.status().unwrap().state, "ready");
}
#[test]
fn dependencies_are_checked_at_commit_against_the_current_library() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("absent-Core")).unwrap();
    let first = bytes("test", "one.test");
    staged(dir.path(), &first).commit().unwrap();
    let update = Prepared(staged(dir.path(), &bytes("other", "two.test")));
    engine.store.library.profiles.push(Profile { id:"owned".into(),name:"Owned".into(),group_id:"personal".into(),kind:ProfileKind::XrayConfig,config:json!({"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"domain":["geosite:test@owned"],"outboundTag":"direct"}]}}),favorite:false,vpn_policy:None });
    assert_eq!(
        engine.commit_xray_geodata(update).err().as_deref(),
        Some("geodata_category_missing")
    );
    assert_eq!(
        Assets::new(dir.path(), None)
            .cached(true)
            .unwrap()
            .file_stem()
            .unwrap(),
        digest(&first).as_str()
    );
    // Opaque strings in profile remarks do not become routing dependencies.
    engine.store.library.profiles[0].config["remarks"] = json!("geosite:not-a-dependency");
    engine
        .commit_xray_geodata(Prepared(staged(dir.path(), &bytes("test", "new.test"))))
        .unwrap();
    let other = tempfile::tempdir().unwrap();
    assert_eq!(
        engine
            .commit_xray_geodata(Prepared(staged(other.path(), &first)))
            .err()
            .as_deref(),
        Some("geodata_request_stale")
    );
}
#[test]
fn source_identity_matches_existing_cache_and_preserves_provider_timestamps() {
    let dir = tempfile::tempdir().unwrap();
    let files = files::Files::new(dir.path(), selection()).unwrap();
    let mut assets = Assets::new(dir.path(), None);
    assert!(files.matches(&assets));
    assets.config["LastUpdated"] = json!("provider-version");
    assert!(!files.matches(&assets));
    for url in [
        "http://example.test/a",
        "https://user:password@example.test/a",
        "https://example.test/a#fragment",
        "file:///tmp/file",
    ] {
        assert!(files::Files::new(
            dir.path(),
            Selection {
                kind: Kind::Geosite,
                url: url.into()
            }
        )
        .is_err());
    }
}
