use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

fn setup(geo: bool) -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), Path::new("/missing-core68")).unwrap();
    let config = json!({"log":{"access":"/configured/access","error":"/configured/error"},
        "dns":{"servers":["1.1.1.1"],"queryStrategy":"UseIPv4"},
        "inbounds":[{"protocol":"socks","tag":"client","port":1234}],
        "outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],
        "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"domain":[if geo {"geosite:TEST"}else{"domain:blocked.test"}],"outboundTag":"block"}]}});
    let draft = serde_json::from_value(
        json!({"name":"Client68","groupId":"personal","kind":"xray-config","config":config}),
    )
    .unwrap();
    let id = e.save_profile(draft).unwrap();
    (dir, e, id)
}
fn seed(e: &Engine, data: &[u8]) -> PathBuf {
    let dir = e.data_dir.join("xray-assets");
    std::fs::create_dir_all(&dir).unwrap();
    let url = super::super::value(&e.store.library, "xray_geosite_url");
    let manifest = dir.join(format!(
        "{:x}.ref",
        Sha256::digest(format!("{}:null", url.as_str().unwrap()).as_bytes())
    ));
    // Distinct lists that carry the TEST category the profile routes by.
    let data = crate::geodata::site_list_fixture("TEST", &String::from_utf8_lossy(data));
    let hash = format!("{:x}", Sha256::digest(&data));
    std::fs::write(dir.join(format!("{hash}.dat")), data).unwrap();
    std::fs::write(&manifest, hash).unwrap();
    manifest
}
fn country(e: &Engine, id: &str) -> Option<String> {
    e.store
        .library
        .country_measurements
        .current(&e.store.library, id)
        .map(|v| v.country_code.clone())
}
#[test]
fn full_ip_and_speed_keep_client_policy_and_share_frozen_asset_identity() {
    let (_dir, mut e, id) = setup(true);
    seed(&e, b"independent geo fixture");
    let before = e.profile(&id).unwrap().config;
    for test in [e.ip_test(&id).unwrap(), e.speed_test(&id).unwrap()] {
        let (sing, xray) = match &test.request {
            Request::Ip(r) => (r.config.as_ref().unwrap(), r.xray_config.as_ref().unwrap()),
            Request::Speed(r) => (r.config.as_ref().unwrap(), r.xray_config.as_ref().unwrap()),
        };
        let sing: Value = serde_json::from_str(sing).unwrap();
        let xray: Value = serde_json::from_str(xray).unwrap();
        assert_eq!(sing["inbounds"], json!([]));
        assert_eq!(sing["services"], json!([]));
        assert_eq!(xray["dns"], before["dns"]);
        assert_eq!(xray["routing"]["domainStrategy"], "IPIfNonMatch");
        assert_eq!(xray["inbounds"][0]["tag"], "client");
        assert_eq!(xray["inbounds"][0]["listen"], "127.0.0.1");
        assert_ne!(xray["inbounds"][0]["port"], 1234);
        assert!(!xray.to_string().contains("/configured/"));
        assert!(xray.to_string().contains("ext:"));
        assert_eq!(
            test.assets.context.as_ref().unwrap().identity(),
            full_xray::asset_identity(&e.data_dir, &e.store.library, &e.profile(&id).unwrap())
                .unwrap()
        );
        assert!(test.matches(&e.store.library, &Default::default()));
    }
    assert_eq!(e.profile(&id).unwrap().config, before);
    assert!(e.rpc.is_none());
}
#[test]
fn asset_update_rejects_both_pending_tests_and_invalidates_stored_country() {
    let (_dir, mut e, id) = setup(true);
    seed(&e, b"first data");
    let ip = e.ip_test(&id).unwrap();
    let speed = e.speed_test(&id).unwrap();
    e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    assert_eq!(country(&e, &id).as_deref(), Some("JP"));
    seed(&e, b"different selected version");
    assert!(!ip.matches(&e.store.library, &Default::default()));
    assert!(!speed.matches(&e.store.library, &Default::default()));
    assert!(country(&e, &id).is_none());
    assert_eq!(
        e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"DE"}))
            .unwrap_err(),
        "probe_stale"
    );
    let test = e.ip_test(&id).unwrap();
    assert!(e.test_matches(&test));
}
#[test]
fn persistence_stamps_the_tested_version_even_if_reference_changes_after_completion_check() {
    let (_dir, mut e, id) = setup(true);
    seed(&e, b"version measured");
    let ip = e.ip_test(&id).unwrap();
    assert!(e.test_matches(&ip));
    seed(&e, b"version after completion check");
    let next = e
        .store
        .library
        .country_measurements
        .updated(
            &e.store.library,
            &id,
            Some("JP"),
            ip.assets.context.as_ref(),
        )
        .unwrap();
    assert!(next.current(&e.store.library, &id).is_none());
    seed(&e, b"version measured");
    assert_eq!(
        next.current(&e.store.library, &id).unwrap().country_code,
        "JP"
    );
}
#[test]
fn full_country_cache_survives_reopen_and_portable_move_without_persisting_paths() {
    let (dir, mut e, id) = setup(true);
    seed(&e, b"portable fixture");
    let ip = e.ip_test(&id).unwrap();
    e.remember_ip_country(&ip, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    let cache = std::fs::read_to_string(dir.path().join("exit-countries-v1.json")).unwrap();
    assert!(
        !cache.contains("203.0.113.9")
            && !cache.contains("xray-assets")
            && !cache.contains(dir.path().to_str().unwrap())
    );
    drop(e);
    let e = Engine::open(dir.path(), Path::new("/missing-core68")).unwrap();
    assert_eq!(country(&e, &id).as_deref(), Some("JP"));
    drop(e);
    let moved = tempfile::tempdir().unwrap();
    for file in ["library.json", "exit-countries-v1.json"] {
        std::fs::copy(dir.path().join(file), moved.path().join(file)).unwrap();
    }
    std::fs::create_dir(moved.path().join("xray-assets")).unwrap();
    for file in std::fs::read_dir(dir.path().join("xray-assets")).unwrap() {
        let file = file.unwrap();
        std::fs::copy(
            file.path(),
            moved.path().join("xray-assets").join(file.file_name()),
        )
        .unwrap();
    }
    let mut e = Engine::open(moved.path(), Path::new("/missing-core68")).unwrap();
    assert_eq!(country(&e, &id).as_deref(), Some("JP"));
    e.store.library.settings.insert(
        "xray_geosite_url".into(),
        json!("https://new.test/geosite.dat"),
    );
    assert!(country(&e, &id).is_none());
}
#[test]
fn structural_capability_does_not_hide_missing_resources_or_start_an_unsupported_core() {
    let (_dir, mut e, id) = setup(true);
    assert!(supported(
        &e.store.library,
        &e.profile(&id).unwrap(),
        &Default::default()
    ));
    assert_eq!(e.ip_test(&id).err().as_deref(), Some("geodata_missing"));
    assert_eq!(e.speed_test(&id).err().as_deref(), Some("geodata_missing"));
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap()
        .config["api"] = json!({});
    assert!(!supported(
        &e.store.library,
        &e.profile(&id).unwrap(),
        &Default::default()
    ));
    assert_eq!(e.ip_test(&id).err().as_deref(), Some("probe_unsupported"));
    assert!(e.rpc.is_none());
}
#[test]
fn full_client_without_geodata_remembers_country_and_rejects_routing_edits() {
    let (_dir, mut e, id) = setup(false);
    let ip = e.ip_test(&id).unwrap();
    e.remember_ip_country(&ip, &json!({"ip":"2001:db8::9","countryCode":"DE"}))
        .unwrap();
    assert_eq!(country(&e, &id).as_deref(), Some("DE"));
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .unwrap()
        .config["routing"]["domainStrategy"] = json!("AsIs");
    assert!(!ip.matches(&e.store.library, &Default::default()));
    assert!(country(&e, &id).is_none());
}
