use super::*;
use crate::{Engine, ProfileDraft};
use serde_json::json;

fn engine() -> (tempfile::TempDir, Engine, String) {
    let directory = tempfile::tempdir().unwrap();
    let mut e = Engine::open(directory.path(), Path::new("/missing-test-core")).unwrap();
    let id = add(&mut e, "Measured", 1080);
    (directory, e, id)
}
fn add(e: &mut Engine, name: &str, port: u16) -> String {
    let draft: ProfileDraft = serde_json::from_value(json!({"name":name,"groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":port,"version":"5","username":"synthetic","password":"country-test-secret"}})).unwrap();
    e.save_profile(draft).unwrap()
}
fn remember(e: &mut Engine, id: &str, code: Option<&str>) {
    let request = e.ip_test(id).unwrap();
    e.remember_ip_country(&request, &json!({"ip":"203.0.113.44","countryCode":code}))
        .unwrap();
}
fn current(e: &Engine, id: &str) -> Option<String> {
    e.store
        .library
        .country_measurements
        .current(&e.store.library, id)
        .map(|v| v.country_code.clone())
}

#[test]
fn country_cache_reopens_without_copying_ip_credentials_or_library_state() {
    let (dir, mut e, id) = engine();
    let library = std::fs::read(dir.path().join("library.json")).unwrap();
    let generation = e.store.generation();
    remember(&mut e, &id, Some("JP"));
    assert!(e.store.generation() > generation);
    assert_eq!(current(&e, &id).as_deref(), Some("JP"));
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        library
    );
    let cache = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
    assert!(!cache.contains("203.0.113.44") && !cache.contains("country-test-secret"));
    assert!(serde_json::to_value(&e.store.library)
        .unwrap()
        .get("countryMeasurements")
        .is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join(FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    drop(e);
    let e = Engine::open(dir.path(), Path::new("/missing-test-core")).unwrap();
    assert_eq!(current(&e, &id).as_deref(), Some("JP"));
}

#[test]
fn changed_profile_rejects_late_result_and_invalidates_old_observation() {
    let (_dir, mut e, id) = engine();
    remember(&mut e, &id, Some("JP"));
    let request = e.ip_test(&id).unwrap();
    let mut next = e.store.library.clone();
    next.profiles[0].config["server_port"] = json!(1081);
    e.store.commit(next).unwrap();
    assert_eq!(current(&e, &id), None);
    assert_eq!(
        e.remember_ip_country(&request, &json!({"ip":"203.0.113.44","countryCode":"DE"}))
            .unwrap_err(),
        "probe_stale"
    );
    assert_eq!(current(&e, &id), None);
}

#[test]
fn rename_and_dependency_display_order_keep_country_but_group_hop_change_does_not() {
    let (_dir, mut e, id) = engine();
    let hop = add(&mut e, "Front", 1081);
    let mut next = e.store.library.clone();
    next.groups[0].proxy_chain.front = Some(hop.clone());
    e.store.commit(next).unwrap();
    remember(&mut e, &id, Some("JP"));
    let mut next = e.store.library.clone();
    next.profiles[0].name = "Renamed".into();
    next.profiles.reverse();
    e.store.commit(next).unwrap();
    assert_eq!(current(&e, &id).as_deref(), Some("JP"));
    let mut next = e.store.library.clone();
    next.profiles
        .iter_mut()
        .find(|p| p.id == hop)
        .unwrap()
        .config["server_port"] = json!(1082);
    e.store.commit(next).unwrap();
    assert_eq!(current(&e, &id), None);
}

#[test]
fn changing_vless_choice_and_effective_presets_invalidates_measurement() {
    let (_dir, mut e, id) = engine();
    let mut next = e.store.library.clone();
    next.profiles[0].config = json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000045"});
    e.store.commit(next).unwrap();
    remember(&mut e, &id, Some("JP"));
    let mut next = e.store.library.clone();
    next.preferences.vless_core = crate::vless::Core::SingBox;
    e.store.commit(next).unwrap();
    assert_eq!(current(&e, &id), None);
    remember(&mut e, &id, Some("DE"));
    let mut next = e.store.library.clone();
    next.settings
        .insert("fragment_default_on".into(), json!(true));
    // Use a real exposed preset key below if this catalog changes.
    assert!(crate::settings::fields()
        .iter()
        .any(|f| f.id == "fragment_default_on"));
    e.store.commit(next).unwrap();
    assert_eq!(current(&e, &id), None);
}

#[test]
fn unknown_country_clears_only_that_profiles_observation() {
    let (_dir, mut e, id) = engine();
    let other = add(&mut e, "Other", 1081);
    remember(&mut e, &id, Some("JP"));
    remember(&mut e, &other, Some("DE"));
    remember(&mut e, &id, None);
    assert_eq!(current(&e, &id), None);
    assert_eq!(current(&e, &other).as_deref(), Some("DE"));
}

#[test]
fn invalid_or_non_ip_results_never_publish_country() {
    let (dir, mut e, id) = engine();
    let request = e.ip_test(&id).unwrap();
    for value in [
        json!({"countryCode":"JP"}),
        json!({"ip":"not-an-ip","countryCode":"JP"}),
        json!({"ip":"203.0.113.44","countryCode":"Japan"}),
        json!({"ip":"203.0.113.44","countryCode":23}),
    ] {
        assert!(e.remember_ip_country(&request, &value).is_err());
        assert_eq!(current(&e, &id), None);
    }
    let speed = e.speed_test(&id).unwrap();
    assert!(e
        .remember_ip_country(&speed, &json!({"ip":"203.0.113.44","countryCode":"JP"}))
        .is_err());
    assert!(!dir.path().join(FILE).exists());
}

#[test]
fn cache_write_failure_keeps_previous_memory_and_library() {
    let (dir, mut e, id) = engine();
    remember(&mut e, &id, Some("JP"));
    let library = std::fs::read(dir.path().join("library.json")).unwrap();
    let generation = e.store.generation();
    std::fs::remove_file(dir.path().join(FILE)).unwrap();
    std::fs::create_dir(dir.path().join(FILE)).unwrap();
    let request = e.ip_test(&id).unwrap();
    assert_eq!(
        e.remember_ip_country(&request, &json!({"ip":"203.0.113.44","countryCode":"DE"}))
            .unwrap_err(),
        "country_cache_write_failed"
    );
    assert_eq!(current(&e, &id).as_deref(), Some("JP"));
    assert_eq!(e.store.generation(), generation);
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        library
    );
}

#[test]
fn corrupt_or_unsupported_cache_does_not_block_library_open() {
    let (dir, e, id) = engine();
    drop(e);
    for contents in [
        "not JSON",
        "{\"version\":99,\"entries\":{}}",
        "{\"version\":1,\"entries\":[],\"unknown\":true}",
    ] {
        std::fs::write(dir.path().join(FILE), contents).unwrap();
        let e = Engine::open(dir.path(), Path::new("/missing-test-core")).unwrap();
        assert_eq!(e.store.library.profiles.len(), 1);
        assert_eq!(current(&e, &id), None);
    }
}

#[test]
fn cache_bound_retains_the_new_observation_even_when_timestamps_tie() {
    let (_dir, e, id) = engine();
    let mut library = e.store.library.clone();
    let template = library.profiles[0].clone();
    let mut cache = Cache::default();
    for index in 0..MAX_ENTRIES {
        let mut profile = template.clone();
        profile.id = format!("old-{index:04}");
        cache.entries.insert(
            profile.id.clone(),
            Observation {
                country_code: "DE".into(),
                tested_at: now(),
                fingerprint: "a".repeat(64),
            },
        );
        library.profiles.push(profile);
    }
    let updated = cache.updated(&library, &id, Some("JP"), None).unwrap();
    assert_eq!(updated.entries.len(), MAX_ENTRIES);
    assert_eq!(updated.current(&library, &id).unwrap().country_code, "JP");
}
