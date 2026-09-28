use super::*;
use crate::{probes::Status, ProfileDraft};
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind,
        config,
    })
    .unwrap()
}
fn socks(port: u16) -> Value {
    json!({"type":"socks","server":"127.0.0.1","server_port":port})
}
fn pool(members: &[&str], pin: Option<&str>) -> Value {
    let mut config = json!({"type":"auto-selector","members":members});
    if let Some(pin) = pin {
        config["pinned_profile"] = json!(pin);
    }
    config
}
fn profile(e: &Engine, id: &str) -> Profile {
    e.store
        .library
        .profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .unwrap()
}

#[test]
fn a_pool_is_measured_through_its_pinned_or_first_member_and_names_it() {
    let (_dir, mut e) = setup();
    let first = add(
        &mut e,
        "First member",
        ProfileKind::SingBoxOutbound,
        socks(1080),
    );
    let second = add(
        &mut e,
        "Second member",
        ProfileKind::SingBoxOutbound,
        socks(1081),
    );
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&first, &second], None),
    );
    assert!(supported(
        &e.store.library,
        &profile(&e, &id),
        &Default::default()
    ));
    let test = e.ip_test(&id).unwrap();
    assert_eq!(test.member(), Some((first.as_str(), "First member")));
    assert_eq!(test.measured_id(), first);
    assert_eq!(test.transport(), "isolated-core");
    assert!(e.test_matches(&test));
    let pinned = add(
        &mut e,
        "Pinned pool",
        ProfileKind::AutoSelector,
        pool(&[&first, &second], Some(&second)),
    );
    let test = e.speed_test(&pinned).unwrap();
    assert_eq!(test.member(), Some((second.as_str(), "Second member")));
    assert_eq!(test.kind_name(), "speed");
    // Country observations belong to the measured member, never to the pool.
    let test = e.ip_test(&id).unwrap();
    e.remember_ip_country(&test, &json!({"ip":"203.0.113.9","countryCode":"JP"}))
        .unwrap();
    let library = &e.store.library;
    assert!(library
        .country_measurements
        .current(library, &first)
        .is_some());
    assert!(library.country_measurements.current(library, &id).is_none());
}

#[test]
fn pool_measurements_go_stale_when_the_pin_or_members_change() {
    let (_dir, mut e) = setup();
    let first = add(&mut e, "First", ProfileKind::SingBoxOutbound, socks(1080));
    let second = add(&mut e, "Second", ProfileKind::SingBoxOutbound, socks(1081));
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&first, &second], None),
    );
    let test = e.ip_test(&id).unwrap();
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(id.clone()),
        name: "Pool".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: pool(&[&first, &second], Some(&second)),
    })
    .unwrap();
    assert!(
        !e.test_matches(&test),
        "a new pin changes the measured member"
    );
    let test = e.ip_test(&id).unwrap();
    assert_eq!(test.member().map(|(id, _)| id), Some(second.as_str()));
    let mut edited = profile(&e, &second);
    edited.config["server_port"] = json!(1090);
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(second.clone()),
        name: edited.name,
        group_id: edited.group_id,
        kind: edited.kind,
        config: edited.config,
    })
    .unwrap();
    assert!(
        !e.test_matches(&test),
        "editing the measured member invalidates the test"
    );
}

#[test]
fn dynamic_pools_and_pools_with_a_missing_member_stay_out_of_diagnostics() {
    let (_dir, mut e) = setup();
    let socks_id = add(&mut e, "Socks", ProfileKind::SingBoxOutbound, socks(1080));
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&socks_id], None),
    );
    let mut dynamic = profile(&e, &id);
    dynamic.config = json!({"type":"auto-selector","member_source":{"group":"personal"}});
    assert!(!supported(&e.store.library, &dynamic, &Default::default()));
    let mut missing = profile(&e, &id);
    missing.config = pool(&["gone"], None);
    assert!(!supported(&e.store.library, &missing, &Default::default()));
    assert_eq!(
        crate::auto_selector::measured_member(&e.store.library, &missing, &Default::default())
            .err()
            .as_deref(),
        Some("selector_profile_missing")
    );
}

#[test]
fn ip_batches_name_the_measured_member_of_a_pool() {
    let (_dir, mut e) = setup();
    let first = add(&mut e, "First", ProfileKind::SingBoxOutbound, socks(1080));
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&first], None),
    );
    let run = e.start_ip_tests(vec![id.clone()]).unwrap();
    let probe = e
        .next_url_test(&run.id)
        .expect("the pool prepares through its member");
    assert_eq!(probe.id, id);
    let entry = e.snapshot().url_tests.unwrap().entries.remove(0);
    assert_eq!(
        (
            entry.status,
            entry.member_id.as_deref(),
            entry.member_name.as_deref()
        ),
        (Status::Testing, Some(first.as_str()), Some("First"))
    );
}

#[test]
fn a_pool_pinned_to_a_wireguard_member_measures_through_the_endpoint_path() {
    let (_dir, mut e) = setup();
    let socks_id = add(&mut e, "Socks", ProfileKind::SingBoxOutbound, socks(1080));
    let wg = add(
        &mut e,
        "WG member",
        ProfileKind::SingBoxOutbound,
        json!({"type":"wireguard","private_key":"cHJpdmF0ZQ==","address":["10.177.43.2/32"],
            "peers":[{"address":"127.0.0.1","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]}),
    );
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&socks_id, &wg], Some(&wg)),
    );
    assert!(supported(
        &e.store.library,
        &profile(&e, &id),
        &Default::default()
    ));
    let test = e.ip_test(&id).unwrap();
    assert_eq!(test.member(), Some((wg.as_str(), "WG member")));
    assert_eq!(test.transport(), "wireguard-endpoint");
    assert_eq!(test.measured_id(), wg);
    // A member without key material leaves the pool out of diagnostics honestly.
    let bare = add(
        &mut e,
        "WG bare",
        ProfileKind::SingBoxOutbound,
        json!({"type":"wireguard"}),
    );
    let bare_pool = add(
        &mut e,
        "Bare pool",
        ProfileKind::AutoSelector,
        pool(&[&bare], None),
    );
    assert!(!supported(
        &e.store.library,
        &profile(&e, &bare_pool),
        &Default::default()
    ));
    assert_eq!(
        e.ip_test(&bare_pool).err().as_deref(),
        Some("probe_unsupported")
    );
}

#[test]
fn a_running_pool_is_measured_through_its_selected_member_and_a_switch_is_stale() {
    let (_dir, mut e) = setup();
    let first = add(
        &mut e,
        "First member",
        ProfileKind::SingBoxOutbound,
        socks(1080),
    );
    let second = add(
        &mut e,
        "Second member",
        ProfileKind::SingBoxOutbound,
        socks(1081),
    );
    let id = add(
        &mut e,
        "Pool",
        ProfileKind::AutoSelector,
        pool(&[&first, &second], Some(&first)),
    );
    // Not running: the pin decides.
    let pinned = e.ip_test(&id).unwrap();
    assert_eq!(pinned.member(), Some((first.as_str(), "First member")));
    assert_eq!(pinned.member_origin(), Some(MemberOrigin::Pinned));
    // Running: the member the pool actually sends traffic through outranks the pin.
    e.running = Some(id.clone());
    e.selector_health.last_selected.insert(
        "proxy".into(),
        crate::auto_selector::member_tag("proxy", &second),
    );
    assert_eq!(e.pool_selection().member(&id), Some(second.as_str()));
    let running = e.ip_test(&id).unwrap();
    assert_eq!(running.member(), Some((second.as_str(), "Second member")));
    assert_eq!(running.member_origin(), Some(MemberOrigin::Running));
    assert_eq!(running.measured_id(), second);
    assert!(e.test_matches(&running));
    assert!(
        !e.test_matches(&pinned),
        "a test issued against the pin no longer describes the running pool"
    );
    // A switch during the test makes its result stale.
    e.selector_health.last_selected.insert(
        "proxy".into(),
        crate::auto_selector::member_tag("proxy", &first),
    );
    assert!(!e.test_matches(&running));
    // Auxiliary routing pools resolve through their route tag; nothing resolves
    // once the connection is gone.
    let route = format!("thronium-route-{id}");
    e.selector_health.last_selected.clear();
    e.selector_health.last_selected.insert(
        route.clone(),
        crate::auto_selector::member_tag(&route, &first),
    );
    e.running = Some(first.clone());
    assert_eq!(e.pool_selection().member(&id), Some(first.as_str()));
    e.running = None;
    assert!(e.pool_selection().is_empty());
}
#[test]
fn a_dynamic_pool_is_measurable_only_through_its_running_selection() {
    let (_dir, mut e) = setup();
    let member = add(
        &mut e,
        "Dynamic member",
        ProfileKind::SingBoxOutbound,
        socks(1080),
    );
    let id = e
        .save_profile(
            serde_json::from_value(
                json!({"name":"Dynamic","groupId":"personal","kind":"auto-selector",
                "config":{"type":"auto-selector","member_source":{"group_id":"personal"}}}),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(!supported(
        &e.store.library,
        &profile(&e, &id),
        &Default::default()
    ));
    assert_eq!(e.ip_test(&id).err().as_deref(), Some("probe_unsupported"));
    e.running = Some(id.clone());
    e.selector_health.last_selected.insert(
        "proxy".into(),
        crate::auto_selector::member_tag("proxy", &member),
    );
    assert!(supported(
        &e.store.library,
        &profile(&e, &id),
        &e.pool_selection()
    ));
    let test = e.ip_test(&id).unwrap();
    assert_eq!(test.member_origin(), Some(MemberOrigin::Running));
    assert_eq!(test.measured_id(), member);
    e.running = None;
    assert!(!e.test_matches(&test));
}
