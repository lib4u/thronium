use super::*;
use serde_json::json;
use std::path::Path;
fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn profile() -> crate::store::Profile {
    crate::store::Profile {
        vpn_policy: None,
        id: "fixture".into(),
        name: "Fixture".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"trojan","server":"127.0.0.1","server_port":443,"password":"profile-secret","tls":{"enabled":true}}),
    }
}
#[tokio::test]
async fn sections_persist_without_overwriting_concurrent_categories() {
    let (dir, mut e) = setup();
    let appearance = section(&e.store.library, "appearance");
    let testing = section(&e.store.library, "testing");
    let mut next = appearance.clone();
    next["theme"] = json!("dark");
    e.save_settings("appearance", appearance.clone(), next.clone())
        .await
        .unwrap();
    let mut test_next = testing.clone();
    test_next["test_concurrent"] = json!(3);
    e.save_settings("testing", testing, test_next.clone())
        .await
        .unwrap();
    assert_eq!(section(&e.store.library, "appearance"), next);
    // Repeating the same desired values is safe even with an old baseline.
    assert_eq!(
        e.save_settings("appearance", appearance, next.clone())
            .await
            .unwrap(),
        next
    );
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(section(&reopened.store.library, "testing"), test_next);
    assert_eq!(section(&reopened.store.library, "appearance"), next);
}
#[tokio::test]
async fn invalid_category_is_atomic_and_secrets_stay_out_of_snapshot() {
    let (dir, mut e) = setup();
    let initial = section(&e.store.library, "inbound");
    let mut next = initial.clone();
    next["inbound_auth"] = json!(true);
    next["inbound_user"] = json!("private-user");
    next["inbound_pass"] = json!("private-password");
    e.save_settings("inbound", initial, next.clone())
        .await
        .unwrap();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let mut invalid = next.clone();
    invalid["inbound_socks_port"] = json!(70000);
    assert!(e.save_settings("inbound", next, invalid).await.is_err());
    assert_eq!(
        before,
        std::fs::read(dir.path().join("library.json")).unwrap()
    );
    let snap = serde_json::to_string(&e.snapshot()).unwrap();
    assert!(!snap.contains("private-user"));
    assert!(!snap.contains("private-password"));
}
#[test]
fn old_library_loads_defaults_without_rewriting_the_file() {
    let (dir, e) = setup();
    let mut library = json!(e.store.library);
    library.as_object_mut().unwrap().remove("settings");
    let bytes = serde_json::to_vec(&library).unwrap();
    std::fs::write(dir.path().join("library.json"), &bytes).unwrap();
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(!boolean(&e.store.library, "inbound_auth"));
    assert_eq!(
        bytes,
        std::fs::read(dir.path().join("library.json")).unwrap()
    );
}
#[tokio::test]
async fn fragment_ranges_reject_zero_size_atomically_but_allow_zero_delay() {
    let (dir, mut e) = setup();
    let original = section(&e.store.library, "presets");
    let mut valid = original.clone();
    valid["fragment_size"] = json!("1-65535");
    valid["fragment_sleep"] = json!("0");
    e.save_settings("presets", original, valid.clone())
        .await
        .unwrap();
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    for (key, value) in [
        ("fragment_size", "0"),
        ("fragment_size", "0-10"),
        ("fragment_size", "10-20-30"),
        ("fragment_size", "65536"),
        ("fragment_size", "20-10"),
        ("fragment_sleep", "65536"),
        ("fragment_sleep", "-1"),
        ("fragment_sleep", "0-1-2"),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = json!(value);
        let error = e
            .save_settings("presets", valid.clone(), invalid)
            .await
            .unwrap_err();
        assert!(error.contains(key), "{key}={value}: {error}");
        assert_eq!(section(&e.store.library, "presets"), valid);
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            disk
        );
    }
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(section(&reopened.store.library, "presets"), valid);
}
#[test]
fn profile_values_override_presets_without_mutating_stored_profile() {
    let mut l = Library::default();
    let mut p = profile();
    p.config["tls"]["insecure"] = json!(false);
    p.config["multiplex"] = json!({"enabled":false});
    l.profiles.push(p.clone());
    l.settings.insert("skip_cert".into(), json!(true));
    l.settings.insert("mux_default_on".into(), json!(true));
    l.settings.insert("utlsFingerprint".into(), json!("chrome"));
    let original = l.clone();
    prepare_profiles(&mut l, &mut p);
    assert_eq!(p.config["tls"]["insecure"], false);
    assert_eq!(p.config["multiplex"]["enabled"], false);
    assert_eq!(p.config["tls"]["utls"]["fingerprint"], "chrome");
    assert!(original.profiles[0].config["tls"].get("utls").is_none());
}
#[test]
fn generated_proxy_uses_saved_address_auth_and_port() {
    let (dir, mut e) = setup();
    e.store.library.settings.extend([
        ("inbound_address".into(), json!("::1")),
        ("inbound_auth".into(), json!(true)),
        ("inbound_user".into(), json!("test")),
        ("inbound_pass".into(), json!("secret")),
    ]);
    let request = Engine::build_with_library(&profile(), &e.store.library, dir.path()).unwrap();
    let config: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    let inbound = config["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["tag"] == "mixed-in")
        .unwrap();
    assert_eq!(inbound["listen"], "::1");
    assert_eq!(inbound["users"][0]["password"], "secret");
}
#[test]
fn dns_interception_uses_or_across_condition_types() {
    let mut l = Library::default();
    l.settings.extend([
        ("enable_dns_server".into(), json!(true)),
        (
            "dns_server_rules".into(),
            json!(["domain:a.test", "suffix:b.test"]),
        ),
    ]);
    let mut c = json!({"inbounds":[],"route":{"rules":[]},"dns":{"rules":[]}});
    intercept::apply(&mut c, &l, &ProfileKind::SingBoxOutbound).unwrap();
    let rules = c["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 4);
    assert!(rules
        .iter()
        .all(|r| r.get("domain").is_some() != r.get("domain_suffix").is_some()));
}
#[test]
fn log_filters_file_and_retention_are_applied() {
    let (dir, mut e) = setup();
    e.store.library.settings.extend([
        ("log_file_enabled".into(), json!(true)),
        ("log_enable_include".into(), json!(true)),
        ("log_include_keyword".into(), json!(["keep"])),
        ("log_enable_exclude".into(), json!(true)),
        ("log_exclude_regex".into(), json!(["secret.*"])),
    ]);
    e.logs.configure(&e.store.library, dir.path());
    e.logs.push("app", Some("info"), "keep this", false);
    e.logs.push("app", Some("info"), "keep secret-data", false);
    e.logs.push("app", Some("info"), "drop this", false);
    let file = std::fs::read_to_string(dir.path().join("diagnostic.log")).unwrap();
    assert!(file.contains("keep this"));
    assert!(!file.contains("secret-data"));
    assert!(!file.contains("drop this"));
    e.history.record(
        dir.path(),
        "p",
        "g",
        vec![crate::traffic::Delta {
            process: "test".into(),
            upload: 10,
            download: 20,
            direct: false,
        }],
        90,
    );
    e.history.flush(dir.path()).unwrap();
    let mut history = history::History::default();
    let items = history.read(dir.path(), 90);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].download, 20);
    history.clear(dir.path()).unwrap();
    assert!(history.read(dir.path(), 90).is_empty());
}
#[test]
fn unsafe_proxy_combinations_and_invalid_regex_are_rejected() {
    let mut l = Library::default();
    l.settings
        .insert("core_box_clash_enabled".into(), json!(true));
    l.settings
        .insert("core_box_clash_listen_addr".into(), json!("0.0.0.0"));
    assert!(validate(&l).is_err());
    l.settings
        .insert("core_box_clash_api_secret".into(), json!("secret"));
    validate(&l).unwrap();
    l.settings.insert("log_include_regex".into(), json!(["["]));
    assert_eq!(
        validate(&l).unwrap_err(),
        "settings_invalid:log_include_regex"
    );
}

#[test]
fn dns_routing_preserves_explicit_rules_and_does_not_broaden_conditions() {
    let mut l = Library::default();
    l.settings.insert("enable_dns_routing".into(), json!(true));
    let mut config = json!({"dns":{"servers":[{"tag":"dns-direct"},{"tag":"dns-remote"}],"rules":[{"domain":["explicit.test"],"action":"reject"}]},"route":{"rules":[{"domain_suffix":["direct.test"],"outbound":"direct"},{"domain":["conditional.test"],"process_name":["browser"],"outbound":"proxy"},{"domain":["vpn.test"],"outbound":"proxy"}]}});
    intercept::follow_routing(&mut config, &l).unwrap();
    let rules = config["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0]["action"], "reject");
    assert_eq!(rules[1]["server"], "dns-direct");
    assert_eq!(rules[2]["server"], "dns-remote");
}
#[test]
fn probe_concurrency_is_bounded_and_cancelled_entries_do_not_restart() {
    let (_dir, mut e) = setup();
    for index in 0..4 {
        let mut p = profile();
        p.id = format!("p{index}");
        e.store.library.profiles.push(p);
    }
    e.store
        .library
        .settings
        .insert("test_concurrent".into(), json!(2));
    let run = e
        .start_url_tests(crate::probes::Options {
            ids: e
                .store
                .library
                .profiles
                .iter()
                .map(|p| p.id.clone())
                .collect(),
            url: "https://example.test".into(),
            timeout_ms: 3000,
            concurrency: None,
        })
        .unwrap();
    assert_eq!(run.concurrency, 2);
    assert!(e.next_url_test(&run.id).is_some());
    assert!(e.next_url_test(&run.id).is_some());
    assert!(e.next_url_test(&run.id).is_none());
    e.finish_url_test(&run.id, "p0", Ok(25));
    assert!(e.next_url_test(&run.id).is_some());
    e.cancel_url_tests();
    assert!(e.next_url_test(&run.id).is_none());
    assert!(*run.cancelled.borrow());
}

#[test]
fn traffic_history_totals_follow_records_pruning_reload_and_clear() {
    let dir = tempfile::tempdir().unwrap();
    let delta = |upload, download| {
        vec![crate::traffic::Delta {
            process: "test".into(),
            upload,
            download,
            direct: false,
        }]
    };
    // A bucket from the epoch is outside every retention window.
    let stale = json!({"old":{"hour":0,"profile":"a","group":"g","process":"test","upload":100,"download":200}});
    std::fs::write(dir.path().join("traffic-history.json"), stale.to_string()).unwrap();
    let mut history = history::History::default();
    history.load(dir.path());
    assert_eq!(history.profile_totals("a"), Some((100, 200)));
    history.record(dir.path(), "a", "g", delta(10, 20), 90);
    assert_eq!(history.profile_totals("a"), Some((10, 20)));
    history.record(dir.path(), "a", "g", delta(1, 2), 90);
    history.record(dir.path(), "b", "g", delta(5, 0), 90);
    assert_eq!(history.profile_totals("a"), Some((11, 22)));
    assert_eq!(history.profile_totals("b"), Some((5, 0)));
    assert_eq!(history.profile_totals("missing"), None);
    history.flush(dir.path()).unwrap();
    let mut reopened = history::History::default();
    reopened.load(dir.path());
    assert_eq!(reopened.profile_totals("a"), Some((11, 22)));
    assert_eq!(reopened.profile_totals("b"), Some((5, 0)));
    reopened.clear(dir.path()).unwrap();
    assert_eq!(reopened.profile_totals("a"), None);
}
#[test]
fn direct_egress_and_remembered_names_are_kept_apart_from_the_running_profile() {
    let dir = tempfile::tempdir().unwrap();
    let mixed = || {
        vec![
            crate::traffic::Delta {
                process: "browser".into(),
                upload: 3,
                download: 4,
                direct: false,
            },
            crate::traffic::Delta {
                process: "browser".into(),
                upload: 30,
                download: 40,
                direct: true,
            },
        ]
    };
    let mut history = history::History::default();
    history.remember(dir.path(), "a", "Exit server", "Team");
    history.record(dir.path(), "a", "g", mixed(), 90);
    // The running profile is credited only with what it carried.
    assert_eq!(history.profile_totals("a"), Some((3, 4)));
    assert_eq!(
        history.profile_totals(history::DIRECT_PROFILE),
        Some((30, 40))
    );
    assert_eq!(history.names()["a"].profile, "Exit server");
    assert_eq!(history.names()["a"].group, "Team");
    history.flush(dir.path()).unwrap();
    // A renamed profile keeps its counted bytes and takes the new name.
    history.remember(dir.path(), "a", "Renamed", "Team");
    history.flush(dir.path()).unwrap();
    let mut reopened = history::History::default();
    reopened.load(dir.path());
    assert_eq!(reopened.profile_totals("a"), Some((3, 4)));
    assert_eq!(reopened.names()["a"].profile, "Renamed");
    // Direct is never a profile of the library, so resetting one leaves it.
    reopened
        .reset_profiles(dir.path(), &["a".to_string()])
        .unwrap();
    assert_eq!(reopened.profile_totals("a"), None);
    assert_eq!(
        reopened.profile_totals(history::DIRECT_PROFILE),
        Some((30, 40))
    );
    reopened.clear(dir.path()).unwrap();
    assert!(reopened.names().is_empty());
}
#[test]
fn unreadable_or_full_traffic_history_never_loses_stored_or_current_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let delta = |process: &str| {
        vec![crate::traffic::Delta {
            process: process.into(),
            upload: 1,
            download: 2,
            direct: false,
        }]
    };
    let file = dir.path().join("traffic-history.json");
    std::fs::write(&file, b"{not json").unwrap();
    let mut history = history::History::default();
    history.record(dir.path(), "a", "g", delta("new"), 90);
    history.flush(dir.path()).unwrap();
    // The unreadable file is set aside unchanged, and new traffic gets a new file.
    let aside: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains("traffic-history.unreadable-"))
        .collect();
    assert_eq!(aside.len(), 1);
    assert_eq!(std::fs::read(&aside[0]).unwrap(), b"{not json");
    let mut reopened = history::History::default();
    assert_eq!(reopened.read(dir.path(), 90).len(), 1);
    // At the bound the oldest hour gives way to current traffic.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old_hour = (now - 3600) / 3600 * 3600;
    let full: serde_json::Map<String, Value> = (0..100_000)
        .map(|i| {
            let hour = old_hour - (i as u64 % 24) * 3600;
            let entry = json!({"hour":hour,"profile":"old","group":"g","process":format!("p{i}"),"upload":1,"download":1});
            (serde_json::to_string(&(hour, "old", "g", format!("p{i}"))).unwrap(), entry)
        })
        .collect();
    std::fs::write(&file, Value::Object(full).to_string()).unwrap();
    let mut history = history::History::default();
    history.record(dir.path(), "current", "g", delta("now"), 90);
    assert_eq!(history.profile_totals("current"), Some((1, 2)));
    assert_eq!(history.profile_totals("old"), Some((99_999, 99_999)));
}
#[test]
fn list_view_fields_appear_only_while_their_switch_is_on() {
    let (dir, mut e) = setup();
    let mut p = profile();
    p.config["tls"]["insecure"] = json!(true);
    e.store.library.profiles.push(p);
    let summary = |e: &mut Engine| e.snapshot().profiles.remove(0);
    let off = summary(&mut e);
    assert_eq!(off["port"], 443);
    assert_eq!(off["security"], "");
    for key in [
        "securityLevel",
        "ipMeasurement",
        "speedMeasurement",
        "traffic",
    ] {
        assert!(off.get(key).is_none(), "{key}");
    }
    e.history.record(
        dir.path(),
        "fixture",
        "personal",
        vec![crate::traffic::Delta {
            process: "t".into(),
            upload: 7,
            download: 9,
            direct: false,
        }],
        90,
    );
    for key in [
        "show_config_security",
        "list_show_ip",
        "list_show_speed",
        "list_show_traffic",
    ] {
        e.store.library.settings.insert(key.into(), json!(true));
    }
    let on = summary(&mut e);
    assert_eq!(on["security"], "TLS");
    assert_eq!(on["securityLevel"], 2);
    assert_eq!(on["ipMeasurement"], Value::Null);
    assert_eq!(on["speedMeasurement"], Value::Null);
    assert_eq!(on["traffic"], json!({"upload": 7, "download": 9}));
    e.store
        .library
        .settings
        .insert("disable_traffic_aggregation".into(), json!(true));
    assert!(summary(&mut e).get("traffic").is_none());
}
#[test]
fn security_display_does_not_reveal_profile_secrets_and_disabling_stats_removes_tracker() {
    let (dir, mut e) = setup();
    let p = profile();
    let text = profile_security(&p);
    assert_eq!(text, "TLS");
    assert!(!text.contains("secret"));
    e.store
        .library
        .settings
        .insert("enable_stats".into(), json!(false));
    let request = Engine::build_with_library(&p, &e.store.library, dir.path()).unwrap();
    let config: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    assert!(config["services"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["type"] != "api"));
}
#[test]
fn subscription_hwid_overrides_and_global_defaults_are_effective() {
    let mut l = Library::default();
    l.settings.insert("sub_send_hwid".into(), json!(true));
    l.settings.insert(
        "sub_custom_hwid_params".into(),
        json!("hwid=fixture,os=FixtureOS,osversion=1,model=fixture-device"),
    );
    l.settings
        .insert("user_agent".into(), json!("fixture-agent"));
    l.settings.insert("sub_auto_update".into(), json!(120));
    let mut sub:crate::subscriptions::Settings=serde_json::from_value(json!({"url":"https://example.test/sub","userAgent":"old","headers":{},"viaProxy":false,"inheritDefaults":true})).unwrap();
    network::subscription_transport(&mut sub, &l);
    assert_eq!(sub.headers["x-hwid"], "fixture");
    assert_eq!(sub.headers["x-ver-os"], "1");
    assert_eq!(sub.user_agent, "fixture-agent");
    assert_eq!(sub.interval_minutes, 120);
}

#[test]
fn tun_kernel_bypass_preserves_ordered_routing_decisions() {
    let mut l = Library::default();
    l.preferences.connection_mode = crate::system_proxy::ConnectionMode::Tun;
    l.settings.insert("enable_tun_routing".into(), json!(true));
    l.settings.insert("vpn_l3_bridge".into(), json!(false));
    let direct = json!({"ip_cidr":["198.18.0.0/24"],"outbound":"direct","action":"route"});
    for (rules, promoted) in [
        (json!([direct.clone()]), true),
        (
            json!([{"domain":["blocked.test"],"action":"reject"},direct.clone()]),
            false,
        ),
        (
            json!([{"port":53,"action":"hijack-dns"},direct.clone()]),
            false,
        ),
        // The captured TUN DNS still keeps its place before any promotion.
        (
            json!([{"inbound":[crate::tun::INTERFACE],"port":53,"action":"hijack-dns"},direct.clone()]),
            false,
        ),
        // Sniffing, resolving and guards of other listeners decide no TUN traffic.
        (
            json!([crate::routing::builtin::sniff(),{"inbound":["mixed-in"],"action":"resolve"},{"inbound":["settings-dns-in"],"action":"hijack-dns"},{"inbound":"settings-redirect","action":"sniff","override_destination":true},direct.clone()]),
            true,
        ),
        (
            json!([{"ip_cidr":["198.18.0.0/24"],"process_name":["private-app"],"outbound":"proxy"},direct]),
            false,
        ),
    ] {
        let mut request = crate::config::build(&profile(), 2080, None).unwrap();
        request.core_config = Some(
            json!({"inbounds":[{"tag":crate::tun::INTERFACE}],"route":{"rules":rules}}).to_string(),
        );
        crate::tun::apply_settings(&mut request, &l).unwrap();
        let config: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
        assert_eq!(
            config["inbounds"][0]["route_exclude_address"]
                .as_array()
                .unwrap()
                .contains(&json!("198.18.0.0/24")),
            promoted
        );
    }
}

#[tokio::test]
async fn interface_reorganization_preserves_saved_flags_and_consumer_values() {
    let (dir, mut e) = setup();
    e.store.library.settings.extend([
        ("show_system_dns".into(), json!(true)),
        ("skip_delete_confirmation".into(), json!(true)),
        ("use_custom_icons".into(), json!(true)),
        ("custom_icon_directory".into(), json!("/fixture/icons")),
        ("font_size".into(), json!(15)),
    ]);
    e.store.commit(e.store.library.clone()).unwrap();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let appearance = section(&e.store.library, "appearance");
    for key in [
        "show_system_dns",
        "skip_delete_confirmation",
        "use_custom_icons",
        "custom_icon_directory",
    ] {
        assert!(appearance.get(key).is_none());
    }
    assert_eq!(appearance["font_size"], 15);
    assert_eq!(
        section(&e.store.library, "logging")["show_system_dns"],
        true
    );
    assert_eq!(
        section(&e.store.library, "system")["custom_icon_directory"],
        "/fixture/icons"
    );
    assert_eq!(e.snapshot().appearance["skip_delete_confirmation"], true);
    assert_eq!(
        before,
        std::fs::read(dir.path().join("library.json")).unwrap()
    );
    let previous = section(&e.store.library, "security");
    let mut next = previous.clone();
    next["skip_delete_confirmation"] = json!(false);
    e.save_settings("security", previous, next).await.unwrap();
    assert_eq!(e.snapshot().appearance["skip_delete_confirmation"], false);
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        section(&reopened.store.library, "system")["use_custom_icons"],
        true
    );
    assert_eq!(
        section(&reopened.store.library, "security")["skip_delete_confirmation"],
        false
    );
}

/// The proxy shortcut used to restart the running request to reset connections.
/// A request that carried a Start-time one-time code must not start again: the
/// same code would be replayed. Turning the proxy off also releases the port the
/// connection claimed, so recovery does not expect to find it retained.
#[tokio::test]
async fn the_proxy_shortcut_never_restarts_a_session_that_spent_a_one_time_code() {
    let (dir, mut e) = setup();
    e.system_proxy = crate::system_proxy::tests::fake_manager(&dir.path().join("proxy"));
    e.system_proxy.enable(2080).unwrap();
    e.store
        .library
        .settings
        .insert("reset_proxy_on_disable_sp".into(), json!(true));
    let mut marks = crate::vpn_auth::otp::StartMarks::new();
    marks.insert(
        "proxy".into(),
        crate::vpn_auth::otp::StartMark {
            otp_id: "otp".into(),
            counter: Some("1".into()),
        },
    );
    e.running = Some("fixture".into());
    e.active_connection = Some(crate::connection::ActiveConnection {
        id: "fixture".into(),
        profiles: Default::default(),
        groups: Default::default(),
        request: Default::default(),
        routing_revision: 0,
        system_port: Some(2080),
        tun: false,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: Default::default(),
        vpn_otp_start: marks,
    });
    e.toggle_system_proxy()
        .await
        .expect("the proxy is released without restarting the core");
    assert!(!e.system_proxy.status().active);
    let active = e.active_connection.as_ref().expect("the session stays up");
    assert_eq!(active.system_port, None);
    assert_eq!(e.running.as_deref(), Some("fixture"));
    assert!(e
        .logs
        .view(Default::default())
        .unwrap()
        .entries
        .iter()
        .any(|entry| entry.text == "vpn_otp_start_stale"));
    e.running = None;
    assert_eq!(
        e.toggle_system_proxy().await.unwrap_err(),
        "not_connected",
        "enabling without a connection names the real reason"
    );
}

/// A library whose saved mode is unavailable here (another desktop session, no
/// proxy backend) must still save unrelated preferences; only choosing that
/// mode again is refused.
#[test]
fn an_unavailable_saved_mode_blocks_choosing_it_not_unrelated_edits() {
    let (_dir, mut e) = setup();
    assert!(
        !e.system_proxy.status().available,
        "no backend in the test session"
    );
    let mut library = e.store.library.clone();
    library.preferences.connection_mode = crate::system_proxy::ConnectionMode::SystemProxy;
    e.store.commit(library).unwrap();
    let mut preferences = e.store.library.preferences.clone();
    preferences.library_sort_descending = !preferences.library_sort_descending;
    e.preferences(preferences)
        .expect("an unrelated preference saves");
    let mut local = e.store.library.preferences.clone();
    local.connection_mode = crate::system_proxy::ConnectionMode::Local;
    e.preferences(local).unwrap();
    let mut proxy = e.store.library.preferences.clone();
    proxy.connection_mode = crate::system_proxy::ConnectionMode::SystemProxy;
    assert_eq!(
        e.preferences(proxy).unwrap_err(),
        "system_proxy_unavailable",
        "choosing the unavailable mode is still refused"
    );
}

/// A first start connects through TUN where it is available; a library saved
/// before keeps the mode it has, even the old default.
#[test]
fn a_new_library_starts_in_tun_and_a_saved_one_keeps_its_mode() {
    use crate::system_proxy::ConnectionMode;
    let (dir, mut e) = setup();
    e.adopt_first_run_defaults();
    let first = e.store.library.preferences.connection_mode;
    assert!(if crate::tun::supported() {
        first == ConnectionMode::Tun
    } else {
        first == ConnectionMode::Local
    });
    let mut local = e.store.library.preferences.clone();
    local.connection_mode = ConnectionMode::Local;
    e.preferences(local).unwrap();
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    e.adopt_first_run_defaults();
    assert!(e.store.library.preferences.connection_mode == ConnectionMode::Local);
}

/// The polled status carries any registered code, including background ones
/// like a stale one-time code, but never raw core text.
#[test]
fn the_snapshot_publishes_registered_codes_and_hides_raw_core_text() {
    let (_dir, mut e) = setup();
    e.error = Some("vpn_otp_start_stale".into());
    assert_eq!(e.snapshot().error.as_deref(), Some("vpn_otp_start_stale"));
    e.error = Some("decode config: outbounds[0].password=private".into());
    assert_eq!(e.snapshot().error.as_deref(), Some("core_error"));
}

/// A directory sync failure after the rename leaves the new preferences in
/// memory and on disk, so their follow-up bookkeeping still runs and the error
/// names the unconfirmed sync rather than a failed save.
#[test]
fn preferences_written_before_a_failed_sync_still_finish_their_bookkeeping() {
    let (_dir, mut e) = setup();
    let mut preferences = e.store.library.preferences.clone();
    preferences.library_sort_descending = !preferences.library_sort_descending;
    let expected = preferences.library_sort_descending;
    e.store
        .fail_next_commit(crate::store::CommitFault::DirectorySync);
    assert_eq!(
        e.preferences(preferences).unwrap_err(),
        crate::store::Store::WRITTEN_UNCERTAIN
    );
    assert_eq!(
        e.store.library.preferences.library_sort_descending, expected,
        "the written preferences are kept"
    );
    assert!(e.store.durability_uncertain());
}

fn measured(e: &mut Engine) -> (String, crate::store::Profile) {
    let id = e
        .save_profile(crate::ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Measured".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
        })
        .unwrap();
    // No selected profile: a network edit would otherwise check it with a Core.
    e.store.library.selected = None;
    e.store.library.preferences.ping.method = crate::probes::Method::Http;
    let options = || crate::probes::Options {
        ids: vec![id.clone()],
        url: "https://example.test/204".into(),
        timeout_ms: 500,
        concurrency: None,
    };
    let run = e.start_url_tests(options()).unwrap();
    e.next_url_test(&run.id).unwrap();
    e.finish_url_test(&run.id, &id, Ok(15));
    let profile = e.profile(&id).unwrap();
    assert!(e.measurement(&profile).is_some());
    (id, profile)
}

/// The log view, log file and traffic history options live in network
/// sections but never reach a Core request: editing them neither waits for a
/// running batch nor forgets measurements.
#[tokio::test]
async fn local_log_options_keep_measurements_while_a_log_level_change_resets_them() {
    let (_dir, mut e) = setup();
    let (id, profile) = measured(&mut e);
    let busy = e
        .start_url_tests(crate::probes::Options {
            ids: vec![id.clone()],
            url: "https://example.test/204".into(),
            timeout_ms: 500,
            concurrency: None,
        })
        .unwrap();
    e.next_url_test(&busy.id).unwrap();
    let logging = section(&e.store.library, "logging");
    let mut local = logging.clone();
    local["log_auto_scroll"] = json!(!logging["log_auto_scroll"].as_bool().unwrap());
    local["connection_sort_asc"] = json!(!logging["connection_sort_asc"].as_bool().unwrap());
    e.save_settings("logging", logging.clone(), local.clone())
        .await
        .unwrap();
    assert!(e.measurement(&profile).is_some());
    let mut level = local.clone();
    level["log_level"] = json!("debug");
    assert_eq!(
        e.save_settings("logging", local.clone(), level.clone())
            .await
            .unwrap_err(),
        "probe_busy"
    );
    e.cancel_url_tests();
    e.save_settings("logging", local, level).await.unwrap();
    assert!(e.measurement(&profile).is_none());
}

#[tokio::test]
async fn measurements_are_reset_only_once_the_settings_are_written() {
    let (_dir, mut e) = setup();
    let (_, profile) = measured(&mut e);
    let logging = section(&e.store.library, "logging");
    let mut level = logging.clone();
    level["log_level"] = json!("debug");
    e.store
        .fail_next_commit(crate::store::CommitFault::BeforeRename);
    assert!(e
        .save_settings("logging", logging.clone(), level.clone())
        .await
        .is_err());
    assert!(
        e.measurement(&profile).is_some(),
        "an unsaved change keeps measurements"
    );
    e.store
        .fail_next_commit(crate::store::CommitFault::DirectorySync);
    assert_eq!(
        e.save_settings("logging", logging, level)
            .await
            .unwrap_err(),
        crate::store::Store::WRITTEN_UNCERTAIN
    );
    assert!(
        e.measurement(&profile).is_none(),
        "a written change resets them"
    );
}

#[test]
fn local_fields_are_catalogued_and_never_change_a_core_request() {
    let (_dir, e) = setup();
    let mut library = e.store.library.clone();
    let profiles = [
        profile(),
        crate::store::Profile {
            id: "xray".into(),
            kind: ProfileKind::XrayOutbound,
            config: json!({"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls"}}),
            ..profile()
        },
    ];
    library.profiles = profiles.to_vec();
    let request = |library: &Library| {
        profiles
            .iter()
            .map(|p| {
                let r = Engine::build_with_library(p, library, &e.data_dir).unwrap();
                // The local Xray bridge port is chosen per build.
                let bridge = r.xray_config.as_deref().map(|x| {
                    serde_json::from_str::<Value>(x).unwrap()["inbounds"][0]["port"].to_string()
                });
                let stable = |text: Option<String>| match (&bridge, text) {
                    (Some(port), Some(text)) => Some(text.replace(port.as_str(), "PORT")),
                    (_, text) => text,
                };
                (
                    stable(r.core_config),
                    stable(r.xray_config),
                    r.xray_full_configs,
                )
            })
            .collect::<Vec<_>>()
    };
    let baseline = request(&library);
    assert_eq!(request(&library), baseline, "builds are deterministic");
    for id in LOCAL_FIELDS {
        let field = fields()
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("{id} is not a settings field"));
        assert!(field.preference.is_none(), "{id}");
        let mut next = library.clone();
        let changed = match &field.default {
            Value::Bool(b) => json!(!b),
            Value::Number(n) => json!(n.as_i64().unwrap() + 1),
            _ => json!(field
                .options
                .as_ref()
                .and_then(|o| o.iter().find(|v| json!(v) != field.default).cloned())
                .unwrap_or_else(|| "fixture".into())),
        };
        next.settings.insert(id.into(), changed);
        assert_eq!(request(&next), baseline, "{id}");
    }
}

/// Saving a network setting checks the selected profile with the same assets
/// Connect would prepare, instead of failing on a not yet downloaded list.
#[tokio::test]
async fn a_network_settings_check_prepares_routing_assets_first() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(profile());
    e.store.library.selected = Some("fixture".into());
    e.store.library.routing.profiles[0].route["rule_set"] = json!([{"type":"geodata","tag":"fixture","kind":"geosite","url":"local:fixture","category":"test"}]);
    let dns = section(&e.store.library, "dns");
    let mut next = dns.clone();
    next["enable_dns_routing"] = json!(!dns["enable_dns_routing"].as_bool().unwrap());
    assert_eq!(
        e.save_settings("dns", dns, next).await.unwrap_err(),
        "geodata_local_missing",
        "the asset preparation ran before the request was built"
    );
}
