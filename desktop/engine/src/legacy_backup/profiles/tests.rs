use super::*;
use crate::legacy_backup::{SourceOtp, SourceRoute, SourceSetting};

const UUID: &str = "11111111-1111-4111-8111-111111111111";
fn row(items: &[(&str, SourceValue)]) -> SourceRow {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}
fn group(id: i64, name: &str, ids: &[i64]) -> SourceGroup {
    SourceGroup {
        id,
        name: name.into(),
        columns: row(&[("profiles_json", SourceValue::Text(json!(ids).to_string()))]),
    }
}
fn profile(id: i64, gid: i64, kind: &str, config: Value) -> SourceProfile {
    SourceProfile {
        id,
        group_id: gid,
        kind: kind.into(),
        name: Some(format!("Source {id}")),
        columns: row(&[("outbound_json", SourceValue::Text(config.to_string()))]),
        outbound: config,
    }
}
fn socks(id: i64, gid: i64) -> SourceProfile {
    profile(
        id,
        gid,
        "socks",
        json!({"type":"socks","tag":format!("Socks {id}"),"server":"127.0.0.1","server_port":19000+id}),
    )
}
fn custom_profile(id: i64, gid: i64, subtype: &str, config: Value) -> SourceProfile {
    profile(
        id,
        gid,
        "custom",
        json!({"type":"custom","name":format!("Custom {id}"),"subtype":subtype,"config":config.to_string()}),
    )
}
fn set(db: &mut SourceDatabase, key: &str, value: &str) {
    db.settings.push(SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: SourceRow::new(),
    });
}
fn simple() -> SourceDatabase {
    SourceDatabase {
        groups: vec![group(0, "Original", &[1])],
        profiles: vec![socks(1, 0)],
        ..Default::default()
    }
}
/// Issues of a conversion that blocked the section or left entries out.
fn codes_report(db: &SourceDatabase) -> Vec<Issue> {
    match convert(db) {
        Ok(plan) => plan.report,
        Err(issues) => issues,
    }
}
/// Codes that block the section or leave entries out of an otherwise accepted plan.
fn codes(db: &SourceDatabase) -> Vec<String> {
    match convert(db) {
        Ok(plan) => {
            let codes: Vec<String> = plan.report.into_iter().map(|issue| issue.code).collect();
            assert!(
                codes
                    .iter()
                    .any(|c| c == "legacy_profile_skipped" || c == "legacy_group_skipped"),
                "unexpected complete conversion: {codes:?}"
            );
            codes
        }
        Err(issues) => issues.into_iter().map(|issue| issue.code).collect(),
    }
}
fn plan(db: &SourceDatabase) -> ProfilePlan {
    match convert(db) {
        Ok(plan) => plan,
        Err(issues) => panic!(
            "conversion failed: {}",
            serde_json::to_string(&issues).unwrap()
        ),
    }
}

#[test]
fn ids_order_names_and_original_source_are_preserved_without_reusing_personal() {
    let mut db = SourceDatabase {
        groups: vec![group(0, "First", &[2, 2]), group(4, "Second", &[3])],
        profiles: vec![socks(1, 0), socks(2, 0), socks(3, 4)],
        group_order: vec![
            row(&[
                ("group_id", SourceValue::Integer(4)),
                ("display_order", SourceValue::Integer(0)),
            ]),
            row(&[
                ("group_id", SourceValue::Integer(0)),
                ("display_order", SourceValue::Integer(1)),
            ]),
        ],
        ..Default::default()
    };
    db.profiles[0]
        .outbound
        .as_object_mut()
        .unwrap()
        .remove("tag");
    db.profiles[0].name = None;
    let before: Vec<_> = db
        .profiles
        .iter()
        .map(|p| (p.outbound.clone(), p.columns.clone()))
        .collect();
    set(&mut db, "remember_id", "2");
    let plan = plan(&db);
    assert_eq!(
        plan.groups
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>(),
        ["Second", "First"]
    );
    assert_eq!(
        plan.profiles
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        [
            plan.profile_ids[&3].as_str(),
            plan.profile_ids[&2].as_str(),
            plan.profile_ids[&1].as_str()
        ]
    );
    assert!(plan
        .group_ids
        .values()
        .all(|id| uuid::Uuid::parse_str(id).is_ok() && id != "personal"));
    assert_eq!(plan.selected, Some(plan.profile_ids[&2].clone()));
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_order_deduplicated"));
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_order_completed"));
    assert!(plan
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_name_generated"));
    assert!(
        before
            == db
                .profiles
                .iter()
                .map(|p| (p.outbound.clone(), p.columns.clone()))
                .collect::<Vec<_>>()
    );
}
#[test]
fn four_custom_subtypes_keep_complete_json_and_source_core() {
    let configs = [
        (
            "outbound",
            ProfileKind::SingBoxOutbound,
            json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":UUID,"custom_future":{"sentinel":true}}),
        ),
        (
            "fullconfig",
            ProfileKind::SingBoxConfig,
            json!({"dns":{"servers":[{"type":"local","tag":"local"}]},"inbounds":[],"outbounds":[{"type":"direct","tag":"out"}],"route":{"final":"out"},"experimental":{"cache_file":{"enabled":false}}}),
        ),
        (
            "xrayoutbound",
            ProfileKind::XrayOutbound,
            json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":UUID,"encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"extra":{"mode":"packet-up"}}}}),
        ),
        (
            "xrayfullconfig",
            ProfileKind::XrayConfig,
            json!({"dns":{"queryStrategy":"UseIP","servers":["127.0.0.1"]},"inbounds":[{"tag":"socks","protocol":"socks","listen":"127.0.0.1","port":10808,"settings":{"udp":true}}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"domain":["domain:fixture.invalid"],"outboundTag":"direct"}]},"remarks":"metadata stays","meta":null}),
        ),
    ];
    let db = SourceDatabase {
        groups: vec![group(0, "Custom", &[1, 2, 3, 4])],
        profiles: configs
            .iter()
            .enumerate()
            .map(|(index, (subtype, _, config))| {
                custom_profile(index as i64 + 1, 0, subtype, config.clone())
            })
            .collect(),
        ..Default::default()
    };
    let plan = plan(&db);
    for (profile, (_, kind, config)) in plan.profiles.iter().zip(configs.iter()) {
        assert_eq!(profile.kind, *kind);
        assert_eq!(profile.config, *config);
    }
    assert_eq!(plan.vless_overrides[&plan.profile_ids[&1]], Core::SingBox);
    assert_eq!(plan.vless_overrides[&plan.profile_ids[&3]], Core::Xray);
    assert!(!plan.vless_overrides.contains_key(&plan.profile_ids[&2]));
}
#[test]
fn subscription_url_metadata_and_timestamp_survive_with_manual_unmanaged_updates() {
    let mut db = simple();
    let columns = &mut db.groups[0].columns;
    for (key, value) in [
        (
            "url",
            SourceValue::Text(
                "https://subscription.invalid/feed?token=private-sentinel&x=%2F".into(),
            ),
        ),
        (
            "info",
            SourceValue::Text("Provider metadata\nquota is unparsed".into()),
        ),
        ("sub_last_update", SourceValue::Integer(1750000000)),
        ("archive", SourceValue::Integer(1)),
        ("skip_auto_update", SourceValue::Integer(1)),
    ] {
        columns.insert(key.into(), value);
    }
    set(&mut db, "sub_auto_update", "30");
    set(&mut db, "sub_clear", "true");
    let plan = plan(&db);
    let subscription = plan.groups[0].subscription.as_ref().unwrap();
    assert_eq!(
        subscription.settings.url,
        "https://subscription.invalid/feed?token=private-sentinel&x=%2F"
    );
    assert_eq!(subscription.settings.interval_minutes, 0);
    assert_eq!(subscription.settings.inherit_defaults, Some(false));
    assert!(subscription.managed_ids.is_empty());
    assert_eq!(subscription.updated_at, Some(1750000000));
    assert_eq!(
        subscription.metadata.announcement.as_deref(),
        Some("Provider metadata\nquota is unparsed")
    );
    let report = serde_json::to_string(&plan.report).unwrap();
    assert!(!report.contains("private-sentinel"));
    assert!(!report.contains("quota"));
    assert!(report.contains("legacy_subscription_manual_review"));
    assert!(report.contains("legacy_group_archive_deferred"));
}
#[test]
fn nested_chains_and_group_wrappers_map_ids_without_reordering_hops() {
    let mut db = SourceDatabase {
        groups: vec![group(0, "Leaves", &[1, 2, 3]), group(1, "Chains", &[4, 5])],
        profiles: vec![
            socks(1, 0),
            socks(2, 0),
            socks(3, 0),
            profile(
                4,
                1,
                "chain",
                json!({"type":"chain","name":"Inner","list":[2]}),
            ),
            profile(
                5,
                1,
                "chain",
                json!({"type":"chain","name":"Outer","list":[4,3]}),
            ),
        ],
        ..Default::default()
    };
    db.groups[1]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(1));
    db.groups[1]
        .columns
        .insert("landing_proxy_id".into(), SourceValue::Integer(3));
    let plan = plan(&db);
    let outer = plan
        .profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&5])
        .unwrap();
    assert_eq!(
        outer.config["hops"],
        json!([plan.profile_ids[&4], plan.profile_ids[&3]])
    );
    assert_eq!(
        crate::chains::flatten(outer, &plan.profiles)
            .unwrap()
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        [plan.profile_ids[&2].as_str(), plan.profile_ids[&3].as_str()]
    );
    assert_eq!(
        plan.groups[1].proxy_chain.front,
        Some(plan.profile_ids[&1].clone())
    );
    assert_eq!(
        plan.groups[1].proxy_chain.landing,
        Some(plan.profile_ids[&3].clone())
    );
}
#[test]
fn bad_ids_membership_order_and_reference_graphs_block_atomically() {
    let mut db = simple();
    db.profiles.push(socks(1, 0));
    assert!(codes(&db).contains(&"legacy_profile_id".into()));
    let mut db = simple();
    db.profiles[0].group_id = 9;
    assert!(codes(&db).contains(&"legacy_profile_group_missing".into()));
    let mut db = simple();
    db.groups[0]
        .columns
        .insert("profiles_json".into(), SourceValue::Text("[99]".into()));
    assert!(codes(&db).contains(&"legacy_group_profile_missing".into()));
    let mut db = simple();
    db.group_order.push(row(&[
        ("group_id", SourceValue::Integer(99)),
        ("display_order", SourceValue::Integer(0)),
    ]));
    assert!(codes(&db).contains(&"legacy_group_order".into()));
    let mut db = simple();
    db.groups[0]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(99));
    assert!(codes(&db).contains(&"legacy_group_proxy_missing".into()));
    let mut db = simple();
    db.profiles[0] = profile(1, 0, "chain", json!({"type":"chain","list":[1]}));
    assert!(codes(&db).contains(&"legacy_chain_cycle".into()));
    let mut db = simple();
    db.profiles[0] = profile(1, 0, "chain", json!({"type":"chain","list":[99]}));
    assert!(codes(&db).contains(&"legacy_chain_reference_missing".into()));
}
#[test]
fn unsupported_types_and_unknown_client_fields_do_not_silently_become_socks() {
    for (kind, code) in [
        ("autoselector", "legacy_selector_snapshot_choice_required"),
        (
            "extracore",
            if cfg!(any(target_os = "linux", target_os = "windows")) {
                "legacy_profile_discriminator"
            } else {
                "legacy_external_platform_unsupported"
            },
        ),
        ("warp", "legacy_profile_wireguard_unsupported"),
        // A Tailscale row carries only Tailscale fields.
        ("tailscale", "legacy_profile_field_unsupported"),
        ("future-kind", "legacy_profile_type_unsupported"),
    ] {
        let mut db = simple();
        db.profiles[0].kind = kind.into();
        assert!(codes(&db).contains(&code.into()));
    }
    let mut db = simple();
    db.profiles[0].outbound["future_client_option"] = json!({"password":"secret-sentinel"});
    let report = serde_json::to_string(&codes_report(&db)).unwrap();
    assert!(report.contains("legacy_profile_field_unsupported"));
    assert!(!report.contains("secret-sentinel"));
    assert!(!report.contains("future_client_option"));
    let mut db = simple();
    db.profiles[0].outbound["type"] = json!("http");
    assert!(codes(&db).contains(&"legacy_profile_discriminator".into()));
}
#[test]
fn ech_query_server_name_converts_while_an_unknown_ech_key_stays_blocked() {
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "vless",
        json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":UUID,"tls":{"enabled":true,"ech":{"enabled":true,"config":["fixture"],"query_server_name":"ech.example"}}}),
    );
    let config = &plan(&db).profiles[0].config;
    assert_eq!(config["tls"]["ech"]["query_server_name"], "ech.example");
    assert_eq!(config["tls"]["ech"]["enabled"], true);
    db.profiles[0] = profile(
        1,
        0,
        "vless",
        json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":UUID,"tls":{"enabled":true,"ech":{"enabled":true,"server_name":"ech.example"}}}),
    );
    assert!(codes(&db).contains(&"legacy_profile_field_unsupported".into()));
}
#[test]
fn tls_false_and_default_states_freeze_effective_off_and_global_certificate_choice() {
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "vless",
        json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":UUID,"tls":{"enabled":true,"spoof_enabled":false,"spoof":"inactive-secret","fragment":false,"tls_tricks":{"mixedcase_sni":false}}}),
    );
    set(&mut db, "tls_spoof_default_on", "true");
    set(&mut db, "tls_spoof", "global-secret");
    set(&mut db, "fragment_default_on", "true");
    set(&mut db, "tls_tricks_default_on", "true");
    set(&mut db, "skip_cert", "true");
    set(&mut db, "utlsFingerprint", "chrome");
    let plan = plan(&db);
    let config = &plan.profiles[0].config;
    assert_eq!(config["tls"]["spoof"], "");
    assert!(config["tls"].get("spoof_enabled").is_none());
    assert_eq!(config["tls"]["fragment"], false);
    assert_eq!(config["tls"]["tls_tricks"]["mixedcase_sni"], false);
    assert_eq!(config["tls"]["insecure"], true);
    assert_eq!(config["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(config["multiplex"]["enabled"], false);
    assert_eq!(plan.vless_overrides[&plan.profiles[0].id], Core::SingBox);
    let mut destination = Library {
        profiles: plan.profiles.clone(),
        groups: plan.groups.clone(),
        ..Library::default()
    };
    for key in [
        "tls_spoof_default_on",
        "fragment_default_on",
        "tls_tricks_default_on",
        "mux_default_on",
    ] {
        destination.settings.insert(key.into(), json!(true));
    }
    destination
        .settings
        .insert("tls_spoof".into(), json!("destination-secret"));
    let mut prepared = destination.profiles[0].clone();
    crate::settings::prepare_profiles(&mut destination, &mut prepared);
    assert_eq!(prepared.config["tls"]["spoof"], "");
    assert_eq!(prepared.config["multiplex"]["enabled"], false);
    assert_eq!(db.profiles[0].outbound["tls"]["spoof"], "inactive-secret");
}
#[test]
fn effective_tls_tricks_external_paths_and_xray_mux_have_explicit_blockers() {
    for tls in [
        json!({"enabled":true,"spoof_enabled":true,"spoof":"secret-spoof"}),
        json!({"enabled":true,"fragment":true}),
        json!({"enabled":true,"tls_tricks":{"mixedcase_sni":true}}),
    ] {
        let mut db = simple();
        db.profiles[0] = profile(
            1,
            0,
            "http",
            json!({"type":"http","server":"127.0.0.1","server_port":443,"tls":tls}),
        );
        assert!(codes(&db).contains(&"legacy_profile_tls_tricks_unsupported".into()));
    }
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "http",
        json!({"type":"http","server":"127.0.0.1","server_port":443,"tls":{"enabled":true,"certificate_path":"/private/cert.pem"}}),
    );
    // The path stays for the review to offer as a selectable resource.
    assert_eq!(
        plan(&db).profiles[0].config["tls"]["certificate_path"],
        "/private/cert.pem"
    );
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "xrayvless",
        json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":UUID,"encryption":"none"},"mux":{"enabled":true}}),
    );
    assert!(codes(&db).contains(&"legacy_profile_xray_mux_unsupported".into()));
}
#[test]
fn inherited_singbox_mux_is_materialized_and_explicit_off_stays_off() {
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "vmess",
        json!({"type":"vmess","server":"127.0.0.1","server_port":443,"uuid":UUID}),
    );
    set(&mut db, "mux_default_on", "true");
    set(&mut db, "mux_protocol", "h2mux");
    set(&mut db, "mux_concurrency", "7");
    set(&mut db, "mux_padding", "true");
    let first = plan(&db);
    assert_eq!(
        first.profiles[0].config["multiplex"],
        json!({"enabled":true,"protocol":"h2mux","max_streams":7,"padding":true})
    );
    db.profiles[0].outbound["multiplex"] = json!({"enabled":false});
    assert_eq!(
        plan(&db).profiles[0].config["multiplex"],
        json!({"enabled":false})
    );
}
#[test]
fn malformed_custom_nested_duplicates_and_wrapped_full_config_are_blocked() {
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "custom",
        json!({"type":"custom","subtype":"fullconfig","config":"{\"outbounds\":[{\"type\":\"direct\",\"type\":\"socks\"}]}"}),
    );
    assert!(codes(&db).contains(&"legacy_profile_json".into()));
    let mut db = simple();
    db.profiles[0] = custom_profile(1, 0, "fullconfig", json!({"outbounds":[{"type":"direct"}]}));
    db.profiles.push(socks(2, 0));
    db.groups[0]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(2));
    assert!(codes(&db).contains(&"legacy_group_chain_unsupported".into()));
    let mut db = simple();
    db.groups[0]
        .columns
        .insert("profiles_json".into(), SourceValue::Text("[1.5]".into()));
    assert!(codes(&db).contains(&"legacy_group_profiles_json".into()));
}
#[test]
fn deferred_parts_are_reported_without_their_values_or_source_mutation() {
    let mut db = simple();
    set(&mut db, "dns_object", "secret-dns-document");
    db.routes.push(SourceRoute {
        id: 1,
        name: "old route".into(),
        columns: SourceRow::new(),
    });
    db.otp.push(SourceOtp {
        id: 1,
        columns: row(&[("secret", SourceValue::Text("otp-secret".into()))]),
    });
    db.other_tables.insert(
        "future".into(),
        vec![row(&[("data", SourceValue::Text("future-secret".into()))])],
    );
    let plan = plan(&db);
    let report = serde_json::to_string(&plan.report).unwrap();
    for code in [
        "legacy_settings_deferred",
        "legacy_routing_deferred",
        "legacy_otp_deferred",
        "legacy_profile_metrics_deferred",
        "legacy_group_layout_deferred",
        "legacy_other_tables_deferred",
    ] {
        assert!(report.contains(code));
    }
    for secret in ["secret-dns-document", "otp-secret", "future-secret"] {
        assert!(!report.contains(secret));
    }
    assert_eq!(db.settings[0].value, "secret-dns-document");
    assert_eq!(db.routes.len(), 1);
    assert_eq!(db.otp.len(), 1);
}

#[tokio::test]
#[ignore = "requires the explicitly supplied disposable local core; no remote profiles"]
async fn real_core_checks_converted_singbox_xray_full_configs_and_mixed_chains() {
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE is required");
    if std::env::var_os("THRONIUM_LEGACY_CORE_FIXTURE").is_none() {
        // Preserve the release core's parent-name, same-directory and peer-PID
        // checks, exactly as scripts/test_core.py does for standalone smoke bins.
        let bundle = tempfile::tempdir().unwrap();
        let executable = bundle.path().join(if cfg!(windows) {
            "Thronium.exe"
        } else {
            "Thronium"
        });
        let bundled_core = bundle.path().join(if cfg!(windows) {
            "ThroniumCore.exe"
        } else {
            "ThroniumCore"
        });
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(&core, &bundled_core).unwrap();
        let output = std::process::Command::new(executable)
            .args(["--exact", "legacy_backup::profiles::tests::real_core_checks_converted_singbox_xray_full_configs_and_mixed_chains", "--ignored", "--nocapture"])
            .env("THRONIUM_LEGACY_CORE_FIXTURE", "1")
            .env("THRONIUM_TEST_CORE", bundled_core)
            .output().unwrap();
        assert!(
            output.status.success(),
            "owned fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut db = SourceDatabase {
        groups: vec![
            group(0, "Ordinary", &[1, 2, 3, 4, 5, 6, 7, 8]),
            group(1, "Full JSON", &[9, 10]),
            group(2, "Wrapped", &[11]),
        ],
        profiles: vec![socks(1, 0)],
        ..Default::default()
    };
    db.profiles.push(profile(2,0,"vless",json!({"type":"vless","server":"127.0.0.1","server_port":19002,"uuid":UUID,"packet_encoding":"xudp","tls":{"enabled":true,"server_name":"fixture.invalid"}})));
    db.profiles.push(profile(3,0,"xrayvless",json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":19003,"id":UUID,"encryption":"none"},"streamSettings":{"network":"raw","security":"tls","tlsSettings":{"serverName":"fixture.invalid","fingerprint":"chrome"}}})));
    db.profiles.push(profile(4,0,"http",json!({"type":"http","server":"127.0.0.1","server_port":19004,"tls":{"enabled":true,"server_name":"fixture.invalid","spoof_enabled":false}})));
    db.profiles.push(profile(5,0,"shadowsocks",json!({"type":"shadowsocks","server":"127.0.0.1","server_port":19005,"method":"aes-128-gcm","password":"fixture-password"})));
    db.profiles.push(profile(6,0,"vmess",json!({"type":"vmess","server":"127.0.0.1","server_port":19006,"uuid":UUID,"packet_encoding":"xudp"})));
    db.profiles.push(profile(7,0,"trojan",json!({"type":"trojan","server":"127.0.0.1","server_port":19007,"password":"fixture-password","tls":{"enabled":true,"server_name":"fixture.invalid"}})));
    db.profiles.push(profile(
        8,
        0,
        "chain",
        json!({"type":"chain","name":"Mixed SB/Xray","list":[1,3,2]}),
    ));
    let sb = json!({"dns":{"servers":[{"type":"udp","tag":"local-dns","server":"127.0.0.1","server_port":5300}],"final":"local-dns"},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":19009}],"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":19109},{"type":"direct","tag":"direct"}],"route":{"rules":[{"domain_suffix":["fixture.invalid"],"outbound":"direct"}],"final":"proxy"}});
    let xray = json!({"dns":{"servers":["127.0.0.1"],"queryStrategy":"UseIP"},"inbounds":[{"tag":"socks","listen":"127.0.0.1","port":19010,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"127.0.0.1","port":19110,"id":UUID,"encryption":"none"}},{"tag":"direct","protocol":"freedom"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"domain":["domain:fixture.invalid"],"outboundTag":"direct"}]}});
    db.profiles
        .push(custom_profile(9, 1, "fullconfig", sb.clone()));
    db.profiles
        .push(custom_profile(10, 1, "xrayfullconfig", xray.clone()));
    db.profiles.push(socks(11, 2));
    db.groups[2]
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(1));
    db.groups[2]
        .columns
        .insert("landing_proxy_id".into(), SourceValue::Integer(3));
    let plan = plan(&db);
    let dir = tempfile::tempdir().unwrap();
    let mut engine = crate::Engine::open(dir.path(), std::path::Path::new(&core)).unwrap();
    let mut library = engine.store.library.clone();
    library.profiles = plan.profiles.clone();
    library.groups = plan.groups.clone();
    library.preferences.vless_overrides = plan.vless_overrides.clone();
    engine.store.commit(library).unwrap();
    for profile in &plan.profiles {
        if let Err(code) = engine.check(profile).await {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            let diagnostics = engine.logs.view(Default::default()).unwrap();
            engine.shutdown().await;
            panic!(
                "synthetic check {} {:?} failed: {code}; {}",
                profile.name,
                profile.kind,
                serde_json::to_string(&diagnostics).unwrap()
            );
        }
    }
    assert_eq!(engine.profile(&plan.profile_ids[&9]).unwrap().config, sb);
    assert_eq!(engine.profile(&plan.profile_ids[&10]).unwrap().config, xray);
    engine.shutdown().await;
}

#[test]
fn consumed_default_values_must_be_well_typed() {
    for (key, value) in [
        ("mux_concurrency", "nonsense-private"),
        ("skip_cert", "maybe-private"),
        ("tls_spoof_default_on", "TRUE"),
    ] {
        let mut db = simple();
        set(&mut db, key, value);
        assert!(codes(&db).contains(&"legacy_profile_defaults_invalid".into()));
        let output = match convert(&db) {
            Ok(_) => panic!("invalid defaults accepted"),
            Err(issues) => serde_json::to_string(&issues).unwrap(),
        };
        assert!(!output.contains(value));
    }
}

#[test]
fn independently_written_native_qt_fixture_converts_and_blockers_remain_atomic() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/legacy-import");
    let valid = crate::legacy_backup::read(&directory.join("valid.thrbackup")).unwrap();
    assert!(valid.parts.profiles);
    let converted = plan(valid.database.as_ref().unwrap());
    assert_eq!(converted.profiles.len(), 13);
    assert_eq!(converted.groups.len(), 4);
    assert_eq!(converted.groups[0].name, "Legacy subscription 日本");
    assert_eq!(
        converted
            .profiles
            .iter()
            .find(|p| p.id == converted.profile_ids[&41])
            .unwrap()
            .name,
        "Legacy socks 🦊"
    );
    assert_eq!(
        converted.vless_overrides[&converted.profile_ids[&45]],
        Core::SingBox
    );
    assert_eq!(
        converted.vless_overrides[&converted.profile_ids[&47]],
        Core::Xray
    );
    let blocked = crate::legacy_backup::read(&directory.join("blocked.thrbackup")).unwrap();
    let codes = codes(blocked.database.as_ref().unwrap());
    for code in [
        "legacy_selector_snapshot_choice_required",
        "legacy_profile_field_unsupported",
    ] {
        assert!(codes.contains(&code.into()));
    }
    // The full sing-box profile with a local rule-set path converts now; its
    // file is requested by the review instead of blocking the batch.
    assert!(!codes.contains(&"legacy_profile_external_resource".into()));
    let external_code = if cfg!(any(target_os = "linux", target_os = "windows")) {
        "legacy_profile_field_unsupported"
    } else {
        "legacy_external_platform_unsupported"
    };
    let issues = convert(blocked.database.as_ref().unwrap()).err().unwrap();
    assert!(issues
        .iter()
        .any(|issue| issue.source_id == Some(56) && issue.code == external_code));
    assert!(!issues.iter().any(|issue| issue.source_id == Some(58)));
}

#[test]
fn subscription_preserves_provider_user_agent_proxy_choice_and_blocks_bad_headers() {
    let mut db = simple();
    db.groups[0].columns.insert(
        "url".into(),
        SourceValue::Text("https://subscription.invalid/synthetic".into()),
    );
    let missing = plan(&db);
    assert!(missing
        .report
        .iter()
        .any(|issue| issue.code == "legacy_subscription_user_agent_review"));
    set(
        &mut db,
        "user_agent2",
        "Happ/3.0.0 (Linux; migration-fixture)",
    );
    set(&mut db, "net_use_proxy", "true");
    let explicit = plan(&db);
    let settings = &explicit.groups[0].subscription.as_ref().unwrap().settings;
    assert_eq!(settings.user_agent, "Happ/3.0.0 (Linux; migration-fixture)");
    assert!(settings.via_proxy);
    assert_eq!(settings.inherit_defaults, Some(false));
    assert_eq!(settings.interval_minutes, 0);
    assert!(!explicit
        .report
        .iter()
        .any(|issue| issue.code == "legacy_subscription_user_agent_review"));
    assert!(explicit
        .report
        .iter()
        .any(|issue| issue.code == "legacy_subscription_transport_review"));
    // Throne's empty value named its own client; Thronium uses its default.
    db.settings[0].value = String::new();
    let empty = plan(&db);
    assert_eq!(
        empty.groups[0]
            .subscription
            .as_ref()
            .unwrap()
            .settings
            .user_agent,
        crate::subscriptions::user_agent()
    );
    assert!(empty
        .report
        .iter()
        .any(|issue| issue.code == "legacy_network_default_user_agent"));
    db.settings[0].value = "Happ\r\nAuthorization: synthetic-private-header".into();
    let errors = match convert(&db) {
        Ok(_) => panic!("malformed user agent accepted"),
        Err(issues) => serde_json::to_string(&issues).unwrap(),
    };
    assert!(errors.contains("legacy_subscription_settings"));
    assert!(!errors.contains("synthetic-private-header"));
}

#[test]
fn excluded_settings_cannot_change_profiles_subscription_defaults_or_selection() {
    let mut db = simple();
    db.profiles[0] = profile(
        1,
        0,
        "vless",
        json!({"type":"vless","server":"127.0.0.1","server_port":443,"uuid":UUID,"tls":{"enabled":true}}),
    );
    db.groups[0].columns.insert(
        "url".into(),
        SourceValue::Text("https://subscription.invalid/selected-profiles".into()),
    );
    for (key, value) in [
        ("skip_cert", "true"),
        ("mux_default_on", "true"),
        ("net_use_proxy", "true"),
        ("user_agent2", "Happ/selected-settings-only"),
        ("remember_id", "1"),
        ("fragment_default_on", "true"),
    ] {
        set(&mut db, key, value);
    }
    let original = db.profiles[0].outbound.clone();
    let settings_before: Vec<_> = db
        .settings
        .iter()
        .map(|setting| (setting.key.clone(), setting.value.clone()))
        .collect();
    let converted = convert_selected(&db, false).unwrap_or_else(|issues| {
        panic!(
            "excluded settings affected conversion: {}",
            serde_json::to_string(&issues).unwrap()
        )
    });
    assert_eq!(converted.profiles.len(), 1);
    assert_eq!(converted.profiles[0].config["uuid"], UUID);
    assert_eq!(converted.profiles[0].config["tls"]["insecure"], false);
    assert_eq!(converted.profiles[0].config["tls"]["fragment"], false);
    assert_eq!(converted.profiles[0].config["multiplex"]["enabled"], false);
    let subscription = converted.groups[0].subscription.as_ref().unwrap();
    assert!(!subscription.settings.via_proxy);
    assert_ne!(
        subscription.settings.user_agent,
        "Happ/selected-settings-only"
    );
    assert_eq!(subscription.settings.interval_minutes, 0);
    assert_eq!(subscription.settings.inherit_defaults, Some(false));
    assert_eq!(converted.selected, None);
    assert!(converted
        .report
        .iter()
        .any(|issue| issue.code == "legacy_subscription_user_agent_review"));
    assert!(!converted
        .report
        .iter()
        .any(|issue| issue.code == "legacy_settings_deferred"
            || issue.code == "legacy_selection_informational"));
    assert!(codes(&db).contains(&"legacy_profile_tls_tricks_unsupported".into()));
    // Even malformed/duplicate excluded rows must never be validated or adopted.
    set(&mut db, "skip_cert", "malformed-excluded-secret");
    assert!(convert_selected(&db, false).is_ok());
    assert!(codes(&db).contains(&"legacy_profile_defaults_invalid".into()));
    assert_eq!(db.profiles[0].outbound, original);
    assert_eq!(
        db.settings[..settings_before.len()]
            .iter()
            .map(|setting| (setting.key.clone(), setting.value.clone()))
            .collect::<Vec<_>>(),
        settings_before
    );
}

#[test]
fn full_configs_keep_input_file_paths_for_the_review_and_name_unsupported_assets() {
    let base = json!({"outbounds":[{"type":"direct","tag":"direct"}]});
    let mut cases = Vec::new();
    for path in ["/missing/private.srs", "rules/private.srs"] {
        let mut config = base.clone();
        config["route"] =
            json!({"rule_set":[{"type":"local","tag":"external","format":"binary","path":path}]});
        cases.push(config);
    }
    for path in [json!("/private/hosts"), json!(["hosts/custom-hosts"])] {
        let mut config = base.clone();
        config["dns"] = json!({"servers":[{"type":"hosts","tag":"hosts","path":path}]});
        cases.push(config);
    }
    {
        let key = "private_key_path";
        let mut config = base.clone();
        config["outbounds"] =
            json!([{"type":"ssh","server":"127.0.0.1","server_port":22,"user":"fixture"}]);
        config["outbounds"][0][key] = json!("private/ssh-resource");
        cases.push(config);
    }
    for config in cases {
        let mut db = simple();
        db.profiles[0] = custom_profile(1, 0, "fullconfig", config.clone());
        let converted = plan(&db);
        assert_eq!(converted.profiles[0].config, config, "paths stay verbatim");
        assert!(converted.report.iter().all(|i| !matches!(
            i.code.as_str(),
            "legacy_profile_initial_path_omitted" | "legacy_profile_resource_unsupported"
        )));
        let mut required = std::collections::BTreeMap::new();
        crate::legacy_backup::profile_resources::discover(&converted, &mut required);
        assert_eq!(required.len(), 1);
        assert!(crate::legacy_backup::profile_resources::unresolved(
            &converted
        ));
        assert_eq!(
            super::super::json::parse(db.profiles[0].outbound["config"].as_str().unwrap()).unwrap(),
            config
        );
    }
    let mut remote = base.clone();
    remote["route"] = json!({"rule_set":[{"type":"remote","tag":"external","url":"https://rules.invalid/source.json","initial_path":"seed-rules.json"}]});
    let mut db = simple();
    db.profiles[0] = custom_profile(1, 0, "fullconfig", remote);
    let converted = plan(&db);
    assert!(converted.profiles[0].config["route"]["rule_set"][0]
        .get("initial_path")
        .is_none());
    assert!(converted
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_initial_path_omitted" && i.source_id == Some(1)));
    assert!(!json!(converted.report).to_string().contains("seed-rules"));
    assert!(!crate::legacy_backup::profile_resources::unresolved(
        &converted
    ));
    // A list an Xray configuration names by `ext:` is a file the review asks
    // for, exactly like a path: the name stays in the profile until it is
    // answered, and the section waits for it.
    let xray = json!({"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["ext:private.dat:tag"],"outboundTag":"direct"}]}});
    db.profiles[0] = custom_profile(1, 0, "xrayfullconfig", xray.clone());
    let converted = plan(&db);
    assert_eq!(
        converted.profiles[0].config, xray,
        "the name stays verbatim"
    );
    let mut required = std::collections::BTreeMap::new();
    crate::legacy_backup::profile_resources::discover(&converted, &mut required);
    assert_eq!(
        required
            .values()
            .map(|r| (r.path.clone(), r.kind))
            .collect::<Vec<_>>(),
        [(
            "private.dat".to_owned(),
            crate::routing::resources::Kind::Geodata
        )]
    );
    assert!(crate::legacy_backup::profile_resources::unresolved(
        &converted
    ));
    db.profiles[0] = custom_profile(
        1,
        0,
        "fullconfig",
        json!({"outbounds":[{"type":"ssh","private_key_path":"bad\u{0}path"}]}),
    );
    assert!(codes(&db).contains(&"legacy_profile_structure".into()));
    let inline = json!({
        "outbounds":[{"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":443,"uuid":UUID,"transport":{"type":"ws","path":"/websocket/path"}}],
        "dns":{"servers":[{"type":"hosts","tag":"inline-hosts","predefined":{"fixture.invalid":["127.0.0.1"]}},{"type":"https","tag":"doh","server":"127.0.0.1","path":"/dns-query"}]},
        "route":{"rule_set":[{"type":"inline","tag":"embedded","rules":[{"domain_suffix":["fixture.invalid"]}]}]},
        "log":{"output":"logs/session.log"}
    });
    let mut db = simple();
    db.profiles[0] = custom_profile(1, 0, "fullconfig", inline.clone());
    let converted = plan(&db);
    assert_eq!(converted.profiles[0].config, inline);
    assert!(!crate::legacy_backup::profile_resources::unresolved(
        &converted
    ));
    let xhttp = json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":UUID,"encryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"path":"/api/v1/sync"}}});
    db.profiles[0] = custom_profile(1, 0, "xrayoutbound", xhttp.clone());
    assert_eq!(plan(&db).profiles[0].config, xhttp);
}
#[test]
fn chains_through_qt_vpn_profiles_convert_with_the_endpoint_hop_in_place() {
    // Synthetic Qt export of an ordinary OpenVPN profile (RFC 5737 address).
    let vpn = profile(
        2,
        0,
        "openvpn",
        json!({"type":"openvpn","tag":"Synthetic OVPN","server":"192.0.2.10","server_port":1194,
            "username":"synthetic-user","password":"synthetic-password"}),
    );
    let db = SourceDatabase {
        groups: vec![group(0, "Mixed", &[1, 2, 3, 4])],
        profiles: vec![
            socks(1, 0),
            vpn,
            profile(
                3,
                0,
                "chain",
                json!({"type":"chain","name":"Socks then VPN","list":[1,2]}),
            ),
            profile(
                4,
                0,
                "chain",
                json!({"type":"chain","name":"VPN then socks","list":[2,1]}),
            ),
        ],
        ..Default::default()
    };
    let plan = plan(&db);
    for (source, expected) in [(3, [1, 2]), (4, [2, 1])] {
        let chain = plan
            .profiles
            .iter()
            .find(|p| p.id == plan.profile_ids[&source])
            .unwrap();
        let hops: Vec<_> = crate::chains::flatten(chain, &plan.profiles)
            .unwrap()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        assert_eq!(
            hops,
            expected.map(|id| plan.profile_ids[&id].clone()),
            "chain {source} keeps Qt's stored order with the VPN hop in place"
        );
    }
    let converted = plan
        .profiles
        .iter()
        .find(|p| p.id == plan.profile_ids[&2])
        .unwrap();
    assert_eq!(converted.config["type"], "openvpn-client");
    assert!(converted.vpn_policy.is_some());
}

#[test]
fn auto_clear_groups_and_columns_of_a_newer_throne_are_reported() {
    let mut db = simple();
    assert!(!plan(&db)
        .report
        .iter()
        .any(|issue| issue.code == "legacy_unknown_columns_deferred"));
    db.groups[0]
        .columns
        .insert("auto_clear_unavailable".into(), SourceValue::Integer(1));
    db.profiles[0]
        .columns
        .insert("future_column".into(), SourceValue::Text("value".into()));
    let converted = plan(&db);
    let report = converted.report;
    assert!(!report
        .iter()
        .any(|issue| issue.code == "legacy_group_auto_clear_deferred"));
    assert!(converted.groups[0].auto_clear_unavailable);
    assert!(report
        .iter()
        .any(|issue| issue.code == "legacy_unknown_columns_deferred"));
}

fn converted(db: &mut SourceDatabase, kind: &str, source: Value) -> (Value, Vec<String>) {
    db.profiles[0] = profile(1, 0, kind, source);
    let plan = plan(db);
    let report = plan.report.iter().map(|issue| issue.code.clone()).collect();
    (plan.profiles[0].config.clone(), report)
}

#[test]
fn every_throne_protocol_converts_to_the_outbound_its_build_sends() {
    let mut db = simple();
    let tls = json!({"enabled":true,"server_name":"example.test"});
    // tls() freezes these client defaults; uTLS only where Qt builds it.
    let mut frozen = tls.clone();
    for (key, value) in [
        ("spoof", json!("")),
        ("spoof_method", json!("")),
        ("fragment", json!(false)),
        ("tls_tricks", json!({"mixedcase_sni":false})),
        ("insecure", json!(false)),
    ] {
        frozen[key] = value;
    }
    let mut with_utls = frozen.clone();
    with_utls["utls"] = json!({"enabled":false});
    let server = |extra: Value| {
        let mut value = json!({"server":"192.0.2.10","server_port":443});
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        value
    };
    let cases = [
        (
            "hysteria",
            server(
                json!({"type":"hysteria","up_mbps":10,"down_mbps":50,"obfs":"obfs-fixture","auth_str":"auth-fixture","recv_window":65536,"tls":tls}),
            ),
            server(
                json!({"type":"hysteria","up_mbps":10,"down_mbps":50,"obfs":"obfs-fixture","auth_str":"auth-fixture","recv_window":65536,"tls":frozen}),
            ),
        ),
        // Unknown obfs types build as salamander; an unknown BBR profile and a
        // maximum hop interval without a minimum are dropped.
        (
            "hysteria2",
            server(
                json!({"type":"hysteria2","password":"fixture","bbr_profile":"invented","hop_interval_max":"30s","obfs":{"type":"future","password":"o","min_packet_size":0,"max_packet_size":0},"tls":tls}),
            ),
            server(
                json!({"type":"hysteria2","password":"fixture","obfs":{"type":"salamander","password":"o"},"tls":frozen}),
            ),
        ),
        (
            "hysteria2",
            json!({"type":"hysteria2","server":"192.0.2.11","server_ports":["20000:30000"],"hop_interval":"10s","hop_interval_max":"30s","bbr_profile":"standard","obfs":{"type":"gecko","password":"o","min_packet_size":10,"max_packet_size":20},"tls":tls}),
            json!({"type":"hysteria2","server":"192.0.2.11","server_ports":["20000:30000"],"hop_interval":"10s","hop_interval_max":"30s","bbr_profile":"standard","obfs":{"type":"gecko","password":"o","min_packet_size":10,"max_packet_size":20},"tls":frozen}),
        ),
        (
            "hysteria2",
            json!({"type":"hysteria2","password":"fixture","realm":{"server_url":"https://realm.example.test","realm_id":"fixture"},"tls":tls}),
            json!({"type":"hysteria2","password":"fixture","realm":{"server_url":"https://realm.example.test","realm_id":"fixture"},"tls":frozen}),
        ),
        (
            "tuic",
            server(
                json!({"type":"tuic","uuid":UUID,"password":"fixture","congestion_control":"bbr","zero_rtt_handshake":true,"tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}),
            ),
            server(
                json!({"type":"tuic","uuid":UUID,"password":"fixture","congestion_control":"bbr","zero_rtt_handshake":true,"tls":{"enabled":true,"spoof":"","spoof_method":"","fragment":false,"tls_tricks":{"mixedcase_sni":false},"insecure":false}}),
            ),
        ),
        (
            "juicity",
            server(json!({"type":"juicity","uuid":UUID,"password":"fixture","tls":tls})),
            server(json!({"type":"juicity","uuid":UUID,"password":"fixture","tls":frozen})),
        ),
        (
            "anytls",
            server(
                json!({"type":"anytls","password":"fixture","min_idle_session":2,"idle_session_timeout":"30s","tls":tls}),
            ),
            server(
                json!({"type":"anytls","password":"fixture","min_idle_session":2,"idle_session_timeout":"30s","tls":with_utls}),
            ),
        ),
        (
            "trusttunnel",
            server(
                json!({"type":"trusttunnel","username":"fixture","password":"fixture","quic":true,"quic_congestion_control":"bbr","health_check":true,"tls":tls}),
            ),
            server(
                json!({"type":"trusttunnel","username":"fixture","password":"fixture","quic":true,"quic_congestion_control":"bbr","health_check":true,"tls":with_utls}),
            ),
        ),
        (
            "naive",
            server(
                json!({"type":"naive","username":"fixture","password":"fixture","udp_over_tcp":true,"tls":tls}),
            ),
            server(
                json!({"type":"naive","username":"fixture","password":"fixture","udp_over_tcp":true,"tls":frozen}),
            ),
        ),
        (
            "shadowtls",
            server(json!({"type":"shadowtls","version":3,"password":"fixture","tls":tls})),
            server(json!({"type":"shadowtls","version":3,"password":"fixture","tls":with_utls})),
        ),
        (
            "mieru",
            json!({"type":"mieru","server":"192.0.2.12","server_ports":["2000-2010"],"transport":"TCP","username":"fixture","password":"fixture","multiplexing":"MULTIPLEXING_LOW"}),
            json!({"type":"mieru","server":"192.0.2.12","server_ports":["2000-2010"],"transport":"TCP","username":"fixture","password":"fixture","multiplexing":"MULTIPLEXING_LOW"}),
        ),
        (
            "snell",
            server(
                json!({"type":"snell","version":4,"psk":"fixture","obfs_mode":"tls","obfs_host":"example.test","reuse":true}),
            ),
            server(
                json!({"type":"snell","version":4,"psk":"fixture","obfs_mode":"tls","obfs_host":"example.test","reuse":true}),
            ),
        ),
        // The key file stays for the review to offer as a selectable resource.
        (
            "ssh",
            server(
                json!({"type":"ssh","user":"fixture","private_key_path":"/fixture/id_ed25519","host_key":["ssh-ed25519 AAAAfixture"],"client_version":"SSH-2.0-fixture"}),
            ),
            server(
                json!({"type":"ssh","user":"fixture","private_key_path":"/fixture/id_ed25519","host_key":["ssh-ed25519 AAAAfixture"],"client_version":"SSH-2.0-fixture"}),
            ),
        ),
        (
            "direct",
            json!({"type":"direct","tag":"Direct fixture","bind_interface":"fixture0","tcp_fast_open":true}),
            json!({"type":"direct","tag":"Direct fixture","bind_interface":"fixture0","tcp_fast_open":true}),
        ),
    ];
    for (kind, source, expected) in cases {
        let (config, _) = converted(&mut db, kind, source);
        assert_eq!(config, expected, "{kind}");
    }
    // One Qt class serves both Hysteria versions under either row type.
    let (config, _) = converted(
        &mut db,
        "hysteria",
        server(json!({"type":"hysteria2","password":"fixture","tls":tls})),
    );
    assert_eq!(config["type"], "hysteria2");
    db.profiles[0] = profile(
        1,
        0,
        "tailscale",
        json!({"type":"tailscale","tag":"Tailnet","auth_key":"tskey-fixture","state_directory":"/fixture/state","globalDNS":true,"accept_routes":true}),
    );
    let converted_plan = plan(&db);
    let node = &converted_plan.profiles[0];
    assert_eq!(
        node.config,
        json!({"type":"tailscale","tag":"Tailnet","auth_key":"tskey-fixture","accept_routes":true})
    );
    // Qt's globalDNS is the node's own resolver policy, not an outbound field.
    assert_eq!(
        node.vpn_policy,
        Some(crate::vpn_policy::Policy {
            only_advertised_routes: false,
            use_tunnel_dns: true,
            block_outside_dns: false,
        })
    );
    let report: Vec<String> = converted_plan
        .report
        .iter()
        .map(|issue| issue.code.clone())
        .collect();
    assert!(report.contains(&"legacy_tailscale_state_omitted".to_string()));
    assert!(!report.contains(&"legacy_tailscale_dns_deferred".to_string()));
}

#[test]
fn quic_profiles_take_the_source_globals_their_build_applies() {
    let mut db = simple();
    set(&mut db, "h2_idle_timeout", " 30s ");
    set(&mut db, "h2_max_concurrent_streams", "16");
    set(&mut db, "quic_initial_packet_size", "1300");
    set(&mut db, "quic_disable_path_mtu_discovery", "true");
    let (config, _) = converted(
        &mut db,
        "tuic",
        json!({"type":"tuic","server":"192.0.2.10","server_port":443,"uuid":UUID,"idle_timeout":"5s"}),
    );
    assert_eq!(config["idle_timeout"], "5s");
    assert_eq!(config["max_concurrent_streams"], 16);
    assert_eq!(config["initial_packet_size"], 1300);
    assert_eq!(config["disable_path_mtu_discovery"], true);
    // Non-QUIC classes ignore the QUIC globals.
    let (config, _) = converted(
        &mut db,
        "anytls",
        json!({"type":"anytls","server":"192.0.2.10","server_port":443,"password":"fixture","tls":{"enabled":true}}),
    );
    assert!(config.get("idle_timeout").is_none());
    set(&mut db, "quic_initial_packet_size", "large");
    db.profiles[0] = profile(
        1,
        0,
        "tuic",
        json!({"type":"tuic","server":"192.0.2.10","server_port":443,"uuid":UUID}),
    );
    assert!(codes(&db).contains(&"legacy_profile_defaults_invalid".into()));
}

#[test]
fn malformed_rows_of_the_new_protocols_stay_blocked() {
    let cases = [
        (
            "hysteria2",
            json!({"type":"hysteria2","server":"192.0.2.10","server_port":443,"realm":{"server_url":"https://realm.example.test","realm_id":"fixture"},"tls":{"enabled":true}}),
            "legacy_profile_structure",
        ),
        (
            "anytls",
            json!({"type":"anytls","server":"192.0.2.10","server_port":443,"password":"fixture"}),
            "legacy_profile_structure",
        ),
        (
            "snell",
            json!({"type":"snell","server":"192.0.2.10","server_port":443,"version":9}),
            "legacy_profile_structure",
        ),
        (
            "tuic",
            json!({"type":"tuic","server":"192.0.2.10","server_port":443,"uuid":"not-a-uuid"}),
            "legacy_profile_structure",
        ),
        (
            "mieru",
            json!({"type":"mieru","server":"192.0.2.10","transport":"TCP"}),
            "legacy_profile_structure",
        ),
        (
            "juicity",
            json!({"type":"juicity","server":"192.0.2.10","server_port":443,"future":true}),
            "legacy_profile_field_unsupported",
        ),
        (
            "naive",
            json!({"type":"tuic","server":"192.0.2.10","server_port":443}),
            "legacy_profile_discriminator",
        ),
    ];
    for (kind, source, code) in cases {
        let mut db = simple();
        db.profiles[0] = profile(1, 0, kind, source);
        assert!(codes(&db).contains(&code.into()), "{kind}: {code}");
    }
}

#[test]
fn an_unconvertible_profile_is_left_out_with_everything_that_depends_on_it() {
    let tricks = json!({"type":"http","server":"192.0.2.10","server_port":443,"tls":{"enabled":true,"fragment":true}});
    let mut fronted = group(5, "Fronted", &[4]);
    fronted
        .columns
        .insert("front_proxy_id".into(), SourceValue::Integer(2));
    let db = SourceDatabase {
        groups: vec![group(0, "Kept", &[1, 2, 3]), fronted],
        profiles: vec![
            socks(1, 0),
            profile(2, 0, "http", tricks),
            profile(
                3,
                0,
                "chain",
                json!({"type":"chain","name":"Through 2","list":[1,2]}),
            ),
            socks(4, 5),
        ],
        ..Default::default()
    };
    let plan = plan(&db);
    assert_eq!(plan.profiles.len(), 1);
    assert_eq!(plan.profiles[0].id, plan.profile_ids[&1]);
    assert_eq!(plan.groups.len(), 1);
    assert_eq!(plan.groups[0].name, "Kept");
    let reasons = |entity: &str, id: i64| -> Vec<String> {
        plan.report
            .iter()
            .filter(|i| i.entity.as_deref() == Some(entity) && i.source_id == Some(id))
            .map(|i| i.code.clone())
            .collect()
    };
    assert_eq!(
        reasons("profile", 2),
        [
            "legacy_profile_skipped",
            "legacy_profile_tls_tricks_unsupported"
        ]
    );
    assert_eq!(
        reasons("profile", 3),
        ["legacy_profile_skipped", "legacy_chain_reference_missing"]
    );
    assert_eq!(
        reasons("group", 5)
            .into_iter()
            .filter(|c| c.ends_with("skipped"))
            .collect::<Vec<_>>(),
        ["legacy_group_skipped", "legacy_group_proxy_skipped"]
    );
    assert_eq!(
        reasons("profile", 4),
        ["legacy_profile_skipped", "legacy_profile_group_skipped"]
    );
    // What is left out never reaches the library identifiers.
    for id in [2, 3, 4] {
        assert!(!plan.profile_ids.contains_key(&id));
    }
    assert!(!plan.group_ids.contains_key(&5));
}
