use super::*;
use crate::legacy_backup::{SourceRule, SourceSetting};

#[test]
fn independent_qt_6_oracle_matches_all_generated_dns_and_strategy_reference_cases() {
    let mut golden: Value = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    let extra: Value = serde_json::from_str(include_str!("fixtures/rulesets/golden.json")).unwrap();
    golden["cases"]
        .as_array_mut()
        .unwrap()
        .extend(extra["cases"].as_array().unwrap().iter().cloned());
    let cases = golden["cases"].as_array().unwrap();
    assert!(cases.len() >= 68);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let mut db = SourceDatabase::default();
        for (key, value) in case["settings"].as_object().unwrap() {
            // The Qt function oracle takes C++ members; SQLite persists this alias.
            let stored_key = if key == "default_domain_strategy" {
                "outbound_domain_strategy"
            } else {
                key
            };
            set(&mut db, stored_key, value.as_str().unwrap());
        }
        for row in case["rules"].as_array().into_iter().flatten() {
            let columns = row["columns"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| {
                    let value = if let Some(n) = value.as_i64() {
                        SourceValue::Integer(n)
                    } else {
                        SourceValue::Text(value.as_str().unwrap().into())
                    };
                    (key.clone(), value)
                })
                .collect();
            db.rules.push(SourceRule {
                route_id: 1,
                order: row["order"].as_i64().unwrap(),
                kind: row["kind"].as_i64().unwrap_or(0),
                columns,
            });
        }
        let mut route = route();
        if case["raw"] == true {
            route
                .columns
                .insert("is_raw".into(), SourceValue::Integer(1));
            route.columns.insert(
                "raw_route".into(),
                SourceValue::Text(case["raw_route"].to_string()),
            );
        }
        if let Some(expected) = case["expectedError"].as_str() {
            assert_eq!(
                build(&db, &route, &mut vec![]).unwrap_err(),
                expected,
                "{id}"
            );
            continue;
        }
        if case["strategyOnly"] != true {
            assert_eq!(
                build(&db, &route, &mut vec![]).unwrap(),
                case["expected"]["dns"],
                "{id}"
            );
        }
        assert_eq!(
            direct_strategy(&db).unwrap(),
            case["expected"]["directStrategy"].as_str().unwrap(),
            "direct strategy: {id}"
        );
        assert_eq!(
            xray_strategy(&db).unwrap(),
            case["expected"]["xrayStrategy"].as_str().unwrap(),
            "Xray strategy: {id}"
        );
    }
}

#[test]
fn quic_and_remote_udp_match_qt_with_runtime_xray_adaptation() {
    let golden: Value = serde_json::from_str(include_str!("fixtures/quic/golden.json")).unwrap();
    let cases = golden["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 32);
    let mut accepted = 0;
    let mut rejected = 0;
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let mut db = SourceDatabase::default();
        for (key, value) in case["settings"].as_object().unwrap() {
            // The Qt function oracle takes C++ members; SQLite persists this alias.
            let stored_key = if key == "default_domain_strategy" {
                "outbound_domain_strategy"
            } else {
                key
            };
            set(&mut db, stored_key, value.as_str().unwrap());
        }
        let before: Vec<_> = db
            .settings
            .iter()
            .map(|s| (s.key.clone(), s.value.clone()))
            .collect();
        let mut report = vec![];
        let result = build(&db, &route(), &mut report);
        if let Some(error) = case["expectedError"].as_str() {
            assert_eq!(result.unwrap_err(), error, "{id}");
            assert!(report.is_empty(), "{id}");
            rejected += 1;
        } else {
            let mut dns = result.unwrap();
            crate::routing::legacy_dns::apply(&mut dns, case["proxyUsesXray"] == true);
            assert_eq!(dns, case["expected"]["dns"], "{id}");
            accepted += 1;
        }
        assert_eq!(
            db.settings
                .iter()
                .map(|s| (s.key.clone(), s.value.clone()))
                .collect::<Vec<_>>(),
            before
        );
        assert_eq!(
            direct_strategy(&db).unwrap(),
            case["expected"]["directStrategy"]
        );
        assert_eq!(
            xray_strategy(&db).unwrap(),
            case["expected"]["xrayStrategy"]
        );
    }
    assert_eq!((accepted, rejected), (30, 2));
}

#[test]
fn quic_malformed_and_ambiguous_addresses_remain_atomic_safe_errors() {
    let mut addresses = vec![
        "quic://".into(),
        "quic://127.0.0.1:".into(),
        "quic://127.0.0.1:0".into(),
        "quic://127.0.0.1:65536".into(),
        "quic://127.0.0.1:2147483648".into(),
        "quic://127.0.0.1:-1".into(),
        "quic://127.0.0.1:+853".into(),
        "quic://127.0.0.1:secret".into(),
        "quic://127.0.0.1:853.0".into(),
        "quic://127.0.0.1/path".into(),
        "quic://127.0.0.1?secret".into(),
        "quic://127.0.0.1#sni".into(),
        "quic://user@127.0.0.1".into(),
        "quic://127.0.0.1\\secret".into(),
        "quic://127.0.0.1 \n".into(),
        "quic://[::1]:853".into(),
        "quic://::1".into(),
        "quic://127.00.0.1".into(),
        "quic://2130706433".into(),
        "quic://127.0.0.256".into(),
        "QUIC://127.0.0.1".into(),
        "udp://127.0.0.1".into(),
        "quic://127.0.0.1\0".into(),
    ];
    addresses.push(format!("quic://{}", "a".repeat(4096)));
    for key in ["direct_dns", "core_box_underlying_dns"] {
        for address in &addresses {
            let mut db = SourceDatabase::default();
            set(&mut db, key, address);
            let mut report = vec![];
            assert_eq!(
                build(&db, &route(), &mut report).unwrap_err(),
                "legacy_dns_address_unsupported",
                "{key}: {address:?}"
            );
            assert!(report.is_empty());
            assert_eq!(value(&db, key).unwrap().unwrap(), address);
        }
    }
    {
        let (key, code) = (
            "core_box_underlying_dns",
            "legacy_dns_bootstrap_hostname_unsupported",
        );
        let mut db = SourceDatabase::default();
        set(&mut db, key, "quic://dns.fixture.invalid:853");
        assert_eq!(build(&db, &route(), &mut vec![]).unwrap_err(), code);
    }
}

#[test]
fn quic_does_not_weaken_dependency_rejections_or_publish_partial_reports() {
    let base = || {
        let mut db = SourceDatabase::default();
        set(&mut db, "direct_dns", "quic://127.0.0.1:8853");
        set(&mut db, "core_box_underlying_dns", "quic://127.0.0.2:8854");
        db
    };
    let mut mutations = vec![];
    for key in [
        "enable_dns_server",
        "adblock_enable",
        "enable_redirect",
        "vpn_l3_bridge",
        "use_mozilla_certs",
    ] {
        mutations.push((key, "true", "legacy_dns_generated_dependency_unsupported"));
    }
    mutations.extend([
        (
            "remote_dns",
            "local",
            "legacy_dns_remote_transport_unsupported",
        ),
        (
            "dns_cache_capacity",
            "1000001",
            "legacy_dns_generated_limit",
        ),
        (
            "dns_optimistic_timeout",
            "invalid-secret",
            "legacy_dns_generated_settings_invalid",
        ),
        (
            "use_dns_object",
            "true",
            "legacy_dns_generated_mode_required",
        ),
    ]);
    for (key, val, code) in mutations {
        let mut db = base();
        set(&mut db, key, val);
        let mut report = vec![Issue {
            code: "existing-safe-issue".into(),
            entity: None,
            source_id: None,
            name: None,
        }];
        let before = serde_json::to_value(&report).unwrap();
        assert_eq!(
            build(&db, &route(), &mut report).unwrap_err(),
            code,
            "{key}"
        );
        assert_eq!(serde_json::to_value(&report).unwrap(), before);
    }
    let mut db = base();
    rule(&mut db, 0, -2, json!({"rule_set":["private-set"]}));
    assert_eq!(
        build(&db, &route(), &mut vec![]).unwrap_err(),
        "legacy_route_ruleset_unsupported"
    );
    db = base();
    db.settings.push(SourceSetting {
        key: "direct_dns".into(),
        value: "quic://127.0.0.1:8853".into(),
        columns: BTreeMap::new(),
    });
    assert_eq!(
        build(&db, &route(), &mut vec![]).unwrap_err(),
        "legacy_dns_generated_settings_invalid"
    );
}

fn route() -> SourceRoute {
    SourceRoute {
        id: 1,
        name: "Synthetic generated DNS".into(),
        columns: BTreeMap::new(),
    }
}
fn set(db: &mut SourceDatabase, key: &str, value: &str) {
    db.settings.retain(|s| s.key != key);
    db.settings.push(SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: BTreeMap::new(),
    });
}
fn output(db: &SourceDatabase) -> Value {
    build(db, &route(), &mut vec![]).unwrap()
}
fn rule(db: &mut SourceDatabase, order: i64, target: i64, fields: Value) {
    let mut columns = BTreeMap::from([
        ("outbound_id".into(), SourceValue::Integer(target)),
        ("action".into(), SourceValue::Text("route".into())),
    ]);
    for (key, value) in fields.as_object().unwrap() {
        columns.insert(format!("{key}_json"), SourceValue::Text(value.to_string()));
    }
    db.rules.push(SourceRule {
        route_id: 1,
        order,
        kind: 0,
        columns,
    });
}
#[test]
fn default_qt_dns_has_local_bootstrap_predefined_localhost_and_unconditional_remote_rule() {
    assert_eq!(
        output(&SourceDatabase::default()),
        json!({"servers":[{"type":"https","server":"8.8.8.8","path":"/dns-query","tag":"dns-remote","domain_resolver":"dns-local","detour":"proxy"},{"type":"local","tag":"dns-direct","domain_resolver":"dns-local"},{"type":"local","tag":"dns-local"}],"rules":[{"domain":"localhost","action":"predefined","query_type":"A","rcode":"NOERROR","answer":["*. IN A 127.0.0.1"]},{"domain":"localhost","action":"predefined","query_type":"AAAA","rcode":"NXDOMAIN"},{"action":"route","server":"dns-remote"}],"cache_capacity":65536})
    );
}
#[test]
fn transports_preserve_qt_explicit_ports_and_encoded_paths_without_added_tls_or_path_defaults() {
    for (address, expected) in [
        (
            "192.0.2.1:5353",
            json!({"type":"udp","server":"192.0.2.1","server_port":5353}),
        ),
        (
            "tcp://dns.fixture.invalid:5353",
            json!({"type":"tcp","server":"dns.fixture.invalid","server_port":5353}),
        ),
        (
            "tls://dns.fixture.invalid",
            json!({"type":"tls","server":"dns.fixture.invalid"}),
        ),
        (
            "https://dns.fixture.invalid",
            json!({"type":"https","server":"dns.fixture.invalid"}),
        ),
        (
            "https://dns.fixture.invalid:8443/dns%2Dquery?token=user%40name@host",
            json!({"type":"https","server":"dns.fixture.invalid","server_port":8443,"path":"/dns%2Dquery?token=user%40name@host"}),
        ),
        (
            "h3://127.0.0.1/query?value=%3A%2F",
            json!({"type":"h3","server":"127.0.0.1","path":"/query?value=%3A%2F"}),
        ),
        ("localhost", json!({"type":"local"})),
    ] {
        assert_eq!(server(address, false).unwrap(), expected);
    }
    for address in [
        "https://user:secret@dns.invalid/query",
        "https://dns.invalid/query#fragment",
        "https://dns.invalid/path%2",
        "https://dns.invalid/path%GG",
        "https://dns.invalid/query?target=https://nested.invalid",
        "tcp://[::1]:53",
        "2001:db8::1",
        "udp://127.0.0.1",
        "local-address.invalid",
        "https://dns.invalid?query=1",
        "dhcp://auto",
        "https://dns.invalid:0",
        "https://dns.invalid:65536",
        "tcp://dns.invalid:secret",
        "https://dns.invalid/white space",
    ] {
        assert!(server(address, false).is_err(), "{address}");
    }
    for address in ["local", "localhost"] {
        assert!(server(address, true).is_err());
    }
}
#[test]
fn predefined_family_order_case_trailing_dots_and_duplicates_follow_qt_without_source_changes() {
    for (input, expected) in [
        ("::1:0", "::0.1.0.0"),
        ("::192.0.2.6", "::192.0.2.6"),
        ("::ffff", "::ffff"),
        ("::ffff:192.0.2.5", "::ffff:192.0.2.5"),
    ] {
        assert_eq!(qt_address(input.parse().unwrap()), expected);
    }
    let mut db = SourceDatabase::default();
    let source = json!([
        "127.0.0.1 MiXeD.Example. alias.example # comment 日本",
        "2001:db8::1 mixed.example",
        "127.0.0.1 mixed.example",
        "127.0.0.2 MIXED.example...",
        "::1 onlyv6.example"
    ]);
    set(&mut db, "dns_predefined_rules", &source.to_string());
    let result = output(&db);
    let rules = result["rules"].as_array().unwrap();
    assert_eq!(
        rules[0],
        json!({"domain":"mixed.example","query_type":"A","action":"predefined","rcode":"NOERROR","answer":["*. IN A 127.0.0.1","*. IN A 127.0.0.2"]})
    );
    assert_eq!(rules[1]["answer"], json!(["*. IN AAAA 2001:db8::1"]));
    assert_eq!(rules[3]["rcode"], "NXDOMAIN");
    assert_eq!(rules[4]["rcode"], "NXDOMAIN");
    assert_eq!(rules[5]["answer"], json!(["*. IN AAAA ::1"]));
    assert_eq!(db.settings[0].value, source.to_string());
    for invalid in [
        "secret-invalid domain.invalid",
        "127.0.0.1",
        "127.0.0.1 ...",
        "fe80::1%eth0 scoped.invalid",
        "127.0.0.1 пример.рф",
    ] {
        set(
            &mut db,
            "dns_predefined_rules",
            &json!([invalid]).to_string(),
        );
        let mut report = vec![];
        assert_eq!(
            build(&db, &route(), &mut report).unwrap_err(),
            "legacy_dns_predefined_unsupported"
        );
        assert!(report.is_empty());
    }
}
#[test]
fn stored_rules_project_in_order_even_for_raw_route_and_do_not_merge_direct_with_proxy() {
    let mut db = SourceDatabase::default();
    set(&mut db, "dns_predefined_enable", "false");
    set(&mut db, "dns_final_out", "direct");
    rule(&mut db, 8, -2, json!({"domain":[" later.invalid "]}));
    rule(
        &mut db,
        1,
        -2,
        json!({"domain":["first.invalid"],"domain_suffix":["suffix.invalid"],"domain_keyword":["keyword"],"domain_regex":["^regex\\."]}),
    );
    rule(&mut db, 4, -1, json!({"domain":["proxy.invalid"]}));
    db.rules[1]
        .columns
        .insert("invert".into(), SourceValue::Integer(1));
    db.rules[1]
        .columns
        .insert("port_json".into(), SourceValue::Text("[\"443\"]".into()));
    let mut raw = route();
    raw.columns.insert("is_raw".into(), SourceValue::Integer(1));
    raw.columns.insert(
        "raw_route".into(),
        SourceValue::Text(
            json!({"rules":[{"domain":["raw-only.invalid"],"outbound":-2}]}).to_string(),
        ),
    );
    let mut report = vec![];
    let result = build(&db, &raw, &mut report).unwrap();
    let rules = result["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(
        rules[0]["domain"],
        json!(["first.invalid", "later.invalid"])
    );
    assert_eq!(rules[0]["server"], "dns-direct");
    assert!(rules[0].get("invert").is_none());
    assert!(rules[0].get("port").is_none());
    assert_eq!(rules[1]["domain"], json!(["proxy.invalid"]));
    assert_eq!(rules[1]["server"], "dns-remote");
    assert_eq!(rules[2], json!({"action":"route","server":"dns-direct"}));
    assert!(!result.to_string().contains("raw-only.invalid"));
    assert!(report
        .iter()
        .any(|i| i.code == "legacy_dns_selector_projection"));
    set(&mut db, "enable_dns_routing", "false");
    assert_eq!(
        output(&db)["rules"],
        json!([{"action":"route","server":"dns-direct"}])
    );
}
#[test]
fn ipv6_guards_and_strategy_alias_conflicts_are_exact_and_order_independent() {
    let mut db = SourceDatabase::default();
    set(&mut db, "dns_predefined_enable", "false");
    set(&mut db, "direct_dns_strategy", "ipv4_only");
    set(&mut db, "remote_dns_disable_ipv6", "true");
    set(&mut db, "dns_final_out", "direct");
    rule(&mut db, 0, -2, json!({"domain":["direct.invalid"]}));
    rule(&mut db, 1, -1, json!({"domain":["proxy.invalid"]}));
    let result = output(&db);
    let rules = result["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 6);
    for i in [0, 2, 4] {
        assert_eq!(rules[i]["action"], "predefined");
        assert_eq!(rules[i]["query_type"], json!(["AAAA"]));
        assert!(rules[i].get("answer").is_none());
        assert!(rules[i].get("rcode").is_none());
        assert_eq!(rules[i + 1]["action"], "route");
    }
    set(&mut db, "direct_dns_disable_ipv6", "true");
    output(&db);
    set(&mut db, "direct_dns_disable_ipv6", "false");
    for _ in 0..2 {
        assert_eq!(
            build(&db, &route(), &mut vec![]).unwrap_err(),
            "legacy_dns_strategy_alias_conflict"
        );
        db.settings.reverse();
    }
    set(&mut db, "direct_dns_strategy", "prefer_ipv6");
    assert!(build(&db, &route(), &mut vec![]).is_ok());
}
#[test]
fn cache_optimistic_truth_table_keeps_qt_suppression_and_rejects_invalid_consumed_values() {
    for optimistic in [false, true] {
        for cache in [false, true] {
            for expire in [false, true] {
                let mut db = SourceDatabase::default();
                for (key, value) in [
                    ("dns_optimistic", optimistic),
                    ("dns_disable_cache", cache),
                    ("dns_disable_expire", expire),
                ] {
                    set(&mut db, key, if value { "true" } else { "false" });
                }
                set(&mut db, "dns_optimistic_timeout", "90s");
                set(&mut db, "dns_query_timeout", "2.5s");
                set(&mut db, "dns_reverse_mapping", "true");
                set(&mut db, "dns_cache_capacity", "4096");
                let mut report = vec![];
                let result = build(&db, &route(), &mut report).unwrap();
                assert_eq!(
                    result.get("optimistic").is_some(),
                    optimistic && !cache && !expire
                );
                assert_eq!(result["cache_capacity"], 4096);
                assert_eq!(result["timeout"], "2.5s");
                assert_eq!(result["reverse_mapping"], true);
                assert_eq!(
                    report
                        .iter()
                        .any(|i| i.code == "legacy_dns_optimistic_suppressed"),
                    optimistic && (cache || expire)
                );
            }
        }
    }
    for (key, invalid) in [
        ("dns_cache_capacity", "not-a-number"),
        ("dns_disable_cache", "secret-boolean"),
        ("dns_query_timeout", "-1s"),
        ("dns_optimistic_timeout", "18446744073709551615h"),
        ("dns_final_out", "unknown"),
    ] {
        let mut db = SourceDatabase::default();
        set(&mut db, key, invalid);
        let mut report = vec![];
        let error = build(&db, &route(), &mut report).unwrap_err();
        assert!(!error.contains(invalid));
        assert!(report.is_empty());
    }
}
#[test]
fn unsupported_dependencies_and_limits_fail_without_a_partial_report() {
    let mut bootstrap = SourceDatabase::default();
    set(
        &mut bootstrap,
        "core_box_underlying_dns",
        "tcp://bootstrap.invalid:5353",
    );
    assert_eq!(
        build(&bootstrap, &route(), &mut vec![]).unwrap_err(),
        "legacy_dns_bootstrap_hostname_unsupported"
    );
    for key in [
        "enable_dns_server",
        "adblock_enable",
        "enable_redirect",
        "vpn_l3_bridge",
        "use_mozilla_certs",
    ] {
        let mut db = SourceDatabase::default();
        set(&mut db, key, "true");
        assert_eq!(
            build(&db, &route(), &mut vec![]).unwrap_err(),
            "legacy_dns_generated_dependency_unsupported"
        );
    }
    let mut db = SourceDatabase::default();
    set(&mut db, "dns_cache_capacity", "1000001");
    assert_eq!(
        build(&db, &route(), &mut vec![]).unwrap_err(),
        "legacy_dns_generated_limit"
    );
    let mut db = SourceDatabase::default();
    rule(
        &mut db,
        0,
        -2,
        json!({"rule_set":["geosite-missing-fixture82f4"]}),
    );
    assert_eq!(
        build(&db, &route(), &mut vec![]).unwrap_err(),
        "legacy_route_ruleset_unsupported"
    );
    let mut db = SourceDatabase::default();
    set(&mut db, "use_dns_object", "true");
    assert_eq!(
        build(&db, &route(), &mut vec![]).unwrap_err(),
        "legacy_dns_generated_mode_required"
    );
}

#[test]
fn source_xray_and_direct_strategies_distinguish_forced_resolution_from_generated_ipv6_cap() {
    for (strategy, expected) in [
        ("", "UseIP"),
        ("as_is", "UseIP"),
        ("prefer_ipv4", "UseIPv4v6"),
        ("prefer_ipv6", "UseIPv6v4"),
        ("ipv4_only", "ForceIPv4"),
        ("ipv6_only", "ForceIPv6"),
    ] {
        for explicit in [false, true] {
            let mut db = SourceDatabase::default();
            set(&mut db, "outbound_domain_strategy", strategy);
            set(
                &mut db,
                "use_dns_object",
                if explicit { "true" } else { "false" },
            );
            assert_eq!(direct_strategy(&db).unwrap(), strategy);
            assert_eq!(xray_strategy(&db).unwrap(), expected);
            set(&mut db, "direct_dns_disable_ipv6", "true");
            assert_eq!(
                direct_strategy(&db).unwrap(),
                if explicit { strategy } else { "ipv4_only" }
            );
            assert_eq!(
                xray_strategy(&db).unwrap(),
                if explicit {
                    expected
                } else if strategy == "ipv4_only" {
                    "ForceIPv4"
                } else {
                    "UseIPv4"
                }
            );
        }
    }
    let mut db = SourceDatabase::default();
    set(&mut db, "direct_dns_strategy", "ipv4_only");
    assert_eq!(direct_strategy(&db).unwrap(), "ipv4_only");
    assert_eq!(xray_strategy(&db).unwrap(), "UseIPv4");
    set(&mut db, "direct_dns_disable_ipv6", "false");
    assert_eq!(
        xray_strategy(&db).unwrap_err(),
        "legacy_dns_strategy_alias_conflict"
    );
    set(&mut db, "use_dns_object", "true");
    assert_eq!(xray_strategy(&db).unwrap(), "UseIP");
    set(&mut db, "outbound_domain_strategy", "invalid-secret");
    assert_eq!(
        xray_strategy(&db).unwrap_err(),
        "legacy_dns_generated_settings_invalid"
    );
}
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an explicitly supplied preserved ThroniumCore; never starts a connection"]
async fn actual_core_checks_generated_dns_transport_and_predefined_families() {
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE required");
    if std::env::var_os("THRONIUM_GENERATED_DNS_CHECK_PARENT").is_none() {
        let folder = tempfile::tempdir().unwrap();
        let parent = folder.path().join("Thronium");
        let target = folder.path().join("ThroniumCore");
        std::fs::copy(std::env::current_exe().unwrap(), &parent).unwrap();
        std::fs::copy(&core, &target).unwrap();
        let result=std::process::Command::new(parent).args(["--exact","legacy_backup::routes::generated_dns::tests::actual_core_checks_generated_dns_transport_and_predefined_families","--ignored","--nocapture"]).env("THRONIUM_GENERATED_DNS_CHECK_PARENT","1").env("THRONIUM_TEST_CORE",target).output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let folder = tempfile::tempdir().unwrap();
    let mut engine = crate::Engine::open(folder.path(), std::path::Path::new(&core)).unwrap();
    let profile = crate::store::Profile {
        vpn_policy: None,
        id: "check-only".into(),
        name: "Synthetic generated DNS".into(),
        group_id: "personal".into(),
        kind: crate::store::ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    };
    for (index, (key, address)) in [
        ("remote_dns", "https://8.8.8.8/dns-query"),
        ("remote_dns", "tcp://127.0.0.1:5353"),
        ("remote_dns", "tls://127.0.0.1:853"),
        (
            "remote_dns",
            "https://127.0.0.1:8443/dns%2Dquery?token=a%40b@host",
        ),
        ("remote_dns", "h3://127.0.0.1:8443/dns-query"),
        ("direct_dns", "127.0.0.1:5353"),
        ("direct_dns", "tcp://127.0.0.1:5353"),
        ("direct_dns", "tls://127.0.0.1:853"),
        ("direct_dns", "https://127.0.0.1:8443/query"),
        ("direct_dns", "h3://127.0.0.1:8443/query"),
        ("core_box_underlying_dns", "tcp://127.0.0.1:5353"),
        ("direct_dns", "quic://127.0.0.1"),
        ("direct_dns", "quic://127.0.0.1:8853"),
        ("core_box_underlying_dns", "quic://127.0.0.1"),
        ("core_box_underlying_dns", "quic://127.0.0.1:8853"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut db = SourceDatabase::default();
        set(&mut db, key, address);
        set(&mut db, "direct_dns_disable_ipv6", "true");
        set(&mut db, "dns_final_out", "direct");
        set(
            &mut db,
            "dns_predefined_rules",
            &json!([
                "127.0.0.1 predefined.invalid",
                "2001:db8::1 predefined.invalid"
            ])
            .to_string(),
        );
        let dns = output(&db);
        let mut library = engine.store.library.clone();
        library.routing.profiles[0].legacy_constraints =
            Some(serde_json::from_value(json!({"version":2})).unwrap());
        library.routing.profiles[0].dns = dns.clone();
        library.routing.profiles[0].route =
            json!({"final":"proxy","default_domain_resolver":"dns-direct"});
        engine.store.commit(library).unwrap();
        if let Err(error) = engine.check(&profile).await {
            engine.shutdown().await;
            panic!("generated DNS Check fixture {index} failed: {error}");
        }
        assert!(engine.running.is_none());
        assert!(engine.active_connection.is_none());
    }
    engine.shutdown().await;
}
