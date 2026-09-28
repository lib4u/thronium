use super::super::{Parts, SourceRule, SourceSetting};
use super::*;
pub(super) fn set(source: &mut SourceArchive, key: &str, value: &str) {
    let db = source.database.as_mut().unwrap();
    db.settings.retain(|s| s.key != key);
    db.settings.push(SourceSetting {
        key: key.into(),
        value: value.into(),
        columns: BTreeMap::new(),
    });
}

#[test]
fn persisted_domain_strategy_keys_win_over_unrecognized_cpp_member_rows() {
    let mut source = fixture();
    set(&mut source, "domain_strategy", "prefer_ipv6");
    set(&mut source, "outbound_domain_strategy", "ipv4_only");
    // These names are C++ members, not SQLite keys. Qt ignores such extra rows.
    set(
        &mut source,
        "resolve_domain_strategy",
        "private-invalid-member",
    );
    set(
        &mut source,
        "default_domain_strategy",
        "private-invalid-member",
    );
    let plan = convert(&source, None).unwrap_or_else(|_| panic!("valid stored keys"));
    let preset = &plan.presets[0];
    assert!(
        preset
            .rules
            .iter()
            .any(|rule| rule.config["action"] == "resolve"
                && rule.config["strategy"] == "prefer_ipv6")
    );
    assert_eq!(
        preset
            .legacy_constraints
            .as_ref()
            .unwrap()
            .xray_dns_strategy
            .as_deref(),
        Some("ForceIPv4")
    );
    set(
        &mut source,
        "outbound_domain_strategy",
        "private-invalid-canonical",
    );
    let errors = convert(&source, None).err().unwrap();
    assert!(!json!(errors).to_string().contains("private-invalid"));
}
pub(super) fn fixture() -> SourceArchive {
    let route = SourceRoute {
        id: 1,
        name: "Fixture routes".into(),
        columns: BTreeMap::new(),
    };
    let mut source = SourceArchive {
        container_version: 2,
        content_version: Some(2),
        metadata: json!({}),
        created_at: None,
        parts: Parts {
            routes: true,
            settings: true,
            ..Default::default()
        },
        files: BTreeMap::new(),
        database: Some(SourceDatabase {
            routes: vec![route],
            ..Default::default()
        }),
    };
    set(&mut source, "use_dns_object", "true");
    set(&mut source,"dns_object",&json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","server_port":5353},{"type":"https","tag":"dns-proxy","server":"127.0.0.2","detour":"proxy","path":"/dns-query","tls":{"enabled":true,"server_name":"fixture.invalid"}}],"rules":[{"domain_suffix":["fixture.invalid"],"server":"dns-proxy"}],"final":"dns-direct","disable_cache":true}).to_string());
    source
}
pub(super) fn plan(source: &SourceArchive) -> RoutePlan {
    match convert(source, None) {
        Ok(p) => p,
        Err(e) => panic!("{}", serde_json::to_string(&e).unwrap()),
    }
}
#[test]
fn explicit_local_hosts_fakeip_dns_is_preserved_and_checks_dependencies() {
    let dns = json!({"servers":[
        {"type":"local","tag":"dns-direct","prefer_go":true,"neighbor_domain":["fixture.invalid"]},
        {"type":"hosts","tag":"hosts","predefined":{"pinned.fixture.invalid":["127.0.0.21","::21"]}},
        {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
    ],"rules":[
        {"preferred_by":["hosts"],"query_type":["A","AAAA"],"server":"hosts"},
        {"query_type":["A","AAAA"],"server":"fake"}
    ],"final":"dns-direct","independent_cache":true});
    let mut source = fixture();
    set(&mut source, "dns_object", &dns.to_string());
    assert_eq!(plan(&source).presets[0].dns, dns);
    for (pointer, invalid) in [
        ("/servers/0/prefer_go", json!("true")),
        ("/servers/0/neighbor_domain", json!(["bad/name"])),
        (
            "/servers/1/predefined/pinned.fixture.invalid",
            json!("not-an-ip"),
        ),
        ("/servers/2/inet4_range", json!("fc00::/18")),
        ("/servers/2/inet6_range", json!("198.18.0.0/15")),
        ("/servers/2/inet4_range", json!("198.18.0.0")),
        ("/rules/0/preferred_by", json!(["missing"])),
        ("/rules/0/preferred_by", json!(["fake"])),
    ] {
        let mut invalid_dns = dns.clone();
        *invalid_dns.pointer_mut(pointer).unwrap() = invalid;
        set(&mut source, "dns_object", &invalid_dns.to_string());
        assert!(convert(&source, None).is_err(), "accepted {pointer}");
    }
    for server in [
        json!({"type":"hosts","tag":"hosts","path":"/private/source-hosts"}),
        json!({"type":"hosts","tag":"hosts","path":["hosts.txt"]}),
        json!({"type":"hosts","tag":"hosts","unknown":true}),
        json!({"type":"fakeip","tag":"fake"}),
    ] {
        let mut invalid_dns = dns.clone();
        let index = if server["type"] == "hosts" { 1 } else { 2 };
        invalid_dns["servers"][index] = server;
        set(&mut source, "dns_object", &invalid_dns.to_string());
        assert!(convert(&source, None).is_err());
    }
}
pub(super) fn code(source: &SourceArchive) -> Vec<String> {
    convert(source, None)
        .err()
        .unwrap()
        .iter()
        .map(|i| i.code.clone())
        .collect()
}
pub(super) fn rule(
    source: &mut SourceArchive,
    kind: i64,
    order: i64,
    columns: &[(&str, SourceValue)],
) {
    source.database.as_mut().unwrap().rules.push(SourceRule {
        route_id: 1,
        order,
        kind,
        columns: columns
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    });
}
pub(super) fn s(value: &str) -> SourceValue {
    SourceValue::Text(value.into())
}
pub(super) fn n(value: i64) -> SourceValue {
    SourceValue::Integer(value)
}
pub(super) fn route_col(source: &mut SourceArchive, key: &str, value: SourceValue) {
    source.database.as_mut().unwrap().routes[0]
        .columns
        .insert(key.into(), value);
}
pub(super) fn raw(source: &mut SourceArchive, value: Value) {
    route_col(source, "is_raw", n(1));
    route_col(source, "raw_route", s(&value.to_string()));
}
#[test]
fn warp_bypass_rules_defaults_and_dns_keep_source_global_mode() {
    for global in [false, true] {
        for is_raw in [false, true] {
            let mut source = fixture();
            set(
                &mut source,
                "enable_warp",
                if global { "true" } else { "false" },
            );
            if is_raw {
                raw(
                    &mut source,
                    json!({"final":-5,"rules":[{"domain":["bypass.test"],"outbound":-5}]}),
                );
            } else {
                route_col(&mut source, "default_outbound_id", n(-5));
                rule(
                    &mut source,
                    0,
                    0,
                    &[
                        ("domain_json", s("[\"bypass.test\"]")),
                        ("outbound_id", n(-5)),
                    ],
                );
            }
            set(&mut source, "dns_object", &json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1","detour":"warp-bypass"}],"final":"dns-direct"}).to_string());
            let plan = plan(&source);
            let preset = &plan.presets[0];
            assert_eq!(preset.route["final"], "warp-bypass");
            assert_eq!(
                preset.rules.last().unwrap().config["outbound"],
                "warp-bypass"
            );
            assert_eq!(preset.dns["servers"][0]["detour"], "warp-bypass");
            let constraints = preset.legacy_constraints.as_ref().unwrap();
            assert_eq!(constraints.warp_enabled, global);
            assert_eq!(constraints.version, if global { 3 } else { 2 });
            assert!(constraints.valid());
        }
    }
    let mut source = fixture();
    set(&mut source, "enable_warp", "private-invalid-flag");
    assert!(convert(&source, None).is_err());
    raw(&mut source, json!({"final":-2408}));
    set(&mut source, "enable_warp", "true");
    assert!(code(&source).contains(&"legacy_route_target_unsupported".into()));
}
#[test]
fn structured_dns_and_technical_rules_are_frozen_without_destination_defaults() {
    let mut source = fixture();
    set(&mut source, "domain_strategy", "ipv4_only");
    set(&mut source, "outbound_domain_strategy", "prefer_ipv4");
    let p = plan(&source);
    let preset = &p.presets[0];
    assert_eq!(
        preset
            .rules
            .iter()
            .map(|r| r.config["action"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["sniff", "resolve", "hijack-dns"]
    );
    assert_eq!(preset.rules[1].config["inbound"], json!(["mixed-in"]));
    assert_eq!(
        preset.route,
        json!({"final":"proxy","rule_set":[],"find_process":true,"default_domain_resolver":{"server":"dns-direct","strategy":"prefer_ipv4"}})
    );
    assert_eq!(
        preset.dns,
        parse(setting(source.database.as_ref().unwrap(), "dns_object", "").unwrap()).unwrap()
    );
    assert_eq!(preset.legacy_constraints.as_ref().unwrap().version, 2);
    assert_eq!(
        preset
            .legacy_constraints
            .as_ref()
            .unwrap()
            .xray_dns_strategy
            .as_deref(),
        Some("UseIPv4v6")
    );
    assert_eq!(p.selected, Some(preset.id.clone()));
    assert!(p
        .report
        .iter()
        .any(|i| i.code == "legacy_route_tun_guarded"));
}
#[test]
fn all_simple_types_use_stored_target_not_ui_enum() {
    for kind in 0..=9 {
        let mut source = fixture();
        let key = if kind <= 3 {
            "domain_json"
        } else if kind <= 6 {
            "process_name_json"
        } else {
            "process_path_json"
        };
        rule(
            &mut source,
            kind,
            9,
            &[(key, s("[\"fixture.invalid\"]")), ("outbound_id", n(-1))],
        );
        let p = plan(&source);
        assert_eq!(p.presets[0].rules[2].config["outbound"], "proxy");
    }
}
#[test]
fn structured_sentinels_order_and_final_reject_are_exact() {
    let mut source = fixture();
    route_col(&mut source, "default_outbound_id", n(-3));
    for (order, target) in [(4, -4), (3, -3), (2, -2), (1, -1)] {
        rule(
            &mut source,
            0,
            order,
            &[
                ("outbound_id", n(target)),
                ("domain_json", s("[\"fixture.invalid\"]")),
            ],
        );
    }
    let p = plan(&source);
    let rules = &p.presets[0].rules;
    assert_eq!(rules[2].config["outbound"], "proxy");
    assert_eq!(rules[3].config["outbound"], "direct");
    assert_eq!(rules[4].config["action"], "reject");
    assert_eq!(rules[5].config["action"], "hijack-dns");
    assert_eq!(rules[6].config, json!({"action":"reject"}));
    assert_eq!(p.presets[0].route["final"], "direct");
    for sentinel in [-4, -99, 0] {
        route_col(&mut source, "default_outbound_id", n(sentinel));
        assert_eq!(code(&source), ["legacy_route_target_unsupported"]);
    }
}
#[test]
fn raw_nested_logic_preserves_order_flags_and_has_no_generated_sniff() {
    let mut source = fixture();
    let route = json!({"rules":[{"type":"logical","mode":"and","invert":true,"rules":[{"domain_suffix":["fixture.invalid"]},{"type":"logical","mode":"or","rules":[{"port":[443]},{"network":"udp"}]}],"outbound":-2}],"final":-1,"find_process":false,"auto_detect_interface":false,"default_domain_resolver":"dns-proxy"});
    raw(&mut source, route.clone());
    let p = plan(&source);
    assert_eq!(p.presets[0].rules.len(), 1);
    let mut expected = route["rules"][0].clone();
    expected["outbound"] = json!("direct");
    assert_eq!(p.presets[0].rules[0].config, expected);
    assert_eq!(p.presets[0].route["find_process"], false);
    assert_eq!(p.presets[0].route["default_domain_resolver"], "dns-proxy");
}
#[test]
fn parts_generated_dns_dependencies_and_runtime_overlays_are_explicit_blockers() {
    for part in ["routes", "settings"] {
        let mut source = fixture();
        if part == "routes" {
            source.parts.routes = false
        } else {
            source.parts.settings = false
        };
        assert_eq!(code(&source), ["legacy_route_parts_required"]);
    }
    let mut source = fixture();
    set(&mut source, "use_dns_object", "false");
    set(&mut source, "fakedns", "true");
    assert_eq!(plan(&source).presets[0].dns["independent_cache"], true);
    for key in [
        "adblock_enable",
        "enable_dns_server",
        "enable_redirect",
        "vpn_l3_bridge",
        "use_mozilla_certs",
    ] {
        let mut source = fixture();
        set(&mut source, key, "true");
        assert_eq!(code(&source), ["legacy_route_runtime_unsupported"]);
    }
}
#[test]
fn generated_dns_uses_source_defaults_and_does_not_parse_inactive_dns_object() {
    let mut source = fixture();
    set(&mut source, "use_dns_object", "false");
    set(&mut source, "dns_object", "inactive malformed JSON");
    let p = plan(&source);
    let preset = &p.presets[0];
    assert_eq!(
        preset.dns["servers"],
        json!([
            {"type":"https","server":"8.8.8.8","path":"/dns-query","tag":"dns-remote","domain_resolver":"dns-local","detour":"proxy"},
            {"type":"local","tag":"dns-direct","domain_resolver":"dns-local"},
            {"type":"local","tag":"dns-local"}
        ])
    );
    assert!(preset.dns.get("final").is_none());
    assert_eq!(
        preset.dns["rules"].as_array().unwrap().last().unwrap(),
        &json!({"action":"route","server":"dns-remote"})
    );
    assert_eq!(preset.legacy_constraints.as_ref().unwrap().version, 2);
    assert_eq!(
        preset
            .legacy_constraints
            .as_ref()
            .unwrap()
            .xray_dns_strategy
            .as_deref(),
        Some("UseIP")
    );
    assert!(p
        .report
        .iter()
        .any(|i| i.code == "legacy_dns_generated_local_modes"));
    assert_eq!(
        setting(source.database.as_ref().unwrap(), "dns_object", "").unwrap(),
        "inactive malformed JSON"
    );
    source
        .database
        .as_mut()
        .unwrap()
        .settings
        .retain(|s| s.key != "use_dns_object");
    assert_eq!(plan(&source).presets[0].dns, preset.dns);
}
#[test]
fn generated_and_explicit_dns_keep_source_xray_strategy_independent_of_raw_resolver() {
    for explicit in [false, true] {
        let mut source = fixture();
        set(
            &mut source,
            "use_dns_object",
            if explicit { "true" } else { "false" },
        );
        set(&mut source, "direct_dns_disable_ipv6", "true");
        set(&mut source, "outbound_domain_strategy", "prefer_ipv6");
        let p = plan(&source);
        let preset = &p.presets[0];
        assert_eq!(
            preset.route["default_domain_resolver"]["strategy"],
            if explicit { "prefer_ipv6" } else { "ipv4_only" }
        );
        assert_eq!(
            preset
                .legacy_constraints
                .as_ref()
                .unwrap()
                .xray_dns_strategy
                .as_deref(),
            Some(if explicit { "UseIPv6v4" } else { "UseIPv4" })
        );
        raw(
            &mut source,
            json!({"rules":[],"default_domain_resolver":{"server":"dns-direct","strategy":"ipv6_only"}}),
        );
        let raw_p = plan(&source);
        assert_eq!(
            raw_p.presets[0].route["default_domain_resolver"]["strategy"],
            "ipv6_only"
        );
        assert_eq!(
            raw_p.presets[0]
                .legacy_constraints
                .as_ref()
                .unwrap()
                .xray_dns_strategy,
            preset
                .legacy_constraints
                .as_ref()
                .unwrap()
                .xray_dns_strategy
        );
    }
}
#[test]
fn generated_dns_is_built_for_each_route_and_raw_stored_rules_still_supply_dns() {
    let mut source = fixture();
    set(&mut source, "use_dns_object", "false");
    set(&mut source, "dns_predefined_enable", "false");
    raw(
        &mut source,
        json!({"rules":[{"domain":["traffic.invalid"],"outbound":-1}]}),
    );
    rule(
        &mut source,
        0,
        0,
        &[
            ("outbound_id", n(-2)),
            ("domain_json", s("[\"dns-only.invalid\"]")),
        ],
    );
    let db = source.database.as_mut().unwrap();
    db.routes.push(SourceRoute {
        id: 2,
        name: "Second route".into(),
        columns: BTreeMap::new(),
    });
    db.rules.push(SourceRule {
        route_id: 2,
        order: 0,
        kind: 0,
        columns: BTreeMap::from([
            ("outbound_id".into(), n(-2)),
            ("domain_json".into(), s("[\"second.invalid\"]")),
        ]),
    });
    let p = plan(&source);
    assert_eq!(p.presets[0].rules.len(), 1);
    assert_eq!(
        p.presets[0].rules[0].config["domain"],
        json!(["traffic.invalid"])
    );
    assert!(p.presets[0].dns.to_string().contains("dns-only.invalid"));
    assert!(!p.presets[0].dns.to_string().contains("second.invalid"));
    assert!(p.presets[1].dns.to_string().contains("second.invalid"));
    assert!(!p.presets[1].dns.to_string().contains("dns-only.invalid"));
    // One unsupported generated dependency blocks the whole selected route part.
    source.database.as_mut().unwrap().rules[1]
        .columns
        .insert("rule_set_json".into(), s("[\"external-rules\"]"));
    assert_eq!(code(&source), ["legacy_route_ruleset_unsupported"]);
}
#[test]
fn repeated_dns_is_bounded_before_all_source_presets_are_materialized() {
    let mut source = fixture();
    let servers:Vec<_> = (0..2).map(|i| json!({"type":"https","tag":if i==0 {"dns-direct"} else {"dns-proxy"},"server":"127.0.0.1","path":format!("/{}", "a".repeat(4000))})).collect();
    let rules:Vec<_> = (0..100).map(|i| json!({"domain":format!("{}.fixture.invalid", "a".repeat(50)+&i.to_string()),"server":"dns-direct"})).collect();
    set(
        &mut source,
        "dns_object",
        &json!({"servers":servers,"rules":rules,"final":"dns-direct"}).to_string(),
    );
    // The individual policy is accepted; repeating it with large rule names
    // crosses Routing's total 4 MiB limit without relying on source file limits.
    for i in 0..90 {
        rule(
            &mut source,
            0,
            i,
            &[
                ("domain_json", s("[\"size.invalid\"]")),
                ("name", s(&"n".repeat(500))),
            ],
        );
    }
    assert_eq!(plan(&source).presets.len(), 1);
    let db = source.database.as_mut().unwrap();
    for id in 2..=99 {
        db.routes.push(SourceRoute {
            id,
            name: format!("Route {id}"),
            columns: BTreeMap::new(),
        });
        for order in 0..90 {
            db.rules.push(SourceRule {
                route_id: id,
                order,
                kind: 0,
                columns: BTreeMap::from([
                    ("domain_json".into(), s("[\"size.invalid\"]")),
                    ("name".into(), s(&"n".repeat(500))),
                ]),
            });
        }
    }
    assert_eq!(code(&source), ["legacy_route_limit"]);
}
#[test]
fn remote_protected_endpoints_rulesets_and_warp_never_silently_drop() {
    for (key, value) in [
        ("is_remote", n(1)),
        ("auto_update", n(1)),
        ("remote_url", s("https://secret.invalid")),
    ] {
        let mut source = fixture();
        route_col(&mut source, key, value);
        assert_eq!(code(&source), ["legacy_route_source_unsupported"]);
    }
    let mut source = fixture();
    rule(&mut source, 99, 0, &[]);
    assert_eq!(code(&source), ["legacy_route_type_unsupported"]);
    // A Qt endpoint rule whose endpoint is not listed is skipped, as Qt's
    // build does; the omission is reported, never silent.
    let mut source = fixture();
    rule(&mut source, 13, 0, &[("outbound_id", n(1))]);
    let p = plan(&source);
    assert_eq!(p.presets[0].rules.len(), 2);
    assert!(p
        .report
        .iter()
        .any(|i| i.code == "legacy_route_endpoint_rule_omitted"));
    let mut source = fixture();
    route_col(&mut source, "endpoint_profile_ids", s("[1]"));
    assert_eq!(code(&source), ["legacy_route_reference_missing"]);
    for sets in [
        json!([{"type":"remote","url":"https://secret.invalid","tag":"secret"}]),
        json!([{"type":"local","path":"/private/rules.srs","format":"binary","tag":"x"}]),
    ] {
        let mut source = fixture();
        raw(&mut source, json!({"rule_set":sets}));
        assert_eq!(code(&source), ["legacy_route_ruleset_unsupported"]);
    }
}
#[test]
fn invalid_values_unknown_fields_and_nested_actions_are_rejected() {
    for rule in [
        json!({"domain":[""],"outbound":-1}),
        json!({"port":[65536],"outbound":-1}),
        json!({"ip_cidr":["127.0.0.1/33"],"outbound":-1}),
        json!({"network":"secret","outbound":-1}),
        json!({"inbound":["tun-in"],"outbound":-1}),
        json!({"type":"logical","mode":"and","rules":[{"domain":"fixture.invalid","outbound":-1}],"outbound":-1}),
        json!({"rule_set":"secret","outbound":-1}),
        json!({"unknown":"private","outbound":-1}),
    ] {
        let mut source = fixture();
        raw(&mut source, json!({"rules":[rule]}));
        assert!(convert(&source, None).is_err());
    }
    // Unsupported values of the chosen action still block the import.
    for columns in [
        vec![("reject_method", s("drop")), ("outbound_id", n(-3))],
        vec![("tls_spoof", s("private"))],
    ] {
        let mut source = fixture();
        rule(&mut source, 0, 0, &columns);
        assert_eq!(code(&source), ["legacy_route_action_unsupported"]);
    }
}
/// As Qt's RouteRule::get_rule_json, columns of an action the rule no longer
/// uses and the never-emitted sniffers are ignored instead of blocking.
#[test]
fn leftover_columns_of_an_inactive_action_are_ignored_like_qt() {
    let mut source = fixture();
    rule(
        &mut source,
        0,
        0,
        &[
            ("reject_method", s("drop")),
            ("no_drop", n(1)),
            ("strategy", s("prefer_ipv4")),
            ("sniff_override_dest", n(1)),
            ("sniffers_json", s("[\"http\"]")),
        ],
    );
    let converted = plan(&source);
    // After the generated sniff and DNS rules.
    let rule = &converted.presets[0].rules[2].config;
    assert_eq!(rule["action"], "route");
    for key in [
        "reject_method",
        "no_drop",
        "strategy",
        "override_destination",
        "sniffers",
    ] {
        assert!(rule.get(key).is_none(), "{key}");
    }
}
#[test]
fn dns_unknown_transport_missing_tags_cycles_and_external_dependencies_block() {
    for dns in [
        json!({"servers":[{"type":"unknown","tag":"dns-direct"}],"final":"dns-direct"}),
        json!({"servers":[{"type":"udp","tag":"dns-direct","server":"bootstrap.invalid"}],"final":"dns-direct"}),
        json!({"servers":[{"type":"udp","tag":"dns-direct","server":"bootstrap.invalid","domain_resolver":"dns-direct"}],"final":"dns-direct"}),
        json!({"servers":[{"type":"udp","tag":"dns-direct","server":"127.0.0.1"}],"final":"absent"}),
        json!({"servers":[{"type":"tls","tag":"dns-direct","server":"127.0.0.1","tls":{"certificate_path":"/private.pem"}}],"final":"dns-direct"}),
    ] {
        let mut source = fixture();
        set(&mut source, "dns_object", &dns.to_string());
        assert!(convert(&source, None).is_err());
    }
}
#[test]
fn missing_references_and_bad_row_block_entire_batch_with_safe_reports() {
    let mut source = fixture();
    source.database.as_mut().unwrap().routes.push(SourceRoute {
        id: 2,
        name: "Bad\nname".into(),
        columns: BTreeMap::new(),
    });
    rule(&mut source, 0, 0, &[("outbound_id", n(77))]);
    let issues = convert(&source, None).err().unwrap();
    assert_eq!(issues.len(), 2);
    let text = serde_json::to_string(&issues).unwrap();
    assert!(!text.contains("127.0.0.1"));
    assert!(!text.contains("\\n"));
    assert!(issues
        .iter()
        .any(|i| i.code == "legacy_route_reference_missing"));
}
#[test]
fn simple_empty_placeholder_is_reported_whitespace_does_not_become_catchall() {
    let mut source = fixture();
    rule(&mut source, 1, 0, &[("domain_json", s("[]"))]);
    let p = plan(&source);
    assert_eq!(p.presets[0].rules.len(), 2);
    assert!(p
        .report
        .iter()
        .any(|i| i.code == "legacy_route_empty_rule_omitted"));
    source.database.as_mut().unwrap().rules[0]
        .columns
        .insert("domain_json".into(), s("[\"  \" ]"));
    assert!(convert(&source, None).is_err());
}
#[test]
fn duplicate_keys_orders_limits_and_invalid_settings_fail_before_mutation() {
    let mut source = fixture();
    route_col(&mut source, "is_raw", n(1));
    route_col(&mut source, "raw_route", s("{\"final\":-1,\"final\":-2}"));
    assert_eq!(code(&source), ["legacy_route_json_invalid"]);
    let mut source = fixture();
    rule(&mut source, 0, 0, &[]);
    rule(&mut source, 0, 0, &[]);
    assert_eq!(code(&source), ["legacy_route_structure"]);
    let mut source = fixture();
    raw(
        &mut source,
        json!({"rules":vec![json!({"action":"reject"});1001]}),
    );
    assert_eq!(code(&source), ["legacy_route_limit"]);
    let mut source = fixture();
    set(&mut source, "enable_stats", "private");
    let issues = convert(&source, None).err().unwrap();
    assert!(!serde_json::to_string(&issues).unwrap().contains("private"));
}

pub(super) fn profiles() -> ProfilePlan {
    use crate::store::{Profile, ProfileKind};
    ProfilePlan {
        resources: Default::default(),
        requires_warp: false,
        profiles: vec![Profile {
            vpn_policy: None,
            id: "fixture-proxy".into(),
            name: "Fixture SOCKS".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":19123,"version":"5"}),
            favorite: false,
        }],
        groups: crate::store::Library::default().groups,
        profile_ids: BTreeMap::from([(42, "fixture-proxy".into())]),
        group_ids: BTreeMap::new(),
        vless_overrides: BTreeMap::new(),
        vpn_bindings: Default::default(),
        selected: None,
        report: vec![],
    }
}
#[test]
fn numeric_references_are_mapped_only_in_same_selected_profile_operation() {
    let mut source = fixture();
    source.parts.profiles = true;
    rule(&mut source, 0, 0, &[("outbound_id", n(42))]);
    let profiles = profiles();
    let p = convert(&source, Some(&profiles))
        .unwrap_or_else(|e| panic!("{}", serde_json::to_string(&e).unwrap()));
    assert_eq!(
        p.presets[0].rules[2].config["outbound"],
        "profile:fixture-proxy"
    );
    source.parts.profiles = false;
    assert_eq!(
        convert(&source, Some(&profiles)).err().unwrap()[0].code,
        "legacy_route_reference_missing"
    );
    source.parts.profiles = true;
    raw(
        &mut source,
        json!({"rules":[{"domain":"fixture.invalid","outbound":42}],"final":42}),
    );
    let p = convert(&source, Some(&profiles))
        .unwrap_or_else(|e| panic!("{}", serde_json::to_string(&e).unwrap()));
    assert_eq!(p.presets[0].route["final"], "profile:fixture-proxy");
}
#[test]
fn optional_sql_text_null_matches_qt_but_null_numeric_is_not_default() {
    let mut source = fixture();
    rule(
        &mut source,
        0,
        0,
        &[
            ("network", SourceValue::Null),
            ("domain_json", SourceValue::Null),
            ("name", SourceValue::Null),
        ],
    );
    assert_eq!(
        plan(&source).presets[0].rules[2].config,
        json!({"action":"route","outbound":"direct"})
    );
    source.database.as_mut().unwrap().rules[0]
        .columns
        .insert("outbound_id".into(), SourceValue::Null);
    assert_eq!(code(&source), ["legacy_column_type"]);
    let mut source = fixture();
    route_col(&mut source, "future_semantics", n(0));
    assert_eq!(code(&source), ["legacy_route_field_unsupported"]);
}
#[test]
fn duration_bounds_match_signed_go_nanoseconds_and_regex_is_opaque() {
    for value in [
        "9223372036854775807ns",
        "2562047h47m16.854775807s",
        "100ms",
        "1.5s",
    ] {
        assert!(duration(&json!(value)).is_ok(), "{value}");
    }
    for value in [
        "9223372036854775808ns",
        "2562047h47m16.854775808s",
        "99999999999999999999999999999999999999999999999h",
        "-1s",
        "5fortnights",
    ] {
        assert!(duration(&json!(value)).is_err(), "{value}");
    }
    let expression = r"(?P<qt_name>fixture)\.invalid$";
    let mut source = fixture();
    raw(
        &mut source,
        json!({"rules":[{"domain_regex":expression,"outbound":-1}]}),
    );
    assert_eq!(
        plan(&source).presets[0].rules[0].config["domain_regex"],
        expression
    );
    assert!(regexp(&"a".repeat(2049)).is_err());
}
#[test]
fn accepted_actions_are_checked_with_strict_action_specific_fields() {
    for config in [
        json!({"action":"route-options","override_port":443}),
        json!({"action":"resolve","server":"dns-direct","strategy":"ipv4_only"}),
        json!({"action":"sniff","sniffer":["http","tls"],"override_destination":true}),
        json!({"action":"reject","method":"reply","no_drop":true}),
        json!({"action":"hijack-dns"}),
    ] {
        let mut source = fixture();
        raw(&mut source, json!({"rules":[config]}));
        plan(&source);
    }
    for config in [
        json!({"action":"reject","method":"drop","no_drop":true}),
        json!({"action":"hijack-dns","override_port":443}),
        json!({"action":"route-options"}),
        json!({"action":"sniff","server":"dns-direct"}),
    ] {
        let mut source = fixture();
        raw(&mut source, json!({"rules":[config]}));
        assert!(convert(&source, None).is_err());
    }
}
#[tokio::test]
#[ignore = "requires explicitly supplied disposable local core; CheckConfig only, no Start"]
async fn real_core_checks_structured_raw_dns_and_auxiliary_profile_references() {
    const TEST:&str="legacy_backup::routes::tests::real_core_checks_structured_raw_dns_and_auxiliary_profile_references";
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE required");
    if std::env::var_os("THRONIUM_LEGACY_ROUTES_FIXTURE").is_none() {
        let bundle = tempfile::tempdir().unwrap();
        let exe = bundle.path().join(if cfg!(windows) {
            "Thronium.exe"
        } else {
            "Thronium"
        });
        let bundled = bundle.path().join(if cfg!(windows) {
            "ThroniumCore.exe"
        } else {
            "ThroniumCore"
        });
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::copy(&core, &bundled).unwrap();
        let output = std::process::Command::new(exe)
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env("THRONIUM_LEGACY_ROUTES_FIXTURE", "1")
            .env("THRONIUM_TEST_CORE", bundled)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use crate::store::{Profile, ProfileKind};
    let dir = tempfile::tempdir().unwrap();
    let mut engine = crate::Engine::open(dir.path(), std::path::Path::new(&core)).unwrap();
    let profiles = profiles();
    let selected = Profile {
        vpn_policy: None,
        id: "selected-fixture".into(),
        name: "Fixture Direct".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    };
    engine.store.library.profiles = profiles.profiles.clone();
    engine.store.library.profiles.push(selected.clone());
    let mut fixtures = vec![];
    let mut structured = fixture();
    structured.parts.profiles = true;
    set(&mut structured, "domain_strategy", "ipv4_only");
    rule(
        &mut structured,
        1,
        1,
        &[
            ("domain_suffix_json", s("[\"fixture.invalid\"]")),
            ("outbound_id", n(42)),
        ],
    );
    rule(
        &mut structured,
        0,
        2,
        &[("protocol", s("bittorrent")), ("outbound_id", n(-3))],
    );
    fixtures.push(structured);
    let mut raw_source = fixture();
    raw_source.parts.profiles = true;
    raw(
        &mut raw_source,
        json!({"rules":[{"action":"sniff"},{"type":"logical","mode":"and","rules":[{"domain_suffix":"fixture.invalid"},{"type":"logical","mode":"or","rules":[{"port":443},{"network":"udp"}]}],"outbound":42},{"protocol":"dns","action":"hijack-dns"},{"action":"resolve","server":"dns-direct","strategy":"prefer_ipv4"},{"action":"route-options","override_port":443}],"final":-1}),
    );
    fixtures.push(raw_source);
    for transport in ["udp", "tcp", "tls", "https", "quic", "h3"] {
        let mut source = fixture();
        let mut server =
            json!({"type":transport,"tag":"dns-direct","server":"127.0.0.1","server_port":5353});
        if matches!(transport, "tls" | "https" | "quic" | "h3") {
            server["tls"] = json!({"enabled":true,"server_name":"fixture.invalid"})
        }
        set(&mut source,"dns_object",&json!({"servers":[server],"rules":[{"type":"logical","mode":"or","rules":[{"domain":"fixture.invalid"},{"query_type":"AAAA"}],"action":"route","server":"dns-direct"}],"final":"dns-direct","optimistic":{"enabled":true,"timeout":"1.5s"}}).to_string());
        fixtures.push(source);
    }
    for (index, source) in fixtures.iter().enumerate() {
        let plan = convert(source, Some(&profiles))
            .unwrap_or_else(|issues| panic!("{}", serde_json::to_string(&issues).unwrap()));
        engine.store.library.routing.active = plan.presets[0].id.clone();
        engine.store.library.routing.profiles = plan.presets;
        if let Err(code) = engine.check(&selected).await {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            let logs = engine.logs.view(Default::default()).unwrap();
            engine.shutdown().await;
            panic!(
                "synthetic Check fixture {index}: {code}; {}",
                serde_json::to_string(&logs).unwrap()
            )
        }
    }
    // Syntax is owned by the Go core; this intentionally invalid pattern remains
    // unchanged by pure conversion and is rejected by Check before any Start.
    let mut source = fixture();
    raw(
        &mut source,
        json!({"rules":[{"domain_regex":"[","outbound":-1}]}),
    );
    let plan = plan(&source);
    engine.store.library.routing.active = plan.presets[0].id.clone();
    engine.store.library.routing.profiles = plan.presets;
    assert!(engine.check(&selected).await.is_err());
    engine.shutdown().await;
}

#[test]
fn route_targets_through_endpoint_kinds_are_recorded_and_vpn_policies_stay_refused() {
    use crate::store::ProfileKind;
    let mut source = fixture();
    source.parts.profiles = true;
    rule(&mut source, 0, 0, &[("outbound_id", n(42))]);
    for grouped in [true, false] {
        let mut profiles = profiles();
        let mut endpoint = profiles.profiles[0].clone();
        endpoint.id = "endpoint-fixture".into();
        endpoint.config = json!({"type":"wireguard"});
        profiles.profiles.push(endpoint);
        if grouped {
            profiles.groups[0].proxy_chain.front = Some("endpoint-fixture".into());
        } else {
            profiles.profiles[0].kind = ProfileKind::Chain;
            profiles.profiles[0].config = json!({"hops":["endpoint-fixture"]});
        }
        let p = convert(&source, Some(&profiles))
            .unwrap_or_else(|e| panic!("{}", serde_json::to_string(&e).unwrap()));
        let constraints = p.presets[0].legacy_constraints.as_ref().unwrap();
        assert_eq!(constraints.version, 6);
        assert_eq!(constraints.endpoints, ["endpoint-fixture"]);
        assert!(constraints.valid());
    }
    let mut profiles = profiles();
    profiles.profiles[0].config = json!({"type":"openvpn-client","server":"192.0.2.10"});
    profiles.profiles[0].vpn_policy = Some(crate::vpn_policy::Policy {
        only_advertised_routes: true,
        use_tunnel_dns: true,
        block_outside_dns: false,
    });
    assert_eq!(
        convert(&source, Some(&profiles)).err().unwrap()[0].code,
        "legacy_route_endpoint_unsupported"
    );
}
#[test]
fn raw_inactive_structured_rows_are_reported_and_dns_json_remains_authoritative() {
    let mut source = fixture();
    rule(&mut source, 13, 0, &[("outbound_id", n(77))]);
    raw(&mut source, json!({"rules":[{"action":"reject"}]}));
    let p = plan(&source);
    assert_eq!(p.presets[0].rules.len(), 1);
    assert!(p
        .report
        .iter()
        .any(|i| i.code == "legacy_route_inactive_rules_omitted"));
}

#[test]
fn dns_tags_cannot_alias_destination_profile_references() {
    let mut source = fixture();
    set(&mut source,"dns_object",&json!({"servers":[{"type":"udp","tag":"profile:fixture-proxy","server":"127.0.0.1"}],"final":"profile:fixture-proxy"}).to_string());
    assert_eq!(code(&source), ["legacy_dns_invalid"]);
}

#[test]
fn actual_qt_container_and_sqlite_rows_convert_without_losing_explicit_dns() {
    let bytes = include_bytes!("fixtures/routes-explicit-dns.thrbackup");
    let source = super::super::parse(bytes).unwrap_or_else(|code| panic!("{code}"));
    let manifest: Value = serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    assert!(source.parts.routes && source.parts.settings && !source.parts.profiles);
    assert_eq!(source.database.as_ref().unwrap().rules.len(), 3);
    let settings = &source.database.as_ref().unwrap().settings;
    assert!(settings
        .iter()
        .any(|row| row.key == "outbound_domain_strategy" && row.value == "prefer_ipv4"));
    assert!(!settings
        .iter()
        .any(|row| row.key == "default_domain_strategy"));
    let p = plan(&source);
    assert!(p.presets.iter().all(|preset| preset
        .legacy_constraints
        .as_ref()
        .unwrap()
        .xray_dns_strategy
        .as_deref()
        == Some("UseIPv4v6")));
    assert_eq!(p.presets.len(), 2);
    assert_eq!(p.selected, Some(p.route_ids[&2].clone()));
    for preset in &p.presets {
        assert_eq!(preset.dns, manifest["dns"]);
    }
    let structured = &p.presets[0];
    assert_eq!(structured.rules.len(), 6);
    assert_eq!(structured.rules[2].config["outbound"], "direct");
    assert_eq!(structured.rules[3].config["outbound"], "proxy");
    assert_eq!(structured.rules[4].config["action"], "reject");
    assert_eq!(structured.rules[5].config, json!({"action":"reject"}));
    let mut expected = manifest["rawRoute"]["rules"][0].clone();
    expected["outbound"] = json!("direct");
    assert_eq!(p.presets[1].rules[0].config, expected);
}

#[test]
fn raw_verbatim_omits_defaults_but_keeps_resolver_and_final_when_explicit() {
    for route in [
        json!({"rules":[]}),
        json!({"rules":[],"final":-2,"find_process":false,"default_domain_resolver":"dns-proxy"}),
    ] {
        let mut source = fixture();
        raw(&mut source, route.clone());
        route_col(&mut source, "prevent_modifications", n(1));
        let plan = plan(&source);
        let preset = &plan.presets[0];
        let mut expected = route.clone();
        expected.as_object_mut().unwrap().remove("rules");
        if expected.get("final").is_some() {
            expected["final"] = json!("direct");
        }
        assert_eq!(preset.route, expected);
        assert!(preset.legacy_constraints.as_ref().unwrap().raw_verbatim);
        assert!(preset.legacy_constraints.as_ref().unwrap().valid());
        assert!(plan
            .report
            .iter()
            .any(|issue| issue.code == "legacy_route_raw_verbatim"));
    }
    let mut source = fixture();
    route_col(&mut source, "prevent_modifications", n(1));
    assert!(
        !plan(&source).presets[0]
            .legacy_constraints
            .as_ref()
            .unwrap()
            .raw_verbatim
    );
}

#[test]
fn explicit_predefined_answers_keep_rr_text_sections_and_empty_nodata() {
    let mut source = fixture();
    let mut dns: Value =
        serde_json::from_str(setting(source.database.as_ref().unwrap(), "dns_object", "").unwrap())
            .unwrap();
    let record = json!({"domain":"records.fixture.invalid","action":"predefined","rcode":"NOERROR","answer":["*. 90 IN A 127.0.0.53","*. 90 IN AAAA ::53"],"ns":"fixture.invalid. 120 IN NS ns.fixture.invalid.","extra":[]});
    dns["rules"] =
        json!([record,{"domain":"empty.fixture.invalid","action":"predefined","answer":[]}]);
    set(&mut source, "dns_object", &dns.to_string());
    assert_eq!(plan(&source).presets[0].dns, dns);
    for (field, value) in [
        ("rcode", json!("PRIVATE-INVALID")),
        ("answer", json!([4])),
        ("ns", json!({"rr":"private"})),
        ("extra", json!("\0private")),
    ] {
        let mut changed = dns.clone();
        changed["rules"][0][field] = value;
        set(&mut source, "dns_object", &changed.to_string());
        let codes = code(&source);
        assert!(!codes.is_empty());
        assert!(!format!("{codes:?}").contains("private"));
    }
}

#[test]
fn named_and_url_rule_sets_share_definitions_and_preserve_source_mirror() {
    let mut source = fixture();
    set(&mut source, "use_dns_object", "false");
    set(&mut source, "ruleset_mirror", "2");
    rule(
        &mut source,
        2,
        0,
        &[
            (
                "rule_set_json",
                s("[\"geosite-openai\",\"geoip-private\",\"https://owned.invalid/custom.srs\"]"),
            ),
            ("domain_suffix_json", s("[\"inline.invalid\"]")),
            ("outbound_id", n(-2)),
        ],
    );
    let preset = plan(&source).presets.remove(0);
    let sets = preset.route["rule_set"].as_array().unwrap();
    assert_eq!(sets.len(), 3);
    assert!(sets
        .iter()
        .filter(|v| v["tag"] != "https://owned.invalid/custom.srs")
        .all(|v| v["url"]
            .as_str()
            .unwrap()
            .starts_with("https://gcore.jsdelivr.net/gh/")));
    assert!(sets
        .iter()
        .any(|v| v["url"] == "https://owned.invalid/custom.srs"
            && v["tag"] == "https://owned.invalid/custom.srs"));
    assert!(preset.rules.iter().any(|r| r.config["rule_set"]
        .as_array()
        .is_some_and(|v| v.len() == 3)));
    let projected: Vec<_> = preset.dns["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["server"] == "dns-direct")
        .collect();
    assert_eq!(projected.len(), 2);
    assert_eq!(projected[0]["rule_set"], json!(["geosite-openai"]));
    assert!(projected[0].get("domain_suffix").is_none());
    assert_eq!(projected[1]["domain_suffix"], json!(["inline.invalid"]));
    assert!(projected[1].get("rule_set").is_none());
}

#[test]
fn raw_rule_sets_keep_inline_conditions_and_explicit_dns_dependencies() {
    let mut source = fixture();
    let dns = json!({"servers":[{"type":"local","tag":"dns-direct"}],"rules":[{"rule_set":"inline-fixture","server":"dns-direct"}],"final":"dns-direct"});
    set(&mut source, "dns_object", &dns.to_string());
    let definitions = json!([
        {"type":"inline","tag":"inline-fixture","rules":[{"type":"logical","mode":"or","rules":[{"domain_suffix":["one.invalid"]},{"ip_cidr":["127.0.0.1/32"]}]}]},
        {"type":"remote","tag":"unused-but-authored","format":"source","url":"https://owned.invalid/route.json","download_detour":-2,"update_interval":"2h"}
    ]);
    raw(
        &mut source,
        json!({"rule_set":definitions,"rules":[{"rule_set":"inline-fixture","outbound":-2}]}),
    );
    route_col(&mut source, "prevent_modifications", n(1));
    let preset = plan(&source).presets.remove(0);
    assert_eq!(preset.route["rule_set"][0], definitions[0]);
    assert_eq!(preset.route["rule_set"][1]["download_detour"], "direct");
    assert_eq!(preset.route["rule_set"][1]["update_interval"], "2h");
    assert_eq!(preset.dns, dns);
    assert_eq!(preset.rules[0].config["rule_set"], "inline-fixture");
    for invalid in [
        json!([]),
        json!([definitions[0].clone(), definitions[0].clone()]),
        json!([{"type":"inline","tag":"inline-fixture","rules":[{"domain":["a.invalid"],"action":"reject"}]}]),
        json!([{"type":"remote","tag":"inline-fixture","format":"binary","url":"file:///private/set.srs"}]),
        json!([{"type":"inline","tag":"inline-fixture","rules":[{"rule_set":"other"}]}]),
    ] {
        raw(
            &mut source,
            json!({"rule_set":invalid,"rules":[{"rule_set":"inline-fixture","outbound":-2}]}),
        );
        assert!(convert(&source, None).is_err());
    }
}
