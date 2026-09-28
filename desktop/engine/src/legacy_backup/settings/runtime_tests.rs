//! Runtime categories (inbound, system, presets, intercept, TUN, core): exact
//! Qt semantics for sign-encoded listeners and intervals, inverted privilege
//! flag, mirror enum, address validators and value-free review.
use super::{
    tests::{codes, row, source},
    *,
};

const RUNTIME: [Group; 6] = [
    Group::Inbound,
    Group::System,
    Group::Presets,
    Group::Intercept,
    Group::Tun,
    Group::Core,
];

fn one(group: Group, key: &str, text: &str) -> Result<SettingsPlan, Vec<Issue>> {
    convert(&source(vec![row(key, text)]), &group)
}
fn value(group: Group, key: &str, text: &str) -> Value {
    let plan = one(group, key, text).unwrap_or_else(|_| panic!("{key}={text}"));
    plan.values[key].clone()
}

#[test]
fn every_runtime_field_is_a_catalog_field_with_a_matching_or_declared_source_key() {
    let catalog = crate::settings::fields();
    let mut seen = std::collections::BTreeSet::new();
    for group in RUNTIME {
        let converter = converter(&group);
        for field in converter.fields {
            assert!(catalog.iter().any(|f| f.id == *field), "{field}");
            assert!(seen.insert(*field), "{field} listed twice");
            let key = (converter.source_key)(field);
            let explicit = matches!(*field, "tun_request_permission" | "tun_system_dns");
            assert_eq!(
                key == *field || key == crate::legacy_backup::source_settings::key(field),
                !explicit,
                "{field} -> {key}"
            );
        }
    }
    assert_eq!(seen.len(), 61);
}

#[test]
fn qt_system_dns_becomes_the_windows_tun_system_dns() {
    let imported =
        |text| one(Group::Tun, "system_dns_set", text).unwrap().values["tun_system_dns"].clone();
    assert_eq!(imported("true"), "interface");
    assert_eq!(imported("false"), "disabled");
    assert!(one(Group::Tun, "system_dns_set", "maybe").is_err());
}

#[test]
fn listener_ports_are_sign_encoded_and_split_into_enabled_and_port() {
    for (field, enabled) in [
        ("core_box_clash_api", "core_box_clash_enabled"),
        ("core_box_api_port", "core_box_api_enabled"),
    ] {
        let plan = one(Group::Core, field, "-9090").unwrap();
        assert_eq!(plan.values[field], 9090);
        assert_eq!(plan.values[enabled], false);
        assert_eq!(plan.imported_fields, [field]);
        assert!(plan.report.is_empty());
        let plan = one(Group::Core, field, "9091").unwrap();
        assert_eq!(plan.values[field], 9091);
        assert_eq!(plan.values[enabled], true);
        assert_eq!(plan.report.len(), 1);
        assert_eq!(plan.report[0].name.as_deref(), Some(field));
        for bad in ["0", "65536", "-65536", "port", ""] {
            assert_eq!(
                codes(one(Group::Core, field, bad)),
                ["legacy_settings_value_invalid"],
                "{field}={bad}"
            );
        }
    }
}

#[test]
fn ntp_port_zero_uses_the_protocol_default_with_a_notice_and_intervals_are_durations() {
    let plan = one(Group::Core, "ntp_server_port", "0").unwrap();
    assert_eq!(plan.values["ntp_server_port"], 123);
    assert_eq!(plan.report[0].code, "legacy_core_ntp_default_port");
    assert_eq!(value(Group::Core, "ntp_server_port", "1123"), 1123);
    assert_eq!(
        codes(one(Group::Core, "ntp_server_port", "70000")),
        ["legacy_settings_value_invalid"]
    );
    assert_eq!(value(Group::Core, "ntp_interval", ""), "");
    assert_eq!(value(Group::Core, "ntp_interval", "1h30m"), "1h30m");
    assert_eq!(
        codes(one(Group::Core, "ntp_interval", "soon")),
        ["legacy_settings_value_invalid"]
    );
    for field in ["h2_idle_timeout", "h2_keep_alive_period"] {
        assert_eq!(value(Group::Presets, field, "15s"), "15s");
        assert_eq!(
            codes(one(Group::Presets, field, "15 seconds")),
            ["legacy_settings_value_invalid"]
        );
    }
}

#[test]
fn route_update_interval_follows_the_subscription_sign_rule() {
    let plan = one(Group::Core, "route_auto_update", "-1440").unwrap();
    assert_eq!(plan.values["route_auto_update"], 0);
    assert_eq!(plan.report[0].code, "legacy_core_route_interval_disabled");
    assert!(one(Group::Core, "route_auto_update", "0")
        .unwrap()
        .report
        .is_empty());
    assert_eq!(value(Group::Core, "route_auto_update", "29"), 0);
    assert_eq!(value(Group::Core, "route_auto_update", "30"), 30);
    assert_eq!(value(Group::Core, "route_auto_update", "43200"), 43200);
    assert_eq!(
        codes(one(Group::Core, "route_auto_update", "43201")),
        ["legacy_settings_limit"]
    );
}

#[test]
fn ruleset_mirror_uses_the_qt_enum_order_and_rejects_unknown_indexes() {
    for (index, name) in ["github", "cloudflare", "gcore", "quantil", "fastly", "cdn"]
        .iter()
        .enumerate()
    {
        assert_eq!(
            value(Group::Core, "ruleset_mirror", &index.to_string()),
            *name
        );
    }
    for bad in ["6", "-1", "cloudflare"] {
        assert_eq!(
            codes(one(Group::Core, "ruleset_mirror", bad)),
            ["legacy_settings_value_invalid"]
        );
    }
}

#[test]
fn privilege_request_is_read_from_the_inverted_qt_key_and_stays_a_choice() {
    let plan = convert(
        &source(vec![
            row("disable_privilege_req", "true"),
            row("tun_request_permission", "true"),
        ]),
        &Group::Tun,
    )
    .unwrap();
    assert_eq!(plan.values["tun_request_permission"], false);
    assert_eq!(plan.deferred_count, 1);
    assert_eq!(plan.report[0].code, "legacy_tun_permission_disabled");
    let plan = one(Group::Tun, "disable_privilege_req", "0").unwrap();
    assert_eq!(plan.values["tun_request_permission"], true);
    assert!(plan.report.is_empty());
    assert_eq!(plan.imported_fields, ["tun_request_permission"]);
}

#[test]
fn tun_addresses_use_the_interface_and_exclusion_validators() {
    assert_eq!(
        value(Group::Tun, "vpn_tun_ipv4_cidr", "172.19.0.1/24"),
        "172.19.0.1/24"
    );
    assert_eq!(
        value(Group::Tun, "vpn_tun_ipv6_cidr", "fdfe:dcba:9876::1/96"),
        "fdfe:dcba:9876::1/96"
    );
    for (field, bad) in [
        ("vpn_tun_ipv4_cidr", "8.8.8.8/24"),
        ("vpn_tun_ipv4_cidr", "172.19.0.1"),
        ("vpn_tun_ipv6_cidr", "172.19.0.1/24"),
        ("vpn_private_ranges", "[\"10.0.0.1/8\"]"),
        ("vpn_private_ranges", "[\"private\"]"),
        ("vpn_private_ranges", "\"10.0.0.0/8\""),
        ("vpn_mtu", "1279"),
        ("vpn_mtu", "9001"),
        ("vpn_impl", "kernel"),
    ] {
        assert_eq!(
            one(Group::Tun, field, bad).err().map(|e| e[0].code.clone()),
            Some("legacy_settings_value_invalid".into()),
            "{field}={bad}"
        );
    }
    let ranges = value(
        Group::Tun,
        "vpn_private_ranges",
        "[\"10.0.0.0/8\",\"fc00::/7\"]",
    );
    assert_eq!(ranges, json!(["10.0.0.0/8", "fc00::/7"]));
    assert_eq!(
        one(Group::Tun, "vpn_impl", "mixed").unwrap().values["vpn_implementation"],
        "mixed"
    );
    assert_eq!(value(Group::Tun, "vpn_mtu", "1280"), 1280);
}

#[test]
fn inbound_authentication_and_listen_address_have_notices_and_credential_rule() {
    let plan = convert(
        &source(vec![
            row("inbound_auth", "true"),
            row("inbound_user", "user"),
            row("inbound_pass", "private-marker82c"),
            row("inbound_address", "0.0.0.0"),
        ]),
        &Group::Inbound,
    )
    .unwrap();
    let report: Vec<_> = plan.report.iter().map(|i| i.code.as_str()).collect();
    assert_eq!(
        report,
        ["legacy_inbound_auth_enabled", "legacy_inbound_lan_listen"]
    );
    assert!(!json!(plan.report).to_string().contains("private-marker82c"));
    assert!(!json!(plan.imported_fields)
        .to_string()
        .contains("private-marker82c"));
    assert_eq!(
        codes(convert(
            &source(vec![row("inbound_auth", "1"), row("inbound_pass", "")]),
            &Group::Inbound
        )),
        ["legacy_inbound_auth_incomplete"]
    );
    assert!(one(Group::Inbound, "inbound_auth", "true").is_ok());
    assert_eq!(
        codes(one(Group::Inbound, "proxy_scheme", "{ip}")),
        ["legacy_settings_value_invalid"]
    );
    assert_eq!(
        value(Group::Inbound, "proxy_scheme", "socks5://{ip}:{port}"),
        "socks5://{ip}:{port}"
    );
    assert_eq!(
        codes(one(Group::Inbound, "inbound_socks_port", "65536")),
        ["legacy_settings_value_invalid"]
    );
    assert_eq!(
        codes(one(Group::Inbound, "inbound_address", "localhost")),
        ["legacy_settings_value_invalid"]
    );
}

#[test]
fn custom_inbounds_become_the_catalog_array_with_reserved_and_duplicate_tags_refused() {
    let plan = one(
        Group::Inbound,
        "custom_inbound",
        r#"{"inbounds":[{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1085},{"type":"http","listen":"127.0.0.1","listen_port":1086}]}"#,
    )
    .unwrap();
    assert_eq!(plan.values["custom_inbound"][0]["tag"], "lan-socks");
    assert_eq!(plan.values["custom_inbound"].as_array().unwrap().len(), 2);
    assert_eq!(plan.report[0].code, "legacy_inbound_custom_listeners");
    let empty = one(Group::Inbound, "custom_inbound", r#"{"inbounds": []}"#).unwrap();
    assert_eq!(empty.values["custom_inbound"], json!([]));
    assert!(empty.report.is_empty());
    for bad in [
        r#"{"inbounds":[{"type":"socks","tag":"mixed-in"}]}"#,
        r#"{"inbounds":[{"type":"socks","tag":"tun-in"}]}"#,
        r#"{"inbounds":[{"type":"socks","tag":"a"},{"type":"http","tag":"a"}]}"#,
        r#"{"inbounds":[{"tag":"a"}]}"#,
        r#"{"inbounds":[1]}"#,
        r#"{"inbounds":{}}"#,
        r#"[]"#,
        r#"{"inbounds":[],"extra":true}"#,
        "not json",
    ] {
        assert_eq!(
            codes(one(Group::Inbound, "custom_inbound", bad)),
            ["legacy_settings_value_invalid"],
            "{bad}"
        );
    }
}

#[test]
fn clash_listener_outside_loopback_requires_a_secret_from_the_same_source() {
    let rows = |secret: &str| {
        vec![
            row("core_box_clash_api", "9090"),
            row("core_box_clash_listen_addr", "0.0.0.0"),
            row("core_box_clash_api_secret", secret),
        ]
    };
    assert_eq!(
        codes(convert(&source(rows("")), &Group::Core)),
        ["legacy_core_clash_secret_required"]
    );
    let plan = convert(&source(rows("private-marker82c")), &Group::Core).unwrap();
    assert_eq!(plan.values["core_box_clash_enabled"], true);
    assert!(!json!(plan.report).to_string().contains("private-marker82c"));
    assert_eq!(crate::legacy_backup::settings::validate_plan(&plan), Ok(()));
    let mut secretless = plan.clone();
    secretless
        .values
        .insert("core_box_clash_api_secret".into(), json!(""));
    assert_eq!(
        crate::legacy_backup::settings::validate_plan(&secretless),
        Err("legacy_core_clash_secret_required")
    );
}

#[test]
fn system_and_intercept_switches_report_only_their_side_effects() {
    for (group, field, code) in [
        (
            Group::System,
            "url_scheme_auto_register",
            "legacy_system_url_scheme_enabled",
        ),
        (Group::System, "disable_tray", "legacy_system_tray_disabled"),
        (
            Group::System,
            "use_custom_icons",
            "legacy_system_custom_icons_deferred",
        ),
        (
            Group::Intercept,
            "dns_server_listen_lan",
            "legacy_intercept_lan_listen",
        ),
    ] {
        let plan = one(group, field, "true").unwrap();
        assert_eq!(plan.report[0].code, code, "{field}");
        assert_eq!(plan.report[0].name.as_deref(), Some(field));
        assert!(one(group, field, "false").unwrap().report.is_empty());
    }
    let rules = value(
        Group::Intercept,
        "dns_server_rules",
        "[\"domain:example.test\",\"suffix:private.test\"]",
    );
    assert_eq!(rules.as_array().unwrap().len(), 2);
    assert_eq!(
        codes(one(Group::Intercept, "dns_server_rules", "[1]")),
        ["legacy_settings_value_invalid"]
    );
    assert_eq!(
        codes(one(Group::Intercept, "dns_v6_resp", "::g")),
        ["legacy_settings_value_invalid"]
    );
}

#[test]
fn runtime_categories_ignore_other_rows_and_never_copy_defaults() {
    let s = source(vec![row("fragment_size", "20-200"), row("theme", "1")]);
    for group in RUNTIME {
        let plan = convert(&s, &group).unwrap();
        if group == Group::Presets {
            assert_eq!(
                plan.values,
                BTreeMap::from([("fragment_size".to_owned(), json!("20-200"))])
            );
            assert_eq!(plan.deferred_count, 1);
            assert_eq!(plan.report[0].code, "legacy_settings_partial");
        } else {
            assert!(plan.values.is_empty());
            assert_eq!(plan.deferred_count, 2);
        }
    }
}
