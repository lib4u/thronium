use super::*;
use std::collections::BTreeMap;
fn source(config: Value) -> SourceProfile {
    SourceProfile {
        id: 17,
        group_id: 1,
        kind: if config["type"] == "openconnect" {
            "openconnect"
        } else {
            "openvpn"
        }
        .into(),
        name: Some("Fixture".into()),
        outbound: config,
        columns: BTreeMap::new(),
    }
}
#[test]
fn independent_actual_qt_thirty_seven_cases_preserve_static_build_and_bound_source() {
    use sha2::{Digest, Sha256};
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/qt-oracle-manifest.json")).unwrap();
    for (data, key) in [
        (
            include_bytes!("fixtures/qt-cases.json").as_slice(),
            "casesSha256",
        ),
        (
            include_bytes!("fixtures/inputs.json").as_slice(),
            "inputsSha256",
        ),
    ] {
        assert_eq!(format!("{:x}", Sha256::digest(data)), manifest[key]);
    }
    let cases: Vec<Value> = serde_json::from_str(include_str!("fixtures/qt-cases.json")).unwrap();
    assert_eq!(cases.len(), 37);
    let refusals: BTreeMap<_, _> = [
        ("ovpn-wrong-type-policy", STRUCTURE),
        ("oc-wrong-type-policy", STRUCTURE),
        ("ovpn-unknown-field", FIELD),
        ("oc-unknown-field", FIELD),
        ("oc-paths-unread", "legacy_profile_external_resource"),
        ("oc-token-precise-counter", "legacy_vpn_auth_unsupported"),
        (
            "oc-bound-credential-placeholder",
            "vpn_otp_start_placeholder_unsupported",
        ),
        ("oc-bound-cached-password", "vpn_otp_form_cache_unsupported"),
        ("oc-bound-shadowed-form", "vpn_otp_form_shadowed"),
    ]
    .into_iter()
    .collect();
    let mut static_pass = 0;
    let mut bound_pass = 0;
    for case in &cases {
        let p = source(case["source"].clone());
        let before = p.outbound.clone();
        let converted = convert(&p);
        let name = case["name"].as_str().unwrap();
        if let Some(expected) = refusals.get(name) {
            assert_eq!(converted.err(), Some(*expected), "{name}");
            continue;
        }
        let got = converted.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            json!(got.policy),
            json!({"onlyAdvertisedRoutes":case["qtExport"]["only_advertised_routes"],"useTunnelDns":case["qtExport"]["use_tunnel_dns"],"blockOutsideDns":case["qtExport"]["block_outside_dns"]}),
            "{name}"
        );
        if case.get("qtBuild").is_some() {
            assert_eq!(got.config, case["qtBuild"], "{name}");
            assert!(got.otp_source_id.is_none());
            static_pass += 1;
        } else {
            assert!(got.otp_source_id.is_some());
            if name == "oc-bound-form" {
                assert_eq!(got.config["form_entries"], case["qtExport"]["form_entries"]);
                assert!(!got.manual_allowed);
            } else if name == "ovpn-bound-credential-placeholder" {
                assert!(got.config["password"].as_str().unwrap().contains("{otp}"));
                assert!(!got.manual_allowed);
            } else {
                assert_eq!(name, "ovpn-bound-static-challenge");
                assert_eq!(
                    got.config["static_challenge"],
                    case["qtExport"]["static_challenge"]
                );
                assert!(got.manual_allowed);
            }
            bound_pass += 1;
        }
        assert_eq!(p.outbound, before);
        assert!(got.config.get("otp_profile_id").is_none());
        for k in [
            "only_advertised_routes",
            "use_tunnel_dns",
            "block_outside_dns",
        ] {
            assert!(got.config.get(k).is_none());
        }
    }
    assert_eq!((static_pass, bound_pass), (25, 3));
}
#[test]
fn unsupported_source_shapes_and_unbound_templates_refuse_without_normalizing_them_away() {
    let base = json!({"type":"openconnect","server":"127.0.0.1","server_port":443,"username":"fixture","password":"fixture"});
    for (key, value, code) in [
        ("system", json!(true), "legacy_vpn_system_unsupported"),
        ("name", json!("old-vpn0"), "legacy_vpn_system_unsupported"),
        ("flavor", json!("gp"), "legacy_vpn_auth_unsupported"),
        ("cookie", json!("opaque"), "legacy_vpn_auth_unsupported"),
        ("server_port", json!(65536), STRUCTURE),
        ("mtu", json!(-1), STRUCTURE),
        ("mtu", json!(1.5), STRUCTURE),
        ("otp_profile_id", json!(2147483648u64), STRUCTURE),
        ("tls", json!({"future":true}), FIELD),
        (
            "form_entries",
            json!([{"name":"otp","value":"{otp}"}]),
            STRUCTURE,
        ),
        (
            "form_entries",
            json!([{"form_id":"main","name":"otp","value":"{otp}"}]),
            "legacy_vpn_binding_required",
        ),
    ] {
        let mut config = base.clone();
        config[key] = value;
        let s = source(config.clone());
        assert_eq!(convert(&s).err(), Some(code), "{key}");
        assert_eq!(s.outbound, config);
    }
    let mut promoted = base.clone();
    promoted["form_entries"] =
        json!([{"form_id":"main","name":"otp","value":"{otp}","promote":true}]);
    let got = convert(&source(promoted.clone())).unwrap();
    assert!(got.manual_allowed);
    assert_eq!(got.config["form_entries"], promoted["form_entries"]);
}

#[test]
fn qt_list_serialization_discards_blank_items_but_keeps_original_nonblank_text_and_presence() {
    for (value, expected) in [
        (
            json!(["   ", "\t", "", " padded ", "\tother\t"]),
            Some(json!([" padded ", "\tother\t"])),
        ),
        (
            json!("   \n\t\n\n padded \n\tother\t\n"),
            Some(json!([" padded ", "\tother\t"])),
        ),
        (json!(["   ", "\t", ""]), Some(json!([]))),
        (json!(" \n\t\n"), Some(json!([]))),
        (json!([]), None),
        (json!("\n\n"), None),
    ] {
        for (protocol, key) in [
            ("openvpn", "routes"),
            ("openvpn", "certificate"),
            ("openconnect", "certificate_authority"),
        ] {
            let mut c = json!({"type":protocol,"server":"127.0.0.1","server_port":443});
            if key == "routes" {
                c[key] = value.clone();
            } else {
                c["tls"] = json!({key:value.clone()});
            }
            let source = source(c);
            let original = source.outbound.clone();
            let got = convert(&source).unwrap();
            let actual = if key == "routes" {
                got.config.get(key)
            } else {
                got.config["tls"].get(key)
            };
            assert_eq!(actual, expected.as_ref(), "{protocol}/{key}/{value}");
            assert_eq!(source.outbound, original);
        }
    }
}

#[test]
fn qt_ipv6_valid_scoped_hosts_preserve_text_and_malformed_brackets_refuse() {
    for host in ["[[::1]]", "[::1", "::1]", "[[::1]", "[::1]]"] {
        let source = source(
            json!({"type":"openconnect","server":host,"server_port":444,"server_path":"login"}),
        );
        let before = source.outbound.clone();
        assert_eq!(convert(&source).err(), Some(STRUCTURE), "{host}");
        assert_eq!(source.outbound, before);
    }
    for (host, expected) in [
        ("::1", "[::1]:444/login"),
        ("[::1]", "[::1]:444/login"),
        ("fe80::1%eth0", "[fe80::1%eth0]:444/login"),
        ("[fe80::1%eth0]", "[fe80::1%eth0]:444/login"),
        ("example.invalid", "example.invalid:444/login"),
    ] {
        let source = source(
            json!({"type":"openconnect","server":host,"server_port":444,"server_path":"login"}),
        );
        let before = source.outbound.clone();
        assert_eq!(
            convert(&source).unwrap().config["server"],
            expected,
            "{host}"
        );
        assert_eq!(source.outbound, before);
    }
}

#[test]
fn independent_qt_parity_raw_and_export_reparse_cases_use_only_supplied_source() {
    use sha2::{Digest, Sha256};
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/parity35/manifest.json")).unwrap();
    for (name, data) in [
        (
            "qt-cases.json",
            include_bytes!("fixtures/parity35/qt-cases.json").as_slice(),
        ),
        (
            "export-reparse-cases.json",
            include_bytes!("fixtures/parity35/export-reparse-cases.json").as_slice(),
        ),
    ] {
        assert_eq!(
            format!("{:x}", Sha256::digest(data)),
            manifest["files"][name]
        );
        let cases: Vec<Value> = serde_json::from_slice(data).unwrap();
        assert_eq!(cases.len(), 19);
        let mut exact = 0;
        let mut refused = 0;
        for case in cases {
            let source = source(case["source"].clone());
            let before = source.outbound.clone();
            if matches!(
                case["name"]
                    .as_str()
                    .map(|name| name.strip_suffix("-export-reparse").unwrap_or(name)),
                Some("oc-host-0" | "oc-host-1" | "oc-host-2")
            ) {
                assert_eq!(convert(&source).err(), Some(STRUCTURE));
                refused += 1;
            } else {
                assert_eq!(
                    convert(&source)
                        .unwrap_or_else(|error| panic!("{name}/{}: {error}", case["name"]))
                        .config,
                    case["qtBuild"],
                    "{name}/{}",
                    case["name"]
                );
                exact += 1;
            }
            assert_eq!(source.outbound, before);
        }
        assert_eq!((exact, refused), (16, 3));
    }
}

#[test]
fn an_openvpn_binding_whose_challenge_only_arrives_from_the_server_is_imported() {
    // Qt binds a code to a profile that has no challenge of its own: the server
    // asks for it while connecting, as a CRV1 refusal does.
    let dynamic = json!({
        "type": "openvpn-client", "server": "192.0.2.9", "server_port": 1194,
        "username": "fixture-user", "password": "fixture-password",
        "otp_profile_id": 5,
    });
    let converted = convert(&source(dynamic)).unwrap();
    assert_eq!(converted.otp_source_id, Some(5));
    assert!(converted.config.get("static_challenge").is_none());
    // Nothing is baked before Start, so the code is spent when the server asks.
    let profile = crate::store::Profile {
        id: "p".into(),
        name: "Fixture".into(),
        group_id: crate::store::PERSONAL_GROUP.into(),
        kind: crate::store::ProfileKind::SingBoxOutbound,
        config: converted.config.clone(),
        favorite: false,
        vpn_policy: Some(converted.policy),
    };
    assert_eq!(
        crate::vpn_auth::otp::recommended_mode(&profile).unwrap(),
        crate::vpn_otp_bindings::Mode::AutoLive
    );
    // A profile that does carry its own challenge still imports the same way.
    let configured = json!({
        "type": "openvpn-client", "server": "192.0.2.9", "server_port": 1194,
        "username": "fixture-user", "password": "fixture-password",
        "static_challenge": "Code", "otp_profile_id": 5,
    });
    let with_challenge = convert(&source(configured)).unwrap();
    assert_eq!(with_challenge.otp_source_id, Some(5));
    assert_eq!(with_challenge.config["static_challenge"], json!("Code"));
}
