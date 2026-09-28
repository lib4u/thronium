use super::*;
use crate::legacy_backup::{SourceRow, SourceValue};
use sha2::{Digest, Sha256};

fn source(outbound: Value) -> SourceProfile {
    SourceProfile {
        id: 7,
        kind: "extracore".into(),
        name: Some("Stale SQLite label".into()),
        group_id: 3,
        columns: SourceRow::from([(
            "outbound_json".into(),
            SourceValue::Text(outbound.to_string()),
        )]),
        outbound,
    }
}
fn complete() -> Value {
    json!({"type":"extracore","name":"  Qt внешнее 🦊  ","socks_address":"127.0.0.1","socks_port":19080,
        "extra_core_path":"/missing/synthetic path/../helper","extra_core_args":"  --config '%s' --literal '' --more '%d %%'\n",
        "extra_core_conf":"\t# opaque synthetic-private-value\r\n秘密 = 🦊\n  ","no_logs":false})
}
fn converted(value: Value) -> Result<Value, &'static str> {
    convert(&source(value), Platform::Supported)
}

#[test]
fn actual_qt_twenty_two_cases_match_supported_exports_and_explicitly_reject_lossy_cases() {
    let manifest: Value = serde_json::from_str(include_str!("fixtures/manifest.json")).unwrap();
    for (name, bytes) in [
        (
            "cases.json",
            include_bytes!("fixtures/cases.json").as_slice(),
        ),
        (
            "inputs.json",
            include_bytes!("fixtures/inputs.json").as_slice(),
        ),
    ] {
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            manifest["artifacts"][name].as_str().unwrap()
        );
    }
    let cases: Vec<Value> = serde_json::from_str(include_str!("fixtures/cases.json")).unwrap();
    assert_eq!(cases.len(), 22);
    let mut accepted = 0;
    for case in cases {
        assert_eq!(case["initialPort"], 0);
        let name = case["name"].as_str().unwrap();
        let error = match name {
            "type-only" | "missing-socks_port" | "zero-port" | "privileged-port" => {
                Some("legacy_external_port_invalid")
            }
            "empty-object" => Some("legacy_profile_discriminator"),
            "missing-extra_core_path" | "relative-path" => Some("legacy_external_path_invalid"),
            "null-port" | "string-port" | "fractional-port" | "wrong-no-logs" | "null-args" => {
                Some("legacy_profile_structure")
            }
            "extra-field" => Some("legacy_profile_field_unsupported"),
            _ => None,
        };
        let result = converted(case["source"].clone());
        match error {
            Some(error) => assert_eq!(result.err(), Some(error), "case {name}"),
            None => {
                assert_eq!(result.unwrap(), case["qtExport"], "case {name}");
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted, 9);
}

#[test]
fn only_missing_fields_receive_qt_defaults_and_present_wrong_types_never_do() {
    let minimum = json!({"type":"extracore","socks_port":1024,"extra_core_path":"/absent/core"});
    assert_eq!(
        converted(minimum).unwrap(),
        json!({"type":"extracore","name":"","socks_address":"127.0.0.1","socks_port":1024,"extra_core_path":"/absent/core","extra_core_args":"","extra_core_conf":"","no_logs":false})
    );
    for key in [
        "name",
        "socks_address",
        "socks_port",
        "extra_core_path",
        "extra_core_args",
        "extra_core_conf",
        "no_logs",
    ] {
        for wrong in [Value::Null, json!([]), json!({})] {
            let mut input = complete();
            input[key] = wrong;
            assert_eq!(
                converted(input).err(),
                Some("legacy_profile_structure"),
                "{key}"
            );
        }
    }
    for no_logs in [true, false] {
        let mut input = complete();
        input["no_logs"] = json!(no_logs);
        assert_eq!(converted(input).unwrap()["no_logs"], no_logs);
    }
}

#[test]
fn schema_and_sqlite_discriminator_are_strict_without_reporting_unknown_names_or_values() {
    for value in [Value::Null, json!([]), json!("synthetic-private-value")] {
        assert_eq!(converted(value).err(), Some("legacy_profile_structure"));
    }
    for kind in ["", "socks", "custom", "EXTRACORE"] {
        let mut row = source(complete());
        row.kind = kind.into();
        assert_eq!(
            convert(&row, Platform::Supported).err(),
            Some("legacy_profile_discriminator")
        );
    }
    for value in [Value::Null, json!(17), json!("external-core")] {
        let mut input = complete();
        input["type"] = value;
        assert_eq!(converted(input).err(), Some("legacy_profile_discriminator"));
    }
    let mut input = complete();
    input.as_object_mut().unwrap().remove("type");
    assert_eq!(converted(input).err(), Some("legacy_profile_discriminator"));
    for key in [
        "command",
        "argv",
        "env",
        "cwd",
        "tls",
        "multiplex",
        "detour",
        "bind_interface",
        "tag",
        "synthetic-private-key",
    ] {
        let mut input = complete();
        input[key] = json!("synthetic-private-value");
        let error = converted(input).unwrap_err();
        assert_eq!(error, "legacy_profile_field_unsupported");
        assert!(!error.contains("synthetic"));
    }
}

#[test]
fn port_is_required_bounded_integer_and_not_qt_coerced_or_wrapped() {
    for n in [1024, 65535] {
        let mut input = complete();
        input["socks_port"] = json!(n);
        assert_eq!(converted(input).unwrap()["socks_port"], n);
    }
    for n in [
        json!(0),
        json!(1023),
        json!(65536),
        json!(-1),
        json!(i64::MIN),
        json!(u64::MAX),
    ] {
        let mut input = complete();
        input["socks_port"] = n;
        assert_eq!(converted(input).err(), Some("legacy_external_port_invalid"));
    }
    for n in [json!(19080.0), json!(19080.5), json!("19080"), json!(true)] {
        let mut input = complete();
        input["socks_port"] = n;
        assert_eq!(converted(input).err(), Some("legacy_profile_structure"));
    }
    let mut missing = complete();
    missing.as_object_mut().unwrap().remove("socks_port");
    assert_eq!(
        converted(missing).err(),
        Some("legacy_external_port_invalid")
    );
}

#[test]
fn supported_platform_loopback_and_absolute_path_are_explicit_without_resolution() {
    assert_eq!(
        convert(&source(complete()), Platform::Unsupported).err(),
        Some("legacy_external_platform_unsupported")
    );
    for address in [
        "localhost",
        "127.1",
        "127.0.0.2",
        "::1",
        "0.0.0.0",
        "192.0.2.1",
        " 127.0.0.1",
        "",
    ] {
        let mut input = complete();
        input["socks_address"] = json!(address);
        assert_eq!(
            converted(input).err(),
            Some("legacy_external_address_unsupported")
        );
    }
    for path in [
        "",
        "./core",
        "core",
        "C:program.exe",
        "/bad\npath",
        "/bad\tpath",
        "/bad\0path",
    ] {
        let mut input = complete();
        input["extra_core_path"] = json!(path);
        assert_eq!(converted(input).err(), Some("legacy_external_path_invalid"));
    }
    for path in [
        "/missing/no-such-executable",
        "/absolute/../with spaces/./core",
        "/nonexistent/🦊/helper",
        // A Windows Qt backup keeps the path it was made with.
        "C:\\Program Files\\Throne\\core\\helper.exe",
    ] {
        let mut input = complete();
        input["extra_core_path"] = json!(path);
        assert_eq!(converted(input).unwrap()["extra_core_path"], path);
    }
}

#[test]
fn byte_limits_and_nul_errors_are_bounded_before_normalized_copy() {
    for (key, max, error) in [
        ("name", 512, "legacy_external_name_invalid"),
        (
            "extra_core_path",
            crate::external_core::MAX_PATH_BYTES,
            "legacy_external_path_invalid",
        ),
        (
            "extra_core_args",
            crate::external_core::MAX_ARGS_BYTES,
            "legacy_external_args_invalid",
        ),
        (
            "extra_core_conf",
            crate::external_core::MAX_CONFIG_BYTES,
            "legacy_external_config_invalid",
        ),
    ] {
        let prefix = if key == "extra_core_path" { "/" } else { "" };
        let mut input = complete();
        input[key] = json!(format!("{prefix}{}", "x".repeat(max - prefix.len())));
        assert!(converted(input.clone()).is_ok(), "{key}");
        input[key] = json!(format!("{prefix}{}", "x".repeat(max + 1 - prefix.len())));
        assert_eq!(converted(input.clone()).err(), Some(error));
        input[key] = json!(format!("{prefix}{}", "🦊".repeat(max / 4 + 1)));
        assert_eq!(converted(input.clone()).err(), Some(error));
        input[key] = json!(format!("{prefix}private\0"));
        assert_eq!(converted(input).err(), Some(error));
    }
    for name in ["name\n", "name\r", "name\t"] {
        let mut input = complete();
        input["name"] = json!(name);
        assert_eq!(converted(input).err(), Some("legacy_external_name_invalid"));
    }
}

#[test]
fn source_launch_bytes_and_authoritative_name_are_unchanged_and_sqlite_label_is_not_substituted() {
    let row = source(complete());
    let columns = row.columns.clone();
    let output = convert(&row, Platform::Supported).unwrap();
    assert_eq!(output, row.outbound);
    assert!(row.columns == columns);
    assert_eq!(row.name.as_deref(), Some("Stale SQLite label"));
    assert!(!output.to_string().contains("Stale SQLite label"));
    let mut missing = row.outbound.clone();
    missing.as_object_mut().unwrap().remove("name");
    assert_eq!(
        convert(&source(missing), Platform::Supported).unwrap()["name"],
        ""
    );
}

#[test]
fn args_and_config_remain_opaque_even_when_a_later_runtime_check_will_reject_them() {
    for args in [
        "",
        "unterminated '",
        "# %s in shlex comment\n--argument",
        "  --config '%s' --literal '' --percent '%% %d'  ",
        "--two %s %s\n\t",
        "no-placeholder",
    ] {
        let mut input = complete();
        input["extra_core_args"] = json!(args);
        let output = converted(input.clone()).unwrap();
        assert_eq!(output, input);
    }
    for config in [
        "",
        "{ not JSON\r\n",
        "\tinclude: ./external-secret\r\n\n",
        "[Peer]\nopaque=🦊\n",
    ] {
        let mut input = complete();
        input["extra_core_conf"] = json!(config);
        assert_eq!(converted(input.clone()).unwrap(), input);
    }
}

#[test]
fn real_qt_archive_rows_preserve_exact_source_and_settings_parts_do_not_change_launch_data() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/legacy_backup/external_core/fixtures/archives");
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/archives/manifest.json")).unwrap();
    assert_eq!(manifest["archives"].as_object().unwrap().len(), 13);
    let mut standalone = Vec::new();
    for (name, entry) in manifest["archives"].as_object().unwrap() {
        let bytes = std::fs::read(directory.join(name)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            entry["sha256"].as_str().unwrap()
        );
        let archive = crate::legacy_backup::parse(&bytes).unwrap();
        assert_eq!(
            archive.parts.profiles,
            (entry["partsMask"].as_u64().unwrap() & 1) != 0
        );
        let Some(database) = archive.database else {
            assert_eq!(name, "standalone-parts-00.thrbackup");
            continue;
        };
        let rows: Vec<_> = database
            .profiles
            .iter()
            .filter(|p| p.kind == "extracore")
            .collect();
        assert_eq!(rows.len(), 2);
        let mut normalized = Vec::new();
        for row in rows {
            let result = convert(row, Platform::Supported);
            if name.starts_with("missing-port") && row.outbound.get("socks_port").is_none() {
                assert_eq!(result.err(), Some("legacy_external_port_invalid"));
            } else if name.starts_with("relative-path")
                && row.outbound["extra_core_path"] == "./original-install/helper"
            {
                assert_eq!(result.err(), Some("legacy_external_path_invalid"));
            } else {
                normalized.push(result.unwrap());
            }
        }
        if name.starts_with("standalone-") {
            standalone.push(normalized);
        }
    }
    assert_eq!(standalone.len(), 3);
    assert!(standalone.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn converted_dto_builds_only_an_in_memory_typed_external_request_without_losing_fields() {
    let config = converted(complete()).unwrap();
    let profile = crate::store::Profile {
        vpn_policy: None,
        id: "fixture".into(),
        name: "Fixture".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: crate::store::ProfileKind::ExternalCore,
        config: config.clone(),
    };
    let request = crate::config::build(&profile, 2080, None).unwrap();
    assert_eq!(request.need_extra_process, Some(true));
    assert_eq!(
        request.extra_process_path.as_deref(),
        config["extra_core_path"].as_str()
    );
    assert_eq!(
        request.extra_process_args.as_deref(),
        config["extra_core_args"].as_str()
    );
    assert_eq!(
        request.extra_process_conf.as_deref(),
        config["extra_core_conf"].as_str()
    );
    assert_eq!(request.extra_no_out, Some(false));
    assert_eq!(
        request.extra_process_options.as_ref().unwrap().version,
        Some(1)
    );
    let adapter: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    // Qt's own adapter carries whatever the external core carries.
    assert!(adapter["outbounds"][0]["network"].is_null());
    assert!(!adapter.to_string().contains("synthetic-private"));
}
