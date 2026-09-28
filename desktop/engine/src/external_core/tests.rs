use super::*;
fn value() -> Value {
    json!({"type":"extracore","name":"Synthetic external 日本","socks_address":"127.0.0.1","socks_port":1080,
        "extra_core_path":"/tmp/no-such-synthetic-core/with spaces","extra_core_args":"  --config '%s'\n--literal '$HOME; `echo nope`'  ",
        "extra_core_conf":"# opaque config\r\n秘密 = synthetic-private-secret\n  ","no_logs":true})
}
#[test]
fn exact_qt_fields_and_opaque_strings_round_trip_without_touching_files() {
    let original = value();
    let draft = parse(&original).unwrap();
    assert_eq!(serde_json::to_value(&draft).unwrap(), original);
    assert_eq!(
        draft.extra_core_args,
        original["extra_core_args"].as_str().unwrap()
    );
    assert_eq!(
        draft.extra_core_conf,
        original["extra_core_conf"].as_str().unwrap()
    );
    let cloned = draft.clone();
    assert!(cloned == draft);
    assert!(parse(&original).is_ok()); // The executable deliberately does not exist.
    let mut absent = original.clone();
    absent.as_object_mut().unwrap().remove("name");
    assert_eq!(
        serde_json::to_value(parse(&absent).unwrap()).unwrap(),
        absent
    );
    let mut empty = original.clone();
    empty["name"] = json!("");
    empty["extra_core_args"] = json!("");
    empty["extra_core_conf"] = json!("");
    assert_eq!(serde_json::to_value(parse(&empty).unwrap()).unwrap(), empty);
}
#[test]
fn strict_unknown_missing_null_types_and_duplicate_json_fields_are_rejected() {
    let base = value();
    for key in [
        "type",
        "socks_address",
        "socks_port",
        "extra_core_path",
        "extra_core_args",
        "extra_core_conf",
        "no_logs",
    ] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(parse(&missing).is_err(), "missing {key}");
    }
    for key in base.as_object().unwrap().keys() {
        let mut null = base.clone();
        null[key] = Value::Null;
        assert!(parse(&null).is_err(), "null {key}");
        let mut array = base.clone();
        array[key] = json!([]);
        assert!(parse(&array).is_err(), "array {key}");
    }
    let mut unknown = base.clone();
    unknown["future_private_key"] = json!("synthetic-private-secret");
    assert_eq!(
        parse(&unknown).err(),
        Some("external_profile_invalid".into())
    );
    for key in base.as_object().unwrap().keys() {
        let mut serialized = base.to_string();
        serialized.pop();
        serialized.push_str(&format!(",{}:{}}}", json!(key), base[key]));
        assert!(
            serde_json::from_str::<Draft>(&serialized).is_err(),
            "duplicate {key}"
        );
    }
    assert!(serde_json::from_value::<Draft>(json!({"type":"extracore","name":null,"socks_address":"127.0.0.1","socks_port":1080,"extra_core_path":"/a","extra_core_args":"","extra_core_conf":"","no_logs":false})).is_err());
}
#[test]
fn endpoint_is_exact_ipv4_loopback_tcp_and_port_is_integer_1024_through_65535() {
    for port in [1024, 65535] {
        let mut v = value();
        v["socks_port"] = json!(port);
        assert!(parse(&v).is_ok());
    }
    for port in [
        json!(0),
        json!(1023),
        json!(65536),
        json!(-1),
        json!(1080.0),
        json!("1080"),
    ] {
        let mut v = value();
        v["socks_port"] = port;
        assert_eq!(parse(&v).err(), Some("external_port_invalid".into()));
    }
    for address in [
        "localhost",
        "::1",
        "127.0.0.2",
        "127.1",
        "0.0.0.0",
        "192.0.2.1",
        " 127.0.0.1",
    ] {
        let mut v = value();
        v["socks_address"] = json!(address);
        assert_eq!(parse(&v).err(), Some("external_address_unsupported".into()));
    }
    let draft = parse(&value()).unwrap();
    let adapter = draft.socks_outbound("proxy").unwrap();
    assert_eq!(
        adapter,
        json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"version":"5"})
    );
    assert!(!adapter.to_string().contains("synthetic-private"));
    for tag in ["", "bad\n", "bad\0"] {
        assert!(draft.socks_outbound(tag).is_err());
    }
}
#[test]
fn byte_limits_are_inclusive_and_controls_do_not_escape_static_errors() {
    for (key, max, error) in [
        ("extra_core_path", MAX_PATH_BYTES, "external_path_invalid"),
        ("extra_core_args", MAX_ARGS_BYTES, "external_args_invalid"),
        (
            "extra_core_conf",
            MAX_CONFIG_BYTES,
            "external_config_invalid",
        ),
        ("name", MAX_NAME_BYTES, "external_name_invalid"),
    ] {
        let mut v = value();
        let prefix = if key == "extra_core_path" { "/" } else { "" };
        v[key] = json!(format!("{prefix}{}", "x".repeat(max - prefix.len())));
        assert!(parse(&v).is_ok(), "atmax {key}");
        v[key] = json!(format!("{prefix}{}", "x".repeat(max + 1 - prefix.len())));
        assert_eq!(parse(&v).err().as_deref(), Some(error));
        v[key] = json!(format!("{prefix}{}", "🦊".repeat(max / 4 + 1)));
        assert_eq!(parse(&v).err().as_deref(), Some(error));
        v[key] = json!(format!("{prefix}synthetic-private\0"));
        assert_eq!(parse(&v).err().as_deref(), Some(error));
    }
    for path in [
        "",
        "relative/core",
        "/tmp/bad\npath",
        "/tmp/bad\tpath",
        // Relative to the current drive, the drive's directory, or nothing.
        "C:core.exe",
        "C:",
        "\\core.exe",
        "1:\\core.exe",
        // Device namespaces and a share without a name.
        "\\\\?\\C:\\core.exe",
        "\\\\.\\pipe\\core",
        "\\\\server",
        "\\\\server\\",
        "\\\\\\share\\core.exe",
    ] {
        let mut v = value();
        v["extra_core_path"] = json!(path);
        assert_eq!(
            parse(&v).err().as_deref(),
            Some("external_path_invalid"),
            "{path}"
        );
    }
    // A Windows library (or Qt backup) keeps its paths on any system; only the
    // core decides at launch whether the form belongs to its host.
    for path in [
        "C:\\Program Files\\Core\\core.exe",
        "c:/tools/core.exe",
        "\\\\server\\share\\core.exe",
        "//server/share/core",
    ] {
        let mut v = value();
        v["extra_core_path"] = json!(path);
        assert_eq!(parse(&v).unwrap().extra_core_path, path);
    }
    let mut v = value();
    v["name"] = json!("bad\nname");
    assert_eq!(parse(&v).err().as_deref(), Some("external_name_invalid"));
    let mut draft = parse(&value()).unwrap();
    draft.socks_port = 1;
    assert_eq!(
        draft.socks_outbound("proxy").err().as_deref(),
        Some("external_port_invalid")
    );
}
