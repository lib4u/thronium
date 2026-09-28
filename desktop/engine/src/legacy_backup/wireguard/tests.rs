use super::*;
use crate::legacy_backup::{SourceRow, SourceValue};
#[cfg(target_os = "linux")]
use crate::store::Profile;
use crate::store::ProfileKind;
fn encoded(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}
fn source(config: Value) -> SourceProfile {
    SourceProfile {
        id: 55,
        kind: "wireguard".into(),
        name: Some("Synthetic WG".into()),
        group_id: 0,
        columns: SourceRow::from([(
            "outbound_json".into(),
            SourceValue::Text(config.to_string()),
        )]),
        outbound: config,
    }
}
fn basic() -> Value {
    json!({"type":"wireguard","tag":"Synthetic WG","private_key":encoded(1),"address":["10.44.0.2/32","fd44::2/128"],"peers":[{"address":"127.0.0.1","port":51820,"public_key":encoded(2),"pre_shared_key":encoded(3),"reserved":[1,2,255],"persistent_keepalive_interval":25}]})
}
fn all_awg() -> Value {
    json!({"jc":3,"jmin":40,"jmax":70,"s1":12,"s2":14,"s3":8,"s4":4,"h1":"1-100","h2":"101-200","h3":"201-300","h4":"301-400","i1":"<b 0x0102>","i2":"<r 8>","i3":"<b 0x0304><r 4>","i4":"<t>","i5":"<b 0x0506>","header_protection_key":encoded(4),"content_padding_addition":"2-4","rekey_after_time":"100-110","rekey_timeout":5,"reject_after_time":"180-200","keepalive_timeout":"10-20","max_handshake_attempts":"10-15","random_trailers":true,"disable_cookies":true})
}
#[test]
fn qt_peer_build_defaults_and_worker_alias_are_explicit_without_source_mutation() {
    let mut config = basic();
    config["address"] = json!([" 10.44.0.2 ", " fd44::2 "]);
    config["worker_count"] = json!(2);
    let source = source(config.clone());
    let columns = source.columns.clone();
    let output = convert(&source).unwrap();
    assert_eq!(output["workers"], 2);
    assert!(output.get("worker_count").is_none());
    assert_eq!(output["mtu"], 1420);
    assert_eq!(output["system"], false);
    assert_eq!(output["address"], json!(["10.44.0.2/32", "fd44::2/128"]));
    assert_eq!(
        output["peers"][0]["allowed_ips"],
        json!(["0.0.0.0/0", "::/0"])
    );
    for field in [
        "address",
        "port",
        "public_key",
        "pre_shared_key",
        "reserved",
        "persistent_keepalive_interval",
    ] {
        assert_eq!(output["peers"][0][field], config["peers"][0][field]);
    }
    assert_eq!(source.outbound, config);
    assert!(source.columns == columns);
}
#[test]
fn all_peers_ipv6_and_explicit_prefixes_survive_in_original_order() {
    let mut config = basic();
    config["mtu"] = json!(1280);
    config["workers"] = json!(3);
    config["peers"][0]["allowed_ips"] = json!(["0.0.0.0/1", "::/1"]);
    config["peers"].as_array_mut().unwrap().push(json!({"address":"::1","port":51821,"public_key":encoded(5),"allowed_ips":["128.0.0.0/1","8000::/1"],"reserved":[0,0,1],"persistent_keepalive_interval":"22-30"}));
    let output = convert(&source(config.clone())).unwrap();
    assert_eq!(output["peers"], config["peers"]);
    assert_eq!(output["mtu"], 1280);
    assert_eq!(output["workers"], 3);
}
#[test]
fn amnezia_3_0_and_3_1_fields_and_dial_fields_are_lossless() {
    let mut config = basic();
    config["amnezia_wg"] = all_awg();
    let fields = json!({"reuse_addr":true,"connect_timeout":"1m0.5s","tcp_fast_open":false,"tcp_multi_path":true,"udp_fragment":true,"bind_interface":"fixture0","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1","udp_timeout":"2m30s","mtu":1380});
    config
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    let output = convert(&source(config.clone())).unwrap();
    assert_eq!(output["amnezia_wg"], config["amnezia_wg"]);
    for (field, value) in fields.as_object().unwrap() {
        assert_eq!(&output[field], value);
    }
}
#[test]
fn unknown_fields_files_and_alias_conflicts_are_blocked_while_a_system_interface_imports() {
    // Qt's "Use System Interface" is a plain field of the profile.
    let mut config = basic();
    config["system"] = json!(true);
    assert_eq!(convert(&source(config)).unwrap()["system"], json!(true));
    let mut config = basic();
    config["system"] = json!("yes");
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_structure"
    );
    for (field, value) in [
        ("PostUp", json!("private shell directive")),
        ("listen_port", json!(51820)),
        ("private_key_path", json!("private/key")),
        ("name", json!("wg-system")),
        ("warp_account", json!({"secret":"private"})),
    ] {
        let mut config = basic();
        config[field] = value;
        assert_eq!(
            convert(&source(config)).unwrap_err(),
            "legacy_wireguard_field_unsupported"
        );
    }
    let mut config = basic();
    config["workers"] = json!(2);
    config["worker_count"] = json!(2);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_alias_conflict"
    );
    let mut warp = source(basic());
    warp.kind = "warp".into();
    assert_eq!(
        convert(&warp).unwrap_err(),
        "legacy_wireguard_type_unsupported"
    );
    let mut config = basic();
    config["peers"][0]["post_up"] = json!("private");
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_field_unsupported"
    );
}
#[test]
fn invalid_keys_ranges_prefixes_reserved_and_signature_controls_have_static_errors() {
    {
        let key_field = "private_key";
        let mut config = basic();
        config[key_field] = json!("secret-invalid");
        assert_eq!(
            convert(&source(config)).unwrap_err(),
            "legacy_wireguard_key_invalid"
        );
    }
    for reserved in [
        json!([1, 2]),
        json!([1, 2, 256]),
        json!([-1, 2, 3]),
        json!("AQID"),
    ] {
        let mut config = basic();
        config["peers"][0]["reserved"] = reserved;
        assert_eq!(
            convert(&source(config)).unwrap_err(),
            "legacy_wireguard_reserved_invalid"
        );
    }
    for interval in [
        json!(-1),
        json!("30-22"),
        json!("1-4294967296"),
        json!("25s"),
        json!("3\npublic_key=secret"),
    ] {
        let mut config = basic();
        config["peers"][0]["persistent_keepalive_interval"] = interval;
        assert!(convert(&source(config)).is_err());
    }
    let mut config = basic();
    config["address"] = json!(["10.0.0.1/33"]);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_prefix_invalid"
    );
    let mut config = basic();
    config["amnezia_wg"] = json!({"i1":"<b 0x01>\nprivate_key=secret"});
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_signature_unsupported"
    );
    let mut config = basic();
    config["amnezia_wg"] = json!({"jc":"3"});
    assert!(convert(&source(config)).is_err());
    for field in ["s1", "s2", "s3", "s4"] {
        let mut config = basic();
        config["amnezia_wg"] = json!({field:65536});
        assert_eq!(
            convert(&source(config)).unwrap_err(),
            "legacy_wireguard_value_unsupported"
        );
    }
    let mut config = basic();
    config["peers"][0]["allowed_ips"] = json!([" 10.0.0.0/8 "]);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_prefix_invalid"
    );
    let mut config = basic();
    let duplicate = config["peers"][0].clone();
    config["peers"].as_array_mut().unwrap().push(duplicate);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_duplicate_peer"
    );
}
#[test]
fn peer_count_prefix_count_and_duration_are_bounded_without_truncation() {
    let mut config = basic();
    config["peers"] = json!(vec![config["peers"][0].clone(); MAX_PEERS + 1]);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_peer_limit"
    );
    let mut config = basic();
    config["address"] = json!(vec!["10.0.0.2/32"; MAX_PREFIXES + 1]);
    assert_eq!(
        convert(&source(config)).unwrap_err(),
        "legacy_wireguard_prefix_invalid"
    );
    for value in [
        json!("-1s"),
        json!("5fortnights"),
        json!("18446744073709551615h"),
        json!(5),
    ] {
        let mut config = basic();
        config["udp_timeout"] = value;
        assert_eq!(
            convert(&source(config)).unwrap_err(),
            "legacy_wireguard_duration_invalid"
        );
    }
    for value in ["0", ".5s", "1m0.5s", "2h10m", "20ms"] {
        let mut config = basic();
        config["udp_timeout"] = json!(value);
        assert_eq!(convert(&source(config)).unwrap()["udp_timeout"], value);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an explicitly supplied owned core; Check only, never Start"]
async fn real_core_checks_wg_multiple_peers_and_awg_without_packets_or_host_changes() {
    let core = std::env::var_os("THRONIUM_TEST_CORE").expect("THRONIUM_TEST_CORE required");
    if std::env::var_os("THRONIUM_LEGACY_WG_FIXTURE").is_none() {
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
        let output=std::process::Command::new(executable).args(["--exact","legacy_backup::wireguard::tests::real_core_checks_wg_multiple_peers_and_awg_without_packets_or_host_changes","--ignored","--nocapture"]).env("THRONIUM_LEGACY_WG_FIXTURE","1").env("THRONIUM_TEST_CORE",bundled_core).output().unwrap();
        assert!(
            output.status.success(),
            "owned WG fixture failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let network_state = || -> Vec<Vec<u8>> {
        ["/proc/net/route", "/proc/net/ipv6_route"]
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .chain(std::iter::once({
                let mut names: Vec<_> = std::fs::read_dir("/sys/class/net")
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                names.join("\n").into_bytes()
            }))
            .collect()
    };
    let network_before = network_state();
    let mut plain = basic();
    plain["peers"][0]["port"] = json!(udp.local_addr().unwrap().port());
    let mut multiple = plain.clone();
    multiple["peers"].as_array_mut().unwrap().push(json!({"address":"::1","port":udp6.local_addr().unwrap().port(),"public_key":encoded(5),"allowed_ips":["fd00::/8"],"persistent_keepalive_interval":"22-30","reserved":[3,2,1]}));
    let mut awg = multiple.clone();
    awg["amnezia_wg"] = all_awg();
    awg["worker_count"] = json!(2);
    let directory = tempfile::tempdir().unwrap();
    let mut engine = crate::Engine::open(directory.path(), std::path::Path::new(&core)).unwrap();
    for (index, config) in [plain, multiple, awg].into_iter().enumerate() {
        let profile = Profile {
            vpn_policy: None,
            id: format!("wg-check-{index}"),
            name: format!("Synthetic WG check {index}"),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: convert(&source(config)).unwrap(),
            favorite: false,
        };
        let request = crate::config::build(&profile, 2080, None).unwrap();
        let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
        assert_eq!(core["endpoints"][0]["type"], "wireguard");
        assert!(core["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["type"] != "wireguard"));
        if let Err(code) = engine.check(&profile).await {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            let logs = engine.logs.view(Default::default()).unwrap();
            engine.shutdown().await;
            panic!(
                "synthetic WG check {index}: {code}; {}",
                serde_json::to_string(&logs).unwrap()
            );
        }
        assert!(engine.running.is_none());
        assert!(engine.active_connection.is_none());
    }
    engine.shutdown().await;
    let mut packet = [0u8; 2048];
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), udp.recv(&mut packet))
            .await
            .is_err()
    );
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(150),
        udp6.recv(&mut packet)
    )
    .await
    .is_err());
    assert_eq!(network_state(), network_before);
}

#[test]
fn independent_qt_wireguard_archives_preserve_both_peers_and_all_awg_values() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/legacy-wireguard");
    let archive = crate::legacy_backup::read(&directory.join("valid.thrbackup")).unwrap();
    let source = archive.database.unwrap();
    assert_eq!(source.profiles.len(), 2);
    for profile in &source.profiles {
        let config = convert(profile).unwrap();
        assert_eq!(config["peers"].as_array().unwrap().len(), 2);
        for (actual, original) in config["peers"]
            .as_array()
            .unwrap()
            .iter()
            .zip(profile.outbound["peers"].as_array().unwrap())
        {
            for (key, value) in original.as_object().unwrap() {
                assert_eq!(&actual[key], value);
            }
        }
        if profile.outbound.get("amnezia_wg").is_some() {
            assert_eq!(config["amnezia_wg"], profile.outbound["amnezia_wg"]);
        }
    }
    let blocked = crate::legacy_backup::read(&directory.join("blocked.thrbackup")).unwrap();
    let errors: Vec<_> = blocked
        .database
        .unwrap()
        .profiles
        .iter()
        .filter_map(|source| convert(source).err())
        .collect();
    assert_eq!(
        errors,
        vec![
            "legacy_wireguard_field_unsupported",
            "legacy_wireguard_alias_conflict"
        ]
    );
}

#[test]
fn profile_plan_imports_qt_wg_groups_and_blocks_the_whole_batch_for_os_fields() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/legacy-wireguard");
    let archive = crate::legacy_backup::read(&directory.join("valid.thrbackup")).unwrap();
    let database = archive.database.unwrap();
    let originals: Vec<_> = database
        .profiles
        .iter()
        .map(|profile| (profile.outbound.clone(), profile.columns.clone()))
        .collect();
    let plan = crate::legacy_backup::profiles::convert_selected(&database, archive.parts.settings)
        .unwrap_or_else(|issues| panic!("{}", serde_json::to_string(&issues).unwrap()));
    assert_eq!(plan.groups.len(), 1);
    assert_eq!(plan.profiles.len(), 2);
    assert_eq!(plan.profiles[0].id, plan.profile_ids[&502]);
    assert_eq!(plan.profiles[1].id, plan.profile_ids[&501]);
    assert!(plan.vless_overrides.is_empty());
    for ((source, (outbound, columns)), target) in
        database.profiles.iter().zip(originals).map(|pair| {
            let target = plan
                .profiles
                .iter()
                .find(|profile| profile.id == plan.profile_ids[&pair.0.id])
                .unwrap();
            (pair, target)
        })
    {
        assert_eq!(target.kind, ProfileKind::SingBoxOutbound);
        assert_eq!(target.config, convert(source).unwrap());
        assert_eq!(source.outbound, outbound);
        assert!(source.columns == columns);
        assert_eq!(target.group_id, plan.groups[0].id);
    }
    let blocked = crate::legacy_backup::read(&directory.join("blocked.thrbackup")).unwrap();
    // Unsupported WireGuard rows are left out and named; supported ones import.
    let partial = crate::legacy_backup::profiles::convert(blocked.database.as_ref().unwrap())
        .unwrap_or_else(|issues| panic!("{}", serde_json::to_string(&issues).unwrap()));
    assert!(partial
        .report
        .iter()
        .any(|i| i.code == "legacy_profile_skipped"));
    let issues = partial.report;
    for code in [
        "legacy_wireguard_field_unsupported",
        "legacy_wireguard_alias_conflict",
    ] {
        assert!(issues.iter().any(|issue| issue.code == code));
    }
    let report = serde_json::to_string(&issues).unwrap();
    assert!(!report.contains("post_up"));
    assert!(!report.contains("private_key"));
}
