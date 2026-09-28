use super::*;
use crate::store::{Profile, ProfileKind};

fn profile(tls: Value) -> Profile {
    Profile {
        vpn_policy: None,
        id: "tls-fixture".into(),
        name: "TLS fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        config: json!({"type":"http","server":"127.0.0.1","server_port":443,"tls":tls}),
    }
}

#[test]
fn spoof_tri_state_matches_original_qt_function_output() {
    let oracle: Value = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    let mut count = 0;
    let mut compatibility = 0;
    for case in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["group"] == "spoof")
    {
        let mut library = Library::default();
        library
            .settings
            .extend(case["settings"].as_object().unwrap().clone());
        let mut p = profile(case["tls"].clone());
        prepare(&mut p.config, &library);
        let tls = &p.config["tls"];
        let old_explicit_off = case["tls"].get("spoof_enabled").is_none()
            && case["tls"].get("spoof").and_then(Value::as_str) == Some("");
        for key in ["spoof", "spoof_method"] {
            assert_eq!(
                tls.get(key),
                if old_explicit_off {
                    case["tls"].get(key)
                } else {
                    case["built"].get(key)
                },
                "{}: {key}",
                case["id"]
            );
        }
        assert!(tls.get("spoof_enabled").is_none(), "{}", case["id"]);
        if old_explicit_off {
            compatibility += 1;
        } else {
            count += 1;
        }
    }
    assert_eq!(count, 52);
    assert_eq!(compatibility, 6);
}

#[test]
fn existing_saved_legacy_off_sentinel_survives_new_defaults_without_reimport() {
    use crate::Engine;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("library.json");
    let mut library = Library::default();
    // This is the exact pre-24 shape produced by the legacy converter. Open
    // the existing library directly: a fix only to new imports cannot pass.
    let original = profile(
        json!({"enabled":true,"server_name":"actual.fixture.invalid","spoof":"","spoof_method":"","fragment":false,"tls_tricks":{"mixedcase_sni":false},"insecure":false}),
    );
    library.profiles.push(original.clone());
    library.settings.extend([
        ("tls_spoof_default_on".into(), json!(true)),
        ("tls_spoof".into(), json!("destination.fixture.invalid")),
        ("tls_spoof_method".into(), json!("wrong-ack")),
        ("tls_tricks_default_on".into(), json!(true)),
    ]);
    let bytes = serde_json::to_vec_pretty(&library).unwrap();
    std::fs::write(&file, &bytes).unwrap();
    let engine = Engine::open(directory.path(), &directory.path().join("absent-core")).unwrap();
    let request = engine.build(&engine.store.library.profiles[0]).unwrap();
    let core: Value = serde_json::from_str(&request.core_config.unwrap()).unwrap();
    let compiled = core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "proxy")
        .unwrap();
    assert_eq!(compiled["tls"], original.config["tls"]);
    assert_eq!(engine.store.library.profiles[0].config, original.config);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    drop(engine);
    let engine = Engine::open(directory.path(), &directory.path().join("absent-core")).unwrap();
    assert_eq!(engine.store.library.profiles[0].config, original.config);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);

    // Explicit user On is still a transition to the configured preset; merely
    // opening a persisted Off profile is not that transition.
    let mut on = original.clone();
    on.config["tls"]["spoof_enabled"] = json!(true);
    prepare(&mut on.config, &library);
    assert_eq!(on.config["tls"]["spoof"], "destination.fixture.invalid");
    assert_eq!(on.config["tls"]["spoof_method"], "wrong-ack");
    let mut inherited = original.clone();
    inherited.config["tls"]
        .as_object_mut()
        .unwrap()
        .remove("spoof");
    prepare(&mut inherited.config, &library);
    assert_eq!(
        inherited.config["tls"]["spoof"],
        "destination.fixture.invalid"
    );
}

#[test]
fn mixedcase_states_and_legacy_boolean_follow_effective_qt_state() {
    let oracle: Value = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    for case in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["group"] == "tricks")
    {
        let mut library = Library::default();
        library
            .settings
            .extend(case["settings"].as_object().unwrap().clone());
        for legacy in [false, true] {
            let mut p = profile(case["tls"].clone());
            if legacy {
                if let Some(value) = p.config["tls"]["tls_tricks"]["mixedcase_sni"].as_bool() {
                    p.config["tls"]["tls_tricks"] = json!(value);
                }
            }
            prepare(&mut p.config, &library);
            assert_eq!(
                p.config["tls"]["tls_tricks"]["mixedcase_sni"] == true,
                case["tricksOn"],
                "{} / legacy={legacy}",
                case["id"]
            );
            assert!(!p.config["tls"]["tls_tricks"].is_boolean());
        }
    }
}

#[test]
fn opaque_and_malformed_values_are_not_silently_dropped() {
    let mut library = Library::default();
    library.settings.extend([
        ("tls_spoof_default_on".into(), json!(true)),
        ("tls_spoof".into(), json!("default.fixture.invalid")),
        ("tls_tricks_default_on".into(), json!(true)),
    ]);
    for (key, value) in [
        ("spoof_enabled", json!(null)),
        ("spoof_enabled", json!(1)),
        ("spoof_enabled", json!("false")),
        ("spoof", json!(42)),
        ("spoof_method", json!([])),
        ("tls_tricks", json!("bad")),
        ("tls_tricks", json!(42)),
        ("tls_tricks", json!(null)),
        ("tls_tricks", json!({"mixedcase_sni":null,"unknown":7})),
    ] {
        let mut p = profile(
            json!({"enabled":true,"spoof_enabled":false,"spoof":"own.fixture.invalid","spoof_method":"wrong-ack","future_tls_option":{"opaque":true}}),
        );
        p.config["tls"][key] = value.clone();
        prepare(&mut p.config, &library);
        assert_eq!(p.config["tls"][key], value, "{key}");
        assert_eq!(p.config["tls"]["future_tls_option"], json!({"opaque":true}));
    }
    for original in [json!({}), json!({"future_trick":[1,2]})] {
        let mut p = profile(json!({"enabled":true,"tls_tricks":original}));
        prepare(&mut p.config, &library);
        assert_eq!(p.config["tls"]["tls_tricks"]["mixedcase_sni"], true);
        for (key, value) in original.as_object().unwrap() {
            assert_eq!(&p.config["tls"]["tls_tricks"][key], value);
        }
    }
}

#[test]
fn compiler_only_changes_ordinary_outbound_copies() {
    let mut library = Library::default();
    library.settings.extend([
        ("tls_spoof_default_on".into(), json!(true)),
        ("tls_spoof".into(), json!("default.fixture.invalid")),
        ("tls_tricks_default_on".into(), json!(true)),
    ]);
    let original = profile(
        json!({"enabled":true,"spoof_enabled":false,"spoof":"own.fixture.invalid","tls_tricks":false}),
    );
    library.profiles.push(original.clone());
    let saved = serde_json::to_value(&library).unwrap();
    let mut compiled = library.clone();
    let mut selected = original.clone();
    settings::prepare_profiles(&mut compiled, &mut selected);
    assert_eq!(serde_json::to_value(&library).unwrap(), saved);
    assert_eq!(
        selected.config["tls"]["tls_tricks"],
        json!({"mixedcase_sni":false})
    );
    assert!(selected.config["tls"].get("spoof").is_none());
    assert_eq!(selected.config, compiled.profiles[0].config);
    for kind in [
        ProfileKind::SingBoxConfig,
        ProfileKind::XrayConfig,
        ProfileKind::XrayOutbound,
    ] {
        let mut full = Profile {
            kind,
            config: json!({"tls":{"enabled":true,"spoof_enabled":true,"tls_tricks":true},"dns":{"servers":["192.0.2.1"]},"outbounds":[original.config.clone()]}),
            ..original.clone()
        };
        let before = full.config.clone();
        settings::prepare_profiles(&mut library.clone(), &mut full);
        assert_eq!(full.config, before, "{kind:?}");
    }
}

#[test]
fn disabled_tls_and_unrelated_full_json_do_not_receive_presets() {
    let mut library = Library::default();
    library.settings.extend([
        ("tls_spoof_default_on".into(), json!(true)),
        ("tls_spoof".into(), json!("default.fixture.invalid")),
        ("tls_tricks_default_on".into(), json!(true)),
    ]);
    for tls in [
        json!({"enabled":false}),
        json!({}),
        json!(null),
        json!("invalid"),
    ] {
        let mut p = profile(tls.clone());
        prepare(&mut p.config, &library);
        assert_eq!(p.config["tls"], tls);
    }
    let mut p = profile(
        json!({"enabled":false,"spoof_enabled":true,"spoof":"own.fixture.invalid","spoof_method":"wrong-ack","tls_tricks":false}),
    );
    prepare(&mut p.config, &library);
    assert_eq!(
        p.config["tls"],
        json!({"enabled":false,"tls_tricks":{"mixedcase_sni":false}})
    );
}

#[tokio::test]
#[ignore = "requires THRONIUM_TEST_CORE; real Check only, no Start or TLS spoof packets"]
async fn real_core_checks_tls_controls_preserve_sources_and_reject_malformed_values() {
    use crate::Engine;
    const NAME: &str = "settings::runtime::tls::tests::real_core_checks_tls_controls_preserve_sources_and_reject_malformed_values";
    if std::env::var_os("THRONIUM_TLS_CHECK_CHILD").is_none() {
        let core = std::path::PathBuf::from(
            std::env::var_os("THRONIUM_TEST_CORE").expect("provide preserved core"),
        );
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("Thronium");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::copy(core, directory.path().join("ThroniumCore")).unwrap();
        let output = std::process::Command::new(executable)
            .args(["--ignored", "--exact", NAME, "--nocapture"])
            .env("THRONIUM_TLS_CHECK_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let core = std::env::current_exe()
        .unwrap()
        .with_file_name("ThroniumCore");
    let mut engine = Engine::open(directory.path(), &core).unwrap();
    let oracle: Value = serde_json::from_str(include_str!("fixtures/golden.json")).unwrap();
    let before_fixtures: Value =
        serde_json::from_str(include_str!("fixtures/before-cycle24.json")).unwrap();
    let mut accepted = 0;
    let mut rejected = 0;
    for fixture in before_fixtures.as_array().unwrap() {
        let p = Profile {
            config: fixture["config"].clone(),
            ..profile(json!({}))
        };
        let before = p.config.clone();
        engine
            .check(&p)
            .await
            .unwrap_or_else(|e| panic!("before fixture {}: {e}", fixture["name"]));
        assert_eq!(p.config, before);
        accepted += 1;
    }
    // Every representable spoof/standard tricks state is checked by the pinned
    // core, independently of the Qt differential tests. No Start is requested.
    for case in oracle["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["group"] == "spoof" || c["group"] == "tricks")
    {
        engine.store.library.settings.clear();
        engine
            .store
            .library
            .settings
            .extend(case["settings"].as_object().unwrap().clone());
        let mut p = profile(case["tls"].clone());
        // Spoof is an additional ClientHello: its real TLS stream also needs
        // an SNI. The oracle intentionally models only the controls themselves.
        p.config["tls"]["server_name"] = json!("actual.fixture.invalid");
        let source = p.config.clone();
        let before = serde_json::to_value(&engine.store.library).unwrap();
        let explicit_empty_with_method = case["tls"].get("spoof_enabled").is_none()
            && case["tls"].get("spoof").and_then(Value::as_str) == Some("")
            && case["tls"]
                .get("spoof_method")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
        if explicit_empty_with_method {
            // Preserve old core JSON, including its invalid method-without-SNI
            // combination; do not coerce it to the different Qt interpretation.
            let error = engine.check(&p).await.unwrap_err();
            assert!(
                error.contains("spoof_method requires spoof"),
                "{}: {error}",
                case["id"]
            );
            rejected += 1;
        } else {
            engine
                .check(&p)
                .await
                .unwrap_or_else(|e| panic!("oracle {}: {e}", case["id"]));
            accepted += 1;
        }
        assert_eq!(serde_json::to_value(&engine.store.library).unwrap(), before);
        assert_eq!(p.config, source);
    }
    engine.store.library.settings.clear();
    for curves in [
        json!(["X25519", "P256"]),
        json!(["P384", "P521"]),
        json!(["X25519MLKEM768"]),
    ] {
        engine
            .check(&profile(json!({"enabled":true,"curve_preferences":curves})))
            .await
            .unwrap();
        accepted += 1;
    }
    for tls in [
        json!({"spoof_enabled":null}),
        json!({"spoof_enabled":1}),
        json!({"spoof_enabled":"false"}),
        json!({"spoof_enabled":false,"spoof":42}),
        json!({"spoof_enabled":false,"spoof_method":[]}),
        json!({"tls_tricks":42}),
        json!({"tls_tricks":"true"}),
        json!({"tls_tricks":{"mixedcase_sni":"true"}}),
        json!({"tls_tricks":{"mixedcase_sni":false,"unknown":1}}),
        json!({"curve_preferences":["secp256r1"]}),
    ] {
        let mut p = profile(tls.clone());
        p.config["tls"]["enabled"] = json!(true);
        let before = p.config.clone();
        assert!(
            engine.check(&p).await.is_err(),
            "unexpected accepted malformed TLS {tls}"
        );
        assert_eq!(p.config, before);
        rejected += 1;
    }
    // A full sing-box client object bypasses normalization, including legacy
    // booleans and client-only controls; the core rejects them unchanged.
    let full = json!({"log":{"disabled":true},"inbounds":[{"type":"mixed","tag":"owned-test","listen":"127.0.0.1","listen_port":23456}],"outbounds":[{"type":"http","tag":"proxy","server":"127.0.0.1","server_port":443,"tls":{"enabled":true,"tls_tricks":true,"spoof_enabled":false}}]});
    let p = Profile {
        kind: ProfileKind::SingBoxConfig,
        config: full.clone(),
        ..profile(json!({}))
    };
    assert_eq!(
        serde_json::from_str::<Value>(&engine.build(&p).unwrap().core_config.unwrap()).unwrap(),
        full
    );
    assert!(engine.check(&p).await.is_err());
    assert_eq!(p.config, full);
    rejected += 1;
    engine.store.library.settings.extend([
        ("tls_spoof_default_on".into(), json!(true)),
        ("tls_spoof".into(), json!("default.fixture.invalid")),
        ("tls_tricks_default_on".into(), json!(true)),
        ("skip_cert".into(), json!(true)),
        ("utlsFingerprint".into(), json!("firefox")),
    ]);
    let mut full_valid = full.clone();
    full_valid["outbounds"][0]["tls"] = json!({"enabled":true,"server_name":"actual.fixture.invalid","tls_tricks":{"mixedcase_sni":false},"insecure":false});
    let p = Profile {
        kind: ProfileKind::SingBoxConfig,
        config: full_valid.clone(),
        ..profile(json!({}))
    };
    assert_eq!(
        serde_json::from_str::<Value>(&engine.build(&p).unwrap().core_config.unwrap()).unwrap(),
        full_valid
    );
    engine.check(&p).await.unwrap();
    assert_eq!(p.config, full_valid);
    accepted += 1;

    let full_xray = json!({"inbounds":[],"dns":{"servers":["localhost"]},"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"d6695721-8b2c-4e8c-aefb-7f3e88d5ba2e","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"actual.fixture.invalid","allowInsecure":false,"fingerprint":"chrome"}}}]});
    let p = Profile {
        kind: ProfileKind::XrayConfig,
        config: full_xray.clone(),
        ..profile(json!({}))
    };
    let compiled: Value =
        serde_json::from_str(&engine.build(&p).unwrap().xray_config.unwrap()).unwrap();
    // Existing full-Xray compilation appends its DNS bridge; the original
    // outbound and its TLS options must remain byte-for-byte JSON-equivalent.
    assert_eq!(compiled["outbounds"][0], full_xray["outbounds"][0]);
    assert_eq!(compiled["outbounds"].as_array().unwrap().len(), 2);
    assert_eq!(compiled["outbounds"][1]["tag"], "thronium-dns");
    assert_eq!(compiled["dns"], full_xray["dns"]);
    engine.check(&p).await.unwrap();
    assert_eq!(p.config, full_xray);
    accepted += 1;
    assert!(engine.running.is_none());
    assert!(engine.active_connection.is_none());
    engine.shutdown().await;
    println!("TLS_CHECK_SUMMARY accepted={accepted} rejected={rejected} actualStarts=0 sourceMutations=0");
}
