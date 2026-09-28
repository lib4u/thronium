//! Runtime categories through the public Engine: real Qt archives, value-free
//! review, preference pointers, reopen and exact undo.
use super::*;

fn manifest() -> Value {
    serde_json::from_str(include_str!(
        "../../../legacy_backup/settings/runtime-fixtures/manifest.json"
    ))
    .unwrap()
}
fn archive(mode: &str) -> crate::legacy_backup::SourceArchive {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "src/legacy_backup/settings/runtime-fixtures/{mode}.thrbackup"
    ));
    crate::legacy_backup::parse(&std::fs::read(path).unwrap()).unwrap()
}
fn runtime(selected: bool) -> SettingsScopes {
    SettingsScopes {
        inbound: selected,
        system: selected,
        presets: selected,
        intercept: selected,
        tun: selected,
        core: selected,
        ..Default::default()
    }
}

#[test]
fn runtime_settings_import_reaches_settings_and_preferences_then_reopens_and_undoes() {
    let manifest = manifest();
    let marker = manifest["marker"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("absent-core");
    let mut engine = Engine::open(dir.path(), &core).unwrap();
    let before = json!(engine.store.library);
    let preview = engine
        .preview_legacy_import(super::super::prepare(&archive("valid")))
        .unwrap();
    let selected = engine
        .legacy_backup_scopes(
            &preview.token,
            super::super::Scopes {
                profiles: false,
                settings: runtime(true),
                ..Default::default()
            },
        )
        .unwrap();
    let public = json!(selected);
    assert_eq!(public["legacy"]["canApply"], true);
    assert_eq!(public["legacy"]["settingsCount"], 60);
    assert!(!public.to_string().contains(marker));
    for (group, fields) in manifest["groups"].as_object().unwrap() {
        assert_eq!(
            public["legacy"]["settingsGroups"][group]["count"],
            fields.as_array().unwrap().len()
        );
    }
    engine.restore_backup(&selected.token).unwrap();
    let after = json!(engine.store.library);
    for (group, values) in manifest["expected"]["valid"].as_object().unwrap() {
        for (field, expected) in values.as_object().unwrap() {
            assert_eq!(
                crate::settings::value(&engine.store.library, field),
                *expected,
                "{group}/{field}"
            );
        }
    }
    let tun = &engine.store.library.preferences.tun;
    assert_eq!(tun.mtu, 1400);
    assert!(tun.ipv6 && tun.strict_route && !tun.request_permission);
    assert_eq!(
        tun.exclude_addresses,
        ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
    );
    assert_eq!(after["preferences"]["inboundPort"], 2085);
    assert_eq!(
        after["preferences"]["language"],
        before["preferences"]["language"]
    );
    drop(engine);
    let mut reopened = Engine::open(dir.path(), &core).unwrap();
    assert_eq!(json!(reopened.store.library), after);
    let undo = reopened.preview_previous_backup().unwrap();
    reopened.restore_backup(&undo.token).unwrap();
    assert_eq!(json!(reopened.store.library), before);
}

#[test]
fn qt_defaults_and_sparse_archives_convert_sign_encoded_values_without_copying_others() {
    let manifest = manifest();
    for mode in ["defaults", "sparse"] {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        let before = engine.store.library.clone();
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive(mode)))
            .unwrap();
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: runtime(true),
                    ..Default::default()
                },
            )
            .unwrap();
        let public = json!(selected);
        assert_eq!(public["legacy"]["canApply"], true, "{mode}");
        let expected = &manifest["expected"][mode];
        let count: usize = expected
            .as_object()
            .unwrap()
            .values()
            .map(|group| {
                group
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| !k.ends_with("_enabled"))
                    .count()
            })
            .sum();
        assert_eq!(public["legacy"]["settingsCount"], count, "{mode}");
        let codes: std::collections::BTreeSet<_> = public["legacy"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["code"].as_str().unwrap().to_owned())
            .collect();
        for (_, notices) in manifest["notices"][mode].as_object().into_iter().flatten() {
            for notice in notices.as_array().unwrap() {
                assert!(codes.contains(notice.as_str().unwrap()), "{mode} {notice}");
            }
        }
        engine.restore_backup(&selected.token).unwrap();
        for (group, values) in expected.as_object().unwrap() {
            for (field, value) in values.as_object().unwrap() {
                assert_eq!(
                    crate::settings::value(&engine.store.library, field),
                    *value,
                    "{mode} {group}/{field}"
                );
            }
        }
        if mode == "sparse" {
            let mut untouched = engine.store.library.clone();
            untouched.preferences.tun.mtu = before.preferences.tun.mtu;
            assert_eq!(json!(untouched), json!(before));
        }
    }
}

#[test]
fn blocked_runtime_archives_disable_only_their_category_and_keep_the_library() {
    let manifest = manifest();
    for (mode, blocked) in manifest["blocked"].as_object().unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        let before = json!(engine.store.library);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive(mode)))
            .unwrap();
        let all = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: runtime(true),
                    ..Default::default()
                },
            )
            .unwrap();
        let public = json!(all);
        assert_eq!(public["legacy"]["canApply"], false, "{mode}");
        for (group, code) in blocked.as_object().unwrap() {
            assert!(
                public["legacy"]["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["code"] == *code),
                "{mode} {group} {code}"
            );
            assert_eq!(public["legacy"]["settingsGroups"][group]["count"], 0);
        }
        assert!(!public
            .to_string()
            .contains(manifest["marker"].as_str().unwrap()));
        assert!(engine.restore_backup(&all.token).is_err());
        let mut scopes = runtime(true);
        for group in blocked.as_object().unwrap().keys() {
            match group.as_str() {
                "core" => scopes.core = false,
                "tun" => scopes.tun = false,
                "inbound" => scopes.inbound = false,
                other => panic!("{other}"),
            }
        }
        let rest = engine
            .legacy_backup_scopes(
                &all.token,
                super::super::Scopes {
                    profiles: false,
                    settings: scopes,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(json!(rest)["legacy"]["canApply"], true, "{mode}");
        assert_eq!(json!(engine.store.library), before);
    }
}
