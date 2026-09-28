use super::*;

fn archive(mode: &str) -> crate::legacy_backup::SourceArchive {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "src/legacy_backup/settings/basic-fixtures/{mode}.thrbackup"
    ));
    crate::legacy_backup::parse(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn functional_settings_import_reopens_and_exactly_undoes_without_enabling_file_logging() {
    for (testing, logging) in [(true, false), (false, true), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("absent-core");
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        let mut library = engine.store.library.clone();
        library
            .settings
            .insert("font".into(), json!("Current font"));
        library.settings.insert("font_size".into(), json!(16));
        engine.store.commit(library).unwrap();
        let before = json!(engine.store.library);
        let preview = engine
            .preview_legacy_import(super::super::prepare(&archive("valid")))
            .unwrap();
        let selected = engine
            .legacy_backup_scopes(
                &preview.token,
                super::super::Scopes {
                    profiles: false,
                    settings: SettingsScopes {
                        testing,
                        logging,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        let public = json!(selected);
        assert_eq!(public["legacy"]["canApply"], true);
        assert_eq!(
            public["legacy"]["settingsCount"],
            (if testing { 1 } else { 0 }) + (if logging { 17 } else { 0 })
        );
        assert!(!public.to_string().contains("private-marker82"));
        engine.restore_backup(&selected.token).unwrap();
        let after = json!(engine.store.library);
        assert_eq!(after["preferences"], before["preferences"]);
        assert_eq!(after["settings"]["font"], "Current font");
        assert_eq!(after["settings"]["font_size"], 16);
        assert!(!crate::settings::boolean(
            &engine.store.library,
            "log_file_enabled"
        ));
        assert_eq!(
            crate::settings::string(&engine.store.library, "log_level"),
            if logging { "debug" } else { "warn" }
        );
        if logging {
            engine.logs.configure(&engine.store.library, dir.path());
            engine.logs.push("app", Some("info"), "PASS", false);
            engine.logs.push("app", Some("info"), "PASS REJECT", false);
            let lines = engine.logs.view(crate::logs::Filter::default()).unwrap();
            assert_eq!(lines.matching, 1);
            assert_eq!(lines.entries[0].text, "PASS");
            assert!(!dir.path().join("diagnostic.log").exists());
        }
        drop(engine);
        let mut reopened = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(json!(reopened.store.library), after);
        let undo = reopened.preview_previous_backup().unwrap();
        reopened.restore_backup(&undo.token).unwrap();
        assert_eq!(json!(reopened.store.library), before);
    }
}
