//! Global shortcuts: Qt portable QKeySequence text to the host's shortcut strings.
use super::{
    tests::{codes, row, source},
    *,
};

fn manifest() -> Value {
    serde_json::from_str(include_str!("hotkeys-fixtures/manifest.json")).unwrap()
}
fn one(key: &str, text: &str) -> Result<SettingsPlan, Vec<Issue>> {
    convert(&source(vec![row(key, text)]), &Group::Hotkeys)
}

#[test]
fn qt_portable_shortcuts_become_host_shortcuts_with_super_and_named_keys() {
    for (qt, host) in [
        ("Ctrl+Shift+M", "Ctrl+Shift+M"),
        ("ctrl+shift+m", "Ctrl+Shift+M"),
        ("Meta+G", "Super+G"),
        ("Alt+F12", "Alt+F12"),
        ("Ctrl+Alt+PgUp", "Ctrl+Alt+PageUp"),
        ("Shift+Return", "Shift+Enter"),
        ("Ctrl+Esc", "Ctrl+Escape"),
        ("Ctrl+Left", "Ctrl+ArrowLeft"),
        ("Ctrl+7", "Ctrl+7"),
        ("F5", "F5"),
        ("", ""),
        ("  ", ""),
    ] {
        let plan = one("hk_mw", qt).unwrap_or_else(|_| panic!("{qt}"));
        assert_eq!(plan.values["hotkey_mainwindow"], host, "{qt}");
        assert_eq!(
            plan.report
                .iter()
                .map(|i| i.code.as_str())
                .collect::<Vec<_>>(),
            if host.is_empty() {
                vec![]
            } else {
                vec!["legacy_hotkeys_registered"]
            },
            "{qt}"
        );
    }
}

#[test]
fn unsupported_or_malformed_shortcuts_block_the_category_without_exposing_text() {
    for text in [
        "Ctrl+Launch (0)",
        "Ctrl+",
        "+M",
        "Ctrl+Shift",
        "Ctrl+M+N",
        "Ctrl+Ctrl+M",
        "Hyper+M",
        "F25",
        "MM",
        "Ctrl+private-marker82d",
    ] {
        let errors = codes(one("hk_route", text));
        assert_eq!(errors, ["legacy_settings_value_invalid"], "{text}");
        let plan = one("hk_route", text).err().unwrap();
        assert_eq!(plan[0].name.as_deref(), Some("hotkey_route"));
        assert!(!json!(plan).to_string().contains("private-marker82d"));
    }
}

#[test]
fn duplicate_shortcuts_block_the_category_as_qt_refused_to_register_them() {
    let s = source(vec![
        row("hk_mw", "Ctrl+Shift+M"),
        row("hk_route", "ctrl+shift+m"),
        row("hk_toggle", ""),
    ]);
    assert_eq!(
        codes(convert(&s, &Group::Hotkeys)),
        ["legacy_hotkeys_duplicate"]
    );
    let s = source(vec![row("hk_mw", ""), row("hk_route", "")]);
    let plan = convert(&s, &Group::Hotkeys).unwrap();
    assert_eq!(plan.values.len(), 2);
    assert!(plan.report.is_empty());
}

#[test]
fn hotkey_real_qt_archives_match_the_manifest() {
    let manifest = manifest();
    for (mode, _) in manifest["modes"].as_object().unwrap() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "src/legacy_backup/settings/hotkeys-fixtures/{mode}.thrbackup"
            )),
        )
        .unwrap();
        let archive = crate::legacy_backup::parse(&bytes).unwrap();
        let result = convert(&archive, &Group::Hotkeys);
        if let Some(code) = manifest["blocked"][mode].as_str() {
            assert_eq!(codes(result), [code], "{mode}");
            continue;
        }
        let plan = result.unwrap_or_else(|_| panic!("{mode}"));
        let expected = manifest["expected"][mode].as_object().unwrap();
        assert_eq!(plan.values.len(), expected.len(), "{mode}");
        for (field, value) in expected {
            assert_eq!(plan.values[field], *value, "{mode}/{field}");
        }
        let notices: Vec<_> = plan.report.iter().map(|i| i.code.clone()).collect();
        let expected: Vec<String> = manifest["notices"][mode]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            notices.first().cloned().into_iter().collect::<Vec<_>>(),
            expected,
            "{mode}"
        );
        assert!(!json!(plan.report).to_string().contains("Ctrl+"));
    }
}
