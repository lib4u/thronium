//! Qt global shortcuts (`hk_*`, QKeySequence portable text) become the host's
//! shortcut strings: the same modifiers, `Meta` as `Super`, and only key names
//! the host parser accepts. Qt refused to register any shortcut while two were
//! equal; the same rule blocks the category here.
use super::{alias, no_derived, no_report, Converter};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const FIELDS: &[&str] = &[
    "hotkey_mainwindow",
    "hotkey_group",
    "hotkey_route",
    "hotkey_system_proxy_menu",
    "hotkey_toggle_system_proxy",
];
const MODIFIERS: &[(&str, &str)] = &[
    ("ctrl", "Ctrl"),
    ("control", "Ctrl"),
    ("shift", "Shift"),
    ("alt", "Alt"),
    ("meta", "Super"),
    ("super", "Super"),
];
/// Qt portable key names that the host parser spells differently.
const KEYS: &[(&str, &str)] = &[
    ("return", "Enter"),
    ("enter", "Enter"),
    ("esc", "Escape"),
    ("escape", "Escape"),
    ("del", "Delete"),
    ("delete", "Delete"),
    ("ins", "Insert"),
    ("insert", "Insert"),
    ("pgup", "PageUp"),
    ("pgdown", "PageDown"),
    ("space", "Space"),
    ("tab", "Tab"),
    ("backspace", "Backspace"),
    ("home", "Home"),
    ("end", "End"),
    ("left", "ArrowLeft"),
    ("right", "ArrowRight"),
    ("up", "ArrowUp"),
    ("down", "ArrowDown"),
];

fn key(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    if let Some((_, name)) = KEYS.iter().find(|(qt, _)| *qt == lower) {
        return Some((*name).into());
    }
    let bytes = token.as_bytes();
    if bytes.len() == 1 && bytes[0].is_ascii_alphanumeric() {
        return Some(token.to_ascii_uppercase());
    }
    if let Some(number) = lower.strip_prefix('f') {
        if number.parse::<u8>().is_ok_and(|n| (1..=24).contains(&n)) {
            return Some(format!("F{number}"));
        }
    }
    None
}
/// One QKeySequence in portable text; an empty text is an unset shortcut.
fn value(_: &str, text: &str) -> Result<Value, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(json!(""));
    }
    let mut parts = Vec::new();
    let mut main = None;
    for token in text.split('+') {
        let token = token.trim();
        if token.is_empty() || main.is_some() {
            return Err("legacy_settings_value_invalid");
        }
        if let Some((_, name)) = MODIFIERS
            .iter()
            .find(|(qt, _)| *qt == token.to_ascii_lowercase())
        {
            if parts.contains(name) {
                return Err("legacy_settings_value_invalid");
            }
            parts.push(*name);
        } else {
            main = Some(key(token).ok_or("legacy_settings_value_invalid")?);
        }
    }
    let main = main.ok_or("legacy_settings_value_invalid")?;
    Ok(json!(parts
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(main))
        .collect::<Vec<_>>()
        .join("+")))
}
fn notice(_: &str, _: &str, converted: &Value) -> Option<&'static str> {
    converted
        .as_str()
        .is_some_and(|s| !s.is_empty())
        .then_some("legacy_hotkeys_registered")
}
fn validate(values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    let mut seen = std::collections::HashSet::new();
    for value in values.values().filter_map(Value::as_str) {
        if !value.is_empty() && !seen.insert(value) {
            return Err("legacy_hotkeys_duplicate");
        }
    }
    Ok(())
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value,
    notice,
    derived: no_derived,
    validate,
    report: no_report,
};
