//! Conversions driven by the destination catalog: the field id names the kind,
//! range and options, so a category lists ids instead of repeating those rules.
use serde_json::{json, Value};

const INVALID: &str = "legacy_settings_value_invalid";

pub(super) fn field(id: &str) -> Result<&'static crate::settings::Field, &'static str> {
    crate::settings::fields()
        .iter()
        .find(|f| f.id == id)
        .ok_or(INVALID)
}
/// Qt SQLite TEXT to the typed value of the catalog field with the same id,
/// followed by the validation the settings form applies. Text is never trimmed,
/// rewritten or logged.
pub(super) fn by_kind(id: &str, text: &str) -> Result<Value, &'static str> {
    let definition = field(id)?;
    let value = match definition.kind.as_str() {
        "bool" => super::boolean(text)?,
        "number" => json!(super::integer(text)?),
        // Qt serializes QStringList as a JSON array inside the TEXT value.
        "list" => {
            if text.len() > 1000 * 8192 {
                return Err("legacy_settings_limit");
            }
            serde_json::from_str(text).map_err(|_| INVALID)?
        }
        "url" => super::url(text)?,
        "optional-url" if text.is_empty() => json!(""),
        "optional-url" => super::url(text)?,
        _ => json!(text),
    };
    checked(definition, value)
}
pub(super) fn checked(
    definition: &crate::settings::Field,
    value: Value,
) -> Result<Value, &'static str> {
    crate::settings::validate_field(definition, &value).map_err(|_| INVALID)?;
    Ok(value)
}
