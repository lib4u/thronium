//! Shared validation/runtime compilation of the log filter expression.
use regex::Regex;
use serde_json::Value;

/// Throne joins rows before compilation, so flags in an earlier row can affect
/// later alternatives. An empty joined expression means no regex condition.
pub(crate) fn expression(values: &Value) -> Result<Option<Regex>, regex::Error> {
    let joined = values
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("|");
    if joined.is_empty() {
        Ok(None)
    } else {
        Regex::new(&joined).map(Some)
    }
}

pub(super) fn patterns(library: &crate::store::Library, kind: &str) -> Option<Vec<Regex>> {
    if !crate::settings::boolean(library, &format!("log_enable_{kind}")) {
        return None;
    }
    let keywords = crate::settings::value(library, &format!("log_{kind}_keyword"));
    let mut patterns: Vec<_> = keywords
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|text| Regex::new(&regex::escape(text)).ok())
        .collect();
    let expressions = crate::settings::value(library, &format!("log_{kind}_regex"));
    if let Ok(Some(expression)) = expression(&expressions) {
        patterns.push(expression);
    }
    // Enabled + no conditions matches nothing; it is distinct from disabled.
    Some(patterns)
}
