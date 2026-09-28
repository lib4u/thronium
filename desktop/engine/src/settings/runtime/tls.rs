//! Resolve client-only TLS controls on the ordinary outbound compilation copy.
//! Stored profiles and full client configurations never pass through this helper.
use crate::{settings, store::Library};
use serde_json::{json, Value};

pub(super) fn prepare(outbound: &mut Value, library: &Library) {
    let Some(tls) = outbound.get_mut("tls").and_then(Value::as_object_mut) else {
        return;
    };
    let enabled = tls.get("enabled") == Some(&Value::Bool(true));

    // Older Thronium URI imports wrote this one known field as a boolean.
    // Normalize only the compilation copy; retain objects and malformed values.
    if let Some(value) = tls.get("tls_tricks").and_then(Value::as_bool) {
        tls.insert("tls_tricks".into(), json!({"mixedcase_sni": value}));
    }
    if enabled && settings::boolean(library, "tls_tricks_default_on") {
        let tricks = tls.entry("tls_tricks").or_insert_with(|| json!({}));
        if let Some(tricks) = tricks.as_object_mut() {
            tricks.entry("mixedcase_sni").or_insert(json!(true));
        }
    }

    // Do not turn malformed client controls or payloads into a successful
    // configuration by deleting them. The core remains their validator.
    if tls.get("spoof_enabled").is_some_and(|v| !v.is_boolean())
        || ["spoof", "spoof_method"]
            .iter()
            .any(|key| tls.get(*key).is_some_and(|v| !v.is_string()))
    {
        return;
    }
    // Earlier legacy imports froze Off as an explicit empty core SNI, without
    // the Qt-only control. Preserve that already-stored JSON contract. An
    // explicit On still inherits defaults, and a missing SNI means Default.
    if !tls.contains_key("spoof_enabled") && tls.get("spoof").and_then(Value::as_str) == Some("") {
        return;
    }
    let source_sni = tls.get("spoof").and_then(Value::as_str).unwrap_or("");
    let source_method = tls
        .get("spoof_method")
        .and_then(Value::as_str)
        .unwrap_or("");
    let on = enabled
        && tls
            .get("spoof_enabled")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                !source_sni.is_empty() || settings::boolean(library, "tls_spoof_default_on")
            });
    let sni = if source_sni.is_empty() {
        settings::string(library, "tls_spoof").trim().to_owned()
    } else {
        source_sni.to_owned()
    };
    let method = if source_method.is_empty() {
        settings::string(library, "tls_spoof_method")
            .trim()
            .to_owned()
    } else {
        source_method.to_owned()
    };
    tls.remove("spoof_enabled");
    tls.remove("spoof");
    tls.remove("spoof_method");
    if on && !sni.is_empty() {
        tls.insert("spoof".into(), json!(sni));
        if !method.is_empty() {
            tls.insert("spoof_method".into(), json!(method));
        }
    }
}

#[cfg(test)]
mod tests;
