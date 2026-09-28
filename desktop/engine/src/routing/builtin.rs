//! Rules every structured route starts with. Qt's `generate.cpp`
//! (buildRouteSection) sniffs first, so connections that arrive as addresses
//! (TUN, SOCKS clients resolving locally) get their domain and protocol and
//! domain, rule-set and protocol rules can match them. Presets converted from
//! Throne carry the sniff as their own rule, and full configurations own their
//! routing.
//!
//! Qt also answers every DNS connection with the core's DNS. Its default DNS
//! goes to a remote resolver through the proxy; the default here resolves
//! locally, so that capture would move a proxied client's DNS off the proxy and
//! stays out until the DNS defaults change.
use serde_json::{json, Value};

pub(crate) fn sniff() -> Value {
    json!({"action":"sniff"})
}

/// The core skips a second sniff of the same connection, so a user's own
/// unconditional sniff (with its sniffers or destination override) stays the
/// only one.
pub(crate) fn for_rules(rules: &[Value]) -> Vec<Value> {
    if rules.iter().any(unconditional_sniff) {
        vec![]
    } else {
        vec![sniff()]
    }
}

fn unconditional_sniff(rule: &Value) -> bool {
    rule["action"] == "sniff"
        && rule.as_object().is_some_and(|rule| {
            rule.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "action" | "sniffer" | "timeout" | "override_destination"
                )
            })
        })
}

/// Rules that only annotate a connection and never decide where it goes.
pub(crate) fn annotates(rule: &Value) -> bool {
    matches!(rule["action"].as_str(), Some("sniff" | "resolve"))
}

/// Qt places ad blocking in front of the first routing decision: after guards
/// bound to internal inbounds and after the rules that let it match domains.
pub(crate) fn first_decision(rules: &[Value]) -> usize {
    rules
        .iter()
        .position(|rule| {
            rule.get("inbound").is_none() && !annotates(rule) && rule["action"] != "hijack-dns"
        })
        .unwrap_or(rules.len())
}
