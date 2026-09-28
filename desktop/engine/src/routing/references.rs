//! Profile references inside routes and DNS: finding them and rewriting them to generated tags.
use super::*;

/// Keys whose string value may name a profile; `preferred_by` lists endpoint tags.
pub(crate) const REFERENCE_KEYS: [&str; 6] = [
    "outbound",
    "final",
    "detour",
    "download_detour",
    "endpoint",
    "preferred_by",
];
pub(crate) fn reference_values<'a>(key: &str, value: &'a mut Value) -> Vec<&'a mut Value> {
    if !REFERENCE_KEYS.contains(&key) {
        vec![]
    } else if key == "preferred_by" {
        value
            .as_array_mut()
            .map(|items| items.iter_mut().collect())
            .unwrap_or_default()
    } else if value.is_string() {
        vec![value]
    } else {
        vec![]
    }
}
pub(crate) fn references(value: &Value, result: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let listed: Vec<&Value> = match value {
                    Value::Array(items) if key == "preferred_by" => items.iter().collect(),
                    Value::String(_) if REFERENCE_KEYS.contains(&key.as_str()) => vec![value],
                    _ => vec![],
                };
                for value in listed {
                    if let Some(id) = value.as_str().and_then(|s| s.strip_prefix("profile:")) {
                        result.insert(id.into());
                    }
                }
                references(value, result);
            }
        }
        Value::Array(list) => {
            for value in list {
                references(value, result);
            }
        }
        _ => {}
    }
}
pub(crate) fn profile_references(routing: &Routing) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    references(&json!(routing), &mut ids);
    ids
}
/// `inner` holds the nodes a route names inside a chain it already compiles:
/// such a node is that chain's own hop, never a second connection of its own.
pub(crate) fn rewrite(value: &mut Value, selected: &str, inner: &BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                for value in reference_values(key, value) {
                    if let Some(id) = value.as_str().and_then(|s| s.strip_prefix("profile:")) {
                        *value = json!(if let Some(tag) = inner.get(id) {
                            tag.clone()
                        } else if id == selected {
                            "proxy".into()
                        } else {
                            format!("thronium-route-{id}")
                        });
                    }
                }
                rewrite(value, selected, inner);
            }
        }
        Value::Array(list) => {
            for value in list {
                rewrite(value, selected, inner);
            }
        }
        _ => {}
    }
}
pub fn uses_profile(routing: &Routing, id: &str) -> bool {
    routing.profiles.iter().any(|p| {
        let mut found = BTreeSet::new();
        references(&p.route, &mut found);
        references(&p.dns, &mut found);
        for rule in &p.rules {
            references(&rule.config, &mut found);
        }
        found.contains(id)
    })
}
