//! Inbound tags a Qt rule may name. `mixed-in` is the shared local listener;
//! custom listeners come from the same source `custom_inbound` setting and are
//! recorded on the preset so the runtime can require them. Qt's own injected
//! listeners (tun-in, dns-in, hijack, throne-bridge) have no counterpart here.
use super::{setting, Result, SourceDatabase};
use crate::{
    legacy_backup::settings::inbound::{custom_inbound, RESERVED_TAGS},
    routing::Rule,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) struct Inbounds {
    custom: BTreeSet<String>,
}
impl Inbounds {
    pub(super) fn parse(db: &SourceDatabase) -> Result<Self> {
        let value = custom_inbound(setting(db, "custom_inbound", "{\"inbounds\":[]}")?)
            .map_err(|_| "legacy_route_settings_invalid")?;
        Ok(Self {
            custom: value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|inbound| inbound["tag"].as_str().map(str::to_owned))
                .collect(),
        })
    }
    pub(super) fn check(&self, tag: &str) -> Result<()> {
        if tag == "mixed-in" || self.custom.contains(tag) {
            Ok(())
        } else if RESERVED_TAGS.contains(&tag) {
            Err("legacy_route_inbound_unsupported")
        } else {
            Err("legacy_route_inbound_unknown")
        }
    }
    /// Custom tags the converted preset depends on, in stable order.
    pub(super) fn used(&self, rules: &[Rule], dns: &Value) -> Vec<String> {
        let mut found = BTreeSet::new();
        for rule in rules {
            collect(&rule.config, &self.custom, &mut found, 0);
        }
        if let Some(rules) = dns.get("rules") {
            collect(rules, &self.custom, &mut found, 0);
        }
        found.into_iter().collect()
    }
}
fn collect(value: &Value, custom: &BTreeSet<String>, found: &mut BTreeSet<String>, depth: usize) {
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "inbound" {
                    let listed: Vec<&Value> = value
                        .as_array()
                        .map_or_else(|| vec![value], |items| items.iter().collect());
                    for tag in listed.into_iter().filter_map(Value::as_str) {
                        if custom.contains(tag) {
                            found.insert(tag.to_owned());
                        }
                    }
                } else {
                    collect(value, custom, found, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect(item, custom, found, depth + 1);
            }
        }
        _ => {}
    }
}
