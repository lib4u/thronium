//! Qt structured rule rows (types 0-12): stored match/action columns become
//! one sing-box rule; the type names the UI group and the empty-placeholder
//! rule only (RouteRule.cpp get_rule_json).
use super::{validate, Context, MATCH};
use crate::legacy_backup::{
    routes::{boolean, integer, parse, row_keys, text, validate::string, Result},
    SourceRule,
};
use serde_json::{json, Value};

pub(in crate::legacy_backup::routes) fn structured(
    row: &SourceRule,
    context: Context<'_>,
) -> Result<Option<Value>> {
    row_keys(
        &row.columns,
        &[
            "route_profile_id",
            "rule_order",
            "name",
            "type",
            "ip_version",
            "network",
            "protocol",
            "inbound_json",
            "domain_json",
            "domain_suffix_json",
            "domain_keyword_json",
            "domain_regex_json",
            "source_ip_cidr_json",
            "source_ip_is_private",
            "ip_cidr_json",
            "ip_is_private",
            "source_port_json",
            "source_port_range_json",
            "port_json",
            "port_range_json",
            "process_name_json",
            "process_path_json",
            "process_path_regex_json",
            "rule_set_json",
            "invert",
            "outbound_id",
            "action",
            "reject_method",
            "no_drop",
            "override_address",
            "override_port",
            "sniffers_json",
            "sniff_override_dest",
            "strategy",
            "wifi_ssid_json",
            "wifi_bssid_json",
            "tls_spoof",
            "tls_spoof_method",
        ],
    )?;
    if !(0..=12).contains(&row.kind) {
        return Err("legacy_route_type_unsupported");
    }
    let mut result = json!({});
    let mut empty_simple = true;
    for key in MATCH {
        if matches!(*key, "source_ip_is_private" | "ip_is_private" | "invert") {
            if boolean(&row.columns, key)? {
                result[*key] = json!(true)
            };
            continue;
        }
        if matches!(*key, "network" | "protocol" | "ip_version") {
            let value = text(&row.columns, key)?.trim();
            if value.is_empty() {
                continue;
            }
            result[*key] = if *key == "ip_version" {
                json!(value.parse::<u8>().map_err(|_| "legacy_route_structure")?)
            } else {
                json!(value)
            };
            continue;
        }
        let raw = text(&row.columns, &format!("{key}_json"))?;
        if raw.is_empty() {
            continue;
        }
        let array = parse(raw)?;
        let array = array.as_array().ok_or("legacy_route_structure")?;
        let relevant = match row.kind {
            1..=3 | 10 => matches!(
                *key,
                "domain"
                    | "domain_suffix"
                    | "domain_keyword"
                    | "domain_regex"
                    | "ip_cidr"
                    | "rule_set"
            ),
            4..=9 | 11..=12 => matches!(*key, "process_name" | "process_path"),
            _ => false,
        };
        if !array.is_empty() && relevant {
            empty_simple = false
        }
        let mut converted = vec![];
        for item in array {
            let s = string(item)?.trim();
            if s.is_empty() {
                return Err("legacy_route_structure");
            };
            converted.push(if matches!(*key, "port" | "source_port") {
                json!(s.parse::<u16>().map_err(|_| "legacy_route_structure")?)
            } else {
                json!(s)
            });
        }
        if !converted.is_empty() {
            result[*key] = json!(converted)
        }
    }
    let original_action = text(&row.columns, "action")?;
    let original_action = if !row.columns.contains_key("action") {
        "route"
    } else {
        original_action
    };
    let outbound = integer(&row.columns, "outbound_id", -2)?;
    let action = if original_action == "route" {
        match outbound {
            -3 => "reject",
            -4 => "hijack-dns",
            _ => "route",
        }
    } else {
        original_action
    };
    result["action"] = json!(action);
    // As Qt's RouteRule::get_rule_json, only the chosen action's columns are
    // written: values left over from an earlier action are ignored, and
    // sniffers are never emitted.
    let filled = |key: &str| -> Result<Option<&str>> {
        Ok(Some(text(&row.columns, key)?.trim()).filter(|s| !s.is_empty()))
    };
    match action {
        "reject" => {
            if filled("reject_method")?.is_some() {
                return Err("legacy_route_action_unsupported");
            }
            if boolean(&row.columns, "no_drop")? {
                result["no_drop"] = json!(true);
            }
        }
        "route" | "route-options" | "bypass" => {
            if filled("tls_spoof")?.is_some() {
                return Err("legacy_route_action_unsupported");
            }
            if let Some(address) = filled("override_address")? {
                result["override_address"] = json!(address);
            }
            if let Some(port) = filled("override_port")?
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|port| *port > 0)
            {
                result["override_port"] = json!(port);
            }
            if action != "route-options" {
                result["outbound"] = json!(outbound);
            }
        }
        "sniff" => {
            if boolean(&row.columns, "sniff_override_dest")? {
                result["override_destination"] = json!(true);
            }
        }
        "resolve" => {
            if let Some(strategy) = filled("strategy")? {
                result["strategy"] = json!(strategy);
            }
        }
        _ => {}
    }
    // Empty simple placeholders are omitted by Qt before serialization; still
    // validate fields/actions, so unknown data cannot disappear behind emptiness.
    validate(&mut result, context, false, 0)?;
    if row.kind != 0 && empty_simple {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}
