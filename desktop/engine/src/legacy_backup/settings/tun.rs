//! TUN preferences. Qt's "do not request privileges" is the inverse of the new
//! permission request switch; addresses use the same validators as the TUN form.
//! Qt's "set system DNS" (Windows, with administrator rights) becomes the
//! Windows system DNS of TUN, which the service applies.
use super::{alias, catalog, no_derived, no_report, no_validate, Converter};
use serde_json::{json, Value};

const FIELDS: &[&str] = &[
    "vpn_implementation",
    "vpn_mtu",
    "vpn_ipv6",
    "vpn_strict_route",
    "vpn_auto_redirect",
    "vpn_tun_ipv4_cidr",
    "vpn_tun_ipv6_cidr",
    "vpn_private_ranges",
    "disable_private_range_bypass",
    "enable_tun_routing",
    "tun_request_permission",
    "tun_system_dns",
];
const INVALID: &str = "legacy_settings_value_invalid";

fn source_key(field: &str) -> &str {
    if field == "tun_request_permission" {
        "disable_privilege_req"
    } else if field == "tun_system_dns" {
        "system_dns_set"
    } else {
        alias(field)
    }
}
fn value(field: &str, text: &str) -> Result<Value, &'static str> {
    match field {
        "tun_request_permission" => {
            let disabled = super::boolean(text)? == true;
            catalog::checked(catalog::field(field)?, json!(!disabled))
        }
        "tun_system_dns" => {
            let set = super::boolean(text)? == true;
            catalog::checked(
                catalog::field(field)?,
                json!(if set { "interface" } else { "disabled" }),
            )
        }
        "vpn_tun_ipv4_cidr" | "vpn_tun_ipv6_cidr" => {
            let value = catalog::by_kind(field, text)?;
            if !crate::tun::valid_interface_cidr(text, field == "vpn_tun_ipv6_cidr") {
                return Err(INVALID);
            }
            Ok(value)
        }
        "vpn_private_ranges" => {
            let value = catalog::by_kind(field, text)?;
            let ranges = value.as_array().ok_or(INVALID)?;
            if ranges.len() > 64
                || ranges
                    .iter()
                    .any(|range| !range.as_str().is_some_and(crate::tun::valid_cidr))
            {
                return Err(INVALID);
            }
            Ok(value)
        }
        _ => catalog::by_kind(field, text),
    }
}
fn notice(field: &str, _: &str, converted: &Value) -> Option<&'static str> {
    match field {
        "tun_request_permission" if converted == false => Some("legacy_tun_permission_disabled"),
        _ => None,
    }
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key,
    value,
    notice,
    derived: no_derived,
    validate: no_validate,
    report: no_report,
};
