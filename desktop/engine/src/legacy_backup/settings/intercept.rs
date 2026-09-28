//! DNS hijack and redirect listeners of the intercept section.
use super::{alias, catalog, no_derived, no_report, no_validate, Converter};
use serde_json::Value;

const FIELDS: &[&str] = &[
    "dns_server_listen_lan",
    "dns_server_listen_port",
    "dns_v4_resp",
    "dns_v6_resp",
    "dns_server_rules",
    "redirect_listen_address",
    "redirect_listen_port",
];
fn notice(field: &str, _: &str, converted: &Value) -> Option<&'static str> {
    match field {
        "dns_server_listen_lan" if converted == true => Some("legacy_intercept_lan_listen"),
        _ => None,
    }
}
pub(super) const CONVERTER: Converter = Converter {
    fields: FIELDS,
    source_key: alias,
    value: catalog::by_kind,
    notice,
    derived: no_derived,
    validate: no_validate,
    report: no_report,
};
