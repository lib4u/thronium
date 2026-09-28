//! Preserve Core DNS record syntax; don't invent a second zone-file parser.
//! The import validates field types/bounds. Core CheckConfig parses RR text or
//! wire-format base64 before a connection can replace the running session.
use super::super::{validate::list, Result};
use serde_json::Value;

pub(crate) fn field(key: &str, value: &Value) -> Result<()> {
    if key == "rcode" {
        if value.as_u64().is_some_and(|n| n <= 4095)
            || matches!(
                value.as_str(),
                Some(
                    "NOERROR"
                        | "FORMERR"
                        | "SERVFAIL"
                        | "NXDOMAIN"
                        | "NOTIMP"
                        | "REFUSED"
                        | "YXDOMAIN"
                        | "YXRRSET"
                        | "NXRRSET"
                        | "NOTAUTH"
                        | "NOTZONE"
                        | "BADSIG"
                        | "BADVERS"
                        | "BADKEY"
                        | "BADTIME"
                        | "BADMODE"
                        | "BADNAME"
                        | "BADALG"
                        | "BADTRUNC"
                        | "BADCOOKIE"
                )
            )
        {
            return Ok(());
        }
        return Err("legacy_dns_invalid");
    }
    // An explicit empty answer is useful for NODATA and must survive unchanged.
    if value.as_array().is_some_and(Vec::is_empty) {
        return Ok(());
    }
    for record in list(value)? {
        let record = record.as_str().ok_or("legacy_dns_invalid")?;
        if record.trim().is_empty()
            || record.len() > 65536
            || record
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
        {
            return Err("legacy_dns_invalid");
        }
    }
    Ok(())
}
