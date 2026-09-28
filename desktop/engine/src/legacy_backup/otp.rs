//! Pure OTP section conversion. The archive flag is authoritative; no Store,
//! Engine, clock, filesystem, network, or VPN credential binding is consulted.
use super::{profiles::Issue, SourceArchive, SourceOtp, SourceValue};
use crate::otp::{Algorithm, Draft, Entry, Kind, MAX_COLLECTION_BYTES, MAX_ENTRIES};
use std::collections::{BTreeMap, BTreeSet};

/// Private data containing credentials. Only the bounded report may be exposed.
#[derive(Clone)]
pub struct OtpPlan {
    pub entries: Vec<Entry>,
    pub otp_ids: BTreeMap<i64, String>,
    pub report: Vec<Issue>,
}
fn issue(code: &str, row: Option<&SourceOtp>) -> Issue {
    Issue {
        code: code.into(),
        entity: Some("otp".into()),
        source_id: row.map(|r| r.id),
        name: row.and_then(|row| match row.columns.get("name") {
            Some(SourceValue::Text(name)) => {
                Some(name.chars().filter(|c| !c.is_control()).take(256).collect())
            }
            _ => None,
        }),
    }
}
fn integer(row: &SourceOtp, key: &str) -> Result<i64, &'static str> {
    match row.columns.get(key) {
        Some(SourceValue::Integer(value)) => Ok(*value),
        _ => Err("legacy_otp_structure"),
    }
}
fn text<'a>(row: &'a SourceOtp, key: &str) -> Result<&'a str, &'static str> {
    match row.columns.get(key) {
        Some(SourceValue::Text(value)) => Ok(value),
        _ => Err("legacy_otp_structure"),
    }
}
fn convert_row(row: &SourceOtp) -> Result<(Entry, i64, bool), &'static str> {
    if row.columns.keys().any(|key| {
        ![
            "id",
            "name",
            "issuer",
            "secret",
            "algorithm",
            "type",
            "digits",
            "period",
            "counter",
            "sort_order",
            "created_at",
            "updated_at",
        ]
        .contains(&key.as_str())
    }) {
        return Err("legacy_otp_field_unsupported");
    }
    if row.columns.contains_key("id") && integer(row, "id")? != row.id {
        return Err("legacy_otp_id_invalid");
    }
    let algorithm = match integer(row, "algorithm")? {
        0 => Algorithm::SHA1,
        1 => Algorithm::SHA256,
        2 => Algorithm::SHA512,
        _ => return Err("legacy_otp_algorithm_invalid"),
    };
    let kind = match integer(row, "type")? {
        0 => Kind::Totp,
        1 => Kind::Hotp,
        _ => return Err("legacy_otp_type_invalid"),
    };
    let digits = integer(row, "digits")?;
    if !(4..=10).contains(&digits) {
        return Err("legacy_otp_digits_invalid");
    }
    let period = integer(row, "period")?;
    if !(1..=3600).contains(&period) {
        return Err("legacy_otp_period_invalid");
    }
    let counter = integer(row, "counter")?;
    if counter < 0 {
        return Err("legacy_otp_counter_invalid");
    }
    let missing_order = !row.columns.contains_key("sort_order");
    // The one documented old-schema migration in OtpProfilesRepo adds exactly
    // this column with DEFAULT 0. No other absent value is invented.
    let order = if missing_order {
        0
    } else {
        integer(row, "sort_order")?
    };
    for key in ["created_at", "updated_at"] {
        if row.columns.contains_key(key) && integer(row, key)? < 0 {
            return Err("legacy_otp_structure");
        }
    }
    let value = Draft {
        name: text(row, "name")?.into(),
        issuer: text(row, "issuer")?.into(),
        secret: text(row, "secret")?.into(),
        algorithm,
        kind,
        digits: digits as u8,
        period: period as u16,
        counter: counter.to_string(),
    }
    .normalized()
    .map_err(|code| match code {
        "otp_label_invalid" => "legacy_otp_label_invalid",
        "otp_secret_too_large" => "legacy_otp_limit",
        "otp_secret_empty" | "otp_secret_invalid" => "legacy_otp_secret_invalid",
        _ => "legacy_otp_structure",
    })?;
    Ok((
        Entry {
            id: uuid::Uuid::new_v4().to_string(),
            revision: uuid::Uuid::new_v4().to_string(),
            value,
        },
        order,
        missing_order,
    ))
}

pub fn convert(source: &SourceArchive) -> Result<OtpPlan, Vec<Issue>> {
    let fail = |code| vec![issue(code, None)];
    if !source.parts.otp {
        return Err(fail("legacy_otp_parts_required"));
    }
    let db = source
        .database
        .as_ref()
        .ok_or_else(|| fail("legacy_database_missing"))?;
    if db.otp.is_empty() {
        return Err(fail("legacy_otp_empty"));
    }
    if db.otp.len() > MAX_ENTRIES {
        return Err(fail("legacy_otp_limit"));
    }
    let mut ids = BTreeSet::new();
    let mut errors = Vec::new();
    let mut converted = Vec::new();
    let mut total = 0usize;
    for row in &db.otp {
        if row.id < 0 || !ids.insert(row.id) {
            errors.push(issue("legacy_otp_id_invalid", Some(row)));
            continue;
        }
        match convert_row(row) {
            Ok((entry, order, missing_order)) => {
                total = total.saturating_add(
                    serde_json::to_vec(&entry)
                        .map_err(|_| fail("legacy_otp_limit"))?
                        .len(),
                );
                // Include separators/brackets in the same 8 MiB bound used by
                // the destination OTP collection. Text exports have a separate
                // 1 MiB limit; a SQLite archive is not a text import.
                if total.saturating_add(converted.len() + 3) > MAX_COLLECTION_BYTES {
                    return Err(fail("legacy_otp_limit"));
                }
                converted.push((order, row.id, entry, missing_order));
            }
            Err(code) => errors.push(issue(code, Some(row))),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    converted.sort_by_key(|(order, id, _, _)| (*order, *id));
    let mut plan = OtpPlan {
        entries: Vec::new(),
        otp_ids: BTreeMap::new(),
        report: Vec::new(),
    };
    for (_, id, entry, missing_order) in converted {
        plan.otp_ids.insert(id, entry.id.clone());
        plan.entries.push(entry);
        if missing_order {
            plan.report.push(issue(
                "legacy_otp_order_default",
                db.otp.iter().find(|row| row.id == id),
            ));
        }
    }
    // Historical row times have no field in the manager. OTP profile references
    // in OpenVPN/OpenConnect remain separate work; never claim they were mapped.
    if db
        .otp
        .iter()
        .any(|row| row.columns.contains_key("created_at") || row.columns.contains_key("updated_at"))
    {
        plan.report
            .push(issue("legacy_otp_timestamps_deferred", None));
    }
    plan.report
        .push(issue("legacy_otp_bindings_deferred", None));
    Ok(plan)
}

#[cfg(test)]
mod tests;
