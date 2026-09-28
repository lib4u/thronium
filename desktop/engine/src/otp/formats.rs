//! Explicit secret-bearing import/export formats. Errors never contain input.
use super::{counter, decode_secret, Algorithm, Draft, Kind, Result, MAX_ENTRIES, MAX_TEXT};
use serde::Deserialize;
use std::collections::BTreeMap;
/// A bare secret line shorter than this is more likely a typo than a key.
pub const MIN_BARE_SECRET_BYTES: usize = 10;

// Missing optional fields use documented defaults; explicitly null fields are
// malformed. Option<T> alone would silently collapse those different inputs.
struct Optional<T>(Option<T>);
impl<T> Default for Optional<T> {
    fn default() -> Self {
        Self(None)
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Optional<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        T::deserialize(d).map(|v| Self(Some(v)))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ImportCounter {
    Text(String),
    Integer(u64),
}
impl ImportCounter {
    fn decimal(self) -> Result<String> {
        let text = match self {
            Self::Text(s) => s,
            Self::Integer(n) => n.to_string(),
        };
        Ok(counter(&text)?.to_string())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Imported {
    #[serde(default)]
    name: String,
    #[serde(default)]
    issuer: String,
    secret: String,
    #[serde(default)]
    algorithm: Optional<String>,
    #[serde(default, rename = "type")]
    kind: Optional<String>,
    #[serde(default)]
    digits: Optional<u8>,
    #[serde(default)]
    period: Optional<u16>,
    #[serde(default)]
    counter: Optional<ImportCounter>,
}
impl Imported {
    fn draft(self) -> Result<Draft> {
        Draft {
            name: self.name,
            issuer: self.issuer,
            secret: self.secret,
            algorithm: self
                .algorithm
                .0
                .as_deref()
                .map(Algorithm::parse)
                .transpose()?
                .unwrap_or_default(),
            kind: self
                .kind
                .0
                .as_deref()
                .map(Kind::parse)
                .transpose()?
                .unwrap_or_default(),
            digits: self.digits.0.unwrap_or(6),
            period: self.period.0.unwrap_or(30),
            counter: self
                .counter
                .0
                .map(ImportCounter::decimal)
                .transpose()?
                .unwrap_or_else(|| "0".into()),
        }
        .normalized()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    otp: Vec<Imported>,
}

pub fn import(text: &str) -> Result<Vec<Draft>> {
    if text.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    let text = text.trim();
    if text.is_empty() {
        return Err("otp_import_empty");
    }
    let entries = if text.starts_with('{') || text.starts_with('[') {
        let imported = if text.starts_with('{') {
            let envelope: Envelope = serde_json::from_str(text).map_err(|_| "otp_json_invalid")?;
            if envelope.version != 1 {
                return Err("otp_format_unsupported");
            }
            envelope.otp
        } else {
            serde_json::from_str::<Vec<Imported>>(text).map_err(|_| "otp_json_invalid")?
        };
        if imported.len() > MAX_ENTRIES {
            return Err("otp_entry_limit");
        }
        imported
            .into_iter()
            .map(Imported::draft)
            .collect::<Result<Vec<_>>>()?
    } else {
        let lines: Vec<_> = text
            .split(['\r', '\n'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let is_migration = |line: &&str| {
            line.get(..20)
                .is_some_and(|v| v.eq_ignore_ascii_case("otpauth-migration://"))
        };
        if lines.iter().any(is_migration) {
            if !lines.iter().all(is_migration) {
                return Err("otp_migration_mixed_input");
            }
            return super::migration::import_migration(&lines);
        }
        let mut result = Vec::new();
        for line in text
            .split(['\r', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if result.len() >= MAX_ENTRIES {
                return Err("otp_entry_limit");
            }
            if line
                .get(..10)
                .is_some_and(|s| s.eq_ignore_ascii_case("otpauth://"))
            {
                result.push(import_uri(line)?);
            } else {
                let groups: Vec<_> = line
                    .split(|c: char| c.is_whitespace() || c == '-')
                    .filter(|s| !s.is_empty())
                    .collect();
                if groups.is_empty()
                    || groups.len() > 1
                        && (groups[0].len() > 8
                            || groups.iter().any(|s| s.len() != groups[0].len()))
                {
                    return Err("otp_import_invalid");
                }
                if decode_secret(line)?.len() < MIN_BARE_SECRET_BYTES {
                    return Err("otp_bare_secret_short");
                }
                result.push(
                    Draft {
                        secret: line.into(),
                        ..Draft::default()
                    }
                    .normalized()?,
                );
            }
        }
        result
    };
    if entries.is_empty() {
        return Err("otp_import_empty");
    }
    Ok(entries)
}

pub(super) fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = |byte: u8| -> Option<u8> {
                match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                }
            };
            if at + 2 >= bytes.len() {
                return Err("otp_uri_invalid");
            }
            output.push(
                hex(bytes[at + 1]).ok_or("otp_uri_invalid")? * 16
                    + hex(bytes[at + 2]).ok_or("otp_uri_invalid")?,
            );
            at += 3;
        } else {
            output.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(output).map_err(|_| "otp_uri_invalid")
}
pub(super) fn encode(value: &str) -> String {
    let mut output = String::new();
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 15) as usize] as char);
        }
    }
    output
}
fn number(value: &str) -> Result<u64> {
    if value.is_empty() || value.len() > 19 || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err("otp_uri_invalid");
    }
    value.parse().map_err(|_| "otp_uri_invalid")
}
pub fn import_uri(input: &str) -> Result<Draft> {
    if input.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    if input.contains('#') || input.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("otp_uri_invalid");
    }
    let (scheme, rest) = input.split_once("://").ok_or("otp_uri_invalid")?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err("otp_uri_invalid");
    }
    let (host, tail) = rest.split_once('/').ok_or("otp_uri_invalid")?;
    let kind = Kind::parse(host)?;
    let (label, query) = tail.split_once('?').ok_or("otp_uri_invalid")?;
    let label = decode(label)?;
    let (prefix, name) = label
        .split_once(':')
        .map_or(("", label.as_str()), |(a, b)| (a, b));
    let mut parameters = BTreeMap::new();
    for part in query.split('&') {
        let (key, value) = part.split_once('=').ok_or("otp_uri_invalid")?;
        let key = decode(key)?;
        let value = decode(value)?;
        if !matches!(
            key.as_str(),
            "secret" | "issuer" | "algorithm" | "digits" | "period" | "counter"
        ) {
            return Err("otp_uri_field_unsupported");
        }
        if parameters.insert(key, value).is_some() {
            return Err("otp_uri_duplicate");
        }
    }
    let issuer = parameters
        .get("issuer")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(prefix.trim());
    if !prefix.trim().is_empty() && !issuer.is_empty() && prefix.trim() != issuer {
        return Err("otp_issuer_conflict");
    }
    let mut draft = Draft {
        name: name.trim().into(),
        issuer: issuer.into(),
        secret: parameters.get("secret").ok_or("otp_secret_empty")?.clone(),
        kind,
        ..Draft::default()
    };
    if draft.name.is_empty() {
        draft.name = draft.issuer.clone();
    }
    if let Some(value) = parameters.get("algorithm") {
        draft.algorithm = Algorithm::parse(value)?;
    }
    if let Some(value) = parameters.get("digits") {
        draft.digits = number(value)?
            .try_into()
            .map_err(|_| "otp_digits_invalid")?;
    }
    if let Some(value) = parameters.get("period") {
        draft.period = number(value)?
            .try_into()
            .map_err(|_| "otp_period_invalid")?;
    }
    if let Some(value) = parameters.get("counter") {
        draft.counter = counter(value)?.to_string();
    } else if draft.kind == Kind::Hotp {
        return Err("otp_counter_invalid");
    }
    draft.normalized()
}

pub fn export_uri(draft: &Draft) -> Result<String> {
    let draft = draft.normalized()?;
    // Qt/otpauth labels use the first colon to split issuer and account and
    // trim both. Refuse labels that cannot roundtrip; JSON preserves them.
    if draft.name.trim() != draft.name
        || draft.issuer.trim() != draft.issuer
        || draft.issuer.contains(':')
        || draft.issuer.is_empty() && draft.name.contains(':')
        || draft.name.is_empty() && !draft.issuer.is_empty()
    {
        return Err("otp_uri_label_unsupported");
    }
    let label = if draft.issuer.is_empty() {
        encode(&draft.name)
    } else {
        format!("{}:{}", encode(&draft.issuer), encode(&draft.name))
    };
    let mut query = vec![format!("secret={}", encode(&draft.secret))];
    if !draft.issuer.is_empty() {
        query.push(format!("issuer={}", encode(&draft.issuer)));
    }
    query.push(format!("algorithm={}", draft.algorithm.as_str()));
    query.push(format!("digits={}", draft.digits));
    if draft.kind == Kind::Totp || draft.period != 30 {
        query.push(format!("period={}", draft.period));
    }
    if draft.kind == Kind::Hotp || draft.counter != "0" {
        query.push(format!("counter={}", draft.counter));
    }
    let result = format!(
        "otpauth://{}/{label}?{}",
        draft.kind.as_str(),
        query.join("&")
    );
    if result.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    Ok(result)
}
pub fn export_json(drafts: &[Draft]) -> Result<String> {
    if drafts.is_empty() {
        return Err("otp_import_empty");
    }
    if drafts.len() > MAX_ENTRIES {
        return Err("otp_entry_limit");
    }
    let drafts = drafts
        .iter()
        .map(Draft::normalized)
        .collect::<Result<Vec<_>>>()?;
    let text = serde_json::to_string_pretty(&serde_json::json!({"version":1,"otp":drafts}))
        .map_err(|_| "otp_export_failed")?;
    if text.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    Ok(text)
}
