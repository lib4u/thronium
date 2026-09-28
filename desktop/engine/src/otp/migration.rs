//! Bounded Google/Throne migration protobuf. No clock, network, store or logging.
//! Secrets remain private Draft values until the caller explicitly imports them.
use super::{decode_secret, encode_secret, Algorithm, Draft, Kind, Result, MAX_ENTRIES, MAX_TEXT};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use std::collections::{BTreeMap, BTreeSet};
const MAX_FRAGMENTS: usize = 256;

struct Fragment {
    entries: Vec<Draft>,
    size: usize,
    index: usize,
    batch: Option<i32>,
}
enum Field<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}
impl Field<'_> {
    fn number(self) -> Result<u64> {
        match self {
            Self::Number(v) => Ok(v),
            _ => Err("otp_migration_invalid"),
        }
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            let byte = *self.bytes.get(self.at).ok_or("otp_migration_invalid")?;
            self.at += 1;
            if i == 9 && byte > 1 {
                return Err("otp_migration_invalid");
            }
            value |= u64::from(byte & 127) << (i * 7);
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err("otp_migration_invalid")
    }
    fn next(&mut self) -> Result<Option<(u32, Field<'a>)>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let number = tag >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err("otp_migration_invalid");
        }
        let value = match tag & 7 {
            0 => Field::Number(self.varint()?),
            2 => {
                let size = usize::try_from(self.varint()?).map_err(|_| "otp_migration_invalid")?;
                let end = self
                    .at
                    .checked_add(size)
                    .filter(|&end| end <= self.bytes.len())
                    .ok_or("otp_migration_invalid")?;
                let value = &self.bytes[self.at..end];
                self.at = end;
                Field::Bytes(value)
            }
            _ => return Err("otp_migration_invalid"),
        };
        Ok(Some((number as u32, value)))
    }
}
fn bytes(field: Field<'_>) -> Result<&[u8]> {
    match field {
        Field::Bytes(v) => Ok(v),
        _ => Err("otp_migration_invalid"),
    }
}
fn text(field: Field<'_>) -> Result<String> {
    let raw = bytes(field)?;
    if raw.len() > 512 {
        return Err("otp_label_invalid");
    }
    std::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| "otp_label_invalid")
}
fn parameters(data: &[u8]) -> Result<Draft> {
    let mut reader = Reader::new(data);
    let mut seen = BTreeSet::new();
    let mut draft = Draft::default();
    while let Some((field, value)) = reader.next()? {
        if !(1..=7).contains(&field) {
            return Err("otp_migration_field_unsupported");
        }
        if !seen.insert(field) {
            return Err("otp_migration_duplicate_field");
        }
        match field {
            1 => {
                let raw = bytes(value)?;
                if raw.is_empty() {
                    return Err("otp_secret_empty");
                }
                if raw.len() > super::MAX_KEY_BYTES {
                    return Err("otp_secret_too_large");
                }
                draft.secret = encode_secret(raw);
            }
            2 => draft.name = text(value)?,
            3 => draft.issuer = text(value)?,
            4 => {
                draft.algorithm = match value.number()? {
                    1 => Algorithm::SHA1,
                    2 => Algorithm::SHA256,
                    3 => Algorithm::SHA512,
                    _ => return Err("otp_migration_enum_unsupported"),
                }
            }
            5 => {
                draft.digits = match value.number()? {
                    1 => 6,
                    2 => 8,
                    _ => return Err("otp_migration_enum_unsupported"),
                }
            }
            6 => {
                draft.kind = match value.number()? {
                    1 => Kind::Hotp,
                    2 => Kind::Totp,
                    _ => return Err("otp_migration_enum_unsupported"),
                }
            }
            7 => {
                let n = value.number()?;
                if n > i64::MAX as u64 {
                    return Err("otp_counter_invalid");
                }
                draft.counter = n.to_string();
            }
            _ => unreachable!(),
        }
    }
    if !seen.contains(&1) {
        return Err("otp_secret_empty");
    }
    if [4, 5, 6].iter().any(|v| !seen.contains(v)) {
        return Err("otp_migration_enum_unsupported");
    }
    // Missing string/counter fields have their protobuf defaults. Preserve names
    // exactly: Qt's display-name fallback must not rewrite a saved account name.
    draft.normalized()
}
fn signed_i32(value: u64) -> Result<i32> {
    if value <= i32::MAX as u64 || value >= i32::MIN as i64 as u64 {
        Ok(value as i32)
    } else {
        Err("otp_migration_batch_invalid")
    }
}
fn fragment(data: &[u8]) -> Result<Fragment> {
    let mut reader = Reader::new(data);
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let (mut version, mut size, mut index, mut batch) = (None, None, 0, None);
    while let Some((field, value)) = reader.next()? {
        if !(1..=5).contains(&field) {
            return Err("otp_migration_field_unsupported");
        }
        if field != 1 && !seen.insert(field) {
            return Err("otp_migration_duplicate_field");
        }
        match field {
            1 => {
                if entries.len() >= MAX_ENTRIES {
                    return Err("otp_entry_limit");
                }
                entries.push(parameters(bytes(value)?)?);
            }
            2 => version = Some(value.number()?),
            3 => size = Some(value.number()?),
            4 => index = value.number()?,
            5 => batch = Some(signed_i32(value.number()?)?),
            _ => unreachable!(),
        }
    }
    if version != Some(1) {
        return Err("otp_migration_version");
    }
    let size = size
        .filter(|&n| (1..=MAX_FRAGMENTS as u64).contains(&n))
        .ok_or("otp_migration_batch_invalid")?;
    if index >= size || (size > 1 && batch.is_none()) {
        return Err("otp_migration_batch_invalid");
    }
    if entries.is_empty() {
        return Err("otp_import_empty");
    }
    Ok(Fragment {
        entries,
        size: size as usize,
        index: index as usize,
        batch,
    })
}
fn decode_uri(link: &str) -> Result<Vec<u8>> {
    if link.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    let link = link.trim();
    if link.chars().any(|c| c.is_control() || c.is_whitespace()) || link.contains('#') {
        return Err("otp_migration_invalid");
    }
    let (scheme, rest) = link.split_once("://").ok_or("otp_migration_invalid")?;
    if !scheme.eq_ignore_ascii_case("otpauth-migration") {
        return Err("otp_migration_invalid");
    }
    let (authority, query) = rest.split_once('?').ok_or("otp_migration_invalid")?;
    if !authority.eq_ignore_ascii_case("offline") {
        return Err("otp_migration_invalid");
    }
    let (key, value) = query.split_once('=').ok_or("otp_migration_invalid")?;
    if key != "data" || value.contains('&') {
        return Err("otp_migration_invalid");
    }
    // '+' is literal Base64, not an application/x-www-form-urlencoded space.
    let value = super::formats::decode(value).map_err(|_| "otp_migration_invalid")?;
    if value.is_empty() || value.len() > MAX_TEXT {
        return Err("otp_migration_invalid");
    }
    let result = if value.contains('=') {
        STANDARD.decode(value)
    } else {
        STANDARD_NO_PAD.decode(value)
    }
    .map_err(|_| "otp_migration_invalid")?;
    if result.is_empty() {
        return Err("otp_migration_invalid");
    }
    Ok(result)
}

/// All fragments must be present in this call. Never returns a partial batch.
/// Groups retain first appearance order; each batch is ordered by its index.
pub fn import_migration(links: &[&str]) -> Result<Vec<Draft>> {
    if links.is_empty() {
        return Err("otp_import_empty");
    }
    if links.len() > MAX_FRAGMENTS {
        return Err("otp_migration_batch_invalid");
    }
    let mut encoded = 0usize;
    let mut decoded = 0usize;
    let mut count = 0usize;
    let mut groups: Vec<(usize, BTreeMap<usize, Vec<Draft>>)> = Vec::new();
    let mut ids = BTreeMap::<i32, usize>::new();
    for link in links {
        encoded = encoded
            .checked_add(link.len())
            .ok_or("otp_text_too_large")?;
        if encoded > MAX_TEXT {
            return Err("otp_text_too_large");
        }
        let data = decode_uri(link)?;
        decoded = decoded
            .checked_add(data.len())
            .ok_or("otp_text_too_large")?;
        if decoded > MAX_TEXT {
            return Err("otp_text_too_large");
        }
        let part = fragment(&data)?;
        count = count
            .checked_add(part.entries.len())
            .ok_or("otp_entry_limit")?;
        if count > MAX_ENTRIES {
            return Err("otp_entry_limit");
        }
        let group = if let Some(id) = part.batch {
            if let Some(&position) = ids.get(&id) {
                position
            } else {
                let position = groups.len();
                ids.insert(id, position);
                groups.push((part.size, BTreeMap::new()));
                position
            }
        } else {
            let position = groups.len();
            groups.push((part.size, BTreeMap::new()));
            position
        };
        let (size, parts) = &mut groups[group];
        if *size != part.size {
            return Err("otp_migration_batch_invalid");
        }
        if parts.insert(part.index, part.entries).is_some() {
            return Err("otp_migration_batch_duplicate");
        }
    }
    let mut entries = Vec::with_capacity(count);
    for (size, parts) in groups {
        if parts.len() != size {
            return Err("otp_migration_batch_incomplete");
        }
        // Valid indices plus size distinct entries imply the complete0..size set.
        for (_, mut part) in parts {
            entries.append(&mut part);
        }
    }
    Ok(entries)
}
fn varint(out: &mut Vec<u8>, mut n: u64) {
    while n > 127 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn number(out: &mut Vec<u8>, field: u64, n: u64) {
    varint(out, field << 3);
    varint(out, n);
}
fn blob(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// One complete version1 payload. Every selected record must fit the format.
/// QR capacity is a separate explicit check in the existing native exporter.
pub fn export_migration(drafts: &[Draft]) -> Result<String> {
    if drafts.is_empty() {
        return Err("otp_import_empty");
    }
    if drafts.len() > MAX_ENTRIES {
        return Err("otp_entry_limit");
    }
    let mut payload = Vec::new();
    for draft in drafts {
        let draft = draft.normalized()?;
        if !matches!(draft.digits, 6 | 8)
            || draft.period != 30
            || (draft.kind == Kind::Totp && draft.counter != "0")
        {
            return Err("otp_migration_export_unsupported");
        }
        if draft.name.is_empty() && !draft.issuer.is_empty() {
            return Err("otp_migration_label_unsupported");
        }
        let mut item = Vec::new();
        blob(&mut item, 1, &decode_secret(&draft.secret)?);
        blob(&mut item, 2, draft.name.as_bytes());
        if !draft.issuer.is_empty() {
            blob(&mut item, 3, draft.issuer.as_bytes());
        }
        number(
            &mut item,
            4,
            match draft.algorithm {
                Algorithm::SHA1 => 1,
                Algorithm::SHA256 => 2,
                Algorithm::SHA512 => 3,
            },
        );
        number(&mut item, 5, if draft.digits == 8 { 2 } else { 1 });
        number(&mut item, 6, if draft.kind == Kind::Hotp { 1 } else { 2 });
        if draft.kind == Kind::Hotp {
            number(&mut item, 7, super::counter(&draft.counter)?);
        }
        blob(&mut payload, 1, &item);
        if payload.len() > MAX_TEXT {
            return Err("otp_text_too_large");
        }
    }
    number(&mut payload, 2, 1);
    number(&mut payload, 3, 1);
    number(&mut payload, 4, 0);
    let result = format!(
        "otpauth-migration://offline?data={}",
        super::formats::encode(&STANDARD.encode(payload))
    );
    if result.len() > MAX_TEXT {
        return Err("otp_text_too_large");
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
