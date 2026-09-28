//! Pure OTP values and RFC 4226/6238 calculations. No clock, store or network.
//! Entry/Draft contain secrets: only explicit editor/export endpoints may return
//! them. Normal application snapshots must use Metadata instead.
pub mod formats;
pub mod migration;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub type Result<T> = std::result::Result<T, &'static str>;
pub const MAX_ENTRIES: usize = 5000;
/// Largest serialized collection, and largest converted legacy OTP section.
pub const MAX_COLLECTION_BYTES: usize = 8 * 1024 * 1024;
/// Most codes one request computes: a visible page of the OTP list.
pub const MAX_CODES_PER_REQUEST: usize = 100;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_PERIOD: u16 = 30;
pub const MAX_TEXT: usize = 1024 * 1024;
pub const MAX_KEY_BYTES: usize = 1024;
/// Longest name or issuer.
pub const MAX_LABEL_BYTES: usize = 512;
pub const DIGITS: std::ops::RangeInclusive<u8> = 4..=10;
pub const PERIOD_SECONDS: std::ops::RangeInclusive<u16> = 1..=3600;
/// Longest secret as typed, before Base32 decoding.
pub const MAX_SECRET_TEXT: usize = 8192;
/// A counter fits a signed 64-bit integer.
pub const MAX_COUNTER_DIGITS: usize = 19;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}
impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA512 => "SHA512",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            _ => Err("otp_algorithm_invalid"),
        }
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Totp,
    Hotp,
}
impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "totp" => Ok(Self::Totp),
            "hotp" => Ok(Self::Hotp),
            _ => Err("otp_type_invalid"),
        }
    }
}
fn digits_default() -> u8 {
    DEFAULT_DIGITS
}
fn period_default() -> u16 {
    DEFAULT_PERIOD
}
fn counter_default() -> String {
    "0".into()
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub issuer: String,
    pub secret: String,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default, rename = "type")]
    pub kind: Kind,
    #[serde(default = "digits_default")]
    pub digits: u8,
    #[serde(default = "period_default")]
    pub period: u16,
    #[serde(default = "counter_default")]
    pub counter: String,
}
impl Default for Draft {
    fn default() -> Self {
        Self {
            name: String::new(),
            issuer: String::new(),
            secret: String::new(),
            algorithm: Algorithm::SHA1,
            kind: Kind::Totp,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            counter: counter_default(),
        }
    }
}

// Do not derive Debug: it would make accidental secret logging too easy.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub id: String,
    pub revision: String,
    #[serde(flatten)]
    pub value: Draft,
}
// Explicit wire fields avoid serde's deny_unknown_fields/flatten interaction.
// Duplicate fields, including secrets and revision, are rejected by derive.
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            id: String,
            revision: String,
            name: String,
            issuer: String,
            secret: String,
            algorithm: Algorithm,
            #[serde(rename = "type")]
            kind: Kind,
            digits: u8,
            period: u16,
            counter: String,
        }
        let s = Stored::deserialize(de)?;
        Ok(Self {
            id: s.id,
            revision: s.revision,
            value: Draft {
                name: s.name,
                issuer: s.issuer,
                secret: s.secret,
                algorithm: s.algorithm,
                kind: s.kind,
                digits: s.digits,
                period: s.period,
                counter: s.counter,
            },
        })
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: String,
    pub revision: String,
    pub name: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub digits: u8,
    pub period: u16,
    pub counter: String,
}
/// Restoring or importing an older copy must never lower a HOTP counter that was
/// already spent: that counter would produce a code the server has seen. Entries
/// are matched by secret, so a re-created entry keeps its high-water mark too.
pub(crate) fn keep_spent_counters(current: &[Entry], next: &mut [Entry]) {
    let mut spent: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for entry in current.iter().filter(|e| e.value.kind == Kind::Hotp) {
        if let Ok(value) = counter(&entry.value.counter) {
            let high = spent.entry(entry.value.secret.as_str()).or_insert(value);
            *high = (*high).max(value);
        }
    }
    for entry in next.iter_mut().filter(|e| e.value.kind == Kind::Hotp) {
        let Some(high) = spent.get(entry.value.secret.as_str()).copied() else {
            continue;
        };
        if counter(&entry.value.counter).is_ok_and(|value| value < high) {
            entry.value.counter = high.to_string();
            entry.revision = uuid::Uuid::new_v4().to_string();
        }
    }
}
impl Entry {
    pub fn metadata(&self) -> Metadata {
        Metadata {
            id: self.id.clone(),
            revision: self.revision.clone(),
            name: self.value.name.clone(),
            issuer: self.value.issuer.clone(),
            algorithm: self.value.algorithm,
            kind: self.value.kind,
            digits: self.value.digits,
            period: self.value.period,
            counter: self.value.counter.clone(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 128
            || self.id.chars().any(char::is_control)
            || uuid::Uuid::parse_str(&self.revision).is_err()
        {
            return Err("otp_identity_invalid");
        }
        self.value.validate()
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Code {
    pub code: String,
    pub seconds_remaining: u16,
}

pub fn counter(value: &str) -> Result<u64> {
    if value.is_empty()
        || value.len() > MAX_COUNTER_DIGITS
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("otp_counter_invalid");
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or("otp_counter_invalid")
}
impl Draft {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.name, &self.issuer] {
            if value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
                return Err("otp_label_invalid");
            }
        }
        if !DIGITS.contains(&self.digits) {
            return Err("otp_digits_invalid");
        }
        if !PERIOD_SECONDS.contains(&self.period) {
            return Err("otp_period_invalid");
        }
        counter(&self.counter)?;
        decode_secret(&self.secret)?;
        Ok(())
    }
    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        Ok(Self {
            secret: normalize_secret(&self.secret)?,
            counter: counter(&self.counter)?.to_string(),
            ..self.clone()
        })
    }
    pub fn code_at(&self, unix_seconds: u64) -> Result<Code> {
        self.validate()?;
        if unix_seconds > i64::MAX as u64 {
            return Err("otp_time_invalid");
        }
        let (counter, remaining) = match self.kind {
            Kind::Hotp => (counter(&self.counter)?, 0),
            Kind::Totp => (
                unix_seconds / u64::from(self.period),
                self.period - (unix_seconds % u64::from(self.period)) as u16,
            ),
        };
        let key = decode_secret(&self.secret)?;
        let message = counter.to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::SHA1 => {
                let mut h = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| "otp_secret_invalid")?;
                h.update(&message);
                h.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                let mut h =
                    Hmac::<Sha256>::new_from_slice(&key).map_err(|_| "otp_secret_invalid")?;
                h.update(&message);
                h.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                let mut h =
                    Hmac::<Sha512>::new_from_slice(&key).map_err(|_| "otp_secret_invalid")?;
                h.update(&message);
                h.finalize().into_bytes().to_vec()
            }
        };
        let offset = (mac[mac.len() - 1] & 15) as usize;
        let binary = u32::from_be_bytes(mac[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let value = u64::from(binary) % 10u64.pow(u32::from(self.digits));
        Ok(Code {
            code: format!("{value:0width$}", width = usize::from(self.digits)),
            seconds_remaining: remaining,
        })
    }
}

/// Exact Qt byte semantics, including ignored separators and unused trailing
/// bits. Decode/re-encode is intentional: changing this would change old keys.
pub fn normalize_secret(input: &str) -> Result<String> {
    Ok(encode_secret(&decode_secret(input)?))
}
pub(crate) fn decode_secret(input: &str) -> Result<Vec<u8>> {
    if input.len() > MAX_SECRET_TEXT {
        return Err("otp_secret_too_large");
    }
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b' ' | b'-' | b'_' | b'\t' | b'\r' | b'\n' | b'=' => continue,
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("otp_secret_invalid"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 255) as u8);
        }
        if output.len() > MAX_KEY_BYTES {
            return Err("otp_secret_too_large");
        }
    }
    if output.is_empty() {
        return Err("otp_secret_empty");
    }
    Ok(output)
}
pub(crate) fn encode_secret(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests;
