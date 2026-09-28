//! What Thronium writes to disk, sealed. The key lives
//! in this desktop's Secret Service keyring, the files the application owns are
//! sealed with it, and nothing ever asks the user for a password. A copy that
//! has no keyring keeps writing plain text and says so, so a library is never
//! locked away from the person it belongs to.
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

pub mod keyring;

/// Marks a sealed file and is authenticated with it, so a header cannot be
/// exchanged for another one.
const MAGIC: &[u8] = b"THRONIUM-SEALED-1\n";
pub const KEY_BYTES: usize = 32;

#[derive(Clone)]
pub struct Key([u8; KEY_BYTES]);
impl Key {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
    pub fn generate() -> Result<Self, String> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; KEY_BYTES];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "key_generation_failed")?;
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
    fn sealing(&self) -> Result<LessSafeKey, String> {
        UnboundKey::new(&AES_256_GCM, &self.0)
            .map(LessSafeKey::new)
            .map_err(|_| "secrets_invalid".into())
    }
}
// A key never reaches a log, a review or a panic message.
impl std::fmt::Debug for Key {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Key(…)")
    }
}

/// Whether these bytes were written sealed. A library from a copy that had no
/// keyring is ordinary JSON and is read as it always was.
pub fn sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub fn seal(key: &Key, plain: &[u8]) -> Result<Vec<u8>, String> {
    use ring::rand::SecureRandom;
    let mut nonce = [0u8; NONCE_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "key_generation_failed")?;
    let mut payload = plain.to_vec();
    key.sealing()?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(MAGIC),
            &mut payload,
        )
        .map_err(|_| "secrets_invalid")?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn unseal(key: &Key, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if !sealed(bytes) || bytes.len() < MAGIC.len() + NONCE_LEN {
        return Err("secrets_invalid".into());
    }
    let (nonce, payload) = bytes[MAGIC.len()..].split_at(NONCE_LEN);
    let nonce = Nonce::assume_unique_for_key(nonce.try_into().map_err(|_| "secrets_invalid")?);
    let mut payload = payload.to_vec();
    let plain = key
        .sealing()?
        .open_in_place(nonce, Aad::from(MAGIC), &mut payload)
        .map_err(|_| "secrets_invalid")?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_file_reads_back_only_with_its_own_key_and_hides_what_it_holds() {
        let key = Key::generate().unwrap();
        let plain = br#"{"profiles":[{"password":"synthetic-secret-value"}]}"#;
        let sealed_bytes = seal(&key, plain).unwrap();
        assert!(sealed(&sealed_bytes) && !sealed(plain));
        // Nothing of the content survives in the open.
        assert!(!sealed_bytes
            .windows(b"synthetic-secret-value".len())
            .any(|window| window == b"synthetic-secret-value"));
        assert_eq!(unseal(&key, &sealed_bytes).unwrap(), plain);
        assert_eq!(
            unseal(&Key::generate().unwrap(), &sealed_bytes).unwrap_err(),
            "secrets_invalid"
        );
    }

    #[test]
    fn a_changed_byte_header_or_key_length_is_refused_rather_than_guessed() {
        let key = Key::generate().unwrap();
        let sealed_bytes = seal(&key, b"library").unwrap();
        for index in [0, MAGIC.len(), sealed_bytes.len() - 1] {
            let mut damaged = sealed_bytes.clone();
            damaged[index] ^= 0x40;
            assert_eq!(unseal(&key, &damaged).unwrap_err(), "secrets_invalid");
        }
        assert_eq!(
            unseal(&key, &sealed_bytes[..MAGIC.len() + 4]).unwrap_err(),
            "secrets_invalid"
        );
        // Plain text is never mistaken for a sealed file.
        assert_eq!(unseal(&key, b"{}").unwrap_err(), "secrets_invalid");
        assert!(Key::from_bytes(&[0u8; KEY_BYTES - 1]).is_none());
        assert!(Key::from_bytes(&[0u8; KEY_BYTES]).is_some());
    }

    #[test]
    fn two_seals_of_the_same_library_never_repeat_their_nonce() {
        let key = Key::generate().unwrap();
        let first = seal(&key, b"library").unwrap();
        let second = seal(&key, b"library").unwrap();
        assert_ne!(first, second);
        assert_eq!(
            unseal(&key, &first).unwrap(),
            unseal(&key, &second).unwrap()
        );
        // The key itself never appears in a debug rendering.
        assert_eq!(format!("{:?}", key), "Key(…)");
    }
}
