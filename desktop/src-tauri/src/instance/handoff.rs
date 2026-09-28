//! What a second launch sends to the running process: its working directory
//! and every argument as UTF-16 units, each prefixed by its length. No
//! separator can split an argument, and a path that is not valid Unicode
//! arrives exactly as the system gave it.

const MAGIC: u32 = 0x5448_5231;
/// Far above any real command line (Windows caps it at 32 767 units).
pub(super) const LIMIT: usize = 1 << 20;

pub(super) fn encode(cwd: &[u16], args: &[Vec<u16>]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC.to_le_bytes());
    bytes.extend(u32::try_from(args.len() + 1).ok()?.to_le_bytes());
    for item in std::iter::once(cwd).chain(args.iter().map(Vec::as_slice)) {
        bytes.extend(u32::try_from(item.len()).ok()?.to_le_bytes());
        bytes.extend(item.iter().flat_map(|unit| unit.to_le_bytes()));
        if bytes.len() > LIMIT {
            return None;
        }
    }
    Some(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Option<(Vec<u16>, Vec<Vec<u16>>)> {
    if bytes.len() > LIMIT {
        return None;
    }
    let mut rest = bytes;
    if word(&mut rest)? != MAGIC as usize {
        return None;
    }
    let count = word(&mut rest)?;
    if count == 0 || count > LIMIT / 4 {
        return None;
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let length = word(&mut rest)?;
        let size = length.checked_mul(2)?;
        if size > rest.len() {
            return None;
        }
        let (item, tail) = rest.split_at(size);
        rest = tail;
        items.push(
            item.as_chunks()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect(),
        );
    }
    if !rest.is_empty() {
        return None;
    }
    let cwd = items.remove(0);
    Some((cwd, items))
}

fn word(rest: &mut &[u8]) -> Option<usize> {
    let (head, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    usize::try_from(u32::from_le_bytes(*head)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }
    #[test]
    fn arguments_arrive_exactly_as_launched() {
        let cwd = wide(r"C:\Users\Тест Пользователь");
        let args = vec![
            wide(r"C:\Program Files\Thronium\Thronium.exe"),
            wide("--data-dir"),
            wide(r"D:\libs\a|b"),
            wide("thronium://import?x=1|2"),
            Vec::new(),
            // An unpaired surrogate is a legal Windows path, not a Rust string.
            vec![0x0041, 0xD800, 0x0042],
        ];
        let bytes = encode(&cwd, &args).unwrap();
        assert_eq!(decode(&bytes), Some((cwd.clone(), args)));
        assert_eq!(decode(&encode(&cwd, &[]).unwrap()), Some((cwd, vec![])));
    }
    #[test]
    fn damaged_or_foreign_messages_are_refused() {
        let bytes = encode(&wide(r"C:\"), &[wide("a.exe"), wide("file.json")]).unwrap();
        for cut in 0..bytes.len() {
            assert_eq!(decode(&bytes[..cut]), None, "{cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode(&longer), None);
        let mut foreign = bytes.clone();
        foreign[0] ^= 1;
        assert_eq!(decode(&foreign), None);
        // A length that claims more than was sent must not be trusted.
        let mut lying = MAGIC.to_le_bytes().to_vec();
        lying.extend(1u32.to_le_bytes());
        lying.extend(u32::MAX.to_le_bytes());
        assert_eq!(decode(&lying), None);
        let mut empty = MAGIC.to_le_bytes().to_vec();
        empty.extend(0u32.to_le_bytes());
        assert_eq!(decode(&empty), None);
        // C:\Windows\Temp in the old `cwd|arg|arg` form of the plugin.
        assert_eq!(decode(br"C:\Windows\Temp|a.exe|x"), None);
        assert_eq!(encode(&vec![0; LIMIT], &[]), None);
    }
}
