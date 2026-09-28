//! Registered machine codes, one per line in `error_codes.txt`. Raw error
//! details never cross the IPC boundary; only these codes do.
use std::sync::LazyLock;

static CODES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("error_codes.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect()
});

pub fn codes() -> &'static [&'static str] {
    &CODES
}
