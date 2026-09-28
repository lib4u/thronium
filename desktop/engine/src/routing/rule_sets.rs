//! One pinned catalog shared with the routing editor. No network during import.
use std::{collections::BTreeMap, sync::LazyLock};

static SOURCES: LazyLock<BTreeMap<String, String>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../contracts/throne-rule-sets.json"))
        .expect("bundled Throne rule-set catalog")
});

pub(crate) fn source(tag: &str) -> Option<&'static str> {
    SOURCES.get(tag).map(String::as_str)
}
