//! The native UI uses the same locale source as the webview and works without it.
use std::{collections::BTreeMap, sync::OnceLock};
use thronium_engine::Engine;
mod generated {
    include!("localization_keys.rs");
}
pub use generated::TextKey;
use generated::CATALOGS;

/// An interface language listed in `locales/languages.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Language(usize);

impl Language {
    /// The saved interface language, as the window uses it; before the
    /// library opens, the stored default applies.
    pub fn of(engine: &Result<Engine, String>) -> Self {
        match engine {
            Ok(engine) => Self::from_code(&engine.store.library.preferences.language),
            Err(_) => Self::default_preference(),
        }
    }
    /// The language a new library starts with.
    pub fn default_preference() -> Self {
        Self::from_code(&thronium_engine::store::Preferences::default().language)
    }
    /// An unknown code uses the source language, the first in the manifest.
    pub fn from_code(code: &str) -> Self {
        Self(
            CATALOGS
                .iter()
                .position(|(known, _)| *known == code)
                .unwrap_or(0),
        )
    }
}

pub fn text(language: Language, key: TextKey) -> &'static str {
    static PARSED: OnceLock<Vec<BTreeMap<String, String>>> = OnceLock::new();
    let catalogs = PARSED.get_or_init(|| {
        CATALOGS
            .iter()
            .map(|(_, text)| serde_json::from_str(text).expect("checked native catalog"))
            .collect()
    });
    catalogs[language.0]
        .get(key.as_str())
        .or_else(|| catalogs[0].get(key.as_str()))
        .expect("generated native key")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_captions_do_not_depend_on_a_webview() {
        for (code, _) in CATALOGS {
            let language = Language::from_code(code);
            assert!(!text(language, TextKey::ConnectA27ba0c).is_empty());
        }
        assert_eq!(Language::from_code("not-a-language"), Language(0));
        let catalogs: Vec<BTreeMap<String, String>> = CATALOGS
            .iter()
            .map(|(_, text)| serde_json::from_str(text).unwrap())
            .collect();
        assert!(catalogs.iter().all(|c| c.keys().eq(catalogs[0].keys())));
    }
}
