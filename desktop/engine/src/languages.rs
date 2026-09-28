//! Interface languages. `locales/languages.json` lists them in one place; the
//! window, the native host and saved preferences accept exactly that list.
use serde::Deserialize;
use std::sync::LazyLock;

#[derive(Deserialize)]
struct Manifest {
    source: String,
    languages: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    code: String,
    locale: String,
}

static MANIFEST: LazyLock<Manifest> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../locales/languages.json"))
        .expect("checked language manifest")
});

/// Codes in manifest order; the first is the source language.
pub fn codes() -> impl Iterator<Item = &'static str> {
    MANIFEST.languages.iter().map(|l| l.code.as_str())
}

pub fn supported(code: &str) -> bool {
    codes().any(|known| known == code)
}

/// The language whose texts every catalog is written from.
pub fn source() -> &'static str {
    &MANIFEST.source
}

/// The supported language of a locale name such as `ru_RU` or `en-US`.
pub fn from_locale(locale: &str) -> Option<&'static str> {
    let locale = locale.replace('_', "-");
    MANIFEST
        .languages
        .iter()
        .find(|l| {
            l.locale.eq_ignore_ascii_case(&locale)
                || locale
                    .split('-')
                    .next()
                    .is_some_and(|base| base.eq_ignore_ascii_case(&l.code))
        })
        .map(|l| l.code.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_starts_with_its_source_and_resolves_locale_names() {
        assert_eq!(codes().next(), Some(source()));
        for code in codes() {
            assert!(supported(code));
            assert_eq!(from_locale(code), Some(code));
        }
        assert!(!supported(""));
        assert_eq!(from_locale("xx_XX"), None);
    }
}
