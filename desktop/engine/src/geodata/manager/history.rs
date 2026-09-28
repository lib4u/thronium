//! Bounded recent explicit download sources. Saving a draft URL is independent.
use super::{Kind, Selection};
use crate::{
    geodata::{DEFAULT_IP, DEFAULT_SITE},
    store::Library,
    Engine,
};
use serde::Serialize;
use serde_json::{json, Value};

/// A published pair of geodata files. Xray assets and routing category databases
/// offer the same providers; raw GitHub URLs keep the download mirrors usable.
#[derive(Serialize)]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub geoip: &'static str,
    pub geosite: &'static str,
}
pub const PROVIDERS: [Provider; 4] = [
    Provider {
        id: "global",
        name: "Loyalsoldier (global / China)",
        geoip: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat",
        geosite: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat",
    },
    Provider {
        id: "ru",
        name: "runetfreedom (Russia)",
        geoip: "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
        geosite:
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
    },
    Provider {
        id: "ir",
        name: "Chocolate4U (Iran)",
        geoip: "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat",
        geosite: "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat",
    },
    Provider {
        id: "v2fly",
        name: "v2fly (upstream)",
        geoip: "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
        geosite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
    },
];
fn key(kind: Kind) -> &'static str {
    if kind.sites() {
        "xray_geosite_url_history"
    } else {
        "xray_geoip_url_history"
    }
}
fn builtin(url: &str) -> bool {
    [DEFAULT_IP, DEFAULT_SITE].contains(&url)
        || PROVIDERS.iter().any(|p| p.geoip == url || p.geosite == url)
}
fn custom(selection: Selection) -> Option<String> {
    let selection = selection.checked().ok()?;
    (!builtin(&selection.url)).then_some(selection.url)
}
fn recent(library: &Library, kind: Kind) -> Vec<String> {
    let mut result = Vec::new();
    // Malformed optional history never prevents opening a user's profiles.
    for value in library
        .settings
        .get(key(kind))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(32)
    {
        let Some(url) = value.as_str().and_then(|url| {
            custom(Selection {
                kind,
                url: url.into(),
            })
        }) else {
            continue;
        };
        if !result.contains(&url) {
            result.push(url);
        }
        if result.len() == 5 {
            break;
        }
    }
    result
}
pub(super) fn remember(engine: &mut Engine, selection: Selection) -> Result<(), String> {
    let kind = selection.kind;
    let Some(url) = custom(selection) else {
        return Ok(());
    };
    let mut values = recent(&engine.store.library, kind);
    values.retain(|old| old != &url);
    values.insert(0, url);
    values.truncate(5);
    let value = json!(values);
    if engine.store.library.settings.get(key(kind)) == Some(&value) {
        return Ok(());
    }
    let mut next = engine.store.library.clone();
    next.settings.insert(key(kind).into(), value);
    engine.store.commit(next)
}
impl Engine {
    pub fn xray_geodata_sources(&self) -> Value {
        json!({"providers":PROVIDERS,"history":{"geoip":recent(&self.store.library, Kind::Geoip),"geosite":recent(&self.store.library, Kind::Geosite)}})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn add(engine: &mut Engine, n: usize, kind: Kind) {
        remember(
            engine,
            Selection {
                kind,
                url: format!("https://custom.test/{n}.dat"),
            },
        )
        .unwrap();
    }
    #[test]
    fn explicit_attempts_persist_five_recent_urls_without_saving_current_setting() {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("absent-core");
        let mut engine = Engine::open(dir.path(), &core).unwrap();
        let before = crate::settings::value(&engine.store.library, "xray_geosite_url");
        for n in 0..7 {
            add(&mut engine, n, Kind::Geosite);
        }
        add(&mut engine, 3, Kind::Geosite);
        add(&mut engine, 99, Kind::Geoip);
        assert_eq!(
            recent(&engine.store.library, Kind::Geosite),
            [3, 6, 5, 4, 2].map(|n| format!("https://custom.test/{n}.dat"))
        );
        assert_eq!(
            recent(&engine.store.library, Kind::Geoip),
            ["https://custom.test/99.dat"]
        );
        assert_eq!(
            crate::settings::value(&engine.store.library, "xray_geosite_url"),
            before
        );
        let restored: Library =
            serde_json::from_slice(&serde_json::to_vec(&engine.store.library).unwrap()).unwrap();
        assert_eq!(
            recent(&restored, Kind::Geosite),
            recent(&engine.store.library, Kind::Geosite)
        );
        let expected = engine.xray_geodata_sources();
        drop(engine);
        let reopened = Engine::open(dir.path(), &core).unwrap();
        assert_eq!(reopened.xray_geodata_sources(), expected);
    }
    #[test]
    fn provider_urls_defaults_and_invalid_values_do_not_enter_custom_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent")).unwrap();
        for url in PROVIDERS.iter().flat_map(|p| [p.geoip, p.geosite]).chain([
            DEFAULT_IP,
            DEFAULT_SITE,
            "",
            "http://bad.test/a",
            "https://u:p@bad.test/a",
            "https://bad.test/a#fragment",
        ]) {
            remember(
                &mut engine,
                Selection {
                    kind: Kind::Geosite,
                    url: url.into(),
                },
            )
            .unwrap();
        }
        assert!(recent(&engine.store.library, Kind::Geosite).is_empty());
        engine.store.library.settings.insert(
            key(Kind::Geosite).into(),
            json!([
                null,
                1,
                "http://bad.test/a",
                " https://custom.test/a ",
                "https://custom.test/a"
            ]),
        );
        assert_eq!(
            recent(&engine.store.library, Kind::Geosite),
            ["https://custom.test/a"]
        );
    }
    #[test]
    fn history_write_failure_keeps_previous_library_and_aborts_download_preparation() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(dir.path(), &dir.path().join("absent")).unwrap();
        add(&mut engine, 1, Kind::Geoip);
        let before = engine.xray_geodata_sources();
        let library = dir.path().join("library.json");
        std::fs::remove_file(&library).unwrap();
        std::fs::create_dir(&library).unwrap();
        assert!(remember(
            &mut engine,
            Selection {
                kind: Kind::Geoip,
                url: "https://custom.test/2.dat".into()
            }
        )
        .is_err());
        assert_eq!(engine.xray_geodata_sources(), before);
    }
}
