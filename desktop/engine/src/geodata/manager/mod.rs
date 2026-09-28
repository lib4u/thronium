//! Explicit management of the Xray assets consumed by full client configurations.
use serde::{Deserialize, Serialize};
mod download;
mod files;
mod history;
pub use history::{Provider, PROVIDERS};
mod index;
mod jobs;
pub use download::{Download, Prepared};
pub use files::Status;
pub use jobs::Jobs;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Geoip,
    Geosite,
}
impl Kind {
    fn sites(self) -> bool {
        self == Self::Geosite
    }
    fn prefix(self) -> &'static str {
        if self.sites() {
            "geosite:"
        } else {
            "geoip:"
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub kind: Kind,
    pub url: String,
}
use crate::routing::MAX_GEODATA_ASSET_BYTES as LIMIT;

pub struct Inspection(files::Files);
impl Inspection {
    pub fn execute(self) -> Result<Status, String> {
        self.0.status()
    }
}
impl crate::Engine {
    pub fn inspect_xray_geodata(&self, selection: Selection) -> Result<Inspection, String> {
        Ok(Inspection(files::Files::new(&self.data_dir, selection)?))
    }
    pub fn commit_xray_geodata(&self, prepared: Prepared) -> Result<Status, String> {
        use crate::geodata::{enabled, provider, visit, xray_references, Assets};
        let staged = prepared.0;
        if !staged.files.belongs_to(&self.data_dir) {
            return Err("geodata_request_stale".into());
        }
        let mut required = std::collections::BTreeSet::new();
        for profile in &self.store.library.profiles {
            let assets = Assets::new(&self.data_dir, provider(profile, &self.store.library))
                .with_library(&self.store.library);
            if !staged.files.matches(&assets) {
                continue;
            }
            let mut collect = |value: &serde_json::Value| {
                visit(value, &mut |s| {
                    if let Some(code) = s.strip_prefix(staged.files.selection.kind.prefix()) {
                        required.insert(code.to_owned());
                    }
                });
            };
            if profile.kind == crate::store::ProfileKind::XrayConfig {
                collect(&xray_references(&profile.config));
            }
            if enabled(profile, &self.store.library) {
                if let Some(policy) = provider(profile, &self.store.library) {
                    collect(&policy.config);
                }
            }
        }
        for code in required {
            staged.index.require(&code)?;
        }
        staged.commit()
    }
}

#[cfg(test)]
mod tests;
