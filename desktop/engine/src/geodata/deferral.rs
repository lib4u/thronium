//! Asset downloads outside the Engine lock (S6). A command running under the
//! lock only reads the cache; when a download is needed it records the exact
//! inputs and fails with [`DOWNLOAD_REQUIRED`]. The host then releases the lock,
//! runs the [`Work`] (cancellable) and repeats the command, which is safe
//! because every caller prepares assets before changing any state.
use super::Fetch;
use crate::store::{Library, Profile};
use crate::Engine;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::sync::watch;

pub const DOWNLOAD_REQUIRED: &str = "geodata_download_required";
/// A command needing more separate downloads than this (for example many
/// subscription members with different lists) reports the last request.
pub const MAX_DOWNLOADS: usize = 16;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum Mode {
    /// Download while preparing: tests, the tray and paths without a host loop.
    #[default]
    Inline,
    /// Report needed downloads; `downloaded` after the host ran one, so a
    /// cached file whose refresh failed is accepted instead of asked again.
    Deferred { downloaded: bool },
}

#[derive(Default)]
pub struct Deferral(Mutex<(Mode, Option<Work>)>);

/// The downloads one command needs, owned so they run without an Engine borrow.
pub struct Work {
    profile: Profile,
    library: Library,
    directory: PathBuf,
    proxy: Option<String>,
}

impl Work {
    /// Cancellation stops the download; files are only published complete.
    pub async fn run(self, cancelled: Option<watch::Receiver<bool>>) -> Result<(), String> {
        let download = super::prepare(
            &self.profile,
            &self.library,
            &self.directory,
            self.proxy.as_deref(),
            Fetch::Download,
        );
        let Some(mut cancelled) = cancelled else {
            return download.await;
        };
        tokio::select! {
            biased;
            _ = cancelled.wait_for(|cancelled| *cancelled) => Err("geodata_cancelled".into()),
            result = download => result,
        }
    }
}

/// Prepare assets for a command under the Engine lock according to the mode
/// the host selected.
pub(crate) async fn prepare_for(
    deferral: &Deferral,
    profile: &Profile,
    library: &Library,
    directory: &Path,
    proxy: Option<&str>,
) -> Result<(), String> {
    let mode = deferral.0.lock().unwrap().0;
    let fetch = match mode {
        Mode::Inline => Fetch::Download,
        Mode::Deferred { downloaded } => Fetch::Cached { stale: downloaded },
    };
    let result = super::prepare(profile, library, directory, proxy, fetch).await;
    if result
        .as_ref()
        .is_err_and(|error| error == DOWNLOAD_REQUIRED)
    {
        deferral.0.lock().unwrap().1 = Some(Work {
            profile: profile.clone(),
            library: library.clone(),
            directory: directory.to_path_buf(),
            proxy: proxy.map(str::to_owned),
        });
    }
    result
}

impl Engine {
    /// Commands after this call report needed downloads instead of running them.
    /// `downloaded` is true when repeating a command after [`Work::run`].
    pub fn defer_geodata(&mut self, downloaded: bool) {
        *self.geodata.0.lock().unwrap() = (Mode::Deferred { downloaded }, None);
    }
    /// Back to downloading while preparing, dropping any unclaimed work.
    pub fn inline_geodata(&mut self) {
        *self.geodata.0.lock().unwrap() = (Mode::Inline, None);
    }
    pub fn take_geodata_work(&mut self) -> Option<Work> {
        self.geodata.0.lock().unwrap().1.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine_with_missing_list() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
        e.store.library.profiles.push(Profile {
            vpn_policy: None,
            id: "fixture".into(),
            name: "Fixture".into(),
            group_id: "personal".into(),
            favorite: false,
            kind: crate::store::ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"192.0.2.10","server_port":1080}),
        });
        e.store.library.selected = Some("fixture".into());
        e.store.library.routing.profiles[0].route["rule_set"] = json!([{"type":"geodata","tag":"fixture","kind":"geosite","url":"https://example.test/geosite.dat","category":"test"}]);
        (dir, e)
    }

    /// Under the host's deferral a command never downloads while holding the
    /// Engine: it reports the work and leaves the library untouched, so the
    /// host can download unlocked and repeat it.
    #[tokio::test]
    async fn a_deferred_command_reports_its_download_and_changes_nothing() {
        let (_dir, mut e) = engine_with_missing_list();
        let dns = crate::settings::section(&e.store.library, "dns");
        let mut next = dns.clone();
        next["enable_dns_routing"] = json!(!dns["enable_dns_routing"].as_bool().unwrap());
        e.defer_geodata(false);
        assert_eq!(
            e.save_settings("dns", dns.clone(), next.clone())
                .await
                .unwrap_err(),
            DOWNLOAD_REQUIRED
        );
        assert_eq!(crate::settings::section(&e.store.library, "dns"), dns);
        let work = e.take_geodata_work().expect("the download is described");
        assert_eq!(work.profile.id, "fixture");
        assert_eq!(
            work.library.settings.get("enable_dns_routing"),
            Some(&next["enable_dns_routing"]),
            "the work uses the library the command would commit"
        );
        e.inline_geodata();
        assert!(e.take_geodata_work().is_none());
        let (sender, cancelled) = watch::channel(false);
        sender.send(true).unwrap();
        assert_eq!(
            work.run(Some(cancelled)).await.unwrap_err(),
            "geodata_cancelled"
        );
    }

    #[tokio::test]
    async fn a_repeated_command_accepts_a_stale_list_whose_refresh_was_attempted() {
        use super::super::{digest, write, Assets, Domain, Site, SiteList};
        use prost::Message;
        let dir = tempfile::tempdir().unwrap();
        let assets = Assets::new(dir.path(), None);
        let library = Library::default();
        let rule = json!({"rules":[{"domain":["geosite:test"]}]});
        for stale in [false, true] {
            assert_eq!(
                assets
                    .prepare(&[&rule], &library, None, Fetch::Cached { stale })
                    .await
                    .unwrap_err(),
                DOWNLOAD_REQUIRED,
                "a missing list is always downloaded"
            );
        }
        std::fs::create_dir_all(&assets.directory).unwrap();
        let bytes = SiteList {
            entry: vec![Site {
                code: "TEST".into(),
                domain: vec![Domain {
                    kind: 2,
                    value: "example.test".into(),
                    attribute: vec![],
                }],
            }],
        }
        .encode_to_vec();
        let hash = digest(&bytes);
        write(&assets.directory.join(format!("{hash}.dat")), &bytes).unwrap();
        write(&assets.manifest(true), hash.as_bytes()).unwrap();
        assets
            .prepare(&[&rule], &library, None, Fetch::Cached { stale: false })
            .await
            .expect("a fresh list needs no download");
        std::fs::File::options()
            .write(true)
            .open(assets.manifest(true))
            .unwrap()
            .set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(8 * 24 * 3600),
            )
            .unwrap();
        assert_eq!(
            assets
                .prepare(&[&rule], &library, None, Fetch::Cached { stale: false })
                .await
                .unwrap_err(),
            DOWNLOAD_REQUIRED
        );
        assets
            .prepare(&[&rule], &library, None, Fetch::Cached { stale: true })
            .await
            .unwrap();
    }
}
