//! An owned HTTP request and an optimistic commit token. No Engine/RPC borrow
//! survives execute; downloaded bytes cannot update a changed library context.
use super::{digest, install, install_bundled, load, sets, sites, valid_url};
use crate::{
    routing::{MAX_CATEGORY_DATABASE_BYTES, MAX_PROFILE_BYTES},
    settings,
    store::Library,
    Engine,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tokio::sync::watch;

pub(super) struct Fetch {
    client: reqwest::Client,
    url: reqwest::Url,
    limit: usize,
    too_large: &'static str,
}
impl Fetch {
    pub(super) fn prepare(
        raw: &str,
        library: &Library,
        proxy: Option<&str>,
        (limit, too_large): (usize, &'static str),
    ) -> Result<Self, String> {
        let url = valid_url(raw)?;
        let client = settings::network::client(library, proxy)?
            .redirect(crate::bounded_download::redirects(|url| {
                valid_url(url.as_str()).is_ok()
            }))
            .build()
            .map_err(|_| "geodata_download_failed")?;
        Ok(Self {
            client,
            url,
            limit,
            too_large,
        })
    }
    pub(super) async fn execute(self) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(|_| "geodata_download_failed")?
            .error_for_status()
            .map_err(|_| "geodata_download_failed")?;
        crate::bounded_download::body(response, self.limit)
            .await
            .map_err(|error| match error {
                crate::bounded_download::BodyError::TooLarge => self.too_large.into(),
                crate::bounded_download::BodyError::Network(_) => "geodata_download_failed".into(),
            })
    }
}
enum Target {
    Geodata {
        kind: String,
        url: String,
        name: String,
    },
    Routing {
        url: String,
    },
    RoutingUpdate {
        profile: Box<crate::routing::RoutingProfile>,
    },
}
pub struct Download {
    fetch: Fetch,
    context: String,
    target: Target,
}
pub struct Prepared {
    context: String,
    target: Target,
    bytes: Vec<u8>,
}
pub enum Preparation {
    Ready(Value),
    Download(Download),
}
impl Download {
    pub async fn execute(self, mut cancelled: watch::Receiver<bool>) -> Result<Prepared, String> {
        if *cancelled.borrow() {
            return Err("geodata_cancelled".into());
        }
        let Self {
            fetch,
            context,
            target,
        } = self;
        let bytes = tokio::select! {
            biased;
            _ = cancelled.wait_for(|value| *value) => return Err("geodata_cancelled".into()),
            result = fetch.execute() => result?,
        };
        if *cancelled.borrow() {
            return Err("geodata_cancelled".into());
        }
        Ok(Prepared {
            context,
            target,
            bytes,
        })
    }
}
impl Engine {
    fn catalog_download_context(&self) -> Result<String, String> {
        let library = &self.store.library;
        let mut profiles: Vec<_> = library
            .profiles
            .iter()
            .map(|profile| self.profile_edit_revision(profile))
            .collect();
        profiles.sort_unstable();
        // Display order, favorite, measurements and language are deliberately absent.
        // Include exact route content: an imported backup can reuse a revision number.
        let owner = self
            .owned_core_process()
            .map(|p| (p.pid, p.instance, p.start_time));
        let network = [
            "net_use_proxy",
            "net_insecure",
            "network_timeout",
            "user_agent",
        ]
        .map(|key| settings::value(library, key));
        let identity = json!({
            "profiles": profiles, "routing": library.routing,
            "network": network,
            "proxy": self.settings_download_proxy()?, "running": self.running, "since": self.since, "owner": owner,
        });
        Ok(digest(identity.to_string().as_bytes()))
    }
    pub fn prepare_geodata_load(&mut self, payload: Value) -> Result<Preparation, String> {
        let kind = payload["kind"].as_str().ok_or("geodata_invalid")?;
        sites(kind)?;
        let url = payload["url"].as_str().unwrap_or("").trim();
        let name = payload["name"].as_str().unwrap_or(url);
        let source = if let Some(encoded) = payload["data"].as_str() {
            if encoded.len() > MAX_CATEGORY_DATABASE_BYTES.div_ceil(3) * 4 {
                return Err("routing_geodata_too_large".into());
            }
            let bytes = STANDARD.decode(encoded).map_err(|_| "geodata_invalid")?;
            let local = format!("local:{}", digest(&bytes));
            install(
                &self.data_dir,
                &self.store.library,
                kind,
                &local,
                name,
                &bytes,
            )?
        } else if !payload["force"].as_bool().unwrap_or(false)
            && load(&self.data_dir, kind, url).is_ok()
        {
            load(&self.data_dir, kind, url)?
        } else if let Some(source) = (!payload["force"].as_bool().unwrap_or(false))
            .then(|| {
                install_bundled(
                    &self.data_dir,
                    &self.store.library,
                    kind,
                    url,
                    name,
                    super::super::bundled::directory().as_deref(),
                )
            })
            .transpose()?
            .flatten()
        {
            source
        } else {
            if url.starts_with("local:") {
                return Err("geodata_local_missing".into());
            }
            return Ok(Preparation::Download(Download {
                fetch: Fetch::prepare(
                    url,
                    &self.store.library,
                    self.settings_download_proxy()?.as_deref(),
                    (MAX_CATEGORY_DATABASE_BYTES, "routing_geodata_too_large"),
                )?,
                context: self.catalog_download_context()?,
                target: Target::Geodata {
                    kind: kind.into(),
                    url: url.into(),
                    name: name.into(),
                },
            }));
        };
        serde_json::to_value(source)
            .map(Preparation::Ready)
            .map_err(|_| "geodata_invalid".into())
    }
    pub fn prepare_routing_source(&self, url: &str) -> Result<Download, String> {
        Ok(Download {
            fetch: Fetch::prepare(
                url,
                &self.store.library,
                self.settings_download_proxy()?.as_deref(),
                (MAX_PROFILE_BYTES, "routing_import_too_large"),
            )?,
            context: self.catalog_download_context()?,
            target: Target::Routing { url: url.into() },
        })
    }
    pub fn prepare_routing_update(&self, id: &str) -> Result<Download, String> {
        let profile = self
            .store
            .library
            .routing
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("routing_profile_missing")?;
        let source = crate::routing::source::Source::parse(
            profile.source.as_ref().ok_or("routing_source_missing")?,
        )?;
        Ok(Download {
            fetch: Fetch::prepare(
                &source.url,
                &self.store.library,
                self.settings_download_proxy()?.as_deref(),
                (MAX_PROFILE_BYTES, "routing_import_too_large"),
            )?,
            context: self.catalog_download_context()?,
            target: Target::RoutingUpdate {
                profile: Box::new(profile.clone()),
            },
        })
    }
    pub fn commit_routing_download(&mut self, prepared: Prepared) -> Result<Value, String> {
        if self.catalog_download_context().as_ref() != Ok(&prepared.context) {
            return Err("geodata_context_changed".into());
        }
        match prepared.target {
            Target::RoutingUpdate { profile } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let next =
                    crate::legacy_backup::routes::remote::refresh(&profile, &prepared.bytes, now)?;
                let mut library = self.store.library.clone();
                let target = library
                    .routing
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == profile.id)
                    .ok_or("routing_profile_missing")?;
                *target = next;
                library.routing.revision = library
                    .routing
                    .revision
                    .checked_add(1)
                    .ok_or("routing_revision_overflow")?;
                library.routing.validate()?;
                self.store.commit(library)?;
                Ok(json!(self.store.library.routing))
            }
            Target::Routing { url } => {
                let text =
                    String::from_utf8(prepared.bytes).map_err(|_| "routing_import_invalid")?;
                Ok(json!({"text":text,"url":url}))
            }
            Target::Geodata { kind, url, name } => {
                let old = load(&self.data_dir, &kind, &url).ok();
                // install validates the categories referenced by the current library.
                let source = install(
                    &self.data_dir,
                    &self.store.library,
                    &kind,
                    &url,
                    &name,
                    &prepared.bytes,
                )?;
                if old.is_some_and(|s| s.hash != source.hash)
                    && sets(self.store.library.routing.active()?)
                        .any(|s| s["url"] == url && s["kind"] == kind)
                {
                    self.routing_revision = None;
                }
                serde_json::to_value(source).map_err(|_| "geodata_invalid".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(dir: &std::path::Path) -> Engine {
        let mut engine = Engine::open(dir, &dir.join("missing-core")).unwrap();
        engine.store.library.routing.profiles[0].source =
            Some(json!({"url":"http://127.0.0.1:9001/routes","importedAt":5}));
        engine
    }
    fn prepared(engine: &Engine, body: Value) -> Prepared {
        Prepared {
            context: engine.catalog_download_context().unwrap(),
            target: Target::RoutingUpdate {
                profile: Box::new(engine.store.library.routing.profiles[0].clone()),
            },
            bytes: body.to_string().into_bytes(),
        }
    }
    fn content() -> Value {
        json!({"kind":"throne-route-profile","v":1,"rules":[{"name":"remote","type":"custom","domain_suffix":["new.invalid"],"outbound":"direct"}],"default_outbound":"proxy"})
    }
    #[test]
    fn updated_profile_commits_once_keeps_other_profiles_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        engine
            .store
            .library
            .routing
            .profiles
            .push(crate::routing::RoutingProfile {
                id: "other".into(),
                ..Default::default()
            });
        let old = engine.store.library.routing.profiles[1].clone();
        let task = prepared(&engine, content());
        let result = engine.commit_routing_download(task).unwrap();
        assert_eq!(result["revision"], 1);
        assert_eq!(json!(engine.store.library.routing.profiles[1]), json!(old));
        assert!(engine.rpc.is_none());
        let saved = json!(engine.store.library.routing);
        drop(engine);
        let reopened = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
        assert_eq!(json!(reopened.store.library.routing), saved);
    }
    #[test]
    fn stale_or_invalid_remote_response_cannot_replace_saved_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = engine(dir.path());
        let task = prepared(&engine, content());
        engine.store.library.routing.profiles[0].dns["final"] = json!("changed");
        let before = json!(engine.store.library);
        assert_eq!(
            engine.commit_routing_download(task).unwrap_err(),
            "geodata_context_changed"
        );
        assert_eq!(json!(engine.store.library), before);
        let task = prepared(&engine, json!({"kind":"wrong","rules":[]}));
        assert!(engine.commit_routing_download(task).is_err());
        assert_eq!(json!(engine.store.library), before);
        assert!(engine.rpc.is_none());
    }
    #[tokio::test]
    async fn cancelling_remote_update_discards_the_prepared_request_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine(dir.path());
        let request = engine.prepare_routing_update("default").unwrap();
        let (_, cancelled) = watch::channel(true);
        assert_eq!(
            request.execute(cancelled).await.err().unwrap(),
            "geodata_cancelled"
        );
    }
}
