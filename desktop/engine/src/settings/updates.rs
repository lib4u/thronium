use crate::{store::Library, Engine};
use serde_json::{json, Value};
/// Upstream metadata only. Thronium's sidecar is built from its own pinned sources;
/// a Throne release must never overwrite this application's binary.
pub struct Check {
    library: Library,
    proxy: Option<String>,
}
impl Engine {
    pub fn release_check(&self) -> Result<Check, String> {
        Ok(Check {
            library: self.store.library.clone(),
            proxy: self.settings_download_proxy()?,
        })
    }
}
impl Check {
    pub async fn execute(self) -> Result<Value, String> {
        let client = super::network::client(&self.library, self.proxy.as_deref())?
            .build()
            .map_err(|_| "update_check_failed")?;
        let mut response = client
            .get("https://api.github.com/repos/throneproj/Throne/releases?per_page=30")
            .send()
            .await
            .map_err(|_| "update_check_failed")?
            .error_for_status()
            .map_err(|_| "update_check_failed")?;
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| "update_check_failed")? {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err("update_check_failed".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let list: Value = serde_json::from_slice(&bytes).map_err(|_| "update_check_failed")?;
        let release = list
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| {
                r["draft"] != true
                    && (super::boolean(&self.library, "allow_beta_update")
                        || r["prerelease"] != true)
            })
            .ok_or("update_release_missing")?;
        let url = release["html_url"]
            .as_str()
            .filter(|s| s.starts_with("https://github.com/throneproj/Throne/releases/"))
            .ok_or("update_check_failed")?;
        Ok(
            json!({"project":"Throne","version":release["tag_name"],"publishedAt":release["published_at"],"prerelease":release["prerelease"],"url":url}),
        )
    }
}
