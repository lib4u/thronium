use super::files::{Assets, Receipt, MAX_ARCHIVE};
use crate::{settings, Engine};
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::watch;

pub const URL: &str =
    "https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/gh-pages.zip";
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
}
pub struct Installation;
impl crate::request_jobs::Codes for Installation {
    const INVALID: &'static str = "dashboard_invalid_request";
    const FINISHED: &'static str = "dashboard_request_finished";
    const BUSY: &'static str = "dashboard_busy";
}
pub type Jobs = crate::request_jobs::Jobs<Installation>;

pub struct Download {
    client: reqwest::Client,
    assets: Assets,
}
impl Engine {
    pub fn prepare_dashboard_download(&mut self) -> Result<Download, String> {
        let proxy = self
            .settings_download_proxy()
            .map_err(|_| "dashboard_proxy_unavailable")?;
        let client = settings::network::client(&self.store.library, proxy.as_deref())
            .map_err(|_| "dashboard_proxy_unavailable")?
            .https_only(true)
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() > 3 || !allowed_redirect(attempt.url()) {
                    attempt.error("dashboard_redirect_refused")
                } else {
                    attempt.follow()
                }
            }))
            .timeout(Duration::from_secs(
                settings::integer(&self.store.library, "network_timeout").clamp(5, 60) as u64,
            ))
            .build()
            .map_err(|_| "dashboard_download_failed")?;
        let assets = Assets::new(&self.data_dir);
        assets.ensure()?;
        Ok(Download { client, assets })
    }
}
fn allowed_redirect(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && matches!(url.host_str(), Some("github.com" | "codeload.github.com"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}
fn network_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "dashboard_timeout"
    } else {
        "dashboard_download_failed"
    }
    .into()
}
impl Download {
    pub async fn execute(self, mut cancelled: watch::Receiver<bool>) -> Result<Receipt, String> {
        if *cancelled.borrow() {
            return Err("dashboard_cancelled".into());
        }
        let fetch = async {
            let mut response = self.client.get(URL).send().await.map_err(network_error)?;
            if !response.status().is_success() {
                return Err("dashboard_download_rejected".to_owned());
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_ARCHIVE as u64)
            {
                return Err("dashboard_archive_too_large".into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(network_error)? {
                if bytes.len().saturating_add(chunk.len()) > MAX_ARCHIVE {
                    return Err("dashboard_archive_too_large".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        };
        let bytes = tokio::select! {biased;_ = cancelled.wait_for(|v|*v)=>return Err("dashboard_cancelled".into()),value=fetch=>value?};
        if *cancelled.borrow() {
            return Err("dashboard_cancelled".into());
        }
        tokio::task::spawn_blocking(move || self.assets.install(&bytes, || *cancelled.borrow()))
            .await
            .map_err(|_| "dashboard_files_unavailable")?
    }
}

#[cfg(test)]
mod tests;
