use super::{
    files::{Files, Staged},
    Selection, LIMIT,
};
use crate::{settings, Engine};
use std::time::Duration;
use tokio::sync::watch;

pub struct Download {
    client: reqwest::Client,
    files: Files,
}
pub struct Prepared(pub(super) Staged);
impl Engine {
    pub fn prepare_xray_geodata_download(
        &mut self,
        selection: Selection,
    ) -> Result<Download, String> {
        let files = Files::new(&self.data_dir, selection)?;
        let proxy = self
            .settings_download_proxy()
            .map_err(|_| "geodata_proxy_unavailable")?;
        let client = settings::network::client(&self.store.library, proxy.as_deref())
            .map_err(|_| "geodata_proxy_unavailable")?
            .https_only(true)
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(
                settings::integer(&self.store.library, "network_timeout").clamp(5, 60) as u64,
            ))
            .redirect(crate::bounded_download::redirects(|url| {
                crate::bounded_download::secure_url(url) && url.fragment().is_none()
            }))
            .build()
            .map_err(|_| "geodata_download_failed")?;
        super::history::remember(self, files.selection.clone())?;
        Ok(Download { client, files })
    }
}
fn network_error(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "geodata_timeout"
    } else {
        "geodata_download_failed"
    }
    .into()
}
impl Download {
    pub async fn execute(self, mut cancelled: watch::Receiver<bool>) -> Result<Prepared, String> {
        if *cancelled.borrow() {
            return Err("geodata_cancelled".into());
        }
        let fetch = async {
            let response = self
                .client
                .get(&self.files.selection.url)
                .send()
                .await
                .map_err(network_error)?;
            if !response.status().is_success() {
                return Err("geodata_download_rejected".to_owned());
            }
            crate::bounded_download::body(response, LIMIT)
                .await
                .map_err(|error| match error {
                    crate::bounded_download::BodyError::TooLarge => "geodata_too_large".into(),
                    crate::bounded_download::BodyError::Network(e) => network_error(e),
                })
        };
        let bytes = tokio::select! {biased;_ = cancelled.wait_for(|v|*v)=>return Err("geodata_cancelled".into()),result=fetch=>result?};
        tokio::task::spawn_blocking(move || {
            self.files
                .stage(&bytes, || *cancelled.borrow())
                .map(Prepared)
        })
        .await
        .map_err(|_| "geodata_write_failed")?
    }
}
