use super::{boolean as b, integer as n, string as s};
use crate::{store::Library, Engine};
use serde_json::Value;

use std::time::Duration;
mod hwid;
pub fn client(l: &Library, proxy: Option<&str>) -> Result<reqwest::ClientBuilder, String> {
    let mut client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(b(l, "net_insecure"))
        .timeout(Duration::from_secs(n(l, "network_timeout") as u64))
        .user_agent(s(l, "user_agent"));
    if b(l, "net_use_proxy") {
        client = client.proxy(
            reqwest::Proxy::all(proxy.ok_or("subscription_proxy_unavailable")?)
                .map_err(|_| "subscription_proxy_unavailable")?,
        );
    }
    Ok(client)
}
pub fn subscription_defaults(settings: &mut crate::subscriptions::Settings, l: &Library) {
    if settings.inherit_defaults == Some(true) {
        settings.user_agent = s(l, "user_agent");
        settings.interval_minutes = n(l, "sub_auto_update") as u32;
    }
}
pub fn subscription_transport(settings: &mut crate::subscriptions::Settings, l: &Library) {
    subscription_defaults(settings, l);
    settings.via_proxy |= b(l, "net_use_proxy");
    settings.allow_insecure = b(l, "net_insecure");
    settings.timeout_seconds = n(l, "network_timeout") as u64;
    hwid::apply(
        &mut settings.headers,
        b(l, "sub_send_hwid"),
        &s(l, "sub_custom_hwid_params"),
        &mut hwid::SystemDevice,
    );
}
impl Engine {
    pub fn settings_download_proxy(&self) -> Result<Option<String>, String> {
        if b(&self.store.library, "net_use_proxy") {
            self.application_proxy()
        } else {
            Ok(None)
        }
    }
    pub fn application_proxy(&self) -> Result<Option<String>, String> {
        let Some(connection) = self.active_connection.as_ref() else {
            return Ok(None);
        };
        let core: Value = serde_json::from_str(
            connection
                .request
                .core_config
                .as_deref()
                .ok_or("subscription_proxy_unavailable")?,
        )
        .map_err(|_| "subscription_proxy_unavailable")?;
        let local = crate::config::local_inbound(&core, crate::config::HTTP_PROXY)
            .ok_or("subscription_proxy_unavailable")?;
        let inbound = local.inbound;
        let mut url = reqwest::Url::parse(&format!("http://{}", local.address()))
            .map_err(|_| "subscription_proxy_unavailable")?;
        if let Some(user) = inbound["users"].as_array().and_then(|users| users.first()) {
            url.set_username(user["username"].as_str().unwrap_or(""))
                .map_err(|_| "subscription_proxy_unavailable")?;
            url.set_password(user["password"].as_str())
                .map_err(|_| "subscription_proxy_unavailable")?;
        }
        Ok(Some(url.to_string()))
    }
}

pub fn mirror(url: &str, kind: &str) -> String {
    let host = match kind {
        "cloudflare" => "testingcf.jsdelivr.net",
        "gcore" => "gcore.jsdelivr.net",
        "quantil" => "quantil.jsdelivr.net",
        "fastly" => "fastly.jsdelivr.net",
        "cdn" => "cdn.jsdelivr.net",
        _ => return url.into(),
    };
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return url.into();
    };
    if parsed.host_str() != Some("raw.githubusercontent.com") || parsed.scheme() != "https" {
        return url.into();
    }
    let segments: Vec<_> = parsed.path().trim_start_matches('/').split('/').collect();
    if segments.len() < 4 {
        return url.into();
    }
    format!(
        "https://{host}/gh/{}/{}@{}/{}",
        segments[0],
        segments[1],
        segments[2],
        segments[3..].join("/")
    )
}
