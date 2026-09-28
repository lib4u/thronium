//! Consumer WARP registration compatible with the original Qt workflow.
//! Only the public key is sent; generated parameters remain an unsaved draft.
use crate::Engine;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};
use tokio::sync::watch;

pub(crate) mod routing;

/// Reserved tag of the original proxy after the settings WARP exit wraps it.
pub(crate) const BASE_TAG: &str = "settings-warp-base";

pub const TERMS_URL: &str = "https://www.cloudflare.com/application/terms/";
const API: &str = "https://api.cloudflareclient.com/v0a737/reg";
const LIMIT: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRequest {
    pub request_id: String,
    pub accept_terms: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelRequest {
    pub request_id: String,
}
pub struct RegistrationRequests;
impl crate::request_jobs::Codes for RegistrationRequests {
    const INVALID: &'static str = "warp_invalid_request";
    const FINISHED: &'static str = "warp_request_finished";
    const BUSY: &'static str = "warp_busy";
}
/// Registration requests; starting one requires accepting the terms.
#[derive(Default)]
pub struct Jobs(crate::request_jobs::Jobs<RegistrationRequests>);
impl Jobs {
    pub fn begin(&mut self, request: &StartRequest) -> Result<watch::Receiver<bool>, String> {
        if !crate::request_jobs::valid_id(&request.request_id) {
            return Err("warp_invalid_request".into());
        }
        if !request.accept_terms {
            return Err("warp_terms_required".into());
        }
        self.0.begin(&request.request_id)
    }
    pub fn cancel(&mut self, id: &str) -> Result<(), String> {
        self.0.cancel(id)
    }
    pub fn cancel_all(&mut self) {
        self.0.cancel_all()
    }
    pub fn finish(&mut self, id: &str) {
        self.0.finish(id)
    }
    pub fn is_active(&self) -> bool {
        self.0.is_active()
    }
}

/// Tunnel values of a WARP WireGuard peer, as Qt generates them.
pub const MTU: u16 = 1280;
pub const PERSISTENT_KEEPALIVE_SECONDS: u16 = 10;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub private_key: String,
    pub client_public_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<String>,
    pub reserved: Vec<u8>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
}
pub struct Registration {
    client: reqwest::Client,
    private_key: String,
    public_key: String,
    accepted_at: String,
}
fn key(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && bytes.iter().any(|b| *b != 0))
}
impl Engine {
    /// Prepare under the Engine lock; release it before execute. Do not cancel
    /// halfway through GenWgKeyPair: finish that RPC before abandoning its result.
    pub async fn prepare_warp_registration(&mut self) -> Result<Registration, String> {
        let proxy = self
            .settings_download_proxy()
            .map_err(|_| "warp_proxy_unavailable")?;
        let client = super::network::client(&self.store.library, proxy.as_deref())
            .map_err(|_| "warp_proxy_unavailable")?
            .user_agent("WARP for Android")
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(
                super::integer(&self.store.library, "network_timeout").clamp(1, 10) as u64,
            ))
            .build()
            .map_err(|_| "warp_request_failed")?;
        let pair = self
            .generate_wg_keys()
            .await
            .map_err(|_| "warp_key_generation_failed")?;
        let private_key = pair["privateKey"]
            .as_str()
            .filter(|s| key(s))
            .ok_or("warp_key_generation_failed")?
            .to_owned();
        let public_key = pair["publicKey"]
            .as_str()
            .filter(|s| key(s))
            .ok_or("warp_key_generation_failed")?
            .to_owned();
        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        Ok(Registration {
            client,
            private_key,
            public_key,
            accepted_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
        })
    }
}
impl Registration {
    fn payload(&self) -> Value {
        json!({"key":self.public_key,"install_id":"","warp_enabled":true,"tos":self.accepted_at,
            "type":match std::env::consts::OS { "linux"=>"Linux","macos"=>"Darwin","windows"=>"Windows",_=>"Unknown" },"locale":"en_US"})
    }
    pub async fn execute(self, cancelled: &mut watch::Receiver<bool>) -> Result<Config, String> {
        if *cancelled.borrow() {
            return Err("warp_cancelled".into());
        }
        let request = async {
            let body = serde_json::to_vec(&self.payload()).map_err(|_| "warp_request_failed")?;
            let mut response = self
                .client
                .post(API)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        "warp_timeout"
                    } else {
                        "warp_request_failed"
                    }
                })?;
            if !response.status().is_success() {
                return Err("warp_registration_rejected".into());
            }
            if response.content_length().is_some_and(|n| n > LIMIT as u64) {
                return Err("warp_invalid_response".into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                if error.is_timeout() {
                    "warp_timeout"
                } else {
                    "warp_request_failed"
                }
            })? {
                if bytes.len().saturating_add(chunk.len()) > LIMIT {
                    return Err("warp_invalid_response".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            parse(&bytes, &self.private_key, &self.public_key)
        };
        tokio::select! {
            biased;
            _ = cancelled.wait_for(|value| *value) => Err("warp_cancelled".into()),
            result = request => result,
        }
    }
}
fn endpoint(raw: &str) -> Result<(String, String, u16), String> {
    let fail = || "warp_invalid_response".to_owned();
    if raw.is_empty()
        || raw.len() > 512
        || raw.trim() != raw
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(fail());
    }
    let url = reqwest::Url::parse(&format!("udp://{raw}")).map_err(|_| fail())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || !url.path().is_empty()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(fail());
    }
    let host = url
        .host_str()
        .ok_or_else(fail)?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port().filter(|p| *p > 0).ok_or_else(fail)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(fail());
        }
    } else if host.len() > 253
        || !host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(fail());
    }
    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok((address, host, port))
}
fn parse(bytes: &[u8], private_key: &str, public_key: &str) -> Result<Config, String> {
    let fail = || "warp_invalid_response".to_owned();
    if bytes.len() > LIMIT || !key(private_key) || !key(public_key) {
        return Err(fail());
    }
    let response: Value = serde_json::from_slice(bytes).map_err(|_| fail())?;
    let config = response
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(fail)?;
    let peers = config
        .get("peers")
        .and_then(Value::as_array)
        .filter(|p| !p.is_empty() && p.len() <= 16)
        .ok_or_else(fail)?;
    let peer = peers[0].as_object().ok_or_else(fail)?;
    let peer_public_key = peer
        .get("public_key")
        .and_then(Value::as_str)
        .filter(|s| key(s))
        .ok_or_else(fail)?
        .to_owned();
    let reserved = STANDARD
        .decode(
            config
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(fail)?,
        )
        .map_err(|_| fail())?;
    if reserved.len() != 3 {
        return Err(fail());
    }
    let endpoint_object = peer
        .get("endpoint")
        .filter(|v| !v.is_null())
        .map(|v| v.as_object().ok_or_else(fail))
        .transpose()?;
    let raw = endpoint_object
        .and_then(|o| o.get("host"))
        .map(|v| v.as_str().ok_or_else(fail))
        .transpose()?
        .filter(|s| !s.is_empty())
        .unwrap_or("engage.cloudflareclient.com:2408");
    let (endpoint, host, port) = endpoint(raw)?;
    let interface = config
        .get("interface")
        .and_then(|v| v.get("addresses"))
        .and_then(Value::as_object)
        .ok_or_else(fail)?;
    let mut addresses = Vec::new();
    for (name, bits) in [("v4", 32), ("v6", 128)] {
        let Some(value) = interface.get(name) else {
            continue;
        };
        let raw = value.as_str().ok_or_else(fail)?;
        if raw.is_empty() {
            continue;
        }
        let ip = raw.parse::<IpAddr>().map_err(|_| fail())?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_ipv4() != (bits == 32) {
            return Err(fail());
        }
        addresses.push(format!("{ip}/{bits}"));
    }
    if addresses.is_empty() {
        return Err(fail());
    }
    Ok(Config {
        private_key: private_key.into(),
        client_public_key: public_key.into(),
        peer_public_key,
        endpoint,
        host,
        port,
        addresses,
        reserved,
        mtu: MTU,
        persistent_keepalive: PERSISTENT_KEEPALIVE_SECONDS,
    })
}

/// Credentials required by either the global exit or an explicit routing target.
pub(super) fn validate(library: &crate::store::Library) -> Result<(), String> {
    use super::{string, value};
    let invalid = |key: &str| format!("settings_invalid:{key}");
    for key in ["warp_private_key", "warp_public_key"] {
        if base64::engine::general_purpose::STANDARD
            .decode(string(library, key))
            .map_or(true, |b| b.len() != 32)
        {
            return Err(invalid(key));
        }
    }
    if value(library, "warp_ifc_addrs")
        .as_array()
        .is_none_or(|a| a.is_empty())
    {
        return Err(invalid("warp_ifc_addrs"));
    }
    if value(library, "warp_reserved").as_array().is_some_and(|a| {
        !a.is_empty()
            && (a.len() != 3
                || a.iter()
                    .any(|v| v.as_str().is_none_or(|s| s.parse::<u8>().is_err())))
    }) {
        return Err(invalid("warp_reserved"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
