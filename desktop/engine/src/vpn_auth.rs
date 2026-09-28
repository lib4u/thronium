//! Ephemeral endpoint authentication. Never serialize the session or raw core
//! status: both may contain server-provided secrets. Public views are explicit.
use crate::{proto, Engine};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Longest username, password or form value, without NUL bytes.
pub const MAX_TEXT_BYTES: usize = 4096;
pub(crate) fn valid_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

mod challenges;
pub mod credentials;
mod managed;
pub(crate) mod otp;
#[cfg(test)]
mod tests;
mod validate;
use challenges::unexpired;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeRequest {
    pub session_id: String,
    pub endpoint_tag: String,
    pub challenge_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitRequest {
    pub session_id: String,
    pub endpoint_tag: String,
    pub challenge_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default, deserialize_with = "unique_form_values")]
    pub form_values: BTreeMap<String, String>,
}

fn unique_form_values<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique form response fields")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, String>()? {
                if result.len() == 128 || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("vpn_auth_invalid_response"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique)
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub session_id: Option<String>,
    pub endpoints: Vec<Endpoint>,
    pub error: Option<String>,
}

/// What the server told the core about the tunnel it established, as Qt's
/// endpoint details show it. Values are the server's own addresses, routes and
/// cipher name; they are bounded and stripped of control characters before they
/// reach the window, and no message of the core is ever among them.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tunnel {
    pub server: String,
    pub network: String,
    pub cipher: String,
    pub mtu: i32,
    pub connected_since: i64,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dns: Vec<String>,
    pub routes: Vec<String>,
    pub excluded_routes: Vec<String>,
    pub search_domains: Vec<String>,
}
/// Longest value and list the window is asked to show.
const MAX_DETAIL: usize = 128;
const MAX_DETAILS: usize = 64;
fn detail(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL)
        .collect()
}
fn details_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| detail(value))
        .filter(|value| !value.is_empty())
        .take(MAX_DETAILS)
        .collect()
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub tag: String,
    pub protocol: String,
    pub state: String,
    pub challenge_id: Option<String>,
    pub challenge_kind: Option<String>,
    pub auth_failed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otp: Option<otp::Metadata>,
    pub error: Option<String>,
    /// Present only while the tunnel is up, as the core reports it only then.
    pub tunnel: Option<Tunnel>,
}

// Serialize is deliberately confined to the explicit details response. No Debug.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub session_id: String,
    pub endpoint_tag: String,
    pub challenge_id: String,
    pub kind: String,
    pub username: String,
    pub message: String,
    pub banner: String,
    pub error: String,
    pub echo: bool,
    pub deadline: i64,
    pub fields: Vec<Field>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: String,
    pub value: String,
    pub options: Vec<Choice>,
}

#[derive(Serialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

#[derive(Default)]
pub(crate) struct Session {
    status: Status,
    instance: Option<u64>,
    primary: bool,
    last_query: Option<Instant>,
    generation: Option<u64>,
    managed_version: u32,
    managed_credentials_version: u32,
    otp: BTreeMap<String, otp::State>,
    credentials: credentials::Edits,
    /// Informational messages this window acknowledged, by (tag, challenge ID).
    acknowledged: HashSet<(String, String)>,
}

impl Session {
    pub(crate) fn start(
        request: &proto::LoadConfigReq,
        primary: bool,
        instance: Option<u64>,
    ) -> Self {
        let Ok(config) =
            serde_json::from_str::<serde_json::Value>(request.core_config.as_deref().unwrap_or(""))
        else {
            return Self::default();
        };
        let Some(endpoints) = config.get("endpoints").and_then(|v| v.as_array()) else {
            return Self::default();
        };
        let mut status = Status::default();
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            let Some(protocol) = endpoint["type"]
                .as_str()
                .and_then(crate::vpn_endpoint::protocol)
            else {
                continue;
            };
            let Some(tag) = endpoint["tag"]
                .as_str()
                .filter(|tag| validate::identity(tag))
            else {
                status.error = Some("vpn_status_unsupported".into());
                status.endpoints.clear();
                break;
            };
            if !seen.insert(tag) || status.endpoints.len() == 128 {
                status.error = Some("vpn_status_unsupported".into());
                status.endpoints.clear();
                break;
            }
            status.endpoints.push(Endpoint {
                tag: tag.into(),
                protocol: protocol.into(),
                state: "connecting".into(),
                challenge_id: None,
                challenge_kind: None,
                auth_failed: false,
                otp: None,
                error: None,
                tunnel: None,
            });
        }
        if !status.endpoints.is_empty() || status.error.is_some() {
            status.session_id = Some(uuid::Uuid::new_v4().to_string());
        }
        Self {
            status,
            instance,
            primary,
            last_query: None,
            generation: None,
            managed_version: 0,
            managed_credentials_version: 0,
            otp: BTreeMap::new(),
            credentials: credentials::Edits::default(),
            acknowledged: HashSet::new(),
        }
    }

    pub(crate) fn snapshot(&self) -> Status {
        self.status.clone()
    }

    pub(crate) fn phase(&self) -> Option<&str> {
        if !self.primary {
            return None;
        }
        if self.status.error.is_some() {
            return Some("unknown");
        }
        self.status
            .endpoints
            .iter()
            .find(|e| e.tag == "proxy")
            .map(|e| e.state.as_str())
    }

    fn unavailable(&mut self) {
        self.credentials.clear();
        self.status.error = Some("vpn_status_unavailable".into());
        for endpoint in &mut self.status.endpoints {
            endpoint.state = "unknown".into();
            endpoint.error = Some("vpn_status_unavailable".into());
            endpoint.challenge_id = None;
            endpoint.challenge_kind = None;
            endpoint.auth_failed = false;
            endpoint.tunnel = None;
        }
    }

    fn managed_unsupported(&mut self) {
        if self.status.session_id.is_none() {
            return;
        }
        self.unavailable();
        self.status.error = Some("vpn_auth_managed_unsupported".into());
        for endpoint in &mut self.status.endpoints {
            endpoint.error = self.status.error.clone();
        }
    }

    fn update(&mut self, response: &proto::VpnStatusResponse) -> Result<(), String> {
        if response.results.len() != self.status.endpoints.len() {
            return Err("vpn_status_unavailable".into());
        }
        let mut tags = HashSet::new();
        let mut endpoints = self.status.endpoints.clone();
        for status in &response.results {
            let tag = status.tag.as_deref().unwrap_or("");
            let Some(endpoint) = endpoints.iter_mut().find(|e| e.tag == tag) else {
                return Err("vpn_status_unavailable".into());
            };
            if !tags.insert(tag) {
                return Err("vpn_status_unavailable".into());
            }
            let state = status.state.as_deref().unwrap_or("");
            if !matches!(state, "connecting" | "auth-pending" | "connected" | "error")
                || (state == "connected") != status.connected.unwrap_or(false)
                || (state == "auth-pending") != status.challenge.is_some()
            {
                return Err("vpn_status_unavailable".into());
            }
            endpoint.state = state.into();
            endpoint.auth_failed = status.auth_failed.unwrap_or(false);
            endpoint.tunnel = (state == "connected").then(|| Tunnel {
                server: detail(status.server.as_deref().unwrap_or("")),
                network: detail(status.network.as_deref().unwrap_or("")),
                cipher: detail(status.cipher.as_deref().unwrap_or("")),
                mtu: status.mtu.unwrap_or(0).clamp(0, 65535),
                connected_since: status.connected_since.unwrap_or(0).max(0),
                ipv4: details_list(&status.ipv4),
                ipv6: details_list(&status.ipv6),
                dns: details_list(&status.dns),
                routes: details_list(&status.routes),
                excluded_routes: details_list(&status.excluded_routes),
                search_domains: details_list(&status.search_domains),
            });
            endpoint.error = (state == "error").then(|| "vpn_endpoint_error".into());
            endpoint.challenge_id = None;
            endpoint.challenge_kind = None;
            if let Some(challenge) = &status.challenge {
                let id = challenge.id.as_deref().unwrap_or("");
                if !validate::identity(id) || challenge.endpoint_tag.as_deref() != Some(tag) {
                    return Err("vpn_status_unavailable".into());
                }
                endpoint.challenge_id = Some(id.into());
                let kind = challenge.kind.as_deref().unwrap_or("");
                endpoint.challenge_kind = Some(
                    if matches!(
                        kind,
                        "credentials" | "secret" | "message" | "open-url" | "form" | "browser"
                    ) {
                        kind
                    } else {
                        "unsupported"
                    }
                    .into(),
                );
                if validate::details(challenge, &endpoint.protocol).is_err() {
                    endpoint.error = Some("vpn_auth_unsupported".into());
                }
                if kind == "message" && self.acknowledged.contains(&(tag.into(), id.into())) {
                    endpoint.challenge_id = None;
                    endpoint.challenge_kind = None;
                }
            }
        }
        self.credentials.observe(&endpoints);
        self.status.endpoints = endpoints;
        self.status.error = None;
        Ok(())
    }
}

impl Session {
    /// The core cannot complete an informational message; like Qt, the window
    /// stops asking once the user acknowledged it.
    pub(crate) fn acknowledge(&mut self, tag: &str, id: &str) {
        if self.acknowledged.len() >= 128 {
            self.acknowledged.clear();
        }
        self.acknowledged.insert((tag.into(), id.into()));
        for endpoint in &mut self.status.endpoints {
            if endpoint.tag == tag && endpoint.challenge_id.as_deref() == Some(id) {
                endpoint.challenge_id = None;
                endpoint.challenge_kind = None;
            }
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

impl Engine {
    pub(crate) fn reset_vpn_session(&mut self) {
        self.vpn = self
            .active_connection
            .as_ref()
            .map(|active| {
                Session::start(
                    &active.request,
                    active.vpn_primary,
                    self.rpc
                        .as_ref()
                        .and_then(|r| r.owned_process())
                        .map(|p| p.instance),
                )
            })
            .unwrap_or_default();
    }

    pub(crate) fn observe_vpn_generation(&mut self, generation: u64, version: u32) {
        if self.vpn.status.session_id.is_none()
            || (self.tun_generation != 0 && self.tun_generation != generation)
            || self.vpn.generation.is_some_and(|old| old != generation)
        {
            self.reset_vpn_session();
        }
        self.vpn.generation = (generation > 0).then_some(generation);
        self.vpn.managed_version = version;
    }

    pub(crate) fn observe_vpn_credentials_capability(&mut self, version: u32) {
        self.vpn.managed_credentials_version = version;
    }

    fn vpn_stale_generation(&mut self) {
        // Do not advance an existing form to another worker. A fresh UUID and
        // absent generation force a new backend observation and human response.
        let version = self.vpn.managed_version;
        self.reset_vpn_session();
        self.vpn.managed_version = version;
        self.vpn.unavailable();
    }

    fn vpn_live(&mut self) -> bool {
        self.vpn_credentials_transition.is_none()
            && self.vpn_credentials_proxy_transition.is_none()
            && self.running.is_some()
            && !self.tun_reconnecting
            && !self.recovery.pending()
            && self.rpc.as_mut().is_some_and(|rpc| {
                rpc.is_alive() && rpc.owned_process().map(|p| p.instance) == self.vpn.instance
            })
    }

    async fn query_vpn(&mut self) -> Result<proto::VpnStatusResponse, String> {
        if !self.vpn_live() || self.vpn.status.endpoints.is_empty() {
            return Err("vpn_status_unavailable".into());
        }
        let tags = self
            .vpn
            .status
            .endpoints
            .iter()
            .map(|e| e.tag.clone())
            .collect();
        self.vpn.last_query = Some(Instant::now());
        let request = proto::VpnStatusRequest {
            endpoint_tags: tags,
            timeout_ms: Some(0),
        };
        let rpc = self.rpc.as_mut().ok_or("vpn_status_unavailable")?;
        let result = if rpc.managed() {
            if self.vpn.managed_version != 1 {
                return Err("vpn_auth_managed_unsupported".into());
            }
            managed::query(rpc, self.vpn.generation.ok_or("vpn_auth_stale")?, request).await
        } else {
            rpc.call_with_timeout::<_, proto::VpnStatusResponse>(
                "QueryVPNStatus",
                request,
                Duration::from_secs(5),
            )
            .await
        };
        match result {
            Ok(response) if self.vpn.update(&response).is_ok() => Ok(response),
            Err(error) if error == "vpn_auth_stale" => {
                self.vpn_stale_generation();
                Err(error)
            }
            Err(error) if error == "vpn_auth_managed_unsupported" => {
                self.vpn.managed_unsupported();
                Err(error)
            }
            _ => {
                self.vpn.unavailable();
                self.observe_core_exit();
                Err("vpn_status_unavailable".into())
            }
        }
    }

    /// Backend-only refresh, also safe from ordinary poll. Never spawns a core.
    pub async fn vpn_tick(&mut self) {
        if self.vpn_credentials_transition.is_some()
            || self.vpn_credentials_proxy_transition.is_some()
        {
            return;
        }
        if self
            .vpn
            .last_query
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        if self.running.is_some() && self.rpc.as_ref().is_some_and(|rpc| rpc.managed()) {
            // The backend worker must also see a guardian generation change
            // when both WebView polling and the native tray are absent.
            let at = Instant::now();
            self.observe_tun().await;
            self.vpn.last_query = Some(at);
            if self.vpn.managed_version != 1 {
                self.vpn.managed_unsupported();
                return;
            }
        }
        if self.vpn.status.endpoints.is_empty() {
            return;
        }
        if !self.vpn_live() {
            return;
        }
        if let Ok(response) = self.query_vpn().await {
            self.auto_vpn_otp(&response).await;
        }
    }
}
