//! Explicit, ephemeral credentials for a terminal primary Local VPN session.
use super::*;
use crate::connection::ActiveConnection;
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod managed;
mod transition;
pub(crate) use transition::Transition;
mod system_proxy;
pub(crate) use system_proxy::ProxyTransition;

#[cfg(all(test, target_os = "linux"))]
mod managed_tests;
#[cfg(all(test, target_os = "linux"))]
mod tests;

const EDIT_TTL: Duration = Duration::from_secs(300);
const MAX_EDITS: usize = 16;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRequest {
    pub session_id: String,
    pub endpoint_tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialEditRequest {
    pub session_id: String,
    pub endpoint_tag: String,
    pub edit_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestartCredentialsRequest {
    pub session_id: String,
    pub endpoint_tag: String,
    pub edit_token: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialView {
    pub session_id: String,
    pub endpoint_tag: String,
    pub edit_token: String,
    pub username: String,
}

struct Prepared {
    session: String,
    tag: String,
    instance: u64,
    generation: Option<u64>,
    fingerprint: [u8; 32],
    created: Instant,
}

#[derive(Default)]
pub(super) struct Edits(BTreeMap<String, Prepared>);
impl Edits {
    pub(super) fn observe(&mut self, endpoints: &[Endpoint]) {
        self.0.retain(|_, edit| {
            endpoints.iter().any(|endpoint| {
                endpoint.tag == edit.tag
                    && endpoint.state == "error"
                    && endpoint.auth_failed
                    && endpoint.challenge_id.is_none()
            })
        });
    }
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
    fn take(&mut self, request: &CredentialEditRequest, capture: &Capture) -> Result<(), String> {
        let edit = self
            .0
            .get(&request.edit_token)
            .ok_or("vpn_credentials_stale")?;
        // Wrong old identity must never consume another dialog's current token.
        if edit.session != request.session_id
            || edit.tag != request.endpoint_tag
            || edit.instance != capture.instance
            || edit.generation != capture.generation
            || edit.fingerprint != capture.fingerprint
        {
            return Err("vpn_credentials_stale".into());
        }
        let expired = edit.created.elapsed() > EDIT_TTL;
        self.0.remove(&request.edit_token);
        if expired {
            Err("vpn_credentials_expired".into())
        } else {
            Ok(())
        }
    }
}

struct Capture {
    connection: ActiveConnection,
    instance: u64,
    generation: Option<u64>,
    fingerprint: [u8; 32],
}

/// The VPN endpoint of the running configuration the person is signing in to
/// again. It is the connection's own exit as often as a hop of a chain, a
/// member of a pool or an endpoint a route sends traffic to.
pub(super) fn endpoint_config(
    request: &proto::LoadConfigReq,
    tag: &str,
) -> Result<(Value, usize), String> {
    let config: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("vpn_credentials_unsupported")?,
    )
    .map_err(|_| "vpn_credentials_unsupported")?;
    let endpoints = config["endpoints"]
        .as_array()
        .ok_or("vpn_credentials_unsupported")?;
    let mut found = endpoints
        .iter()
        .enumerate()
        .filter(|(_, endpoint)| endpoint["tag"] == tag);
    let (index, primary) = found.next().ok_or("vpn_credentials_unsupported")?;
    if found.next().is_some() || !crate::vpn_endpoint::is_vpn(primary) {
        return Err("vpn_credentials_unsupported".into());
    }
    if primary["type"] == "openconnect" {
        let nonempty = |key: &str| {
            primary.get(key).is_some_and(|value| match value {
                Value::Null => false,
                Value::String(value) => !value.is_empty(),
                Value::Array(value) => !value.is_empty(),
                Value::Object(value) => !value.is_empty(),
                _ => true,
            })
        };
        if primary["password_authentication_disabled"] == true
            || ["cookie", "token", "form_entries"]
                .iter()
                .any(|key| nonempty(key))
        {
            return Err("vpn_credentials_configuration_unsupported".into());
        }
    }
    Ok((config, index))
}

fn valid_credentials(username: &str, password: &str) -> bool {
    (!username.is_empty() || !password.is_empty())
        && [username, password]
            .iter()
            .all(|value| super::valid_text(value) && !value.contains("{otp}"))
}

impl Engine {
    fn credentials_capture(&mut self, session: &str, tag: &str) -> Result<Capture, String> {
        if !cfg!(target_os = "linux") || !super::validate::identity(tag) {
            return Err("vpn_credentials_unsupported".into());
        }
        if self.vpn_credentials_transition.is_some() {
            return Err("tun_recovery_failed".into());
        }
        self.credentials_proxy_guard()?;
        if !validate::identity(session) || self.vpn.status.session_id.as_deref() != Some(session) {
            return Err("vpn_credentials_stale".into());
        }
        let active = self
            .active_connection
            .as_ref()
            .ok_or("vpn_credentials_stale")?;
        if active.external_instance.is_some() {
            return Err("vpn_credentials_unsupported".into());
        }
        if active.system_port.is_some() && (active.tun || !self.system_proxy.status().available) {
            return Err("vpn_credentials_unsupported".into());
        }
        let is_managed = self.rpc.as_ref().is_some_and(|rpc| rpc.managed());
        if active.tun != is_managed {
            return Err("vpn_credentials_unsupported".into());
        }
        let generation = if is_managed {
            if self.vpn.managed_credentials_version != 1 {
                return Err("vpn_credentials_managed_unsupported".into());
            }
            Some(self.vpn.generation.ok_or("vpn_credentials_stale")?)
        } else {
            None
        };
        if self.running.as_deref() != Some(active.id.as_str()) {
            return Err("vpn_credentials_stale".into());
        }
        let connection = active.clone();
        // A complete configuration the person wrote is never rewritten from
        // here, whatever it happens to tag its endpoints.
        if self.profile(&connection.id).is_ok_and(|profile| {
            matches!(
                profile.kind,
                crate::store::ProfileKind::SingBoxConfig | crate::store::ProfileKind::XrayConfig
            )
        }) {
            return Err("vpn_credentials_unsupported".into());
        }
        endpoint_config(&connection.request, tag)?;
        if connection
            .vpn_otp
            .get(tag)
            .is_some_and(|binding| !binding.credentials_supported())
        {
            return Err("vpn_credentials_configuration_unsupported".into());
        }
        if !self.vpn_live() {
            return Err("vpn_credentials_stale".into());
        }
        let instance = self
            .rpc
            .as_ref()
            .and_then(|rpc| rpc.owned_process())
            .map(|process| process.instance)
            .ok_or("vpn_credentials_stale")?;
        let mut hash = Sha256::new();
        hash.update(connection.id.as_bytes());
        hash.update([0]);
        hash.update(connection.request.encode_to_vec());
        Ok(Capture {
            connection,
            instance,
            generation,
            fingerprint: hash.finalize().into(),
        })
    }

    async fn fresh_credentials_status(
        &mut self,
        session: &str,
        tag: &str,
        capture: &Capture,
    ) -> Result<(), String> {
        let response = self.query_vpn().await.map_err(|error| {
            if error == "vpn_auth_stale" {
                "vpn_credentials_stale"
            } else {
                "vpn_credentials_unavailable"
            }
        })?;
        let current = self.credentials_capture(session, tag)?;
        if current.instance != capture.instance
            || current.generation != capture.generation
            || current.fingerprint != capture.fingerprint
        {
            return Err("vpn_credentials_stale".into());
        }
        if !response.results.iter().any(|result| {
            result.tag.as_deref() == Some(tag)
                && result.state.as_deref() == Some("error")
                && result.auth_failed == Some(true)
                && result.challenge.is_none()
        }) {
            return Err("vpn_credentials_unavailable".into());
        }
        Ok(())
    }

    pub async fn vpn_credentials(
        &mut self,
        request: CredentialRequest,
    ) -> Result<CredentialView, String> {
        let capture = self.credentials_capture(&request.session_id, &request.endpoint_tag)?;
        if capture.connection.system_port.is_some() {
            self.proxy_credentials_details(&request, &capture).await?;
        } else {
            self.fresh_credentials_status(&request.session_id, &request.endpoint_tag, &capture)
                .await?;
        }
        let (config, index) = endpoint_config(&capture.connection.request, &request.endpoint_tag)?;
        let username = config["endpoints"][index]["username"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        if !super::valid_text(&username) {
            return Err("vpn_credentials_configuration_unsupported".into());
        }
        let edits = &mut self.vpn.credentials.0;
        edits.retain(|_, edit| edit.created.elapsed() <= EDIT_TTL);
        if edits.len() >= MAX_EDITS {
            if let Some(oldest) = edits
                .iter()
                .min_by_key(|(_, edit)| edit.created)
                .map(|(token, _)| token.clone())
            {
                edits.remove(&oldest);
            }
        }
        let token = uuid::Uuid::new_v4().to_string();
        edits.insert(
            token.clone(),
            Prepared {
                session: request.session_id.clone(),
                tag: request.endpoint_tag.clone(),
                instance: capture.instance,
                generation: capture.generation,
                fingerprint: capture.fingerprint,
                created: Instant::now(),
            },
        );
        Ok(CredentialView {
            session_id: request.session_id,
            endpoint_tag: request.endpoint_tag,
            edit_token: token,
            username,
        })
    }

    pub fn cancel_vpn_credentials(&mut self, request: CredentialEditRequest) -> Result<(), String> {
        let capture = self.credentials_capture(&request.session_id, &request.endpoint_tag)?;
        self.vpn.credentials.take(&request, &capture)
    }

    async fn check_credentials_request(
        &mut self,
        request: &proto::LoadConfigReq,
        instance: u64,
    ) -> Result<(), String> {
        let rpc = self.rpc.as_mut().ok_or("vpn_credentials_stale")?;
        if !rpc.is_alive() || rpc.owned_process().map(|owned| owned.instance) != Some(instance) {
            return Err("vpn_credentials_stale".into());
        }
        let mut singbox = request.clone();
        singbox.need_xray = Some(false);
        let result = rpc
            .call::<_, proto::ErrorResp>("CheckConfig", singbox)
            .await
            .and_then(crate::core_result);
        let result = if result.is_ok() && request.need_xray == Some(true) {
            rpc.call::<_, proto::ErrorResp>("CheckConfig", request.clone())
                .await
                .and_then(crate::core_result)
        } else {
            result
        };
        result.map_err(|_| {
            self.logs
                .event("warn", "vpn_credentials_check_logged", None);
            "vpn_credentials_check_failed".into()
        })
    }

    pub async fn restart_vpn_credentials(
        &mut self,
        request: RestartCredentialsRequest,
    ) -> Result<(), String> {
        let capture = self.credentials_capture(&request.session_id, &request.endpoint_tag)?;
        let identity = CredentialEditRequest {
            session_id: request.session_id,
            endpoint_tag: request.endpoint_tag,
            edit_token: request.edit_token,
        };
        self.vpn.credentials.take(&identity, &capture)?;
        if !valid_credentials(&request.username, &request.password) {
            return Err("vpn_credentials_invalid".into());
        }
        if capture.connection.system_port.is_some() {
            return self
                .restart_proxy_credentials(&identity, capture, request.username, request.password)
                .await;
        }
        self.fresh_credentials_status(&identity.session_id, &identity.endpoint_tag, &capture)
            .await?;
        let mut candidate = capture.connection.clone();
        let (mut config, index) = endpoint_config(&candidate.request, &identity.endpoint_tag)?;
        config["endpoints"][index]["username"] = json!(request.username);
        config["endpoints"][index]["password"] = json!(request.password);
        candidate.request.core_config = Some(config.to_string());
        if let Some(binding) = candidate.vpn_otp.get_mut(&identity.endpoint_tag) {
            binding.session_credentials(&request.username, &request.password);
        }
        if let Some(generation) = capture.generation {
            return self
                .replace_managed_credentials(
                    capture,
                    candidate,
                    generation,
                    request.username,
                    request.password,
                )
                .await;
        }
        self.check_credentials_request(&candidate.request, capture.instance)
            .await?;
        self.fresh_credentials_status(&identity.session_id, &identity.endpoint_tag, &capture)
            .await?;
        let applied_revision = self.routing_revision;
        if self.disconnect().await.is_err() {
            if self.running.is_some() {
                return Err("vpn_credentials_restart_failed".into());
            }
            let error = self
                .recover_connection(
                    Some(capture.connection),
                    "vpn_credentials_restart_failed".into(),
                )
                .await;
            if self.running.is_some() {
                self.routing_revision = applied_revision;
            }
            return Err(error);
        }
        if self.start_connection(candidate).await.is_err() {
            let error = self
                .recover_connection(
                    Some(capture.connection),
                    "vpn_credentials_restart_failed".into(),
                )
                .await;
            if self.running.is_some() {
                self.routing_revision = applied_revision;
            }
            return Err(error);
        }
        self.routing_revision = applied_revision;
        self.recovery = crate::recovery::Recovery::default();
        Ok(())
    }
}
