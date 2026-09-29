//! Subscription transport and atomic reconciliation. URLs and headers are only
//! returned by explicit group editing, never by the periodic public snapshot.
use crate::{
    routing,
    store::{Group, Profile},
    Engine, ProfileDraft,
};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION},
    redirect::Policy,
    Url,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{watch, Mutex};
mod identity;
mod reconcile;
use reconcile::reconcile;
pub mod jobs;
pub mod metadata;
pub mod name_rules;
pub(crate) mod provider_policy;
pub mod provider_routing;
use metadata::Metadata;

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROFILES: usize = 1000;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// User-Agent a subscription sends unless it overrides it.
pub const DEFAULT_USER_AGENT: &str = concat!("Throne/Thronium-", env!("CARGO_PKG_VERSION"));
/// Longest automatic update interval, in minutes (30 days).
pub const MAX_INTERVAL_MINUTES: u32 = 43_200;
pub const MAX_URL_BYTES: usize = 8192;
pub const MAX_USER_AGENT_BYTES: usize = 1024;
pub const MAX_HEADERS: usize = 64;
/// Total bytes of all custom header names and values.
pub const MAX_HEADER_BYTES: usize = 16384;
pub(crate) fn user_agent() -> String {
    DEFAULT_USER_AGENT.into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default)]
    pub name_rules: name_rules::NameRules,
    #[serde(default)]
    pub inherit_defaults: Option<bool>,
    #[serde(skip)]
    pub allow_insecure: bool,
    #[serde(skip)]
    pub timeout_seconds: u64,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub via_proxy: bool,
    #[serde(default)]
    pub use_provider_routing: bool,
    #[serde(default)]
    pub interval_minutes: u32,
}
impl Settings {
    /// The "network timeout" setting (5–300 s) for a whole download; a
    /// subscription without resolved defaults uses 30 s.
    fn timeout(&self) -> Duration {
        Duration::from_secs(if self.timeout_seconds == 0 {
            30
        } else {
            self.timeout_seconds
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        valid_url(&self.url)?;
        self.name_rules.validate()?;
        if self.interval_minutes > MAX_INTERVAL_MINUTES {
            return Err("invalid_subscription_interval".into());
        }
        if self.headers.len() > MAX_HEADERS
            || self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > MAX_HEADER_BYTES
            || self.user_agent.len() > MAX_USER_AGENT_BYTES
            || HeaderValue::from_str(&self.user_agent).is_err()
        {
            return Err("invalid_subscription_headers".into());
        }
        for (key, value) in &self.headers {
            if HeaderName::from_bytes(key.as_bytes()).is_err()
                || HeaderValue::from_str(value).is_err()
                || matches!(
                    key.to_ascii_lowercase().as_str(),
                    "host"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "proxy-authorization"
                )
            {
                return Err("invalid_subscription_headers".into());
            }
        }
        Ok(())
    }
}
/// Statuses a subscription server commonly answers with; each is a registered
/// code the window shows with its number. Any other failure status is
/// `subscription_http_error`.
const HTTP_STATUSES: [u16; 16] = [
    206, 400, 401, 402, 403, 404, 405, 407, 408, 410, 429, 451, 500, 502, 503, 504,
];
fn valid_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "invalid_subscription_url")?;
    if value.len() > MAX_URL_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid_subscription_url".into());
    }
    Ok(url)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(flatten)]
    pub settings: Settings,
    #[serde(default)]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub usage: Option<Usage>,
    #[serde(default)]
    pub managed_ids: Vec<String>,
    #[serde(default)]
    pub last_update: Option<jobs::LastUpdate>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupDraft {
    #[serde(default)]
    pub proxy_chain: Option<crate::group_chains::GroupChain>,
    #[serde(default)]
    pub auto_clear_unavailable: Option<bool>,
    pub id: Option<String>,
    pub name: String,
    pub subscription: Option<Settings>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub id: String,
    pub name: String,
    pub action: String,
    pub reason: Option<String>,
}
#[derive(Clone)]
pub struct Plan {
    pub profiles: Vec<Profile>,
    pub managed_ids: Vec<String>,
    pub changes: Vec<Change>,
}

pub struct Request {
    pub settings: Settings,
    pub proxy: Option<String>,
    group_id: String,
    stamp: Value,
}
/// A downloaded subscription stays reviewable this long after its last use; a
/// long validation of a large subscription keeps it alive.
const TICKET_IDLE: Duration = Duration::from_secs(600);
pub struct Ticket {
    metadata: Metadata,
    group_id: String,
    stamp: Value,
    used: Instant,
    usage: Option<Usage>,
    plan: Option<Plan>,
    /// Rows the caller could not import. Set with the preview, reported by the
    /// applied update; a manual import that lost nothing leaves it at zero.
    pub(crate) omitted: jobs::Omitted,
    /// Why an automatic check left something out; the update then asks for review.
    pub(crate) review: Option<&'static str>,
}
impl Ticket {
    fn expired(&self) -> bool {
        self.used.elapsed() > TICKET_IDLE
    }
    fn touch(&mut self) {
        self.used = Instant::now();
    }
}
impl Engine {
    /// A subscription change to this profile would restart the running
    /// connection: it is in use and not a pool member that opted into rebuilds.
    pub(crate) fn subscription_change_restarts(&self, id: &str) -> bool {
        self.running_uses(id) && !self.selector_member_subscription_allowed(id)
    }
    /// An automatic update keeps such a profile unless the user allowed
    /// updates to stop the active profile.
    pub(crate) fn subscription_update_keeps_running(&self, id: &str) -> bool {
        self.subscription_change_restarts(id)
            && !crate::settings::boolean(&self.store.library, "allow_stopping_active_profile")
    }
    fn subscription_stamp(&self, id: &str) -> Result<Value, String> {
        let mut group = json!(self.group(id)?);
        group.as_object_mut().unwrap().remove("collapsed");
        if let Some(subscription) = group["subscription"].as_object_mut() {
            subscription.remove("lastUpdate");
        }
        let group_proxies = self
            .store
            .library
            .profiles
            .iter()
            .filter(|p| {
                crate::group_chains::referenced(
                    &self.store.library,
                    &HashSet::from([p.id.clone()]),
                    None,
                )
            })
            .map(|p| json!([p, self.store.library.preferences.vless_overrides.get(&p.id)]))
            .collect::<Vec<_>>();
        Ok(
            json!({"defaults":crate::settings::section(&self.store.library,"subscriptions"),"network":crate::settings::section(&self.store.library,"network"),"group":group, "groupProxyProfiles":group_proxies,"vlessCore":self.store.library.preferences.vless_core,"vlessOverrides":self.store.library.preferences.vless_overrides,"groupChains":self.store.library.groups.iter().map(|g| (&g.id,&g.proxy_chain)).collect::<Vec<_>>(), "profiles":self.store.library.profiles.iter().filter(|p| p.group_id == id).collect::<Vec<_>>(), "chains":self.store.library.profiles.iter().filter(|p|crate::references::key(p.kind).is_some()).collect::<Vec<_>>(), "routing":self.store.library.routing, "running":self.running}),
        )
    }
    pub fn subscription_request(&self, id: &str) -> Result<Request, String> {
        let group = self.group(id)?;
        let mut settings = group.subscription.ok_or("subscription_missing")?.settings;
        crate::settings::network::subscription_transport(&mut settings, &self.store.library);
        settings.validate()?;
        let proxy = if settings.via_proxy {
            Some(
                self.application_proxy()?
                    .ok_or("subscription_proxy_unavailable")?,
            )
        } else {
            None
        };
        Ok(Request {
            settings,
            proxy,
            group_id: id.into(),
            stamp: self.subscription_stamp(id)?,
        })
    }
}

mod download;
mod groups;
mod review;
#[cfg(test)]
mod tests;
pub use download::*;

impl Engine {
    pub(crate) async fn stop_for_subscription(
        &mut self,
        token: &str,
    ) -> Result<Option<crate::connection::ActiveConnection>, String> {
        if !crate::settings::boolean(&self.store.library, "allow_stopping_active_profile") {
            return Ok(None);
        }
        let ticket = self
            .subscription_tickets
            .get(token)
            .ok_or("subscription_expired")?;
        if ticket.expired() {
            return Err("subscription_expired".into());
        }
        if ticket.stamp != self.subscription_stamp(&ticket.group_id)? {
            return Err("subscription_changed".into());
        }
        let plan = ticket
            .plan
            .as_ref()
            .ok_or("subscription_preview_required")?;
        if !plan.changes.iter().any(|c| {
            matches!(c.action.as_str(), "updated" | "removed")
                && self.subscription_change_restarts(&c.id)
        }) {
            return Ok(None);
        }
        let group_id = ticket.group_id.clone();
        let previous = self.active_connection.clone();
        self.disconnect().await?;
        let stamp = self.subscription_stamp(&group_id)?;
        self.subscription_tickets
            .get_mut(token)
            .ok_or("subscription_expired")?
            .stamp = stamp;
        Ok(previous)
    }
    pub async fn apply_subscription_with_stop(
        &mut self,
        token: &str,
        use_routing: Option<bool>,
    ) -> Result<Vec<Change>, String> {
        let previous = self.stop_for_subscription(token).await?;
        match self.apply_subscription_routing(token, use_routing) {
            Ok(changes) => Ok(changes),
            Err(error) => {
                if previous.is_some() {
                    Err(self.recover_connection(previous, error).await)
                } else {
                    Err(error)
                }
            }
        }
    }
}
