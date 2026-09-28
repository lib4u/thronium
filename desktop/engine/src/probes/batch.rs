//! Measurement batches: kinds, statuses, entries and their staleness rules.
use super::{full_xray, vpn};
use crate::store::Profile;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What one batch measures. Latency batches keep the ping method semantics;
/// IP and speed batches run the same isolated tests as the single diagnostics.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Latency,
    Ip,
    Speed,
}

/// A completed speed measurement as the isolated core reported it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpeedResult {
    pub download: String,
    pub upload: String,
    pub latency_ms: Option<i32>,
    pub download_bytes: u64,
    pub upload_bytes: u64,
}

/// An HTTP attempt can establish a VPN without reaching the requested URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Latency(i32),
    HttpFailed(HttpFailure),
    ConnectedOnly,
    AuthRequired,
    Ip { ip: String, country: Option<String> },
    Speed(SpeedResult),
}

/// Only a completed Core HTTP result can create this classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpFailure {
    Timeout,
    Tls,
    Request,
}
impl HttpFailure {
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Timeout => "probe_timeout",
            Self::Tls => "probe_tls_failed",
            Self::Request => "probe_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    #[default]
    Auto,
    Http,
    Tcp,
    Icmp,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PingSettings {
    #[serde(default)]
    pub method: Method,
    pub url: String,
    pub timeout_ms: u32,
}
/// Address checked when a test or pool has no URL of its own.
pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
/// Allowed test timeout, in milliseconds.
pub const TIMEOUT_MS: std::ops::RangeInclusive<u32> = 100..=10_000;
/// How long a probe waits for VPN endpoints to report their state.
pub const VPN_STATUS_TIMEOUT_MS: i32 = 10_000;
impl Default for PingSettings {
    fn default() -> Self {
        Self {
            method: Method::Auto,
            url: DEFAULT_TEST_URL.into(),
            timeout_ms: 3000,
        }
    }
}
impl PingSettings {
    pub(crate) fn validate(&self) -> Result<reqwest::Url, String> {
        if !TIMEOUT_MS.contains(&self.timeout_ms) {
            return Err("probe_invalid_timeout".into());
        }
        let url = reqwest::Url::parse(self.url.trim()).map_err(|_| "probe_invalid_url")?;
        if self.url.len() > 8192
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("probe_invalid_url".into());
        }
        Ok(url)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub ids: Vec<String>,
    pub url: String,
    pub timeout_ms: u32,
    /// Parallel probes for this batch; the `test_concurrent` setting otherwise.
    #[serde(default)]
    pub concurrency: Option<usize>,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Queued,
    Testing,
    Ok,
    Error,
    Cancelled,
    Stale,
    Unsupported,
    ConnectedOnly,
    AuthRequired,
}
impl Status {
    pub(super) fn active(self) -> bool {
        matches!(self, Self::Queued | Self::Testing)
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attempt {
    pub method: Method,
    pub status: Status,
    pub error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Measurement {
    pub kind: Kind,
    pub method: Method,
    pub effective_method: Method,
    pub attempts: Vec<Attempt>,
    pub first_hop: bool,
    pub profile_id: String,
    pub name: String,
    pub status: Status,
    pub latency_ms: Option<i32>,
    pub error: Option<String>,
    pub at: Option<u64>,
    pub ip: Option<String>,
    pub country_code: Option<String>,
    pub download: Option<String>,
    pub upload: Option<String>,
    pub download_bytes: Option<u64>,
    pub upload_bytes: Option<u64>,
    pub transport: Option<String>,
    /// A pool is measured through one member; the row names it and says how
    /// the member was chosen.
    pub member_id: Option<String>,
    pub member_name: Option<String>,
    pub member_origin: Option<crate::auto_selector::MemberOrigin>,
    /// Fingerprint of the isolated test's inputs (settings, route, context),
    /// checked again before an IP or speed result is published.
    #[serde(skip)]
    pub(super) test_stamp: Option<Value>,
    #[serde(skip)]
    pub(super) profile: Profile,
    #[serde(skip)]
    pub(super) dependencies: Value,
    #[serde(skip)]
    pub(super) managed_context: bool,
    #[serde(skip)]
    pub(super) http_context: Option<String>,
    #[serde(skip)]
    pub(super) http_sample: Option<Option<i32>>,
    #[serde(skip)]
    pub(super) http_asset_context: Option<full_xray::Context>,
}
pub(crate) fn dependencies(p: &Profile, library: &crate::store::Library) -> Result<Value, String> {
    Ok(if vpn::is_profile(p) {
        vpn::stamp(p, library)
    } else {
        crate::group_chains::stamp(library, p)
    })
}
impl Measurement {
    // A profile retains its place in the queue between attempts.
    // Cancellation and stale results are terminal, never fallback triggers.
    pub(super) fn attempt(&mut self, status: Status, latency: Option<i32>, error: Option<String>) {
        self.attempts.push(Attempt {
            method: self.effective_method,
            status,
            error: error.clone(),
        });
        if self.method == Method::Auto
            && matches!(status, Status::Error | Status::Unsupported)
            && !error.as_deref().is_some_and(vpn::terminal)
        {
            let next = match self.effective_method {
                Method::Http => Some(Method::Tcp),
                Method::Tcp => Some(Method::Icmp),
                _ => None,
            };
            if let Some(next) = next {
                self.effective_method = next;
                self.status = Status::Queued;
                self.first_hop = false;
                self.error = None;
                self.latency_ms = None;
                return;
            }
            let failed = self.attempts.iter().any(|a| a.status == Status::Error);
            self.finish(
                if failed {
                    Status::Error
                } else {
                    Status::Unsupported
                },
                None,
                Some(
                    if failed {
                        "probe_auto_failed"
                    } else {
                        "probe_auto_unsupported"
                    }
                    .into(),
                ),
            );
            return;
        }
        self.finish(status, latency, error);
    }

    pub(super) fn matches(&self, p: &Profile, library: &crate::store::Library) -> bool {
        self.http_context.as_ref().is_none_or(|stamp| {
            crate::latency_measurements::fingerprint(library, &p.id).as_ref() == Some(stamp)
        }) && self.profile.kind == p.kind
            && self.profile.config == p.config
            && dependencies(p, library).is_ok_and(|d| d == self.dependencies)
    }
    pub(super) fn finish(&mut self, status: Status, latency: Option<i32>, error: Option<String>) {
        self.status = status;
        self.latency_ms = latency;
        self.error = error;
        self.at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }
}
/// Who asked for the batch: a user action, the opt-in periodic schedule or
/// the auto-select sweep that runs when the quick pool connects. The sweep
/// uses the pool's own settings and stays out of the library's measurements.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    #[default]
    Manual,
    Periodic,
    AutoSelect,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Batch {
    pub kind: Kind,
    pub method: Method,
    pub source: Source,
    pub id: String,
    pub url: String,
    pub timeout_ms: u32,
    pub entries: Vec<Measurement>,
}
