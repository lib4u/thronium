//! Latency measurements use a disposable core and never the active IPC stream.
use crate::{
    config, proto,
    store::{Profile, ProfileKind},
    transport::Rpc,
    Engine,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;

mod batch;
mod endpoint;
pub(crate) mod endpoint_profile;
mod execute;
mod managed;
mod queue;
use batch::dependencies;
pub use batch::*;
pub(crate) use execute::safe_error;
use execute::{http_error, unsupported};
pub(crate) use queue::bake_config;
mod capacity;
pub(crate) mod full_sing;
pub(crate) mod full_xray;
pub mod journal;
mod owned;
pub mod periodic;
pub(crate) mod vpn;

#[derive(Default)]
pub struct Queue {
    concurrency: usize,
    batch: Option<Batch>,
    cache: HashMap<(String, Method, Kind), Measurement>,
    cancel: Option<watch::Sender<bool>>,
    singles: capacity::Singles,
    periodic: periodic::Schedule,
    // Incremented when a VPN Probe is issued, before its first await. A dropped
    // caller transfers cleanup to the owned task, which retains this permit.
    vpn_owners: Arc<AtomicUsize>,
    cleanup_failed: Arc<AtomicBool>,
}
/// Servers in one measurement batch.
pub(crate) const MAX_BATCH: usize = crate::store::MAX_BATCH_PROFILES;
#[derive(Clone)]
pub struct Run {
    pub concurrency: usize,
    pub id: String,
    pub cancelled: watch::Receiver<bool>,
}
pub struct Probe {
    pub id: String,
    core: PathBuf,
    request: Request,
    timeout_ms: u32,
    vpn_permit: Option<owned::Permit>,
    assets: full_xray::Assets,
    logs: crate::logs::Logs,
    /// The bound VPN nodes this test compiled, each under the tag the compiler
    /// announced for it.
    otp: crate::vpn_auth::otp::Build,
}

enum Request {
    Http(proto::TestReq),
    Endpoint(proto::EndpointProbeReq),
    /// An isolated IP or speed test, identical to the single diagnostics.
    Profile(Box<crate::settings::tests_runtime::ProfileTest>),
}

/// All outbound measurements use this route, including group front/landing hops.
/// Global routing is deliberately excluded: it must not bypass the tested server.
#[cfg(test)]
pub(crate) fn prepared_request(
    source: &crate::store::Library,
    selected: &Profile,
    url: &str,
    timeout_ms: u32,
) -> Result<proto::TestReq, String> {
    prepared_request_with_sources(
        source,
        selected,
        url,
        timeout_ms,
        &mut crate::vpn_auth::otp::Build::default(),
    )
}
/// `sources` receives the tag of every bound VPN node this test compiles, so a
/// one-time code can be baked exactly where that node is.
pub(crate) fn prepared_request_with_sources(
    source: &crate::store::Library,
    selected: &Profile,
    url: &str,
    timeout_ms: u32,
    sources: &mut crate::vpn_auth::otp::Build,
) -> Result<proto::TestReq, String> {
    if selected.kind == ProfileKind::SingBoxConfig && !full_sing::supported(source, selected) {
        return Err("probe_full_config_unsupported".into());
    }
    if selected.kind == ProfileKind::XrayConfig && !full_xray::supported(source, selected) {
        return Err("probe_full_config_unsupported".into());
    }
    if vpn::is_profile(selected) && !vpn::wrapped(source, selected) {
        return vpn::request(source, selected, url, timeout_ms, sources);
    }
    if endpoint_profile::is_profile(selected) {
        return endpoint_profile::request(source, selected, url, timeout_ms);
    }
    if crate::external_core::runtime::carrier(&source.profiles, selected).is_some() {
        return Err("probe_unsupported".into());
    }
    // Hops keep the single-profile ownership and authentication rules; they
    // are checked against the original library, before wrappers rename them.
    vpn::hops_eligible(source, selected)?;
    let mut source = source.clone();
    source.routing = Default::default();
    let (mut library, mut profile) = crate::vless::library(&source, selected)?;
    crate::settings::prepare_profiles(&mut library, &mut profile);
    // A wrapper compiles renamed copies of its hops; a copy answers for the
    // binding of the profile it was made from.
    sources.alias(crate::group_chains::prepare(
        &mut library,
        &mut profile,
        &HashSet::from([selected.id.clone()]),
    )?);
    request_with_sources(&profile, &library.profiles, url, timeout_ms, sources)
}

pub(crate) fn request_with_sources(
    profile: &Profile,
    profiles: &[Profile],
    url: &str,
    timeout_ms: u32,
    sources: &mut crate::vpn_auth::otp::Build,
) -> Result<proto::TestReq, String> {
    if profile.kind == ProfileKind::SingBoxConfig {
        return full_sing::request(profile, url, timeout_ms);
    }
    if matches!(
        profile.kind,
        ProfileKind::AutoSelector | ProfileKind::ExternalCore
    ) || crate::chains::is_endpoint_type(&profile.config)
    {
        return Err("probe_unsupported".into());
    }
    let normalized;
    let profile = if profile.kind == ProfileKind::XrayConfig {
        if !full_xray::client_shape(&profile.config) {
            return Err("probe_full_config_unsupported".into());
        }
        normalized = full_xray::diagnostic_profile(profile);
        &normalized
    } else {
        profile
    };
    let port = if matches!(
        profile.kind,
        ProfileKind::XrayOutbound | ProfileKind::XrayConfig
    ) {
        let (port, _listener) =
            crate::loopback_ports::claim(&HashSet::new()).ok_or("probe_configuration_failed")?;
        Some(port)
    } else {
        None
    };
    // Measure this outbound itself, independently of the user's global routing mode.
    let mut built = if profile.kind == ProfileKind::Chain {
        crate::chains::build_with_sources(
            profile,
            profiles,
            config::PLACEHOLDER_INBOUND_PORT,
            sources,
        )
    } else {
        config::build_with_sources(profile, config::PLACEHOLDER_INBOUND_PORT, port, sources)
    }
    .map_err(|_| "probe_configuration_failed")?;
    let mut vpn_endpoint_tags = vec![];
    if profile.kind == ProfileKind::Chain {
        // A VPN exit keeps its gating and tunnel DNS, exactly as when connecting.
        if let Some(exit) = crate::vpn_policy::carrier(&crate::chains::flatten(profile, profiles)?)
        {
            crate::vpn_policy::apply(&mut built, exit)
                .map_err(|_| "probe_vpn_context_unsupported")?;
        }
    }
    let mut core: Value = serde_json::from_str(built.core_config.as_deref().unwrap_or(""))
        .map_err(|_| "probe_configuration_failed")?;
    if profile.kind == ProfileKind::Chain {
        core["inbounds"]
            .as_array_mut()
            .ok_or("probe_configuration_failed")?
            .retain(|i| i["tag"] != "mixed-in");
        vpn_endpoint_tags = vpn::endpoint_tags(&core);
    } else {
        core["inbounds"] = json!([]);
    }
    core["services"] = json!([]);
    Ok(proto::TestReq {
        config: Some(core.to_string()),
        outbound_tags: vec!["proxy".into()],
        vpn_status_timeout_ms: (!vpn_endpoint_tags.is_empty()).then_some(VPN_STATUS_TIMEOUT_MS),
        vpn_endpoint_tags,
        use_default_outbound: Some(false),
        test_current: Some(false),
        url: Some(url.into()),
        max_concurrency: Some(1),
        test_timeout_ms: Some(timeout_ms as i32),
        need_xray: built.need_xray,
        xray_config: built.xray_config,
        xray_full_configs: built.xray_full_configs,
        ..Default::default()
    })
}

impl Engine {
    pub fn save_ping_settings(&mut self, mut settings: PingSettings) -> Result<(), String> {
        settings.url = settings.validate()?.to_string();
        let mut next = self.store.library.clone();
        next.preferences.ping = settings;
        self.store.commit(next)
    }

    pub fn start_ping(&mut self, ids: Vec<String>) -> Result<Run, String> {
        let settings = self.store.library.preferences.ping.clone();
        self.start_probes(
            Options {
                ids,
                url: settings.url.clone(),
                timeout_ms: settings.timeout_ms,
                concurrency: None,
            },
            settings.method,
            Kind::Latency,
            Source::Manual,
        )
    }

    pub fn start_url_tests(&mut self, options: Options) -> Result<Run, String> {
        self.start_probes(options, Method::Http, Kind::Latency, Source::Manual)
    }

    /// One chunk of a connection plan's pool: the plan owns the URL, timeout,
    /// parallelism and source, so a host never assembles probe options itself.
    pub fn start_preflight_tests(
        &mut self,
        pool: &crate::auto_selector::ConnectionMeasurementPool,
        ids: &[String],
    ) -> Result<Run, String> {
        // Background checks of favorites must not refuse a connection the user
        // asked for; a manual batch still does.
        self.cancel_periodic_probes();
        self.start_probes(
            Options {
                ids: ids.to_vec(),
                url: pool.url.clone(),
                timeout_ms: pool.timeout_ms,
                concurrency: pool.concurrency,
            },
            Method::Http,
            Kind::Latency,
            pool.source,
        )
    }

    /// Bulk exit IP/country through the same isolated tests as the diagnostics
    /// dialog; the batch shares the latency queue, its concurrency and staleness.
    pub fn start_ip_tests(&mut self, ids: Vec<String>) -> Result<Run, String> {
        self.start_profile_tests(ids, Kind::Ip)
    }

    /// Bulk speed, one profile at a time: a speed sample saturates the link.
    pub fn start_speed_tests(&mut self, ids: Vec<String>) -> Result<Run, String> {
        self.start_profile_tests(ids, Kind::Speed)
    }

    fn start_profile_tests(&mut self, ids: Vec<String>, kind: Kind) -> Result<Run, String> {
        self.start_profile_tests_from(ids, kind, Source::Manual)
    }

    /// Latency keeps the configured ping method; exit IP and speed always run
    /// the isolated HTTP tests.
    pub(crate) fn start_profile_tests_from(
        &mut self,
        ids: Vec<String>,
        kind: Kind,
        source: Source,
    ) -> Result<Run, String> {
        let settings = self.store.library.preferences.ping.clone();
        let method = if kind == Kind::Latency {
            settings.method
        } else {
            Method::Http
        };
        let mut run = self.start_probes(
            Options {
                ids,
                url: settings.url,
                timeout_ms: settings.timeout_ms,
                concurrency: None,
            },
            method,
            kind,
            source,
        )?;
        if kind == Kind::Speed {
            run.concurrency = 1;
            self.probes.concurrency = 1;
        }
        Ok(run)
    }

    fn start_probes(
        &mut self,
        options: Options,
        method: Method,
        kind: Kind,
        source: Source,
    ) -> Result<Run, String> {
        self.vpn_probe_guard()?;
        if self.batch_active() || self.singles_active() {
            return Err("probe_busy".into());
        }
        if options.ids.is_empty()
            || options.ids.len() > MAX_BATCH
            || !TIMEOUT_MS.contains(&options.timeout_ms)
        {
            return Err("probe_invalid_options".into());
        }
        let url = PingSettings {
            method,
            url: options.url,
            timeout_ms: options.timeout_ms,
        }
        .validate()?;
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        for id in options.ids {
            if !seen.insert(id.clone()) {
                continue;
            }
            let p = self.profile(&id)?;
            entries.push(Measurement {
                kind,
                method,
                effective_method: if method == Method::Auto {
                    Method::Http
                } else {
                    method
                },
                attempts: vec![],
                first_hop: false,
                http_context: matches!(method, Method::Auto | Method::Http)
                    .then(|| crate::latency_measurements::fingerprint(&self.store.library, &p.id))
                    .flatten(),
                http_sample: None,
                http_asset_context: None,
                dependencies: dependencies(&p, &self.store.library)
                    .map_err(|_| "probe_configuration_failed")?,
                managed_context: self.managed_probe_context(),
                profile_id: id,
                name: p.name.clone(),
                status: Status::Queued,
                latency_ms: None,
                error: None,
                at: None,
                ip: None,
                country_code: None,
                download: None,
                upload: None,
                download_bytes: None,
                upload_bytes: None,
                transport: None,
                member_id: None,
                member_name: None,
                member_origin: None,
                test_stamp: None,
                profile: p,
            });
        }
        let id = uuid::Uuid::new_v4().to_string();
        let (sender, cancelled) = watch::channel(false);
        self.probes.cleanup_failed.store(false, Ordering::Release);
        self.probes.cancel = Some(sender);
        self.probes.batch = Some(Batch {
            kind,
            method,
            source,
            id: id.clone(),
            url: url.to_string(),
            timeout_ms: options.timeout_ms,
            entries,
        });
        let concurrency = options
            .concurrency
            .map(|n| n.clamp(1, 64))
            .unwrap_or_else(|| {
                crate::settings::integer(&self.store.library, "test_concurrent") as usize
            });
        self.probes.concurrency = concurrency;
        Ok(Run {
            id,
            cancelled,
            concurrency,
        })
    }
}
#[cfg(test)]
mod auto_tests;
#[cfg(test)]
mod bulk_tests;
#[cfg(test)]
mod capacity_tests;
#[cfg(test)]
mod journal_tests;
#[cfg(test)]
mod periodic_tests;
#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod vpn_tests;
