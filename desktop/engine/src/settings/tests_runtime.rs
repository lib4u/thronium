//! Isolated speed and exit-IP measurements share the URL-probe route compiler.
use crate::{
    auto_selector::{MemberOrigin, PoolSelection},
    probes::full_xray,
    proto,
    store::{Library, Profile, ProfileKind},
    transport::Rpc,
    Engine,
};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Speed,
    Ip,
}
enum Request {
    Speed(proto::SpeedTestRequest),
    Ip(proto::IpTestRequest),
}
pub struct ProfileTest {
    core: PathBuf,
    logs: crate::logs::Logs,
    request: Request,
    duration: u64,
    id: String,
    kind: Kind,
    stamp: Value,
    assets: full_xray::Assets,
    vpn_ready_ms: u64,
    transport: &'static str,
    /// A pool is measured through one member (id, name, origin); see `auto_selector::measured_member`.
    member: Option<(String, String, MemberOrigin)>,
}
/// Structural capability shared by the snapshot and both diagnostic RPCs.
/// VPN measurements use the same eligibility rules as isolated HTTP probes
/// and explicitly carry their readiness/status protocol into both RPCs.
/// This check never compiles a config, binds a socket or starts a process.
pub(crate) fn supported(library: &Library, profile: &Profile, selection: &PoolSelection) -> bool {
    if profile.kind == ProfileKind::AutoSelector {
        return crate::auto_selector::measured_member(library, profile, selection).is_ok_and(
            |(member, _)| {
                member.kind != ProfileKind::AutoSelector && supported(library, member, selection)
            },
        );
    }
    // A disposable test box does not start the program the person runs, so a
    // configuration that needs one is measured by connecting and nothing else.
    if crate::external_core::runtime::carrier(&library.profiles, profile).is_some() {
        return false;
    }
    if crate::probes::vpn::is_profile(profile) {
        return crate::probes::vpn::diagnostics_supported(profile, library);
    }
    if crate::probes::endpoint_profile::is_profile(profile) {
        return crate::probes::endpoint_profile::diagnostics_supported(profile, library);
    }
    if profile.kind == ProfileKind::XrayConfig {
        return full_xray::supported(library, profile);
    }
    if profile.kind == ProfileKind::SingBoxConfig {
        return crate::probes::full_sing::supported(library, profile);
    }
    // A bare Tailscale endpoint has no measured form; hops follow their own rules.
    if crate::chains::is_endpoint(profile)
        || crate::probes::vpn::hops_eligible(library, profile).is_err()
    {
        return false;
    }
    let Ok(hops) = crate::chains::flatten(profile, &library.profiles) else {
        return false;
    };
    let mut count = hops.len();
    for id in crate::group_chains::policy(library, profile).ids() {
        let Some(hop) = library.profiles.iter().find(|p| p.id == id) else {
            return false;
        };
        let Ok(hops) = crate::chains::flatten(hop, &library.profiles) else {
            return false;
        };
        count += hops.len();
    }
    count > 0 && count <= crate::chains::MAX_HOPS
}
fn stamp(library: &Library, id: &str, kind: Kind, selection: &PoolSelection) -> Option<Value> {
    let profile = library.profiles.iter().find(|p| p.id == id)?;
    if !supported(library, profile, selection) {
        return None;
    }
    if profile.kind == ProfileKind::AutoSelector {
        // The pool's own definition (members, pin), the member the pool went
        // through and how it was chosen: a switch during the test is stale.
        let (member, origin) =
            crate::auto_selector::measured_member(library, profile, selection).ok()?;
        return Some(json!([
            "pool",
            profile.config,
            origin,
            member.id,
            stamp(library, &member.id, kind, selection)?
        ]));
    }
    let mut value = json!([
        crate::group_chains::stamp(library, profile),
        super::section(library, "presets"),
        super::section(library, "core"),
        super::section(library, "security"),
        match kind {
            Kind::Speed => json!([
                super::string(library, "speed_test_mode"),
                super::integer(library, "speed_test_timeout_ms"),
                super::string(library, "simple_dl_url")
            ]),
            Kind::Ip => json!(library.preferences.ping.timeout_ms),
        }
    ]);
    if crate::probes::vpn::is_profile(profile) {
        value
            .as_array_mut()?
            .push(crate::probes::vpn::stamp(profile, library));
    }
    Some(value)
}
/// The country cache context of a measured profile; pools are cached through
/// their measured member, so no running selection is involved.
pub(crate) fn ip_stamp(library: &Library, id: &str) -> Option<Value> {
    stamp(library, id, Kind::Ip, &PoolSelection::default())
}
pub(crate) fn stamp_for(
    library: &Library,
    id: &str,
    kind: Kind,
    selection: &PoolSelection,
) -> Option<Value> {
    stamp(library, id, kind, selection)
}
/// One preparation path for the diagnostics dialog and the bulk queue; it only
/// borrows the library so a queued batch can prepare while it is being walked.
/// `sources` receives the tag of every bound VPN node this test compiles.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_with_sources(
    library: &Library,
    core: &std::path::Path,
    data_dir: &std::path::Path,
    logs: &crate::logs::Logs,
    id: &str,
    kind: Kind,
    selection: &PoolSelection,
    sources: &mut crate::vpn_auth::otp::Build,
) -> Result<ProfileTest, String> {
    {
        let profile = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or("profile_not_found")?;
        if !supported(library, &profile, selection) {
            return Err("probe_unsupported".into());
        }
        if profile.kind == ProfileKind::AutoSelector {
            let (member, origin) =
                crate::auto_selector::measured_member(library, &profile, selection)?;
            let mut test = prepare_with_sources(
                library, core, data_dir, logs, &member.id, kind, selection, sources,
            )?;
            test.member = Some((member.id.clone(), member.name.clone(), origin));
            test.id = id.into();
            test.stamp = stamp(library, id, kind, selection).ok_or("profile_not_found")?;
            return Ok(test);
        }
        let mut test = crate::probes::prepared_request_with_sources(
            library,
            &profile,
            "https://www.gstatic.com/generate_204",
            library.preferences.ping.timeout_ms,
            sources,
        )?;
        let assets = if profile.kind == ProfileKind::XrayConfig {
            full_xray::Assets::prepare(&mut test, data_dir, library, &profile)?
        } else {
            full_xray::Assets::default()
        };
        let duration = match kind {
            Kind::Speed => super::integer(library, "speed_test_timeout_ms") as u64,
            Kind::Ip => library.preferences.ping.timeout_ms as u64,
        };
        let vpn_ready_ms = if test.vpn_endpoint_tags.is_empty() {
            0
        } else {
            10_000
        };
        // Named in the published result so a reader knows which path measured.
        let transport = if !test.vpn_endpoint_tags.is_empty() {
            "vpn-endpoint"
        } else if crate::probes::endpoint_profile::is_profile(&profile) {
            "wireguard-endpoint"
        } else {
            "isolated-core"
        };
        let request = match kind {
            Kind::Speed => {
                let mode = super::string(library, "speed_test_mode");
                Request::Speed(proto::SpeedTestRequest {
                    config: test.config,
                    outbound_tags: test.outbound_tags,
                    test_current: Some(false),
                    use_default_outbound: Some(false),
                    test_download: Some(matches!(mode.as_str(), "full" | "download")),
                    test_upload: Some(matches!(mode.as_str(), "full" | "upload")),
                    simple_download: Some(mode == "simple"),
                    simple_download_addr: Some(super::string(library, "simple_dl_url")),
                    timeout_ms: Some(duration as i32),
                    only_country: Some(false),
                    country_concurrency: Some(1),
                    need_xray: test.need_xray,
                    xray_config: test.xray_config,
                    xray_full_configs: test.xray_full_configs,
                    xray_outbound_dns_strategy: test.xray_outbound_dns_strategy,
                    vpn_endpoint_tags: test.vpn_endpoint_tags,
                    vpn_status_timeout_ms: test.vpn_status_timeout_ms,
                })
            }
            Kind::Ip => Request::Ip(proto::IpTestRequest {
                config: test.config,
                outbound_tags: test.outbound_tags,
                use_default_outbound: Some(false),
                max_concurrency: Some(1),
                test_timeout_ms: Some(duration as i32),
                need_xray: test.need_xray,
                xray_config: test.xray_config,
                xray_full_configs: test.xray_full_configs,
                xray_outbound_dns_strategy: test.xray_outbound_dns_strategy,
                vpn_endpoint_tags: test.vpn_endpoint_tags,
                vpn_status_timeout_ms: test.vpn_status_timeout_ms,
            }),
        };
        Ok(ProfileTest {
            core: core.to_path_buf(),
            logs: logs.for_probe(
                &profile,
                match kind {
                    Kind::Speed => "speed",
                    Kind::Ip => "ip",
                },
            ),
            assets,
            vpn_ready_ms,
            request,
            duration,
            id: id.into(),
            kind,
            stamp: stamp(library, id, kind, selection).ok_or("profile_not_found")?,
            transport,
            member: None,
        })
    }
}
impl ProfileTest {
    pub(crate) fn stamp(&self) -> &Value {
        &self.stamp
    }
    /// Apply a baking step to the test's core configuration.
    pub(crate) fn bake<T>(
        &mut self,
        bake: impl FnOnce(&mut Value) -> Result<T, String>,
    ) -> Result<(), String> {
        match &mut self.request {
            Request::Speed(request) => crate::probes::bake_config(request.config.as_mut(), bake),
            Request::Ip(request) => crate::probes::bake_config(request.config.as_mut(), bake),
        }
    }
    pub(crate) fn asset_context(&self) -> Option<&full_xray::Context> {
        self.assets.context.as_ref()
    }
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::Speed => "speed",
            Kind::Ip => "ip",
        }
    }
    pub fn transport(&self) -> &'static str {
        self.transport
    }
    /// The member a pool measurement went through, for the published result.
    pub fn member(&self) -> Option<(&str, &str)> {
        self.member
            .as_ref()
            .map(|(id, name, _)| (id.as_str(), name.as_str()))
    }
    /// How the measured member was chosen: running selection, pin or first.
    pub fn member_origin(&self) -> Option<MemberOrigin> {
        self.member.as_ref().map(|(_, _, origin)| *origin)
    }
    /// The profile whose exit the result describes: the member of a pool.
    pub(crate) fn measured_id(&self) -> &str {
        self.member.as_ref().map_or(&self.id, |(id, _, _)| id)
    }
    pub fn matches(&self, library: &Library, selection: &PoolSelection) -> bool {
        stamp(library, &self.id, self.kind, selection).is_some_and(|v| v == self.stamp)
            && self.assets.context.as_ref().is_none_or(|context| {
                library
                    .profiles
                    .iter()
                    .find(|p| p.id == self.id)
                    .is_some_and(|p| context.matches(library, p))
            })
    }
    pub async fn execute(&self, cancelled: &mut watch::Receiver<bool>) -> Result<Value, String> {
        let configs: Vec<&str> = match &self.request {
            Request::Speed(test) => [test.config.as_deref(), test.xray_config.as_deref()]
                .into_iter()
                .flatten()
                .chain(test.xray_full_configs.iter().map(String::as_str))
                .collect(),
            Request::Ip(test) => [test.config.as_deref(), test.xray_config.as_deref()]
                .into_iter()
                .flatten()
                .chain(test.xray_full_configs.iter().map(String::as_str))
                .collect(),
        };
        let log = self.logs.begin_probe(configs);
        let result = self.execute_inner(cancelled).await;
        let error = result
            .as_ref()
            .err()
            .map(|e| crate::probes::safe_error(e.clone()));
        log.finish(error.as_deref());
        result
    }
    async fn execute_inner(&self, cancelled: &mut watch::Receiver<bool>) -> Result<Value, String> {
        if *cancelled.borrow() {
            return Err("probe_cancelled".into());
        }
        let limit = match self.kind {
            Kind::Speed => self.duration * 3 + 30000,
            Kind::Ip => self.duration + 8000,
        } + self.vpn_ready_ms;
        tokio::select! {biased;
            _=cancelled.changed()=>Err("probe_cancelled".into()),
            result=tokio::time::timeout(Duration::from_millis(limit),async {
                let dir=tempfile::tempdir().map_err(|_|"probe_core_failed")?;
                let dir=self.assets.clone().stage(dir).await?;
                let mut rpc=Rpc::spawn_logged(&self.core,dir.path(),Some(self.logs.clone())).await.map_err(|_|"probe_core_failed")?;
                let result = match &self.request {
                    Request::Speed(request) => {
                        let reply:proto::SpeedTestResponse=rpc.call_with_timeout("SpeedTest",request.clone(),Duration::from_millis(limit)).await.map_err(rpc_error)?;
                        let result=reply.results.first().filter(|_|reply.results.len()==1).ok_or("probe_failed")?;
                        if result.cancelled==Some(true){return Err("probe_cancelled".into());}
                        if !matches_tag(&request.outbound_tags, result.outbound_tag.as_deref()){return Err("probe_failed".into());}
                        measurement_error(result.error.as_deref(), &request.vpn_endpoint_tags, &reply.vpn_status)?;
                        json!({"download":result.dl_speed,"upload":result.ul_speed,"latencyMs":result.latency,"downloadBytes":result.dl_bytes,"uploadBytes":result.ul_bytes})
                    }
                    Request::Ip(request) => {
                        let reply:proto::IpTestResp=rpc.call_with_timeout("IPTest",request.clone(),Duration::from_millis(limit)).await.map_err(rpc_error)?;
                        let result=reply.results.first().filter(|_|reply.results.len()==1).ok_or("probe_failed")?;
                        if !matches_tag(&request.outbound_tags, result.outbound_tag.as_deref()){return Err("probe_failed".into());}
                        measurement_error(result.error.as_deref(), &request.vpn_endpoint_tags, &reply.vpn_status)?;
                        ip_result(result.ip.as_deref(),result.country_code.as_deref())?
                    }
                };
                rpc.terminate().await;
                Ok(result)
            })=>result.map_err(|_|"probe_timeout".to_string())?
        }
    }
}
fn matches_tag(expected: &[String], actual: Option<&str>) -> bool {
    matches!(expected, [tag] if actual==Some(tag.as_str()))
}
fn rpc_error(error: String) -> String {
    if error == "core_request_timeout" {
        "probe_timeout"
    } else {
        "probe_configuration_failed"
    }
    .into()
}
fn measurement_error(
    error: Option<&str>,
    requested: &[String],
    statuses: &[proto::VpnEndpointStatus],
) -> Result<(), String> {
    if error.unwrap_or("").is_empty() || requested.is_empty() {
        if !statuses.is_empty() {
            return Err("probe_failed".into());
        }
        return check_error(error);
    }
    match crate::probes::vpn::failure_status(statuses, requested)? {
        Some(crate::probes::Outcome::ConnectedOnly) => Err("probe_vpn_diagnostic_failed".into()),
        Some(crate::probes::Outcome::AuthRequired) => Err("probe_vpn_auth_required".into()),
        Some(_) => Err("probe_failed".into()),
        None => check_error(error),
    }
}
fn check_error(error: Option<&str>) -> Result<(), String> {
    let error = error.unwrap_or("");
    if error.is_empty() {
        return Ok(());
    }
    let lower = error.to_ascii_lowercase();
    Err(
        if lower.contains("timeout") || lower.contains("deadline exceeded") {
            "probe_timeout"
        } else if lower.contains("certificate") {
            "probe_tls_failed"
        } else {
            "probe_failed"
        }
        .into(),
    )
}
fn ip_result(ip: Option<&str>, country: Option<&str>) -> Result<Value, String> {
    let ip = ip
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .ok_or("ip_test_invalid_response")?;
    let code = country.unwrap_or("");
    let country = if code.is_empty() || code == "-" {
        None
    } else if code.len() == 2 && code.bytes().all(|c| c.is_ascii_alphabetic()) {
        Some(code.to_ascii_uppercase())
    } else {
        return Err("ip_test_invalid_response".into());
    };
    Ok(json!({"ip":ip.to_string(),"countryCode":country,"provider":"IP2Location"}))
}

#[cfg(test)]
mod endpoint_tests;
#[cfg(test)]
mod full_xray_tests;
#[cfg(test)]
mod pool_tests;
mod requests;
#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod vpn_tests;

/// Windows' own verdict on reaching the Internet (Network Connectivity Status
/// Indicator), read through `INetworkListManager` as GNOME's is through GIO.
#[cfg(target_os = "windows")]
mod network_list {
    use windows_sys::core::GUID;
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
    };

    const CLSID_NETWORK_LIST_MANAGER: GUID =
        GUID::from_u128(0xdcb00c01_570f_4a9b_8d69_199fdba5723b);
    const IID_INETWORK_LIST_MANAGER: GUID = GUID::from_u128(0xdcb00000_570f_4a9b_8d69_199fdba5723b);
    /// IUnknown (3) and IDispatch (4) come first; then GetNetworks,
    /// GetNetwork, GetNetworkConnections, GetNetworkConnection and
    /// get_IsConnectedToInternet at 11.
    const IS_CONNECTED_TO_INTERNET: usize = 11;
    const RELEASE: usize = 2;

    type Getter = unsafe extern "system" fn(*mut std::ffi::c_void, *mut i16) -> i32;
    type Release = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

    pub(super) fn connected() -> Option<bool> {
        unsafe {
            let entered = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) >= 0;
            let mut manager: *mut std::ffi::c_void = std::ptr::null_mut();
            let created = CoCreateInstance(
                &CLSID_NETWORK_LIST_MANAGER,
                std::ptr::null_mut(),
                CLSCTX_ALL,
                &IID_INETWORK_LIST_MANAGER,
                &mut manager,
            );
            let result = (created >= 0 && !manager.is_null()).then(|| {
                let table = *(manager as *const *const usize);
                let getter: Getter = std::mem::transmute(*table.add(IS_CONNECTED_TO_INTERNET));
                let mut value: i16 = 0;
                let status = getter(manager, &mut value);
                let release: Release = std::mem::transmute(*table.add(RELEASE));
                release(manager);
                (status >= 0).then_some(value != 0)
            });
            if entered {
                CoUninitialize();
            }
            result.flatten()
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn windows_answers_whether_the_internet_is_reachable() {
            assert!(super::connected().is_some());
        }
    }
}

pub async fn direct(
    url: String,
    timeout: u64,
    cancelled: &mut watch::Receiver<bool>,
) -> Result<Value, String> {
    if *cancelled.borrow() {
        return Err("probe_cancelled".into());
    }
    if url.is_empty() {
        #[cfg(target_os = "linux")]
        {
            use gio::prelude::*;
            let connected = gio::NetworkMonitor::default().is_network_available();
            return Ok(json!({"online":connected,"source":"system"}));
        }
        #[cfg(target_os = "windows")]
        {
            let connected = tokio::task::spawn_blocking(network_list::connected)
                .await
                .ok()
                .flatten()
                .ok_or("network_status_unavailable")?;
            return Ok(json!({"online":connected,"source":"system"}));
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        return Err("network_status_unavailable".into());
    }
    tokio::select! {biased;_=cancelled.changed()=>Err("probe_cancelled".into()),result=async{
     let client=reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(timeout)).build().map_err(|_|"probe_failed")?;
     let start=std::time::Instant::now();let response=client.get(url).send().await.map_err(|_|"probe_failed")?;
     Ok(json!({"online":response.status().is_success(),"status":response.status().as_u16(),"latencyMs":start.elapsed().as_millis(),"source":"http"}))
    }=>result}
}
