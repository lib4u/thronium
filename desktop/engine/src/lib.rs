pub mod auto_selector;
pub mod backups;
mod bounded_download;
pub(crate) mod bounded_log;
pub mod chains;
pub mod config;
mod connection;
mod core_requests;
pub mod country_measurements;
pub mod dashboard;
pub mod duplicates;
pub mod exports;
pub mod external_core;
mod geodata;
pub mod group_chains;
pub mod ipc;
pub mod languages;
pub mod latency_measurements;
pub mod launch;
pub mod legacy_backup;
mod library_profiles;
#[cfg(windows)]
mod nofollow;
pub mod otp;
mod otp_engine;
pub(crate) mod ownership;
mod preferences_ops;
pub mod profile_descriptor;
pub mod profile_edit;
mod recovery;
mod routing_ops;
mod session;
mod snapshot;
pub mod vpn_endpoint;
pub mod vpn_otp_bindings;
pub use geodata::catalog::downloads as routing_downloads;
pub use geodata::deferral as geodata_deferral;
pub use geodata::manager as geodata_assets;
pub use recovery::RAPID_EXIT_WINDOW as CORE_RAPID_EXIT_WINDOW;
pub use snapshot::Snapshot;
mod library_maintenance;
mod library_ops;
pub mod logs;
mod loopback_ports;
pub mod probes;
#[cfg(test)]
mod qt_source;
pub mod references;
pub mod request_jobs;
pub mod routing;
mod runtime_config;
pub mod secrets;
pub mod settings;
pub mod store;
pub(crate) mod strict_json;
pub mod subscriptions;
pub mod system_proxy;
mod traffic;
mod traffic_stats;
pub mod transport;
pub mod tray_icons;
pub mod tun;
pub mod vless;
pub mod vpn_auth;
pub mod vpn_policy;
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/libcore.rs"));
}

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use store::{Group, Preferences, Profile, ProfileKind, Store};
use transport::Rpc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDraft {
    #[serde(default)]
    pub vpn_policy: vpn_policy::Edit,
    pub id: Option<String>,
    pub name: String,
    pub group_id: String,
    pub kind: ProfileKind,
    pub config: Value,
}

pub struct Engine {
    system_proxy: system_proxy::Manager,
    pub store: Store,
    pub logs: logs::Logs,
    rpc: Option<Rpc>,
    core: PathBuf,
    data_dir: PathBuf,
    running: Option<String>,
    active_connection: Option<connection::ActiveConnection>,
    selector_health: auto_selector::health::State,
    selector_rebuild: auto_selector::rebuild::State,
    quick_select: auto_selector::quick::State,
    vpn: vpn_auth::Session,
    /// How often a connection was restarted for a fresh before-Start code,
    /// per profile and endpoint. Only an explicit Connect clears it.
    vpn_start_restarts: std::collections::HashMap<(String, String), u32>,
    vpn_credentials_transition: Option<vpn_auth::credentials::Transition>,
    vpn_credentials_proxy_transition: Option<vpn_auth::credentials::ProxyTransition>,
    vpn_otp_binding_edits: vpn_otp_bindings::Edits,
    /// Last TOTP time step spent per OTP entry, for the Engine lifetime.
    spent_totp_steps: std::collections::HashMap<String, u64>,
    geodata: geodata::Deferral,
    recovery: recovery::Recovery,
    external_cleanup_ports: std::collections::BTreeSet<u16>,
    tun_reconnecting: bool,
    tun_generation: u64,
    since: Option<u64>,
    error: Option<String>,
    traffic: traffic::Traffic,
    history: settings::history::History,
    traffic_available: bool,
    routing_revision: Option<u64>,
    subscription_tickets: std::collections::HashMap<String, subscriptions::Ticket>,
    subscription_jobs: subscriptions::jobs::Queue,
    probes: probes::Queue,
    measurement_journal: probes::journal::Journal,
    switch_history: auto_selector::switches::Journal,
    duplicates: Option<duplicates::Pending>,
    restore: Option<backups::Pending>,
}

/// The core checks sing-box first and Xray only when the request needs it.
/// A rejection names the stage that refused, for the log.
pub(crate) async fn check_config(
    rpc: &mut transport::Rpc,
    request: &proto::LoadConfigReq,
) -> Result<(), (&'static str, String)> {
    let mut singbox = request.clone();
    singbox.need_xray = Some(false);
    let reply: proto::ErrorResp = rpc
        .call("CheckConfig", singbox)
        .await
        .map_err(|e| ("check_config_failed", e))?;
    core_result(reply).map_err(|e| ("check_config_failed", e))?;
    if request.need_xray == Some(true) {
        let reply: proto::ErrorResp = rpc
            .call("CheckConfig", request.clone())
            .await
            .map_err(|e| ("check_config_xray_failed", e))?;
        core_result(reply).map_err(|e| ("check_config_xray_failed", e))?;
    }
    Ok(())
}

impl Engine {
    /// Copy ownership while holding the engine lock; collect process metrics only
    /// after releasing it. No arbitrary PID can be supplied by the frontend.
    pub fn owned_core_process(&self) -> Option<transport::OwnedProcess> {
        self.rpc.as_ref().and_then(Rpc::owned_process)
    }

    pub fn open(data_dir: &Path, core: &Path) -> Result<Self, String> {
        Self::open_with(data_dir, core, true)
    }
    /// Runs no core but this application's own pair (`transport::pair`);
    /// a mismatch stays the visible error until the installation is repaired.
    pub fn verify_core_pair(&mut self) {
        if let Err(error) = transport::pair::verify(&self.core) {
            self.logs.event("error", "core_pair_mismatch", None);
            self.error = Some(error);
        }
    }
    /// `seal` as in [`Store::open_with`].
    pub fn open_with(data_dir: &Path, core: &Path, seal: bool) -> Result<Self, String> {
        let store = Store::open_with(data_dir, seal)?;
        let logs = logs::Logs::default();
        if store.auto_select_source_repaired {
            logs.event("info", "auto_select_source_reset", None);
        }
        Ok(Self {
            system_proxy: system_proxy::Manager::default(),
            store,
            logs,
            rpc: None,
            core: core.into(),
            data_dir: data_dir.into(),
            running: None,
            active_connection: None,
            selector_health: Default::default(),
            selector_rebuild: Default::default(),
            quick_select: auto_selector::quick::State::load(data_dir),
            vpn: vpn_auth::Session::default(),
            vpn_start_restarts: Default::default(),
            vpn_credentials_transition: None,
            vpn_credentials_proxy_transition: None,
            vpn_otp_binding_edits: Default::default(),
            spent_totp_steps: Default::default(),
            geodata: Default::default(),
            recovery: recovery::Recovery::default(),
            external_cleanup_ports: std::collections::BTreeSet::new(),
            tun_reconnecting: false,
            tun_generation: 0,
            since: None,
            error: None,
            traffic: traffic::Traffic::default(),
            history: settings::history::History::default(),
            traffic_available: false,
            routing_revision: None,
            subscription_tickets: std::collections::HashMap::new(),
            subscription_jobs: subscriptions::jobs::Queue::default(),
            probes: probes::Queue::default(),
            measurement_journal: probes::journal::Journal::load(data_dir),
            switch_history: auto_selector::switches::Journal::load(data_dir),
            duplicates: None,
            restore: None,
        })
    }
}

fn core_result(result: proto::ErrorResp) -> Result<(), String> {
    match result.error {
        Some(e) if !e.is_empty() => {
            // This upstream diagnostic prefixes the error with the entire config,
            // including credentials of unrelated auxiliary outbounds and DNS servers.
            if let Some(payload) = e.strip_prefix("decode config at ") {
                let mut json = serde_json::Deserializer::from_str(payload).into_iter::<Value>();
                if matches!(json.next(), Some(Ok(_))) {
                    // The registered code leads; the key path stays for the log.
                    return Err(format!(
                        "invalid_configuration{}",
                        &payload[json.byte_offset()..]
                    ));
                }
                return Err("invalid_configuration".into());
            }
            Err(e)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
