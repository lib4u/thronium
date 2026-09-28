//! The snapshot the window polls: library rows, connection state and settings.
use super::*;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub library_revision: u64,
    pub vpn: vpn_auth::Status,
    pub appearance: Value,
    pub subscription_notifications: bool,
    pub tun_supported: bool,
    pub system_proxy: system_proxy::Status,
    pub profiles: Vec<Value>,
    pub groups: Vec<Value>,
    pub preferences: Preferences,
    pub selected: Option<String>,
    pub running: Option<String>,
    pub core_available: bool,
    pub phase: String,
    pub since: Option<u64>,
    pub error: Option<String>,
    pub traffic_available: bool,
    pub traffic_up: i64,
    pub traffic_down: i64,
    pub local_proxy: Option<String>,
    pub connections: Vec<traffic::Connection>,
    pub routing: Value,
    pub subscription_jobs: Vec<subscriptions::jobs::Job>,
    pub url_tests: Option<probes::Batch>,
    pub auto_select_available: bool,
    pub auto_select_member_count: usize,
    /// How the files this installation owns are written: sealed with the key of
    /// this desktop's store, or in the open because there is none.
    pub sealing: &'static str,
}

/// Switches of the "displayed data" group in the interface settings that
/// need extra per-profile snapshot fields.
struct ListView {
    security: bool,
    ip: bool,
    speed: bool,
    traffic: bool,
}

impl Engine {
    /// Server-list data the user chose to display, read once per snapshot.
    fn list_view(&self) -> ListView {
        let library = &self.store.library;
        ListView {
            security: settings::boolean(library, "show_config_security"),
            ip: settings::boolean(library, "list_show_ip"),
            speed: settings::boolean(library, "list_show_speed"),
            traffic: settings::boolean(library, "list_show_traffic")
                && !settings::boolean(library, "disable_traffic_aggregation"),
        }
    }

    /// Optional list data is sent only while its switch is on: the snapshot is
    /// polled every second and large libraries must not pay for hidden columns.
    fn profile_summary(
        &self,
        p: &Profile,
        view: &ListView,
        selection: &auto_selector::PoolSelection,
    ) -> Value {
        let descriptor = profile_descriptor::describe(p);
        let library = &self.store.library;
        let mut summary = json!({"id":p.id, "name":p.name, "groupId":p.group_id, "kind":p.kind, "protocol":descriptor.protocol, "address":descriptor.address, "favorite":p.favorite, "ipSpeedSupported":settings::tests_runtime::supported(library,p,selection),"poolEligible":crate::auto_selector::member_eligible(p,&library.profiles), "vpn":vpn_endpoint::profile_protocol(p).is_some(), "security":if view.security {descriptor.security} else {String::new()}, "measurement":self.measurement(p)});
        if let Some(port) = descriptor.port {
            summary["port"] = json!(port);
        }
        if view.security {
            summary["securityLevel"] = json!(descriptor.security_level);
        }
        if view.ip {
            summary["ipMeasurement"] = json!(self.cached(p, probes::Kind::Ip));
        }
        if view.speed {
            summary["speedMeasurement"] = json!(self.cached(p, probes::Kind::Speed));
        }
        if view.traffic {
            if let Some((upload, download)) = self.history.profile_totals(&p.id) {
                summary["traffic"] = json!({"upload": upload, "download": download});
            }
        }
        summary
    }

    pub fn snapshot(&mut self) -> Snapshot {
        self.refresh_vpn_otp_bindings();
        self.logs.configure(&self.store.library, &self.data_dir);
        let url_tests = self.url_tests_snapshot();
        self.observe_core_exit();
        if self.vpn_credentials_proxy_transition.is_some() {
            // The owned cleanup operation decides when restore/relinquish is safe.
        } else if self.running.is_none() {
            let _ = self.system_proxy.restore();
        } else {
            self.system_proxy.observe();
        }
        let view = self.list_view();
        if view.traffic {
            self.history.load(&self.data_dir);
        }
        let selection = self.pool_selection();
        let profiles = self
            .store
            .library
            .profiles
            .iter()
            .map(|p| self.profile_summary(p, &view, &selection))
            .collect();
        let active_route = self
            .store
            .library
            .routing
            .active()
            .expect("validated routing");
        let owns_route = self
            .running
            .as_ref()
            .or(self.store.library.selected.as_ref())
            .and_then(|id| self.profile(id).ok())
            .is_some_and(|p| {
                matches!(p.kind, ProfileKind::SingBoxConfig | ProfileKind::XrayConfig)
            });
        let provider_owned = self
            .running
            .as_ref()
            .or(self.store.library.selected.as_ref())
            .and_then(|id| self.profile(id).ok())
            .is_some_and(|p| geodata::enabled(&p, &self.store.library));
        let auto_select_member_count = self.auto_select_member_count();
        Snapshot {
            library_revision: self.store.generation(),
            vpn: self.vpn.snapshot(),
            system_proxy: self.system_proxy.status(),
            url_tests,
            subscription_jobs: self.subscription_jobs.jobs.clone(),
            routing: json!({"active":active_route.id, "name":active_route.name, "mode":active_route.mode,
                "revision":self.store.library.routing.revision, "profileOwned":owns_route, "providerOwned":provider_owned,
                "pending":self.running.is_some() && !owns_route && self.routing_revision != Some(self.store.library.routing.revision)}),
            profiles,
            groups: self.store.library.groups.iter().map(|g| json!({"id":g.id, "name":g.name,
                "proxyChain":g.proxy_chain,"collapsed":g.collapsed, "displayName":g.display_name(),
                "announcement":g.subscription.as_ref().and_then(|s| s.metadata.announcement.as_ref()),
                "providerRouting":g.subscription.as_ref().and_then(|s|s.metadata.routing.as_ref().map(|r|{let mut summary=r.summary();summary["enabled"]=json!(s.settings.use_provider_routing);summary})),
                "subscribed":g.subscription.is_some(), "updatedAt":g.subscription.as_ref().and_then(|s| s.updated_at),
                "autoClearUnavailable":g.auto_clear_unavailable,
                "usage":g.subscription.as_ref().and_then(|s| s.usage.as_ref()),
                "intervalMinutes":g.subscription.as_ref().map(|s| s.settings.interval_minutes).unwrap_or(0),
                "nextUpdateAt":g.subscription.as_ref().and_then(subscriptions::jobs::next_due),
                "lastUpdate":g.subscription.as_ref().and_then(|s| s.last_update.as_ref())})).collect(),
            tun_supported: tun::supported(),
            auto_select_available: self.store.library.preferences.auto_select.enabled
                && auto_select_member_count >= auto_selector::AUTO_SELECT_MIN,
            auto_select_member_count,
            appearance: {
                let mut view = settings::section(&self.store.library, "appearance");
                // The confirmation control lives in Security; retain its safe
                // UI flag here for existing library action consumers.
                view["skip_delete_confirmation"] = json!(settings::boolean(&self.store.library, "skip_delete_confirmation"));
                view
            },
            subscription_notifications:settings::boolean(&self.store.library,"sub_show_change_popup"),
            preferences: self.store.library.preferences.clone(),
            selected: self.store.library.selected.clone(),
            running: self.running.clone(),
            core_available: self.core.is_file() && crate::transport::pair::required().is_ok(),
            phase: if self.tun_reconnecting || self.recovery.pending() {
                "reconnecting"
            } else if self.running.is_some() {
                self.vpn.phase().unwrap_or("connected")
            } else {
                "disconnected"
            }
            .into(),
            since: self.since,
            // Detailed core errors belong to the explicit operation response.
            // A periodically shared status must not echo configuration values.
            // Only a registered code is published; raw core text is not.
            error: self.error.as_ref().map(|error| {
                if ipc::registered(error).is_some() {
                    error.clone()
                } else {
                    "core_error".into()
                }
            }),
            sealing: match self.store.secrets.as_ref() {
                Ok(_) => "sealed",
                Err(crate::secrets::keyring::Absent::Refused) => "refused",
                Err(crate::secrets::keyring::Absent::Portable) => "portable",
                Err(_) => "unavailable",
            },
            traffic_available: self.traffic_available,
            traffic_up: self.traffic.upload,
            traffic_down: self.traffic.download,
            connections: self.settings_connections(),
            local_proxy: self.settings_proxy_address(),
        }
    }
}
