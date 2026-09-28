//! Traffic history, connection list and local proxy address for the settings view.
use super::*;

impl Engine {
    pub fn traffic_history(&mut self) -> Value {
        serde_json::to_value(self.history.read(
            &self.data_dir,
            integer(&self.store.library, "traffic_stats_retention_days") as u64,
        ))
        .unwrap_or(Value::Null)
    }
    /// Qt's traffic statistics dialog: one period of counted bytes with its
    /// chart buckets and the breakdowns by profile and by application.
    pub fn traffic_stats(&mut self, days: u32, offset_minutes: i64) -> Result<Value, String> {
        if !crate::traffic_stats::PERIODS.contains(&days) || offset_minutes.abs() > 16 * 60 {
            return Err("invalid_command_payload".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "operation_failed")?
            .as_secs();
        let window = crate::traffic_stats::Window::of(days, now, offset_minutes * 60);
        // Reading keeps the retained window of the settings, not the asked one.
        let retention = integer(&self.store.library, "traffic_stats_retention_days") as u64;
        self.history.load(&self.data_dir);
        let names = self.history.names().clone();
        let entries = self.history.read(&self.data_dir, retention);
        let stats = crate::traffic_stats::aggregate(
            entries.into_iter(),
            &names,
            &self.store.library,
            window,
        );
        serde_json::to_value(stats).map_err(|_| "operation_failed".into())
    }
    pub fn clear_traffic_history(&mut self) -> Result<(), String> {
        self.history.clear(&self.data_dir)
    }
    pub(crate) fn settings_connections(&self) -> Vec<crate::traffic::Connection> {
        if !boolean(&self.store.library, "enable_stats") {
            return vec![];
        }
        let mut list = self.traffic.active.clone();
        if !boolean(&self.store.library, "show_system_dns") {
            list.retain(|c| c.protocol != "dns" && !c.outbound.starts_with("dns-"));
        }
        let key = string(&self.store.library, "connection_sort");
        list.sort_by(|a, b| match key.as_str() {
            "upload" => a.upload.cmp(&b.upload),
            "download" => a.download.cmp(&b.download),
            "destination" => a.destination.cmp(&b.destination),
            "process" => a.process.cmp(&b.process),
            _ => a.created_at.cmp(&b.created_at),
        });
        if !boolean(&self.store.library, "connection_sort_asc") {
            list.reverse();
        }
        list
    }
    pub(crate) fn settings_proxy_address(&self) -> Option<String> {
        let address = self.settings_raw_proxy_address()?;
        let (host, port) = address.rsplit_once(':')?;
        Some(
            string(&self.store.library, "proxy_scheme")
                .replace("{ip}", host)
                .replace("{port}", port),
        )
    }
    pub(crate) fn settings_raw_proxy_address(&self) -> Option<String> {
        if let Some(c) = &self.active_connection {
            let core: Value = serde_json::from_str(c.request.core_config.as_deref()?).ok()?;
            return crate::config::local_inbound(&core, crate::config::ANY_PROXY)
                .map(|inbound| inbound.address());
        }
        let id = self.store.library.selected.as_ref()?;
        let profile = self.profile(id).ok()?;
        if profile.kind == ProfileKind::SingBoxConfig {
            return crate::config::local_proxy(
                &profile,
                self.store.library.preferences.inbound_port,
            );
        }
        if boolean(&self.store.library, "disable_mixed_inbound") {
            return None;
        }
        let address = string(&self.store.library, "inbound_address");
        let address = match address.as_str() {
            "0.0.0.0" => "127.0.0.1",
            "::" => "::1",
            a => a,
        };
        let address = if address.contains(':') {
            format!("[{address}]")
        } else {
            address.into()
        };
        Some(format!(
            "{}:{}",
            address, self.store.library.preferences.inbound_port
        ))
    }
}
