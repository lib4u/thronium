//! Preferences, connection mode, TUN settings and the system proxy lifecycle.
use super::*;

impl Engine {
    pub fn preferences(&mut self, mut preferences: Preferences) -> Result<(), String> {
        if preferences
            .auto_select
            .source_group_id
            .as_ref()
            .is_some_and(|id| {
                !self
                    .store
                    .library
                    .groups
                    .iter()
                    .any(|group| &group.id == id)
            })
        {
            return Err("auto_select_source_missing".into());
        }
        preferences.auto_select.config =
            auto_selector::quick::config::normalize(&preferences.auto_select.config)?;
        self.check_connection_mode(preferences.connection_mode)?;
        if self.running.is_some()
            && (preferences.inbound_port != self.store.library.preferences.inbound_port
                || preferences.connection_mode != self.store.library.preferences.connection_mode
                || preferences.tun != self.store.library.preferences.tun)
        {
            return Err("stop_before_editing".into());
        }
        let mut next = self.store.library.clone();
        let core_changed = preferences.vless_core != next.preferences.vless_core
            || preferences.vless_overrides != next.preferences.vless_overrides;
        if core_changed {
            self.url_tests_resettable()?;
        }
        next.preferences = preferences;
        let committed = self.store.commit(next);
        if !Store::written(&committed) {
            return committed;
        }
        self.clear_disabled_quick_memory();
        if core_changed {
            self.reset_url_tests_after_commit();
            if self.running.is_some() {
                self.routing_revision = None;
            }
        }
        committed
    }

    pub fn initialize_system_proxy(&mut self) {
        if self.vpn_credentials_proxy_transition.is_some() {
            return;
        }
        self.system_proxy = system_proxy::Manager::platform();
    }
    pub fn initialize_guarded_system_proxy(&mut self) {
        if self.vpn_credentials_proxy_transition.is_some() {
            return;
        }
        self.system_proxy = system_proxy::Manager::platform_guarded();
    }
    pub fn restore_system_proxy(&mut self) -> Result<(), String> {
        self.credentials_proxy_guard()?;
        self.system_proxy.restore()
    }
    pub fn retry_system_proxy_recovery(&mut self) -> Result<(), String> {
        self.credentials_proxy_guard()?;
        self.system_proxy.retry_recovery()
    }
    /// A connection mode this session cannot provide is refused only while it is
    /// being chosen. A library saved in another desktop session or on another
    /// platform must still accept unrelated edits; Connect reports the mode.
    pub(crate) fn check_connection_mode(
        &self,
        next: system_proxy::ConnectionMode,
    ) -> Result<(), String> {
        if next == self.store.library.preferences.connection_mode {
            return Ok(());
        }
        if next == system_proxy::ConnectionMode::Tun && !tun::supported() {
            return Err(crate::tun::unavailable());
        }
        if next == system_proxy::ConnectionMode::SystemProxy
            && !self.system_proxy.status().available
        {
            return Err("system_proxy_unavailable".into());
        }
        Ok(())
    }

    pub fn connection_settings(
        &mut self,
        mode: system_proxy::ConnectionMode,
        port: u16,
    ) -> Result<(), String> {
        let mut preferences = self.store.library.preferences.clone();
        preferences.connection_mode = mode;
        preferences.inbound_port = port;
        self.preferences(preferences)
    }

    pub fn tun_settings(
        &mut self,
        mode: system_proxy::ConnectionMode,
        port: u16,
        tun: tun::Settings,
    ) -> Result<(), String> {
        let mut preferences = self.store.library.preferences.clone();
        preferences.connection_mode = mode;
        preferences.inbound_port = port;
        preferences.tun = tun;
        self.preferences(preferences)
    }
}
