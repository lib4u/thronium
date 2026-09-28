//! Application events in the shared log. Each event carries a code that the
//! window shows in the user's language; the English line is what the log
//! file, search and exported logs contain.
use super::Logs;

/// Codes with their English log line. A code that is not listed is an error
/// code; its log line is the code itself.
#[rustfmt::skip]
pub const EVENTS: &[(&str, &str)] = &[
    ("autostart_switched_off_in_windows", "Autostart was switched off in Windows Task Manager; the setting now follows it"),
    ("deeplink_foreign_handler_kept", "The throne:// handler of another application was left in place; thronium:// links open here"),
    ("qt_throne_running", "Qt Throne is running; its system proxy, TUN or system DNS may interfere"),
    ("auto_select_source_deleted", "Auto-select source group was deleted; using all groups"),
    ("auto_select_source_reset", "Auto-select source group was missing; using all groups"),
    ("check_config_failed", "CheckConfig"),
    ("check_config_xray_failed", "CheckConfig Xray"),
    ("connection_change_failed", "Connection change"),
    ("connection_previous_restored", "Previous connection restored"),
    ("connection_restore_error", "Connection restore"),
    ("connection_restore_skipped_otp", "Previous connection used a one-time code and is not restored"),
    ("connection_started", "Connection started"),
    ("connection_stop_failed", "Stop"),
    ("connection_stopped", "Connection stopped"),
    ("core_exited", "Core process exited unexpectedly"),
    ("core_pair_mismatch", "ThroniumCore beside the application is from another version"),
    ("core_log_stream_failed", "Core log stream closed with an I/O error"),
    ("core_recovery_cleanup_failed", "Local core recovery cleanup failed"),
    ("core_recovery_error", "Local core recovery failed"),
    ("core_recovery_restored", "Local core connection restored"),
    ("core_recovery_scheduled", "Local core recovery scheduled"),
    ("core_recovery_skipped_otp", "Local core recovery skipped: the connection used a one-time code"),
    ("core_recovery_stopped", "Local core exits too frequently; automatic restart stopped"),
    ("core_started", "Core process started"),
    ("external_core_exited", "External core stopped unexpectedly"),
    ("library_restored", "Library restored from backup"),
    (
        "vpn_otp_restarted",
        "Connection restarted with a fresh one-time code",
    ),
    (
        "traffic_history_imported",
        "Traffic history imported from an older copy",
    ),
    ("routing_update_error", "Remote routing update"),
    ("selector_rebuild_finished", "Automatic pool rebuilt successfully"),
    ("selector_rebuild_health_unreadable", "Could not read automatic pool health for rebuilding"),
    ("selector_rebuild_kept_previous", "Could not rebuild the automatic pool; keeping the previous connection when available"),
    ("auto_clear_failed", "Unavailable servers could not be removed"),
    ("auto_clear_removed", "Unavailable servers removed after the test"),
    ("selector_rebuild_started", "Rebuilding automatic pool after all running servers failed"),
    ("selector_subscription_applying", "Applying subscription changes to the automatic pool"),
    ("system_integrations_restore_failed", "Could not restore system integrations"),
    ("system_proxy_shortcut_failed", "System proxy shortcut failed"),
    ("session_end_cleanup_incomplete", "Network settings were not fully restored before the session ended; the next launch finishes it"),
    ("test_cancelled", "Test cancelled"),
    ("test_completed", "Test completed"),
    ("test_failed", "Test failed"),
    ("test_started", "Test started"),
    ("tray_connection_failed", "Tray connection action failed"),
    ("tray_reconnect_failed", "The setting was changed but the connection was not restored"),
    ("tray_routing_apply_failed", "Tray routing was saved but could not be applied"),
    ("tray_routing_save_failed", "Tray routing could not be saved"),
    ("tray_setting_failed", "Tray setting could not be changed"),
    ("tray_unavailable", "System tray is unavailable"),
    ("tun_reconnected", "TUN automatically reconnected"),
    ("tun_reconnecting", "TUN reconnecting"),
    ("tun_service_connected", "Connected to the Thronium service for TUN"),
    ("vpn_credentials_check_logged", "VPN credential configuration check failed"),
    ("vpn_credentials_cleanup_required", "VPN credential replacement requires cleanup"),
];

fn english(code: &str) -> &str {
    EVENTS
        .iter()
        .find(|(known, _)| *known == code)
        .map_or(code, |(_, text)| text)
}

impl Logs {
    /// Records an application event; `detail` is an error code or core
    /// message that follows the event text.
    pub fn event(&self, level: &str, code: &str, detail: Option<&str>) {
        let text = match detail {
            Some(detail) => format!("{}: {detail}", english(code)),
            None => english(code).to_owned(),
        };
        self.record("app", Some(level), &text, false, Some((code, detail)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::Filter;

    #[test]
    fn events_keep_english_lines_and_carry_their_code_and_detail() {
        let logs = Logs::default();
        logs.event("error", "check_config_failed", Some("bad outbound"));
        logs.event("warn", "latency_cache_write_failed", None);
        let view = logs.view(Filter::default()).unwrap();
        assert_eq!(view.entries[0].text, "CheckConfig: bad outbound");
        assert_eq!(view.entries[0].code.as_deref(), Some("check_config_failed"));
        assert_eq!(view.entries[0].detail.as_deref(), Some("bad outbound"));
        assert_eq!(view.entries[1].text, "latency_cache_write_failed");
        assert_eq!(view.entries[1].detail, None);
    }

    #[test]
    fn every_event_has_a_window_text_in_both_languages() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../locales");
        for language in crate::languages::codes() {
            let catalog: serde_json::Value = serde_json::from_slice(
                &std::fs::read(root.join(language).join("diagnostics.json")).unwrap(),
            )
            .unwrap();
            let errors: serde_json::Value = serde_json::from_slice(
                &std::fs::read(root.join(language).join("errors.json")).unwrap(),
            )
            .unwrap();
            // Error codes the engine logs without an event of their own.
            let logged = [
                "auto_select_memory_write_failed",
                "backup_recovery_write_failed",
                "country_cache_write_failed",
                "latency_cache_write_failed",
                "measurement_journal_write_failed",
                "selector_health_read_failed",
                "selector_history_write_failed",
                "store_sync_uncertain",
                "switch_history_write_failed",
                "vpn_otp_start_stale",
            ];
            for code in EVENTS.iter().map(|(code, _)| *code).chain(logged) {
                assert!(
                    catalog[format!("log_{code}")].is_string() || errors[code].is_string(),
                    "{language}: diagnostics.log_{code}"
                );
            }
        }
    }
}
