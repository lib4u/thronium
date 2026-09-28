//! SQLite keys differ from some SettingsRepo member names. Keep that boundary
//! explicit: this maps a requested member, never rewrites untrusted source rows.
pub(super) const ALIASES: &[(&str, &str)] = &[
    ("fake_dns", "fakedns"),
    ("disable_run_admin", "disable_win_admin"),
    ("remember_system_proxy", "system_proxy_enabled"),
    ("remember_tun", "tun_mode_enabled"),
    ("user_agent", "user_agent2"),
    ("test_latency_url", "test_url"),
    ("custom_route_global", "custom_route"),
    ("hotkey_mainwindow", "hk_mw"),
    ("hotkey_group", "hk_group"),
    ("hotkey_route", "hk_route"),
    ("hotkey_system_proxy_menu", "hk_spmenu"),
    ("hotkey_toggle_system_proxy", "hk_toggle"),
    ("vpn_implementation", "vpn_impl"),
    ("mainWindowGeometry", "main_window_geometry"),
    ("resolve_domain_strategy", "domain_strategy"),
    ("default_domain_strategy", "outbound_domain_strategy"),
    ("extraCorePaths", "extra_core_paths"),
    ("dial_bind_interface_history", "dial_bind_ifc_history"),
    ("dial_inet4_bind_address_history", "dial_inet4_bind_history"),
    ("dial_inet6_bind_address_history", "dial_inet6_bind_history"),
];

pub(super) fn key(member: &str) -> &str {
    ALIASES
        .iter()
        .find_map(|&(name, key)| (name == member).then_some(key))
        .unwrap_or(member)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_match_every_persisted_qt_member_without_rewriting_unknown_rows() {
        let source = crate::qt_source::frozen("settings-repo-init-maps.cpp");
        let pattern = regex::Regex::new(r#"\{"(\w+)",\s*&(\w+)\}"#).unwrap();
        let actual: std::collections::BTreeMap<_, _> = pattern
            .captures_iter(source)
            .filter(|row| row[1] != row[2])
            .map(|row| (row[2].to_owned(), row[1].to_owned()))
            .collect();
        let expected: std::collections::BTreeMap<_, _> = ALIASES
            .iter()
            .map(|&(member, key)| (member.to_owned(), key.to_owned()))
            .collect();
        assert_eq!(actual, expected);
        for (member, stored) in actual {
            assert_eq!(key(&member), stored);
            assert_eq!(key(&stored), stored);
        }
        assert_eq!(key("private-unknown"), "private-unknown");
    }
}
