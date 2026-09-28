use super::*;
#[test]
fn system_dns_is_opt_in_and_requires_dns_capture() {
    let mut settings = Settings::default();
    assert_eq!(settings.system_dns, SystemDns::Disabled);
    settings.system_dns = SystemDns::Resolved;
    assert!(settings.validate().is_ok());
    settings.dns_hijack = false;
    assert_eq!(
        settings.validate().unwrap_err(),
        "tun_system_dns_requires_hijack"
    );
    assert!(serde_json::from_value::<Settings>(json!({"systemDns":"unknown"})).is_err());
    assert_eq!(
        serde_json::from_value::<Settings>(json!({}))
            .unwrap()
            .system_dns,
        SystemDns::Disabled
    );
}
#[test]
fn resolvconf_is_explicit_and_requires_capture() {
    let mut settings: Settings = serde_json::from_value(json!({"systemDns":"resolvconf"})).unwrap();
    assert_eq!(settings.system_dns, SystemDns::Resolvconf);
    assert!(settings.validate().is_ok());
    assert_eq!(
        serde_json::to_value(&settings).unwrap()["systemDns"],
        "resolvconf"
    );
    settings.dns_hijack = false;
    assert_eq!(
        settings.validate().unwrap_err(),
        "tun_system_dns_requires_hijack"
    );
}
#[test]
fn endpoint_profiles_leave_the_gvisor_stack_for_mixed_and_others_keep_theirs() {
    let endpoint = json!({"endpoints":[{"type":"wireguard","tag":"proxy"}],"outbounds":[]});
    let outbound = json!({"endpoints":[],"outbounds":[{"type":"vless","tag":"proxy"}]});
    let plain = json!({"outbounds":[{"type":"direct","tag":"proxy"}]});
    assert_eq!(effective_stack(Stack::Gvisor, &endpoint), Stack::Mixed);
    assert_eq!(effective_stack(Stack::Gvisor, &outbound), Stack::Gvisor);
    assert_eq!(effective_stack(Stack::Gvisor, &plain), Stack::Gvisor);
    assert_eq!(effective_stack(Stack::Mixed, &endpoint), Stack::Mixed);
    assert_eq!(effective_stack(Stack::System, &endpoint), Stack::System);
}
#[test]
fn refuses_overlapping_connected_networks_including_broader_subnets() {
    for cidr in ["172.19.0.2/32", "172.19.1.1/16", "172.19.0.0/31"] {
        assert!(overlaps(cidr, IPV4_ADDRESS));
    }
    assert!(overlaps("fdfe:dcba:9876::12/64", IPV6_ADDRESS));
    for cidr in ["172.18.0.1/16", "192.168.1.1/24", "172.19.0.4/30", "::/0"] {
        assert!(!overlaps(cidr, IPV4_ADDRESS));
    }
}
#[test]
fn validates_ranges_and_bounds() {
    for cidr in [
        "0.0.0.0/0",
        "192.0.2.0/24",
        "192.0.2.1/32",
        "::/0",
        "2001:db8::/32",
        "::1/128",
    ] {
        assert!(valid_cidr(cidr), "{cidr}");
    }
    for cidr in [
        "192.0.2.1/24",
        "0.0.0.0/33",
        "::/129",
        "2001:db8::1/64",
        "127.0.0.1",
        " x/2",
        "::/-1",
        "::/0/0",
    ] {
        assert!(!valid_cidr(cidr), "{cidr}");
    }
    for mtu in [0, 1279, 9001, 65535] {
        assert!(Settings {
            mtu,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    assert!(Settings::default().validate().is_ok());
}
#[test]
fn old_preferences_get_tun_defaults() {
    let mut old = serde_json::to_value(Preferences::default()).unwrap();
    old.as_object_mut().unwrap().remove("tun");
    assert_eq!(
        serde_json::from_value::<Preferences>(old).unwrap().tun,
        Settings::default()
    );
}
#[test]
#[cfg(target_os = "linux")]
fn generation_preserves_routing_dns_and_opaque_profiles() {
    let profile = Profile {
        vpn_policy: None,
        id: "a".into(),
        name: "a".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
    };
    let mut library = crate::store::Library::default();
    library.preferences.connection_mode = ConnectionMode::Tun;
    library.preferences.tun.ipv6 = true;
    let mut request = crate::config::build(&profile, 2080, None).unwrap();
    crate::routing::apply(
        &mut request,
        &profile,
        library.routing.active().unwrap(),
        &[],
    )
    .unwrap();
    let before: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    apply(&mut request, &profile, &library.preferences).unwrap();
    let after: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(before["dns"], after["dns"]);
    assert_eq!(before["inbounds"][0], after["inbounds"][0]);
    assert_eq!(after["inbounds"][1]["address"].as_array().unwrap().len(), 2);
    assert_eq!(after["route"]["rules"][0]["inbound"], json!([INTERFACE]));
    request = crate::config::build(&profile, 2080, None).unwrap();
    request.need_xray = Some(true);
    apply(&mut request, &profile, &library.preferences).unwrap();
    request.need_xray = Some(false);
    let original = request.core_config.clone();
    let raw = Profile {
        kind: ProfileKind::SingBoxConfig,
        ..profile
    };
    library.preferences.connection_mode = ConnectionMode::Local;
    apply(&mut request, &raw, &library.preferences).unwrap();
    assert_eq!(original, request.core_config);
}
#[test]
#[cfg(target_os = "linux")]
fn complete_sing_box_json_gets_the_managed_listener_and_keeps_its_own_network() {
    let raw = Profile {
        vpn_policy: None,
        id: "raw".into(),
        name: "raw".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxConfig,
        favorite: false,
        config: json!({"outbounds":[{"type":"socks","tag":"exit","server":"192.0.2.10","server_port":1080}],
            "endpoints":[{"type":"wireguard","tag":"wg","private_key":"cHJpdmF0ZQ==","address":["10.7.0.2/32"],
                "peers":[{"address":"192.0.2.11","port":51820,"public_key":"cHVibGlj","allowed_ips":["0.0.0.0/0"]}]}],
            "route":{"final":"exit","rules":[{"domain_suffix":["wg.test"],"action":"route","outbound":"wg"}]},
            "dns":{"servers":[{"type":"udp","tag":"remote","server":"192.0.2.12"}],"final":"remote"}}),
    };
    let mut library = crate::store::Library::default();
    library.preferences.connection_mode = ConnectionMode::Tun;
    library.preferences.tun.dns_hijack = true;
    library.preferences.tun.system_dns = SystemDns::Resolved;
    let mut request = crate::config::build(&raw, 2080, None).unwrap();
    let before: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    apply(&mut request, &raw, &library.preferences).unwrap();
    let after: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(after["outbounds"], before["outbounds"]);
    assert_eq!(after["endpoints"], before["endpoints"]);
    assert_eq!(after["dns"], before["dns"]);
    assert_eq!(after["route"]["final"], "exit");
    assert_eq!(after["route"]["auto_detect_interface"], true);
    assert_eq!(after["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(after["inbounds"][0]["type"], "tun");
    // The endpoint switches the default gvisor stack to mixed.
    assert_eq!(after["inbounds"][0]["stack"], "mixed");
    assert_eq!(after["route"]["rules"][0]["action"], "hijack-dns");
    assert_eq!(after["route"]["rules"][1], before["route"]["rules"][0]);
    assert_eq!(request.managed_tun_dns_mode.as_deref(), Some("resolved"));
    // A JSON without inbounds/route still gets the listener; one with its own
    // terminating inbound is refused before any core starts.
    let minimal = Profile {
        config: json!({"outbounds":[{"type":"direct","tag":"direct"}]}),
        ..raw.clone()
    };
    let mut request = crate::config::build(&minimal, 2080, None).unwrap();
    apply(&mut request, &minimal, &library.preferences).unwrap();
    let after: Value = serde_json::from_str(request.core_config.as_ref().unwrap()).unwrap();
    assert_eq!(after["inbounds"][0]["type"], "tun");
    assert_eq!(after["route"]["rules"][0]["action"], "hijack-dns");
    for own in ["tun", "redirect", "tproxy"] {
        let owned = Profile {
            config: json!({"inbounds":[{"type":own,"tag":"mine"}],"outbounds":[{"type":"direct","tag":"direct"}]}),
            ..raw.clone()
        };
        let mut request = crate::config::build(&owned, 2080, None).unwrap();
        assert_eq!(
            apply(&mut request, &owned, &library.preferences).unwrap_err(),
            "tun_full_config_inbound_unsupported",
            "{own}"
        );
    }
}

fn listener(system: inbound::System, settings: &Settings) -> (Value, Option<String>) {
    let mut config =
        json!({"inbounds":[], "route":{"rules":[{"outbound":"direct"}]}, "outbounds":[]});
    let mode = inbound::add(&mut config, settings, system).unwrap();
    (config, mode)
}

#[test]
fn windows_tun_has_no_linux_policy_routing_and_captures_dns_on_its_adapter() {
    let mut settings = Settings {
        strict_route: true,
        ..Default::default()
    };
    let (config, mode) = listener(inbound::System::Windows, &settings);
    let tun = &config["inbounds"][0];
    assert_eq!(tun["interface_name"], INTERFACE);
    assert_eq!(tun["dns_mode"], "hijack");
    assert_eq!(tun["strict_route"], true);
    for linux_only in ["iproute2_rule_index", "auto_redirect"] {
        assert!(tun.get(linux_only).is_none(), "{linux_only}");
    }
    assert_eq!(config["route"]["rules"][0]["action"], "hijack-dns");
    assert_eq!(mode, None);
    settings.dns_hijack = false;
    let (config, _) = listener(inbound::System::Windows, &settings);
    assert_eq!(config["inbounds"][0]["dns_mode"], "disabled");
    assert_eq!(config["route"]["rules"][0]["outbound"], "direct");
    let (linux, _) = listener(inbound::System::Linux, &Settings::default());
    assert_eq!(linux["inbounds"][0]["iproute2_rule_index"], RULE_PRIORITY);
    assert_eq!(linux["inbounds"][0]["dns_mode"], "disabled");
}

#[test]
fn interface_dns_is_the_windows_system_dns_and_each_system_ignores_the_others() {
    let mut settings: Settings = serde_json::from_value(json!({"systemDns":"interface"})).unwrap();
    assert!(settings.validate().is_ok());
    let (config, mode) = listener(inbound::System::Windows, &settings);
    assert_eq!(mode.as_deref(), Some("interface"));
    assert_eq!(
        config["inbounds"][1],
        json!({"type":"direct","tag":"dns-in","listen":"127.1.1.1","listen_port":53})
    );
    assert_eq!(
        config["route"]["rules"][0],
        json!({"inbound":["dns-in"],"action":"hijack-dns"})
    );
    assert_eq!(config["route"]["rules"][1]["inbound"], json!([INTERFACE]));
    let (linux, mode) = listener(inbound::System::Linux, &settings);
    assert_eq!(mode, None);
    assert_eq!(linux["inbounds"].as_array().unwrap().len(), 1);
    settings.system_dns = SystemDns::Resolved;
    assert_eq!(listener(inbound::System::Windows, &settings).1, None);
    assert_eq!(
        listener(inbound::System::Linux, &settings).1.as_deref(),
        Some("resolved")
    );
    settings.system_dns = SystemDns::Interface;
    settings.dns_hijack = false;
    assert_eq!(
        settings.validate().unwrap_err(),
        "tun_system_dns_requires_hijack"
    );
}

#[test]
fn interface_dns_reuses_the_local_dns_server_already_on_its_address() {
    let settings: Settings = serde_json::from_value(json!({"systemDns":"interface"})).unwrap();
    let mut config = json!({"inbounds":[{"type":"direct","tag":"dns-server-in","listen":"127.1.1.1","listen_port":53}],
        "route":{"rules":[]}});
    inbound::add(&mut config, &settings, inbound::System::Windows).unwrap();
    assert_eq!(config["inbounds"].as_array().unwrap().len(), 2);
    assert_eq!(
        config["route"]["rules"][0],
        json!({"inbound":["dns-server-in"],"action":"hijack-dns"})
    );
}

#[test]
fn windows_starts_with_the_system_stack_and_strict_route() {
    let settings = Settings::default();
    let expected = if cfg!(windows) {
        (Stack::System, true)
    } else {
        (Stack::Gvisor, false)
    };
    assert_eq!((settings.stack, settings.strict_route), expected);
    // The window shows the same defaults on each system.
    let catalog: Value =
        serde_json::from_str(include_str!("../../../contracts/settings.catalog.json")).unwrap();
    let field = |id: &str| {
        catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .unwrap()
            .clone()
    };
    let (stack, strict) = (field("vpn_implementation"), field("vpn_strict_route"));
    assert_eq!(
        (&stack["default"], &strict["default"]),
        (&json!("gvisor"), &json!(false))
    );
    assert_eq!(stack["byPlatform"]["windows"]["default"], "system");
    assert_eq!(strict["byPlatform"]["windows"]["default"], true);
}

#[cfg(target_os = "linux")]
#[test]
fn a_core_on_an_ordinary_filesystem_is_reachable_by_root() {
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("ThroniumCore");
    std::fs::write(&core, b"core").unwrap();
    assert!(super::root_can_reach(&core));
    // A path that cannot be inspected is left to pkexec to report.
    assert!(super::root_can_reach(std::path::Path::new(
        "/no/such/ThroniumCore"
    )));
}

#[cfg(target_os = "linux")]
#[test]
fn root_runs_a_verified_private_copy_and_only_the_current_one_is_kept() {
    use std::os::unix::fs::PermissionsExt;
    let image = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let core = image.path().join("ThroniumCore");
    std::fs::write(&core, b"first core").unwrap();
    let first = super::reachable_copy(&core, data.path()).unwrap();
    assert_eq!(std::fs::read(&first).unwrap(), b"first core");
    assert_eq!(
        std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(data.path().join("tun-core"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    // The same core reuses its copy; a new one replaces it.
    assert_eq!(super::reachable_copy(&core, data.path()).unwrap(), first);
    std::fs::write(&core, b"second core").unwrap();
    let second = super::reachable_copy(&core, data.path()).unwrap();
    assert_ne!(second, first);
    assert!(!first.exists());
    assert_eq!(std::fs::read(&second).unwrap(), b"second core");
}
