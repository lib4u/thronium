use super::*;
use crate::{
    routing::Rule,
    store::{Library, Store},
    Engine, ProfileDraft,
};
use std::path::Path;

fn policy(gate: bool, dns: bool, block: bool) -> Policy {
    Policy {
        only_advertised_routes: gate,
        use_tunnel_dns: dns,
        block_outside_dns: block,
    }
}
fn profile(protocol: &str, policy: Option<Policy>) -> Profile {
    Profile {
        id: "vpn".into(),
        name: "VPN".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        vpn_policy: policy,
        config: json!({"type":protocol,"server":"127.0.0.1","server_port":1194,"username":"private-user","password":"private-password"}),
    }
}
fn library(profile: &Profile) -> Library {
    Library {
        version: if profile.vpn_policy.is_some() { 4 } else { 1 },
        profiles: vec![profile.clone()],
        ..Default::default()
    }
}
fn built(profile: &Profile, library: &Library) -> Result<Value, String> {
    let directory = tempfile::tempdir().unwrap();
    Engine::build_with_library(profile, library, directory.path())
        .map(|r| serde_json::from_str(r.core_config.as_deref().unwrap()).unwrap())
}
fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, engine)
}
fn draft(profile: &Profile) -> ProfileDraft {
    serde_json::from_value(json!({"name":profile.name,"groupId":profile.group_id,"kind":profile.kind,"config":profile.config,"vpnPolicy":profile.vpn_policy})).unwrap()
}

#[test]
fn sixteen_policies_preserve_stored_bits_and_exact_route_dns_precedence() {
    for protocol in ["openvpn-client", "openconnect"] {
        for gate in [false, true] {
            for dns in [false, true] {
                for block in [false, true] {
                    let p = profile(protocol, Some(policy(gate, dns, block)));
                    let mut l = library(&p);
                    let explicit = json!({"domain_suffix":["explicit.test"],"action":"route","outbound":"direct"});
                    let dns_rule =
                        json!({"domain":["explicit.test"],"action":"route","server":"other"});
                    l.routing.profiles[0].rules.push(Rule {
                        id: "r1".into(),
                        name: "Explicit".into(),
                        enabled: true,
                        config: explicit.clone(),
                        simple: None,
                    });
                    l.routing.profiles[0].dns = json!({"servers":[{"type":"local","tag":"dns-direct"},{"type":"udp","tag":"other","server":"192.0.2.1"}],"rules":[dns_rule.clone()],"final":"other"});
                    let before = json!(l);
                    let core = built(&p, &l).unwrap();
                    assert_eq!(core["route"]["rules"][0], crate::routing::builtin::sniff());
                    assert_eq!(core["route"]["rules"][1], explicit);
                    assert_eq!(
                        core["route"]["rules"].as_array().unwrap().len(),
                        if gate { 4 } else { 2 }
                    );
                    if gate {
                        assert_eq!(
                            core["route"]["rules"][2],
                            json!({"preferred_by":["proxy"],"action":"route","outbound":"proxy"})
                        );
                        assert_eq!(core["route"]["rules"][3], json!({"action":"reject"}));
                    }
                    assert_eq!(core["route"]["final"], "proxy");
                    let servers = core["dns"]["servers"].as_array().unwrap();
                    assert_eq!(servers.len(), if gate || dns { 3 } else { 2 });
                    if gate || dns {
                        let mut expected = json!({"tag":DNS_TAG,"type":if protocol=="openvpn-client" {"openvpn"} else {"openconnect"},"endpoint":"proxy"});
                        if gate {
                            expected["accept_default_resolvers"] = json!(true);
                            expected["accept_search_domain"] = json!(true);
                        }
                        assert_eq!(servers[2], expected);
                        assert_eq!(
                            core["dns"]["rules"][0],
                            json!({"preferred_by":[DNS_TAG],"action":"route","server":DNS_TAG})
                        );
                        assert_eq!(core["dns"]["rules"][1], dns_rule);
                    } else {
                        assert_eq!(core["dns"]["rules"], json!([dns_rule]));
                    }
                    assert_eq!(
                        core["dns"]["final"],
                        if !gate {
                            "other"
                        } else if block {
                            DNS_TAG
                        } else {
                            "dns-direct"
                        }
                    );
                    assert_eq!(core["endpoints"][0]["password"], p.config["password"]);
                    assert!(core["endpoints"][0].get("vpnPolicy").is_none());
                    assert_eq!(json!(l), before);
                    assert_eq!(
                        built(&p, &l).unwrap(),
                        core,
                        "fresh repeated build must not append duplicate policy"
                    );
                }
            }
        }
    }
}

#[test]
fn absent_metadata_and_non_vpn_final_preserve_existing_behavior() {
    let p = profile("openvpn-client", None);
    let l = library(&p);
    let before = built(&p, &l).unwrap();
    assert_eq!(
        before["route"]["rules"],
        json!([crate::routing::builtin::sniff()])
    );
    assert_eq!(before["dns"]["servers"].as_array().unwrap().len(), 1);
    for final_tag in ["direct", "other"] {
        let p = profile("openvpn-client", Some(policy(true, true, false)));
        let mut l = library(&p);
        l.routing.profiles[0].route["final"] = json!(final_tag);
        let core = built(&p, &l).unwrap();
        assert_eq!(core["route"]["final"], final_tag);
        assert_eq!(
            core["route"]["rules"],
            json!([crate::routing::builtin::sniff()])
        );
        assert_eq!(core["dns"]["final"], "dns-direct");
    }
}

#[test]
#[cfg_attr(
    windows,
    ignore = "OpenVPN and OpenConnect hosts are refused on Windows"
)]
fn basic_tun_preserves_policy_rules_and_dns_with_own_hijack_first() {
    for protocol in ["openvpn-client", "openconnect"] {
        for bits in 0..8 {
            let p = profile(
                protocol,
                Some(policy(bits & 1 != 0, bits & 2 != 0, bits & 4 != 0)),
            );
            let mut l = library(&p);
            l.preferences.connection_mode = crate::system_proxy::ConnectionMode::Tun;
            let dir = tempfile::tempdir().unwrap();
            let mut request = Engine::build_with_library(&p, &l, dir.path()).unwrap();
            let before: Value =
                serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
            crate::tun::apply(&mut request, &p, &l.preferences).unwrap();
            crate::tun::apply_settings(&mut request, &l).unwrap();
            let after: Value =
                serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
            assert_eq!(after["dns"], before["dns"]);
            assert_eq!(
                &after["route"]["rules"].as_array().unwrap()[1..],
                before["route"]["rules"].as_array().unwrap()
            );
            assert_eq!(after["route"]["rules"][0]["action"], "hijack-dns");
        }
    }
}

#[test]
fn conflicts_refuse_before_core_or_mutation_without_affecting_unrelated_policy() {
    let p = profile("openconnect", Some(policy(true, true, false)));
    let l = library(&p);
    for key in [
        "enable_warp",
        "vpn_l3_bridge",
        "vpn_auto_redirect",
        "enable_dns_server",
        "enable_dns_routing",
    ] {
        let mut l = l.clone();
        l.settings.insert(key.into(), json!(true));
        let before = json!(l);
        assert_eq!(built(&p, &l).unwrap_err(), "vpn_policy_context_unsupported");
        assert_eq!(json!(l), before);
    }
    let mut l = l.clone();
    l.routing.profiles[0].dns["servers"] = json!([{"type":"local","tag":["dns-direct",DNS_TAG]}]);
    assert_eq!(built(&p, &l).unwrap_err(), "vpn_policy_tag_conflict");
    l.routing.profiles[0].dns["servers"] =
        json!([{"type":"tcp","tag":"dns-direct","server":"192.0.2.1","detour":"proxy"}]);
    assert_eq!(built(&p, &l).unwrap_err(), "vpn_policy_dns_unsupported");
    let mut plain = p.clone();
    plain.id = "plain".into();
    plain.vpn_policy = None;
    l.profiles.push(plain.clone());
    assert!(built(&plain, &l).is_ok());
    l.routing.profiles[0].route["final"] = json!("profile:vpn");
    assert_eq!(
        built(&plain, &l).unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    let mut full = p.clone();
    full.id = "full".into();
    full.vpn_policy = None;
    full.kind = ProfileKind::SingBoxConfig;
    full.config = json!({"outbounds":[{"type":"direct","tag":"proxy"}],"dns":{"servers":[{"type":"local","tag":"mine"}]},"route":{"final":"proxy"}});
    assert_eq!(built(&full, &l).unwrap(), full.config);
}

#[test]
fn missing_keep_null_clear_and_version_four_are_distinct_and_monotonic() {
    let (dir, mut e) = setup();
    let p = profile("openvpn-client", Some(policy(true, false, true)));
    let id = e.save_profile(draft(&p)).unwrap();
    assert_eq!(e.store.library.version, 4);
    let config = e.profile(&id).unwrap().config;
    let d:ProfileDraft=serde_json::from_value(json!({"id":id,"name":"Renamed","groupId":"personal","kind":"sing-box-outbound","config":config})).unwrap();
    assert_eq!(d.vpn_policy, Edit::Keep);
    e.save_profile(d).unwrap();
    assert_eq!(e.profile(&id).unwrap().vpn_policy, p.vpn_policy);
    let d:ProfileDraft=serde_json::from_value(json!({"id":id,"name":"Renamed","groupId":"personal","kind":"sing-box-outbound","config":config,"vpnPolicy":null})).unwrap();
    assert_eq!(d.vpn_policy, Edit::Set(None));
    e.save_profile(d).unwrap();
    assert_eq!(e.profile(&id).unwrap().vpn_policy, None);
    assert_eq!(e.store.library.version, 4);
    drop(e);
    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(reopened.library.version, 4);
    assert_eq!(reopened.library.profiles[0].config, config);
}

#[test]
fn metadata_wire_versions_backup_and_portable_bundle_cannot_silently_drop_policy() {
    let (_dir, mut e) = setup();
    let p = profile("openconnect", Some(policy(false, true, true)));
    let id = e.save_profile(draft(&p)).unwrap();
    let backup = e.export_backup().unwrap();
    let preview = e.preview_backup(&backup).unwrap();
    e.restore_backup(&preview.token).unwrap();
    assert_eq!(e.profile(&id).unwrap().vpn_policy, p.vpn_policy);
    let text = e
        .export_profiles(vec![id.clone()], crate::exports::Format::Profiles)
        .unwrap();
    let bundle: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(bundle["version"], 2);
    assert_eq!(
        bundle["profiles"][0]["vpnPolicy"],
        json!(p.vpn_policy.unwrap())
    );
    assert_eq!(
        e.export_profiles(vec![id.clone()], crate::exports::Format::Configurations)
            .unwrap_err(),
        "vpn_policy_export_requires_bundle"
    );
    let mut entry = bundle["profiles"][0].clone();
    entry["groupId"] = json!("personal");
    let imported = e
        .import_referenced_profiles(vec![serde_json::from_value(entry).unwrap()])
        .unwrap();
    assert_eq!(e.profile(&imported[0]).unwrap().vpn_policy, p.vpn_policy);
    let mut invalid: Value = serde_json::from_str(&backup).unwrap();
    invalid["library"]["version"] = json!(3);
    assert!(e.preview_backup(&invalid.to_string()).is_err());
    for body in [
        r#"{"onlyAdvertisedRoutes":true,"useTunnelDns":false,"blockOutsideDns":false,"onlyAdvertisedRoutes":false}"#,
        r#"{"onlyAdvertisedRoutes":true,"useTunnelDns":false}"#,
        r#"{"onlyAdvertisedRoutes":true,"useTunnelDns":false,"blockOutsideDns":false,"unknown":true}"#,
    ] {
        let bytes = format!("{{\"profiles\":[{{\"vpnPolicy\":{body}}}]}}");
        assert!(validate_wire(bytes.as_bytes(), false).is_err());
    }
    assert!(validate_wire(
        br#"{"profiles":[{"vpnPolicy":null,"vpnPolicy":null}]}"#,
        false
    )
    .is_err());
}

#[test]
fn policy_difference_prevents_destructive_duplicate_coalescing() {
    let (_dir, mut e) = setup();
    let p = profile("openvpn-client", Some(policy(true, true, false)));
    let a = e.save_profile(draft(&p)).unwrap();
    let mut second = p.clone();
    second.vpn_policy = Some(policy(false, true, false));
    let b = e.save_profile(draft(&second)).unwrap();
    assert_eq!(
        e.preview_duplicates(vec![a.clone(), b.clone()])
            .unwrap()
            .count,
        0
    );
    let c = e.save_profile(draft(&p)).unwrap();
    let preview = e.preview_duplicates(vec![a, b, c]).unwrap();
    assert_eq!(preview.count, 1);
}

#[test]
fn profile_kind_changes_and_commit_faults_do_not_silently_clear_or_rewind_metadata() {
    use crate::store::CommitFault;
    let (directory, mut e) = setup();
    let p = profile("openvpn-client", Some(policy(true, true, false)));
    let id = e.save_profile(draft(&p)).unwrap();
    let before = std::fs::read(directory.path().join("library.json")).unwrap();
    let incompatible:ProfileDraft=serde_json::from_value(json!({"id":id,"name":"Wrong kind","groupId":"personal","kind":"sing-box-outbound","config":{"type":"direct"}})).unwrap();
    assert_eq!(
        e.save_profile(incompatible).unwrap_err(),
        "vpn_policy_profile_unsupported"
    );
    assert_eq!(
        std::fs::read(directory.path().join("library.json")).unwrap(),
        before
    );
    for fault in [
        CommitFault::BeforeRename,
        CommitFault::AfterRename,
        CommitFault::DirectorySync,
    ] {
        let old = e.profile(&id).unwrap();
        let mut replacement = old.clone();
        replacement.vpn_policy = Some(policy(
            !old.vpn_policy.unwrap().only_advertised_routes,
            false,
            true,
        ));
        let mut change = draft(&replacement);
        change.id = Some(id.clone());
        e.store.fail_next_commit(fault);
        assert!(e.save_profile(change).is_err());
        let memory = e.profile(&id).unwrap();
        let disk: Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("library.json")).unwrap())
                .unwrap();
        let expected = if fault == CommitFault::BeforeRename {
            old.vpn_policy
        } else {
            replacement.vpn_policy
        };
        assert_eq!(memory.vpn_policy, expected);
        assert_eq!(disk["profiles"][0]["vpnPolicy"], json!(expected));
        assert_eq!(e.store.library.version, 4);
        assert!(e.owned_core_process().is_none());
    }
}

#[tokio::test]
async fn unsupported_policy_is_rejected_before_asset_preparation_and_core_commands() {
    let (_directory, mut e) = setup();
    let p = profile("openvpn-client", Some(policy(true, true, false)));
    let id = e.save_profile(draft(&p)).unwrap();
    e.store
        .library
        .settings
        .insert("enable_warp".into(), json!(true));
    let before = json!(e.store.library);
    let profile = e.profile(&id).unwrap();
    assert_eq!(
        e.check(&profile).await.unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    assert_eq!(
        e.connection_configuration(&id, false).await.unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    assert_eq!(
        e.connect(&id).await.unwrap_err(),
        "vpn_policy_context_unsupported"
    );
    assert!(e.owned_core_process().is_none());
    assert_eq!(json!(e.store.library), before);
}

fn socks(id: &str) -> Profile {
    Profile {
        id: id.into(),
        name: id.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        vpn_policy: None,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    }
}
fn chain(id: &str, hops: &[&str]) -> Profile {
    Profile {
        kind: ProfileKind::Chain,
        config: json!({"type":"chain","hops":hops}),
        ..socks(id)
    }
}
#[test]
fn chain_exit_policy_is_applied_and_earlier_hop_policies_are_ignored_as_in_qt() {
    let vpn = profile("openvpn-client", Some(policy(true, true, false)));
    let mut l = library(&vpn);
    l.profiles.extend([
        socks("socks"),
        chain("exit-chain", &["socks", "vpn"]),
        chain("entry-chain", &["vpn", "socks"]),
    ]);
    let core = built(&chain("exit-chain", &["socks", "vpn"]), &l).unwrap();
    let dns = core["dns"]["servers"].as_array().unwrap();
    let tunnel = dns.iter().find(|s| s["tag"] == DNS_TAG).unwrap();
    assert_eq!(tunnel["endpoint"], "proxy");
    assert_eq!(core["endpoints"][0]["detour"], "thronium-chain-proxy-0");
    let rules = core["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[rules.len() - 1], json!({"action":"reject"}));
    assert_eq!(rules[rules.len() - 2]["preferred_by"], json!(["proxy"]));
    // The same VPN as the device-side hop only carries the next hop's dial.
    let core = built(&chain("entry-chain", &["vpn", "socks"]), &l).unwrap();
    assert!(core["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["tag"] != DNS_TAG));
    assert!(core["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["action"] != "reject"));
    assert_eq!(core["endpoints"][0]["tag"], "thronium-chain-proxy-0");
    // A policy on an auxiliary target outside the physical sequence stays refused.
    l.routing.profiles[0].rules.push(Rule {
        id: "aux".into(),
        name: "Aux".into(),
        enabled: true,
        simple: None,
        config: json!({"domain_suffix":["aux.test"],"action":"route","outbound":"profile:vpn"}),
    });
    assert_eq!(
        built(&socks("socks"), &l).unwrap_err(),
        "vpn_policy_context_unsupported"
    );
}
