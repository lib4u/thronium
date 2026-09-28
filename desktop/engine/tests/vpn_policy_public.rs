//! Independent public API contract. Pure generation/Store; no Core or network.
use serde_json::{json, Value};
use std::path::PathBuf;
use thronium_engine::{exports::Format, Engine, ProfileDraft};

struct App {
    engine: Engine,
    dir: tempfile::TempDir,
}
impl App {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(dir.path(), &dir.path().join("absent-core")).unwrap();
        Self { engine, dir }
    }
    fn path(&self) -> PathBuf {
        self.dir.path().join("library.json")
    }
    fn disk(&self) -> Vec<u8> {
        std::fs::read(self.path()).unwrap()
    }
    fn idle(&mut self) {
        assert!(self.engine.owned_core_process().is_none());
        assert!(self.engine.snapshot().running.is_none());
    }
}
fn policy(g: bool, d: bool, b: bool) -> Value {
    json!({"onlyAdvertisedRoutes":g,"useTunnelDns":d,"blockOutsideDns":b})
}
fn endpoint(protocol: &str) -> Value {
    if protocol == "openvpn-client" {
        json!({"type":protocol,"server":"192.0.2.34","server_port":1194,"system":false,"username":"public-policy-user","password":"public-policy-password"})
    } else {
        json!({"type":protocol,"server":"vpn.fixture.invalid","system":false,"username":"public-policy-user","password":"public-policy-password"})
    }
}
fn draft(id: Option<&str>, name: &str, config: Value, meta: Option<Value>) -> ProfileDraft {
    let mut v = json!({"id":id,"name":name,"groupId":"personal","kind":"sing-box-outbound","config":config});
    if let Some(p) = meta {
        v["vpnPolicy"] = p;
    }
    serde_json::from_value(v).unwrap()
}
fn profile_value(app: &App, id: &str) -> Value {
    serde_json::to_value(app.engine.profile(id).unwrap()).unwrap()
}
fn fixture_routing(app: &mut App) {
    let mut routing = app.engine.routing();
    let p = &mut routing.profiles[0];
    p.rules=vec![serde_json::from_value(json!({"id":"explicit-direct","name":"Private direct exception","enabled":true,"config":{"domain":["explicit.fixture.invalid"],"action":"route","outbound":"direct"}})).unwrap()];
    p.dns = json!({"servers":[{"type":"local","tag":"dns-direct"},{"type":"udp","tag":"owned-resolver","server":"192.0.2.53"}],"rules":[{"domain":["dns.fixture.invalid"],"action":"route","server":"owned-resolver","disable_cache":true}],"final":"owned-resolver"});
    app.engine.save_routing(routing).unwrap();
}
async fn preview(app: &mut App, id: &str) -> Value {
    let v = app
        .engine
        .connection_configuration(id, false)
        .await
        .unwrap();
    app.idle();
    v["parts"][0]["config"].clone()
}

#[tokio::test]
async fn baseline_v33_no_policy_keeps_profile_backup_bundle_and_complete_request() {
    let mut app = App::new();
    let id = app
        .engine
        .save_profile(draft(
            None,
            "Existing endpoint",
            endpoint("openvpn-client"),
            None,
        ))
        .unwrap();
    fixture_routing(&mut app);
    let before = app.disk();
    let request = preview(&mut app, &id).await;
    assert!(profile_value(&app, &id).get("vpnPolicy").is_none());
    assert_eq!(app.engine.store.library.version, 1);
    assert!(request["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["tag"] == "owned-resolver"));
    assert!(request["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["domain"] == json!(["explicit.fixture.invalid"])));
    assert_eq!(app.disk(), before);
    assert_eq!(preview(&mut app, &id).await, request);
    let bundle: Value = serde_json::from_str(
        &app.engine
            .export_profiles(vec![id.clone()], Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bundle["version"], 1);
    let backup = app.engine.export_backup().unwrap();
    let mut other = App::new();
    let plan = other.engine.preview_backup(&backup).unwrap();
    other.engine.restore_backup(&plan.token).unwrap();
    assert_eq!(profile_value(&other, &id), profile_value(&app, &id));
    assert_eq!(preview(&mut other, &id).await, request);
    other.idle();
}

#[test]
fn v34_public_missing_null_replace_reopen_version_and_atomic_import() {
    let mut app = App::new();
    let source = endpoint("openvpn-client");
    let id = app
        .engine
        .save_profile(draft(None, "Original", source.clone(), None))
        .unwrap();
    let selected = app.engine.snapshot().selected;
    let p = policy(true, true, false);
    app.engine
        .save_profile(draft(Some(&id), "Policy", source.clone(), Some(p.clone())))
        .unwrap();
    assert_eq!(app.engine.store.library.version, 4);
    assert_eq!(profile_value(&app, &id)["vpnPolicy"], p);
    app.engine.favorite(&id).unwrap();
    app.engine
        .save_profile(draft(Some(&id), "Renamed", source.clone(), None))
        .unwrap();
    assert_eq!(profile_value(&app, &id)["vpnPolicy"], p);
    assert!(profile_value(&app, &id)["favorite"] == true);
    assert_eq!(app.engine.snapshot().selected, selected);
    let before = app.disk();
    let invalid = draft(
        None,
        "Unsupported policy target",
        json!({"type":"direct"}),
        Some(p.clone()),
    );
    assert!(app
        .engine
        .import_profiles(vec![
            draft(
                None,
                "Valid batch member",
                endpoint("openconnect"),
                Some(p.clone())
            ),
            invalid
        ])
        .is_err());
    assert_eq!(app.disk(), before);
    let cloned = app
        .engine
        .save_profile(draft(
            None,
            "Explicit clone",
            source.clone(),
            Some(p.clone()),
        ))
        .unwrap();
    assert_eq!(profile_value(&app, &cloned)["vpnPolicy"], p);
    app.engine.delete(&cloned).unwrap();
    assert_eq!(profile_value(&app, &id)["vpnPolicy"], p);
    let backup = app.engine.export_backup().unwrap();
    let mut target = App::new();
    let plan = target.engine.preview_backup(&backup).unwrap();
    target.engine.restore_backup(&plan.token).unwrap();
    assert_eq!(profile_value(&target, &id)["vpnPolicy"], p);
    app.engine
        .save_profile(draft(Some(&id), "Cleared", source, Some(Value::Null)))
        .unwrap();
    assert!(profile_value(&app, &id).get("vpnPolicy").is_none());
    assert_eq!(app.engine.store.library.version, 4);
    let path = app.dir.path().to_owned();
    drop(app.engine);
    let mut reopened = Engine::open(&path, &path.join("absent-core")).unwrap();
    assert_eq!(reopened.store.library.version, 4);
    assert!(serde_json::to_value(reopened.profile(&id).unwrap())
        .unwrap()
        .get("vpnPolicy")
        .is_none());
    assert!(reopened.snapshot().running.is_none());
    target.idle();
}

fn rejected_library(text: &str) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("library.json"), text).unwrap();
    assert!(Engine::open(dir.path(), &dir.path().join("absent-core")).is_err());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("library.json")).unwrap(),
        text
    );
}
#[test]
fn v34_public_strict_metadata_old_reader_boundaries_and_fullbackup() {
    let mut app = App::new();
    let source = endpoint("openvpn-client");
    let good = policy(true, true, false);
    for bad in [
        json!({}),
        json!({"onlyAdvertisedRoutes":true,"useTunnelDns":true}),
        json!({"onlyAdvertisedRoutes":"true","useTunnelDns":true,"blockOutsideDns":false}),
        json!({"onlyAdvertisedRoutes":true,"useTunnelDns":true,"blockOutsideDns":false,"future":true}),
        json!([]),
        json!(false),
    ] {
        let wire = json!({"name":"Bad policy","groupId":"personal","kind":"sing-box-outbound","config":source,"vpnPolicy":bad});
        assert!(serde_json::from_value::<ProfileDraft>(wire).is_err());
    }
    let duplicate = r#"{"name":"Duplicate","groupId":"personal","kind":"sing-box-outbound","config":{"type":"openconnect","server":"vpn.fixture.invalid"},"vpnPolicy":{"onlyAdvertisedRoutes":true,"onlyAdvertisedRoutes":false,"useTunnelDns":true,"blockOutsideDns":false}}"#;
    assert!(serde_json::from_str::<ProfileDraft>(duplicate).is_err());
    let id = app
        .engine
        .save_profile(draft(None, "Valid policy", source, Some(good.clone())))
        .unwrap();
    let library = serde_json::to_value(&app.engine.store.library).unwrap();
    // Before version 4 a library cannot hold a VPN policy; a version from the
    // future is unknown whatever it is (5–8 are real formats by now).
    for version in [1, 2, 3, u32::MAX] {
        let mut value = library.clone();
        value["version"] = json!(version);
        rejected_library(&value.to_string());
    }
    let wire =
        library
            .to_string()
            .replacen("\"vpnPolicy\":", "\"vpnPolicy\":null,\"vpnPolicy\":", 1);
    rejected_library(&wire);
    let text = app.engine.export_backup().unwrap();
    let mut backup: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(backup["version"], 1);
    assert_eq!(backup["library"]["version"], 4);
    let before = app.disk();
    backup["library"]["version"] = json!(3);
    assert!(app.engine.preview_backup(&backup.to_string()).is_err());
    assert_eq!(app.disk(), before);
    let bundle: Value = serde_json::from_str(
        &app.engine
            .export_profiles(vec![id.clone()], Format::Profiles)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bundle["version"], 2);
    assert_eq!(bundle["profiles"][0]["vpnPolicy"], good);
    assert!(
        app.engine
            .export_profiles(vec![id.clone()], Format::Configurations)
            .err()
            .as_deref()
            == Some("vpn_policy_export_requires_bundle")
    );
    let drafts = bundle["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let mut p = p.clone();
            p["groupId"] = json!("personal");
            serde_json::from_value(p).unwrap()
        })
        .collect();
    let mut target = App::new();
    let ids = target.engine.import_referenced_profiles(drafts).unwrap();
    assert_eq!(profile_value(&target, &ids[0])["vpnPolicy"], good);
    assert_eq!(target.engine.store.library.version, 4);
    target.idle();
    app.idle();
}

#[tokio::test]
async fn v34_public_primary_policy_matrix_retains_dns_routes_and_never_spawns() {
    for protocol in ["openvpn-client", "openconnect"] {
        for gate in [false, true] {
            for dns in [false, true] {
                for block in [false, true] {
                    let mut app = App::new();
                    let source = endpoint(protocol);
                    let id = app
                        .engine
                        .save_profile(draft(None, "Matrix", source.clone(), None))
                        .unwrap();
                    fixture_routing(&mut app);
                    let baseline = preview(&mut app, &id).await;
                    let p = policy(gate, dns, block);
                    app.engine
                        .save_profile(draft(Some(&id), "Matrix", source.clone(), Some(p.clone())))
                        .unwrap();
                    let disk = app.disk();
                    let request = preview(&mut app, &id).await;
                    assert_eq!(request["endpoints"], baseline["endpoints"]);
                    assert_eq!(request["inbounds"], baseline["inbounds"]);
                    assert_eq!(request["outbounds"], baseline["outbounds"]);
                    let servers = request["dns"]["servers"].as_array().unwrap();
                    let transports: Vec<_> = servers
                        .iter()
                        .filter(|s| s["endpoint"] == "proxy")
                        .collect();
                    assert_eq!(transports.len(), usize::from(gate || dns));
                    for old in baseline["dns"]["servers"].as_array().unwrap() {
                        assert!(servers.contains(old));
                    }
                    let rules = request["route"]["rules"].as_array().unwrap();
                    let original = baseline["route"]["rules"].as_array().unwrap();
                    assert_eq!(&rules[..original.len()], original.as_slice());
                    if gate {
                        assert_eq!(rules.len(), original.len() + 2);
                        assert_eq!(
                            rules[original.len()],
                            json!({"preferred_by":["proxy"],"action":"route","outbound":"proxy"})
                        );
                        assert_eq!(rules.last().unwrap(), &json!({"action":"reject"}));
                    } else {
                        assert_eq!(rules, original);
                    }
                    if let Some(transport) = transports.first() {
                        assert_eq!(
                            transport["type"],
                            if protocol == "openvpn-client" {
                                "openvpn"
                            } else {
                                "openconnect"
                            }
                        );
                        assert_eq!(transport["tag"], "thronium-vpn-dns-proxy");
                        assert_eq!(
                            transport["accept_default_resolvers"],
                            if gate { json!(true) } else { Value::Null }
                        );
                        assert_eq!(
                            transport["accept_search_domain"],
                            if gate { json!(true) } else { Value::Null }
                        );
                        assert!(transport.get("accept_search_domains").is_none());
                        let dr = request["dns"]["rules"].as_array().unwrap();
                        assert_eq!(
                            dr[0],
                            json!({"preferred_by":["thronium-vpn-dns-proxy"],"action":"route","server":"thronium-vpn-dns-proxy"})
                        );
                        let existing = baseline["dns"]["rules"].as_array().unwrap();
                        assert!(dr.windows(existing.len()).any(|w| w == existing.as_slice()));
                    }
                    if !gate && !dns {
                        assert_eq!(request, baseline);
                    }
                    assert_eq!(
                        request["dns"]["final"],
                        if gate {
                            json!(if block {
                                "thronium-vpn-dns-proxy"
                            } else {
                                "dns-direct"
                            })
                        } else {
                            baseline["dns"]["final"].clone()
                        }
                    );
                    assert_eq!(preview(&mut app, &id).await, request);
                    assert_eq!(app.disk(), disk);
                    assert_eq!(profile_value(&app, &id)["config"], source);
                    assert_eq!(profile_value(&app, &id)["vpnPolicy"], p);
                    app.engine
                        .connection_settings(
                            thronium_engine::system_proxy::ConnectionMode::Tun,
                            2080,
                        )
                        .unwrap();
                    let tun = preview(&mut app, &id).await;
                    assert_eq!(tun["dns"], request["dns"]);
                    assert_eq!(tun["endpoints"], request["endpoints"]);
                    let tun_rules = tun["route"]["rules"].as_array().unwrap();
                    assert_eq!(
                        tun_rules[0],
                        json!({"inbound":["thronium-tun"],"port":53,"action":"hijack-dns"})
                    );
                    assert_eq!(
                        &tun_rules[1..],
                        request["route"]["rules"].as_array().unwrap().as_slice()
                    );
                    assert!(tun["inbounds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|i| i["type"] == "tun"));
                    app.idle();
                }
            }
        }
    }
}

#[tokio::test]
async fn v34_public_context_refusals_keep_library_and_never_start_core() {
    let mut app = App::new();
    let mut source = endpoint("openvpn-client");
    source["detour"] = json!("direct");
    let id = app
        .engine
        .save_profile(draft(
            None,
            "Unsupported detour",
            source,
            Some(policy(true, true, false)),
        ))
        .unwrap();
    let ordinary = app
        .engine
        .save_profile(draft(
            None,
            "Unrelated direct",
            json!({"type":"direct"}),
            None,
        ))
        .unwrap();
    let before = app.disk();
    assert!(
        app.engine
            .connection_configuration(&id, false)
            .await
            .err()
            .as_deref()
            == Some("vpn_policy_context_unsupported")
    );
    preview(&mut app, &ordinary).await;
    assert_eq!(app.disk(), before);
    app.idle();

    let mut app = App::new();
    let id = app
        .engine
        .save_profile(draft(
            None,
            "Reserved collision",
            endpoint("openconnect"),
            Some(policy(true, true, false)),
        ))
        .unwrap();
    let mut routing = app.engine.routing();
    routing.profiles[0].dns["servers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"local","tag":"thronium-vpn-dns-proxy"}));
    app.engine.save_routing(routing).unwrap();
    let before = app.disk();
    assert!(
        app.engine
            .connection_configuration(&id, false)
            .await
            .err()
            .as_deref()
            == Some("vpn_policy_tag_conflict")
    );
    assert_eq!(app.disk(), before);
    app.idle();

    let mut app = App::new();
    let id = app
        .engine
        .save_profile(draft(
            None,
            "Legacy constraint",
            endpoint("openvpn-client"),
            Some(policy(true, true, false)),
        ))
        .unwrap();
    let mut routing = app.engine.routing();
    routing.profiles[0].legacy_constraints =
        Some(serde_json::from_value(json!({"version":2})).unwrap());
    app.engine.save_routing(routing).unwrap();
    let before = app.disk();
    assert!(app
        .engine
        .connection_configuration(&id, false)
        .await
        .is_err());
    assert_eq!(app.disk(), before);
    app.idle();

    let mut app = App::new();
    let source = json!({"dns":{"servers":[{"type":"local","tag":"whole-dns"}],"final":"whole-dns"},"route":{"rules":[{"domain":["opaque.fixture.invalid"],"action":"route","outbound":"direct"}],"final":"direct"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"future":{"untouched":[true,false]}});
    let raw =
        json!({"name":"Opaque","groupId":"personal","kind":"sing-box-config","config":source});
    let full = app
        .engine
        .save_profile(serde_json::from_value(raw.clone()).unwrap())
        .unwrap();
    let before = app.disk();
    let mut bad = raw;
    bad["id"] = json!(full);
    bad["vpnPolicy"] = policy(true, true, false);
    assert!(app
        .engine
        .save_profile(serde_json::from_value(bad).unwrap())
        .is_err());
    assert_eq!(app.disk(), before);
    assert_eq!(preview(&mut app, &full).await, source);
    app.idle();
}

#[tokio::test]
async fn v34_public_direct_final_and_untrusted_dns_fallback_are_explicit() {
    for protocol in ["openvpn-client", "openconnect"] {
        let mut app = App::new();
        let id = app
            .engine
            .save_profile(draft(
                None,
                "Direct final",
                endpoint(protocol),
                Some(policy(true, true, false)),
            ))
            .unwrap();
        fixture_routing(&mut app);
        let mut routing = app.engine.routing();
        routing.profiles[0].mode = "direct".into();
        app.engine.save_routing(routing).unwrap();
        let before = app.disk();
        let request = preview(&mut app, &id).await;
        assert_eq!(request["route"]["final"], "direct");
        assert!(!request["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("preferred_by").is_some() || r["action"] == "reject"));
        assert_eq!(request["dns"]["final"], "dns-direct");
        assert_eq!(app.disk(), before);
        for fallback in [
            json!([]),
            json!([{"type":"local","tag":"different-tag"}]),
            json!([{"type":"udp","tag":"dns-direct","server":"192.0.2.53","detour":"proxy"}]),
            json!([{"type":"https","tag":"dns-direct","server":"dns.fixture.invalid","domain_resolver":"owned-resolver"}]),
        ] {
            let mut routing = app.engine.routing();
            routing.profiles[0].dns = json!({"servers":fallback,"rules":[],"final":"dns-direct"});
            app.engine.save_routing(routing).unwrap();
            let before = app.disk();
            assert_eq!(
                app.engine
                    .connection_configuration(&id, false)
                    .await
                    .err()
                    .as_deref(),
                Some("vpn_policy_dns_unsupported")
            );
            assert_eq!(app.disk(), before);
            app.idle();
        }
    }
}
