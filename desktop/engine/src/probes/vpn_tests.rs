use super::*;
use crate::{vpn_policy::Policy, ProfileDraft};
use std::path::Path;

fn setup(protocol: &str) -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let id=engine.save_profile(ProfileDraft {id:None,name:"Private VPN".into(),group_id:"personal".into(),
        kind:ProfileKind::SingBoxOutbound,vpn_policy:Default::default(),
        config:json!({"type":protocol,"server":"127.0.0.1","server_port":444,"username":"private-user","password":"private-password"})}).unwrap();
    (dir, engine, id)
}
fn options(ids: &[&str]) -> Options {
    Options {
        ids: ids.iter().map(|id| (*id).into()).collect(),
        url: "https://probe.invalid/".into(),
        timeout_ms: 100,
        concurrency: None,
    }
}
fn proxy() -> Vec<String> {
    vec!["proxy".into()]
}
fn reply(error: &str, state: &str, connected: bool, auth: bool) -> proto::TestResp {
    proto::TestResp {
        results: vec![proto::UrlTestResp {
            outbound_tag: Some("proxy".into()),
            error: Some(error.into()),
            latency_ms: Some(17),
        }],
        vpn_status: vec![proto::VpnEndpointStatus {
            tag: Some("proxy".into()),
            state: Some(state.into()),
            connected: Some(connected),
            auth_failed: Some(auth),
            ..Default::default()
        }],
    }
}
#[test]
fn strict_verdict_never_promotes_missing_contradictory_or_wrong_endpoint_status() {
    assert_eq!(
        vpn::decode(reply("", "nonsense", false, true), &proxy(), "proxy"),
        Ok(Outcome::Latency(17))
    );
    assert_eq!(
        vpn::decode(
            reply("private-password", "connected", true, false),
            &proxy(),
            "proxy"
        ),
        Ok(Outcome::ConnectedOnly)
    );
    assert_eq!(
        vpn::decode(
            reply("private-password", "error", false, true),
            &proxy(),
            "proxy"
        ),
        Ok(Outcome::AuthRequired)
    );
    let mut pending = reply("failed", "auth-pending", false, false);
    pending.vpn_status[0].challenge = Some(proto::VpnChallenge {
        endpoint_tag: Some("proxy".into()),
        id: Some("one".into()),
        message: Some("private-password".into()),
        url: Some("https://private.invalid/token".into()),
        ..Default::default()
    });
    assert_eq!(
        vpn::decode(pending.clone(), &proxy(), "proxy"),
        Ok(Outcome::AuthRequired)
    );
    let mut bad = Vec::new();
    for (state, connected, auth) in [
        ("connected", true, true),
        ("connected", false, true),
        ("error", true, true),
        ("connecting", false, true),
        ("auth-pending", false, true),
        ("", false, true),
    ] {
        bad.push(reply("failed", state, connected, auth));
    }
    for missing in 0..4 {
        let mut r = reply("failed", "connected", true, false);
        match missing {
            0 => r.vpn_status[0].tag = None,
            1 => r.vpn_status[0].state = None,
            2 => r.vpn_status[0].connected = None,
            _ => r.vpn_status[0].auth_failed = None,
        };
        bad.push(r);
    }
    for wrong in 0..3 {
        let mut r = pending.clone();
        let c = r.vpn_status[0].challenge.as_mut().unwrap();
        match wrong {
            0 => c.endpoint_tag = Some("other".into()),
            1 => c.id = None,
            _ => c.id = Some("".into()),
        };
        bad.push(r);
    }
    let mut duplicate = pending;
    duplicate.vpn_status.push(duplicate.vpn_status[0].clone());
    bad.push(duplicate);
    let mut wrong = reply("", "connected", true, false);
    wrong.results[0].outbound_tag = Some("other".into());
    bad.push(wrong);
    let mut missing = reply("", "connected", true, false);
    missing.results[0].error = None;
    bad.push(missing);
    for result in bad {
        assert_eq!(
            vpn::decode(result, &proxy(), "proxy"),
            Err("probe_failed".into())
        );
    }
}
#[test]
fn both_vpn_protocols_preserve_all_policy_combinations_in_private_test_config() {
    for protocol in ["openvpn-client", "openconnect"] {
        let (dir, mut engine, id) = setup(protocol);
        let before = std::fs::read(dir.path().join("library.json")).unwrap();
        for bits in 0..8 {
            let mut profile = engine.profile(&id).unwrap();
            profile.vpn_policy = Some(Policy {
                only_advertised_routes: bits & 1 != 0,
                use_tunnel_dns: bits & 2 != 0,
                block_outside_dns: bits & 4 != 0,
            });
            let request = prepared_request(
                &engine.store.library,
                &profile,
                "https://probe.invalid/",
                123,
            )
            .unwrap();
            assert_eq!(request.vpn_endpoint_tags, ["proxy"]);
            assert_eq!(request.outbound_tags, ["proxy"]);
            assert_eq!(request.vpn_status_timeout_ms, Some(10_000));
            assert_eq!(request.test_timeout_ms, Some(123));
            assert_eq!(request.test_current, Some(false));
            assert_eq!(request.use_default_outbound, Some(false));
            let mut expected = config::build(&profile, 2080, None).unwrap();
            crate::vpn_policy::apply(&mut expected, &profile).unwrap();
            let mut expected: Value =
                serde_json::from_str(expected.core_config.as_ref().unwrap()).unwrap();
            expected["inbounds"] = json!([]);
            expected["services"] = json!([]);
            assert_eq!(
                serde_json::from_str::<Value>(request.config.as_ref().unwrap()).unwrap(),
                expected
            );
        }
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            before
        );
        assert!(engine.rpc.is_none());
        assert!(engine.snapshot().running.is_none());
    }
}
#[test]
fn unsupported_binding_placeholders_provider_and_context_are_terminal_before_core() {
    for case in 0..8 {
        let (dir, mut engine, id) = setup("openconnect");
        let code = match case {
            // An unbound template has no code source; a bound one is baked at issue.
            0 => {
                engine.store.library.profiles[0].config["token"] = json!({"pin":"{otp}"});
                "probe_vpn_otp_binding_required"
            }
            1 => {
                engine.store.library.profiles[0].config["password"] = json!("prefix-{otp}");
                "probe_vpn_otp_binding_required"
            }
            2 => {
                engine.store.library.profiles[0].config["form_entries"] =
                    json!([{"name":"otp","value":"{otp}"}]);
                "probe_vpn_otp_binding_required"
            }
            3 => {
                engine.store.library.profiles[0].config["token"] = json!({"type":"totp"});
                "probe_vpn_auth_unsupported"
            }
            4 => {
                engine.store.library.profiles[0].config["flavor"] = json!("globalprotect");
                "probe_vpn_auth_unsupported"
            }
            5 => {
                engine.store.library.profiles[0].config["cookie"] = json!("sensitive-cookie");
                "probe_vpn_auth_unsupported"
            }
            6 => {
                engine.store.library.profiles[0].config["system"] = json!(true);
                "probe_vpn_context_unsupported"
            }
            _ => {
                engine.store.library.preferences.connection_mode =
                    crate::system_proxy::ConnectionMode::Tun;
                "probe_vpn_context_unsupported"
            }
        };
        let disk = std::fs::read(dir.path().join("library.json")).unwrap();
        let run = engine.start_ping(vec![id.clone()]).unwrap();
        assert!(engine.next_url_test(&run.id).is_none());
        let batch = engine.url_tests_snapshot().unwrap();
        let e = &batch.entries[0];
        assert_eq!(e.status, Status::Unsupported);
        assert_eq!(e.attempts.len(), 1);
        assert_eq!(e.error.as_deref(), Some(code));
        assert_eq!(e.effective_method, Method::Http);
        assert_eq!(e.latency_ms, None);
        assert!(!serde_json::to_string(&batch)
            .unwrap()
            .contains("sensitive-cookie"));
        assert!(engine.rpc.is_none());
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            disk
        );
    }
}
#[test]
fn terminal_verdicts_preserve_attempts_and_old_adapter_never_fabricates_latency() {
    for outcome in [Outcome::ConnectedOnly, Outcome::AuthRequired] {
        let (_dir, mut engine, id) = setup("openvpn-client");
        let run = engine.start_ping(vec![id.clone()]).unwrap();
        drop(engine.next_url_test(&run.id).unwrap());
        engine.finish_url_test_detailed(&run.id, &id, Ok(outcome.clone()));
        assert!(engine.next_url_test(&run.id).is_none());
        let batch = engine.url_tests_snapshot().unwrap();
        let e = &batch.entries[0];
        assert_eq!(e.attempts.len(), 1);
        assert_eq!(e.effective_method, Method::Http);
        assert_eq!(e.latency_ms, None);
        assert_eq!(
            e.status,
            if outcome == Outcome::ConnectedOnly {
                Status::ConnectedOnly
            } else {
                Status::AuthRequired
            }
        );
        assert_eq!(
            e.error.as_deref(),
            if outcome == Outcome::ConnectedOnly {
                None
            } else {
                Some("probe_vpn_auth_required")
            }
        );
        let serialized = serde_json::to_value(batch).unwrap();
        assert!(serialized["entries"][0]["latencyMs"].is_null());
        assert!(!serialized.to_string().contains("private-password"));
    }
}
#[test]
fn policy_binding_and_effective_settings_invalidate_queued_inflight_and_cached_results() {
    for stage in 0..3 {
        for change in 0..3 {
            let (_dir, mut engine, id) = setup("openconnect");
            engine.store.library.profiles[0].config["tls"] = json!({"enabled":true});
            let run = engine.start_url_tests(options(&[&id])).unwrap();
            if stage > 0 {
                drop(engine.next_url_test(&run.id).unwrap());
            }
            if stage == 2 {
                engine.finish_url_test_detailed(&run.id, &id, Ok(Outcome::Latency(5)));
            }
            match change {
                0 => {
                    engine.store.library.profiles[0].vpn_policy = Some(Policy {
                        only_advertised_routes: true,
                        use_tunnel_dns: true,
                        block_outside_dns: false,
                    })
                }
                1 => {
                    engine.store.library.vpn_otp_bindings.insert(
                        id.clone(),
                        crate::vpn_otp_bindings::Binding {
                            revision: "changed".into(),
                            otp_id: "otp".into(),
                            mode: crate::vpn_otp_bindings::Mode::AutoLive,
                        },
                    );
                }
                _ => {
                    engine
                        .store
                        .library
                        .settings
                        .insert("skip_cert".into(), json!(true));
                }
            }
            if stage == 0 {
                assert!(engine.next_url_test(&run.id).is_none());
            } else if stage == 1 {
                engine.finish_url_test_detailed(&run.id, &id, Ok(Outcome::ConnectedOnly));
            }
            assert_eq!(
                engine.url_tests_snapshot().unwrap().entries[0].status,
                Status::Stale
            );
            assert!(engine.measurement(&engine.profile(&id).unwrap()).is_none());
        }
    }
    let (_dir, mut engine, id) = setup("openconnect");
    let run = engine.start_url_tests(options(&[&id])).unwrap();
    drop(engine.next_url_test(&run.id).unwrap());
    engine.store.library.profiles[0].name = "New label".into();
    engine.store.library.profiles[0].favorite = true;
    engine.finish_url_test_detailed(&run.id, &id, Ok(Outcome::Latency(5)));
    assert_eq!(
        engine.url_tests_snapshot().unwrap().entries[0].status,
        Status::Ok
    );
}
#[tokio::test]
async fn actual_managed_context_refuses_http_despite_pending_local_and_preserves_endpoint_methods()
{
    let (_dir, mut engine, id) = setup("openvpn-client");
    engine.rpc = Some(Rpc::managed_vpn_test_rpc());
    assert!(
        engine.store.library.preferences.connection_mode
            == crate::system_proxy::ConnectionMode::Local
    );
    let run = engine.start_ping(vec![id.clone()]).unwrap();
    assert!(engine.next_url_test(&run.id).is_none());
    assert_eq!(
        engine.url_tests_snapshot().unwrap().entries[0]
            .error
            .as_deref(),
        Some("probe_vpn_context_unsupported")
    );
    engine.store.library.preferences.ping.method = Method::Tcp;
    engine.store.library.profiles[0].config["network"] = json!("tcp");
    let run = engine.start_ping(vec![id.clone()]).unwrap();
    assert!(engine.next_url_test(&run.id).is_some());
    engine.cancel_url_tests();
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    engine.rpc = None;
}
#[tokio::test]
async fn issued_vpn_permit_blocks_tun_before_effects_even_after_cancel_and_until_dispose() {
    let (dir, mut engine, id) = setup("openvpn-client");
    let run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    engine.cancel_url_tests();
    assert_eq!(
        engine.start_url_tests(options(&[&id])).err().as_deref(),
        Some("probe_busy")
    );
    assert_eq!(engine.clear_url_tests(), Err("probe_busy".into()));
    let disk = std::fs::read(dir.path().join("library.json")).unwrap();
    engine.store.library.preferences.connection_mode = crate::system_proxy::ConnectionMode::Tun;
    assert_eq!(engine.connect(&id).await, Err("probe_busy".into()));
    assert!(engine.rpc.is_none());
    assert_eq!(
        engine.ensure_tun_rpc().await.err().as_deref(),
        Some("probe_busy")
    );
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        disk
    );
    drop(probe);
    assert!(engine.vpn_probe_guard().is_ok());
}
#[test]
fn uncertain_cleanup_stops_same_batch_admission_without_disabling_legitimate_concurrency() {
    let (_dir, mut engine, id) = setup("openvpn-client");
    let mut ids = vec![id];
    for index in 1..3 {
        let mut p = engine.store.library.profiles[0].clone();
        p.id = format!("copy-{index}");
        ids.push(p.id.clone());
        engine.store.library.profiles.push(p);
    }
    let refs: Vec<_> = ids.iter().map(String::as_str).collect();
    let run = engine.start_url_tests(options(&refs)).unwrap();
    engine.probes.concurrency = 2;
    let first = engine.next_url_test(&run.id).unwrap();
    let second = engine.next_url_test(&run.id).unwrap();
    assert!(engine.next_url_test(&run.id).is_none());
    engine.probes.cleanup_failed.store(true, Ordering::Release);
    // A different worker observes the latch before the failing worker delivers
    // its result. Only queued rows are cancelled; the failure must still land.
    assert!(engine.next_url_test(&run.id).is_none());
    assert_eq!(
        engine.url_tests_snapshot().unwrap().entries[0].status,
        Status::Testing
    );
    engine.finish_url_test_detailed(&run.id, &first.id, Err("probe_cleanup_failed".into()));
    assert!(engine.next_url_test(&run.id).is_none());
    assert_eq!(engine.vpn_probe_guard(), Err("probe_busy".into()));
    let b = engine.url_tests_snapshot().unwrap();
    assert_eq!(b.entries[0].error.as_deref(), Some("probe_cleanup_failed"));
    assert_eq!(b.entries[2].status, Status::Cancelled);
    assert!(*run.cancelled.borrow());
    drop(first);
    drop(second);
    assert!(engine.vpn_probe_guard().is_ok());
    engine.cancel_url_tests();
    assert!(engine.start_url_tests(options(&refs)).is_ok());
}

fn peer_fixture(dir: &Path, mode: &str, response: proto::TestResp) -> std::path::PathBuf {
    use prost::Message;
    use std::os::unix::fs::PermissionsExt;
    let helper = dir.join(format!("private-peer-{mode}"));
    let marker = serde_json::to_string(&dir.join("peer.json")).unwrap();
    let received = serde_json::to_string(&dir.join("request.bin")).unwrap();
    let payload = response
        .encode_to_vec()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let script = format!(
        r#"#!/usr/bin/python3
import json, os, socket, struct, time
mode={mode:?}
with open({marker}+'.tmp', 'w') as f: json.dump({{'pid':os.getpid(),'cwd':os.getcwd()}},f)
os.replace({marker}+'.tmp', {marker})
if mode == 'handshake':
    while True: time.sleep(1)
s=socket.socket(socket.AF_UNIX)
s.connect(os.environ['THRONE_CORE_SOCKET'])
def read(n):
    result=b''
    while len(result)<n:
        v=s.recv(n-len(result))
        if not v: raise SystemExit(0)
        result+=v
    return result
ident=read(4)
method=read(struct.unpack('<H',read(2))[0])
data=read(struct.unpack('<I',read(4))[0])
assert method == b'Test'
with open({received}+'.tmp','wb') as f: f.write(data)
os.replace({received}+'.tmp', {received})
if mode != 'hang':
    payload=b'\xff' if mode == 'malformed' else bytes.fromhex('{payload}')
    s.sendall(ident+b'\0'+struct.pack('<I',len(payload))+payload)
while s.recv(1): pass
"#
    );
    std::fs::write(&helper, script).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    helper
}
async fn observe_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while std::fs::metadata(path).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
fn peer_identity(dir: &Path) -> (u32, std::path::PathBuf) {
    let v: Value = serde_json::from_slice(&std::fs::read(dir.join("peer.json")).unwrap()).unwrap();
    (
        v["pid"].as_u64().unwrap() as u32,
        std::path::PathBuf::from(v["cwd"].as_str().unwrap()),
    )
}
fn assert_peer_gone(pid: u32, cwd: &Path) {
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "exact test child must have been reaped"
    );
    assert!(
        !cwd.exists(),
        "private working directory must be gone before completion"
    );
}
#[tokio::test]
async fn dropped_execute_future_retains_child_during_handshake_and_confirms_cleanup_before_reopening_admission(
) {
    let (dir, mut engine, id) = setup("openvpn-client");
    engine.core = peer_fixture(dir.path(), "handshake", Default::default());
    let run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    let mut cancelled = run.cancelled.clone();
    let call = tokio::spawn(async move { probe.execute_detailed(&mut cancelled).await });
    observe_file(&dir.path().join("peer.json")).await;
    let (pid, cwd) = peer_identity(dir.path());
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    engine.cancel_url_tests();
    assert_eq!(
        engine.start_url_tests(options(&[&id])).err().as_deref(),
        Some("probe_busy")
    );
    engine.shutdown_checked().await.unwrap();
    assert_peer_gone(pid, &cwd);
    assert!(engine.rpc.is_none());
    assert!(engine.start_url_tests(options(&[&id])).is_ok());
}
#[tokio::test]
async fn cancelled_inflight_test_reaps_before_result_and_never_queries_or_stops_the_main_core() {
    use prost::Message;
    let (dir, mut engine, id) = setup("openconnect");
    engine.core = peer_fixture(dir.path(), "hang", Default::default());
    engine.rpc = Some(Rpc::scripted_local_test_rpc(|method, _| {
        panic!("main core was touched: {method}")
    }));
    let main = engine.owned_core_process().unwrap();
    let mut run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    let mut cancelled = run.cancelled.clone();
    let call = tokio::spawn(async move { probe.execute_detailed(&mut cancelled).await });
    observe_file(&dir.path().join("request.bin")).await;
    let (pid, cwd) = peer_identity(dir.path());
    let request = proto::TestReq::decode(
        std::fs::read(dir.path().join("request.bin"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(request.vpn_endpoint_tags, ["proxy"]);
    assert_eq!(request.test_current, Some(false));
    engine.cancel_url_tests();
    assert!(*run.cancelled.borrow_and_update());
    assert_eq!(call.await.unwrap(), Err("probe_cancelled".into()));
    assert_peer_gone(pid, &cwd);
    assert_eq!(engine.owned_core_process().unwrap(), main);
    assert!(engine.start_url_tests(options(&[&id])).is_ok());
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}
#[tokio::test]
async fn successful_malformed_and_compatibility_results_are_published_only_after_reap() {
    for (mode, legacy, state, expected) in [
        ("ok", false, "connected", Ok(Outcome::ConnectedOnly)),
        ("ok", true, "error", Err("probe_vpn_auth_required".into())),
        (
            "malformed",
            false,
            "connected",
            Err("probe_configuration_failed".into()),
        ),
    ] {
        let (dir, mut engine, id) = setup("openvpn-client");
        engine.core = peer_fixture(
            dir.path(),
            mode,
            reply(
                "private-password",
                state,
                state == "connected",
                state == "error",
            ),
        );
        let mut run = engine.start_url_tests(options(&[&id])).unwrap();
        let probe = engine.next_url_test(&run.id).unwrap();
        let actual = if legacy {
            probe
                .execute(&mut run.cancelled)
                .await
                .map(Outcome::Latency)
        } else {
            probe.execute_detailed(&mut run.cancelled).await
        };
        assert_eq!(actual, expected);
        let (pid, cwd) = peer_identity(dir.path());
        assert_peer_gone(pid, &cwd);
        assert!(engine.vpn_probe_guard().is_ok());
        assert!(engine.rpc.is_none());
    }
}
#[tokio::test]
async fn cancel_before_execute_and_missing_core_release_issued_permit_without_child() {
    let (_dir, mut engine, id) = setup("openvpn-client");
    let mut run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    engine.cancel_url_tests();
    assert_eq!(
        probe.execute_detailed(&mut run.cancelled).await,
        Err("probe_cancelled".into())
    );
    assert!(engine.vpn_probe_guard().is_ok());
    let mut run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    assert_eq!(
        probe.execute_detailed(&mut run.cancelled).await,
        Err("probe_core_failed".into())
    );
    assert!(engine.vpn_probe_guard().is_ok());
}
#[test]
fn thousand_profile_cache_uses_selected_compilation_without_storing_otp_secrets() {
    let (_dir, mut engine, id) = setup("openconnect");
    for n in 1..1000 {
        let mut p = engine.store.library.profiles[0].clone();
        p.id = format!("vpn-{n}");
        engine.store.library.profiles.push(p);
    }
    let ids: Vec<_> = engine
        .store
        .library
        .profiles
        .iter()
        .map(|p| p.id.clone())
        .collect();
    let refs: Vec<_> = ids.iter().map(String::as_str).collect();
    let start = std::time::Instant::now();
    let run = engine.start_url_tests(options(&refs)).unwrap();
    engine.cancel_url_tests();
    let batch = engine.url_tests_snapshot().unwrap();
    let queue = start.elapsed();
    let start = std::time::Instant::now();
    let snapshot = engine.snapshot();
    let snapshot_time = start.elapsed();
    assert_eq!(batch.entries.len(), 1000);
    assert_eq!(snapshot.url_tests.unwrap().entries.len(), 1000);
    let p = engine.profile(&id).unwrap();
    assert!(!dependencies(&p, &engine.store.library)
        .unwrap()
        .to_string()
        .contains("private-password"));
    eprintln!(
        "VPN_CACHE_1000 queue+cache_ms={} snapshot_ms={} batch={}",
        queue.as_millis(),
        snapshot_time.as_millis(),
        run.id
    );
}

#[tokio::test]
async fn queued_gui_vpn_can_release_permit_while_checked_quit_owns_engine_mutex() {
    let (_dir, mut engine, id) = setup("openvpn-client");
    let mut run = engine.start_url_tests(options(&[&id])).unwrap();
    let probe = engine.next_url_test(&run.id).unwrap();
    assert!(probe.is_disposable_vpn());
    let shared = Arc::new(tokio::sync::Mutex::new(engine));
    let mut quitting = shared.lock().await;
    // probe_runner takes this direct branch before requesting the Engine lock.
    let worker = tokio::spawn(async move {
        tokio::task::yield_now().await;
        probe.execute_detailed(&mut run.cancelled).await
    });
    tokio::time::timeout(Duration::from_secs(1), quitting.shutdown_checked())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(worker.await.unwrap(), Err("probe_cancelled".into()));
    assert!(quitting.rpc.is_none());
}

#[tokio::test]
async fn checked_quit_reports_pending_cleanup_and_explicit_retry_clears_only_that_error() {
    let (_dir, mut engine, id) = setup("openvpn-client");
    let run = engine.start_url_tests(options(&[&id])).unwrap();
    let held = engine.next_url_test(&run.id).unwrap();
    // A public caller deliberately retains an issued Probe. No child is claimed
    // here: this proves the admission/Quit contract and its truthful UI error.
    assert_eq!(
        engine.shutdown_checked().await,
        Err("probe_cleanup_failed".into())
    );
    assert_eq!(engine.error.as_deref(), Some("probe_cleanup_failed"));
    assert!(engine.rpc.is_none());
    drop(held);
    engine.shutdown_checked().await.unwrap();
    assert!(engine.error.is_none());
    engine.error = Some("unrelated-safe-error".into());
    engine.finish_probe_cleanup().await.unwrap();
    assert_eq!(engine.error.as_deref(), Some("unrelated-safe-error"));
}
#[tokio::test]
async fn managed_context_change_invalidates_old_result_even_if_saved_preferences_stay_local() {
    let (_dir, mut engine, id) = setup("openconnect");
    let run = engine.start_url_tests(options(&[&id])).unwrap();
    drop(engine.next_url_test(&run.id).unwrap());
    engine.rpc = Some(Rpc::managed_vpn_test_rpc());
    engine.finish_url_test_detailed(&run.id, &id, Ok(Outcome::Latency(7)));
    assert_eq!(
        engine.url_tests_snapshot().unwrap().entries[0].status,
        Status::Stale
    );
    assert!(engine.measurement(&engine.profile(&id).unwrap()).is_none());
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[test]
fn checked_shutdown_future_remains_send_for_the_tauri_worker() {
    fn require_send<T: Send>(_: T) {}
    let (_directory, mut engine, _) = setup("openvpn-client");
    // This is the compile-time contract of Tauri async_runtime::spawn. It must
    // hold without adding Sync to either the proxy backend or the IPC stream.
    require_send(engine.shutdown_checked());
}

fn add(e: &mut Engine, name: &str, kind: ProfileKind, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind,
        config,
    })
    .unwrap()
}
#[test]
fn chains_with_vpn_hops_wait_for_their_endpoints_and_keep_the_per_hop_rules() {
    let (_dir, mut e, vpn) = setup("openvpn-client");
    let socks = add(
        &mut e,
        "Socks",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    let chain = |e: &mut Engine, name: &str, hops: Value| {
        add(
            e,
            name,
            ProfileKind::Chain,
            json!({"type":"chain","hops":hops}),
        )
    };
    let exit = chain(&mut e, "Exit", json!([socks, vpn]));
    let entry = chain(&mut e, "Entry", json!([vpn, socks]));
    let url = "https://probe.invalid/";
    for (id, tag) in [(&exit, "proxy"), (&entry, "thronium-chain-proxy-0")] {
        let profile = e.profile(id).unwrap();
        let request = prepared_request(&e.store.library, &profile, url, 123).unwrap();
        assert_eq!(request.vpn_endpoint_tags, [tag]);
        assert_eq!(request.vpn_status_timeout_ms, Some(10_000));
        assert_eq!(request.outbound_tags, ["proxy"]);
        let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
        assert!(core["inbounds"].as_array().unwrap().is_empty());
        assert!(core["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["tag"] == tag && v["type"] == "openvpn-client"));
        assert!(vpn::involves(&e.store.library, &profile));
        assert!(crate::settings::tests_runtime::supported(
            &e.store.library,
            &profile,
            &Default::default()
        ));
    }
    // A plain chain neither waits for endpoints nor takes the VPN admission slot.
    let plain = chain(&mut e, "Plain", json!([socks]));
    let profile = e.profile(&plain).unwrap();
    let request = prepared_request(&e.store.library, &profile, url, 123).unwrap();
    assert!(request.vpn_endpoint_tags.is_empty());
    assert_eq!(request.vpn_status_timeout_ms, None);
    assert!(!vpn::involves(&e.store.library, &profile));
    // The exit hop's policy shapes the disposable core exactly as a connection.
    let mut gated = e.profile(&vpn).unwrap();
    gated.vpn_policy = Some(Policy {
        only_advertised_routes: true,
        use_tunnel_dns: true,
        block_outside_dns: false,
    });
    e.save_profile(ProfileDraft {
        vpn_policy: crate::vpn_policy::Edit::Set(gated.vpn_policy),
        id: Some(vpn.clone()),
        name: gated.name.clone(),
        group_id: gated.group_id.clone(),
        kind: gated.kind,
        config: gated.config.clone(),
    })
    .unwrap();
    let request = prepared_request(&e.store.library, &e.profile(&exit).unwrap(), url, 123).unwrap();
    let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(
        core["route"]["rules"].as_array().unwrap().last().unwrap(),
        &json!({"action":"reject"})
    );
    let request =
        prepared_request(&e.store.library, &e.profile(&entry).unwrap(), url, 123).unwrap();
    let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert!(core["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["action"] != "reject"));
    // Per-hop rules: an interactive OTP placeholder or a Tailscale hop is not measured.
    let mut interactive = e.profile(&vpn).unwrap();
    interactive.config["password"] = json!("{otp}");
    let hidden = add(
        &mut e,
        "Interactive",
        ProfileKind::SingBoxOutbound,
        interactive.config,
    );
    let chained = chain(&mut e, "Interactive chain", json!([socks, hidden]));
    let profile = e.profile(&chained).unwrap();
    assert_eq!(
        prepared_request(&e.store.library, &profile, url, 123).unwrap_err(),
        "probe_vpn_otp_binding_required"
    );
    assert!(!crate::settings::tests_runtime::supported(
        &e.store.library,
        &profile,
        &Default::default()
    ));
    let ts = add(
        &mut e,
        "Tailscale",
        ProfileKind::SingBoxOutbound,
        json!({"type":"tailscale","auth_key":"tskey-fixture"}),
    );
    let chained = chain(&mut e, "Tailscale chain", json!([ts, socks]));
    assert_eq!(
        prepared_request(&e.store.library, &e.profile(&chained).unwrap(), url, 123).unwrap_err(),
        "probe_unsupported"
    );
}
#[test]
fn multi_endpoint_failure_status_ranks_authentication_above_a_connected_tunnel() {
    let status = |tag: &str, state: &str, connected: bool, auth: bool| proto::VpnEndpointStatus {
        tag: Some(tag.into()),
        state: Some(state.into()),
        connected: Some(connected),
        auth_failed: Some(auth),
        ..Default::default()
    };
    let tags = vec!["thronium-chain-proxy-0".to_string(), "proxy".to_string()];
    assert_eq!(
        vpn::failure_status(
            &[
                status("proxy", "connected", true, false),
                status("thronium-chain-proxy-0", "connecting", false, false)
            ],
            &tags
        ),
        Ok(Some(Outcome::ConnectedOnly))
    );
    assert_eq!(
        vpn::failure_status(
            &[
                status("proxy", "connected", true, false),
                status("thronium-chain-proxy-0", "error", false, true)
            ],
            &tags
        ),
        Ok(Some(Outcome::AuthRequired))
    );
    assert_eq!(vpn::failure_status(&[], &tags), Ok(None));
    for statuses in [
        vec![status("proxy", "connected", true, false)],
        vec![
            status("proxy", "connected", true, false),
            status("proxy", "connected", true, false),
        ],
        vec![
            status("proxy", "connected", true, false),
            status("other", "connecting", false, false),
        ],
    ] {
        assert_eq!(
            vpn::failure_status(&statuses, &tags),
            Err("probe_failed".into())
        );
    }
}

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
fn otp_entry(e: &mut Engine, kind: crate::otp::Kind) -> (String, String) {
    let meta = e
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                secret: SECRET.into(),
                kind,
                ..Default::default()
            },
        )
        .unwrap();
    (
        meta["id"].as_str().unwrap().to_owned(),
        meta["revision"].as_str().unwrap().to_owned(),
    )
}
fn bind(
    e: &mut Engine,
    profile: &str,
    otp: &(String, String),
    mode: crate::vpn_otp_bindings::Mode,
) {
    let view = e.get_vpn_otp_binding(profile).unwrap();
    e.save_vpn_otp_binding(crate::vpn_otp_bindings::SaveRequest {
        profile_id: profile.into(),
        edit_token: view.edit_token,
        otp_id: Some(otp.0.clone()),
        otp_revision: Some(otp.1.clone()),
        mode: Some(mode),
    })
    .unwrap();
}
fn counter(e: &Engine, otp_id: &str) -> String {
    e.store
        .library
        .otp
        .iter()
        .find(|entry| entry.id == otp_id)
        .unwrap()
        .value
        .counter
        .clone()
}
fn code_at_counter(e: &Engine, otp_id: &str, counter: &str) -> String {
    let mut value = e
        .store
        .library
        .otp
        .iter()
        .find(|entry| entry.id == otp_id)
        .unwrap()
        .value
        .clone();
    value.counter = counter.into();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    value.code_at(now).unwrap().code
}
fn everything_visible(e: &mut Engine) -> String {
    let mut text = serde_json::to_string(&e.url_tests_snapshot()).unwrap();
    for entry in e.logs.view(Default::default()).unwrap().entries {
        text.push_str(&entry.text);
    }
    text.push_str(&serde_json::to_string(&e.snapshot()).unwrap());
    text
}
/// Qt's test build bakes the code; Thronium reserves the HOTP step at issue,
/// under the Engine lock, once per issued test, and never shows the digits.
#[test]
fn bound_hotp_probe_reserves_one_step_at_issue_and_never_publishes_the_code() {
    let (_dir, mut e, id) = setup("openvpn-client");
    e.store.library.profiles[0].config["password"] = json!("pw-{otp}");
    e.store.library.profiles[0].config["auth_retry"] = json!("none");
    e.store.commit(e.store.library.clone()).unwrap();
    let hotp = otp_entry(&mut e, crate::otp::Kind::Hotp);
    bind(&mut e, &id, &hotp, crate::vpn_otp_bindings::Mode::AutoStart);
    assert!(crate::settings::tests_runtime::supported(
        &e.store.library,
        &e.profile(&id).unwrap(),
        &Default::default()
    ));
    let run = e.start_ping(vec![id.clone()]).unwrap();
    assert_eq!(counter(&e, &hotp.0), "0", "queueing spends nothing");
    let probe = e.next_url_test(&run.id).expect("a bound profile is issued");
    assert_eq!(counter(&e, &hotp.0), "1", "one step per issued test");
    let Request::Http(request) = &probe.request else {
        panic!("HTTP probe expected");
    };
    let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    let expected = code_at_counter(&e, &hotp.0, "1");
    assert_eq!(core["endpoints"][0]["password"], format!("pw-{expected}"));
    assert_eq!(core["endpoints"][0]["single_use_auth"], true);
    assert_eq!(core["endpoints"][0]["auth_retry"], "none");
    assert!(probe.is_disposable_vpn());
    assert!(!everything_visible(&mut e).contains(&expected));
    e.finish_url_test(&run.id, &id, Err("probe_failed".into()));
    assert!(!everything_visible(&mut e).contains(&expected));
    // The dialog test is manual as well: it spends the next step.
    let test = e.ip_test(&id).unwrap();
    assert_eq!(counter(&e, &hotp.0), "2");
    assert!(
        e.test_matches(&test),
        "reserving a step does not make the issued test stale"
    );
    assert!(e.rpc.is_none());
}
/// A busy probe queue must refuse the dialog test before a bound profile
/// spends its HOTP step; the slot is released when preparation fails.
#[test]
fn a_busy_queue_refuses_a_dialog_test_before_any_hotp_step_is_spent() {
    let (_dir, mut e, id) = setup("openvpn-client");
    e.store.library.profiles[0].config["password"] = json!("pw-{otp}");
    e.store.library.profiles[0].config["auth_retry"] = json!("none");
    e.store.commit(e.store.library.clone()).unwrap();
    let hotp = otp_entry(&mut e, crate::otp::Kind::Hotp);
    bind(&mut e, &id, &hotp, crate::vpn_otp_bindings::Mode::AutoStart);
    e.start_ping(vec![id.clone()]).unwrap();
    for _ in 0..3 {
        assert_eq!(
            e.reserved_ip_test("dialog", &id).err().as_deref(),
            Some("probe_busy")
        );
        assert_eq!(
            e.reserved_speed_test("dialog", &id).err().as_deref(),
            Some("probe_busy")
        );
    }
    assert_eq!(counter(&e, &hotp.0), "0", "refused clicks spend nothing");
    e.cancel_url_tests();
    e.reserved_ip_test("dialog", &id).unwrap();
    assert_eq!(
        counter(&e, &hotp.0),
        "1",
        "an admitted test spends one step"
    );
    assert_eq!(
        e.reserve_probe("other").unwrap_err(),
        "probe_busy",
        "the admitted test holds the slot until the host releases it"
    );
    e.release_probe("dialog");
    assert!(e.reserved_ip_test("dialog", "missing-profile").is_err());
    e.reserve_probe("other")
        .expect("a failed preparation releases its reservation");
}
#[test]
fn bound_probes_are_manual_only_and_reservation_failures_are_terminal_but_logged() {
    let (_dir, mut e, id) = setup("openvpn-client");
    e.store.library.profiles[0].config["password"] = json!("pw-{otp}");
    e.store.library.profiles[0].config["auth_retry"] = json!("none");
    e.store.commit(e.store.library.clone()).unwrap();
    let hotp = otp_entry(&mut e, crate::otp::Kind::Hotp);
    bind(&mut e, &id, &hotp, crate::vpn_otp_bindings::Mode::AutoStart);
    // Periodic and automatic sources never spend a code.
    let run = e
        .start_profile_tests_from(vec![id.clone()], Kind::Ip, Source::Periodic)
        .unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    let entry = &e.url_tests_snapshot().unwrap().entries[0];
    assert_eq!(entry.status, Status::Unsupported);
    assert_eq!(entry.error.as_deref(), Some("probe_vpn_otp_manual_only"));
    assert_eq!(counter(&e, &hotp.0), "0");
    // A cancelled queued entry spends nothing either.
    let run = e.start_ping(vec![id.clone()]).unwrap();
    e.cancel_url_tests();
    assert!(e.next_url_test(&run.id).is_none());
    assert_eq!(counter(&e, &hotp.0), "0");
    // An exhausted HOTP counter fails the test with one published code and the
    // exact reason in the log; nothing is reserved.
    for entry in &mut e.store.library.otp {
        entry.value.counter = i64::MAX.to_string();
    }
    e.store.commit(e.store.library.clone()).unwrap();
    let run = e.start_ping(vec![id.clone()]).unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    let entry = &e.url_tests_snapshot().unwrap().entries[0];
    assert_eq!(entry.status, Status::Error);
    assert_eq!(entry.error.as_deref(), Some("probe_vpn_otp_failed"));
    assert!(e
        .logs
        .view(Default::default())
        .unwrap()
        .entries
        .iter()
        .any(|entry| entry.text == "vpn_otp_counter_exhausted"));
    assert_eq!(
        e.ip_test(&id).err().as_deref(),
        Some("probe_vpn_otp_failed")
    );
    assert!(e.rpc.is_none());
}
/// A composite configuration spends a code for the node that actually
/// carries the tunnel. The compiler announces the tag of that hop, so the code
/// is baked there and nowhere else, and the stored profile keeps its template.
#[test]
fn a_bound_hop_of_a_chain_receives_its_own_code_under_the_tag_the_compiler_announced() {
    let (_dir, mut e, vpn) = setup("openvpn-client");
    e.store.library.profiles[0].config["password"] = json!("pw-{otp}");
    e.store.library.profiles[0].config["auth_retry"] = json!("none");
    e.store.commit(e.store.library.clone()).unwrap();
    let hotp = otp_entry(&mut e, crate::otp::Kind::Hotp);
    bind(
        &mut e,
        &vpn,
        &hotp,
        crate::vpn_otp_bindings::Mode::AutoStart,
    );
    let socks = add(
        &mut e,
        "Socks",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
    );
    let chain = add(
        &mut e,
        "Bound hop chain",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[vpn, socks]}),
    );
    let profile = e.profile(&chain).unwrap();
    assert!(
        crate::settings::tests_runtime::supported(&e.store.library, &profile, &Default::default()),
        "a chain whose hop is bound is measurable"
    );
    let run = e.start_ping(vec![chain.clone()]).unwrap();
    assert_eq!(counter(&e, &hotp.0), "0", "queueing spends nothing");
    let probe = e.next_url_test(&run.id).expect("the chain is issued");
    assert_eq!(counter(&e, &hotp.0), "1", "one step per issued test");
    let Request::Http(request) = &probe.request else {
        panic!("HTTP probe expected");
    };
    let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    let expected = code_at_counter(&e, &hotp.0, "1");
    let hop = core["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|endpoint| endpoint["tag"] == "thronium-chain-proxy-0")
        .expect("the hop keeps the tag the chain compiler gave it");
    assert_eq!(hop["password"], format!("pw-{expected}"));
    assert_eq!(hop["single_use_auth"], true);
    assert_eq!(request.vpn_endpoint_tags, ["thronium-chain-proxy-0"]);
    assert_eq!(
        e.profile(&vpn).unwrap().config["password"],
        "pw-{otp}",
        "the code never reaches the stored profile"
    );
    assert!(!everything_visible(&mut e).contains(&expected));
    e.finish_url_test(&run.id, &chain, Err("probe_failed".into()));
    assert!(!everything_visible(&mut e).contains(&expected));
    // Nothing a person did not ask for spends a code.
    drop(probe);
    e.cancel_url_tests();
    let run = e
        .start_profile_tests_from(vec![chain.clone()], Kind::Ip, Source::Periodic)
        .unwrap();
    assert!(e.next_url_test(&run.id).is_none());
    let entry = &e.url_tests_snapshot().unwrap().entries[0];
    assert_eq!(entry.error.as_deref(), Some("probe_vpn_otp_manual_only"));
    assert_eq!(counter(&e, &hotp.0), "1");
    // The dialog test of the same chain spends the next step, in the same place.
    let test = e.ip_test(&chain).unwrap();
    assert_eq!(counter(&e, &hotp.0), "2");
    assert!(e.test_matches(&test));
    assert!(e.rpc.is_none());
}
/// A group wrapper compiles renamed copies of its hops; a copy answers for the
/// binding of the profile it was made from, so the code lands in the wrapper.
#[test]
fn a_bound_profile_measured_through_a_group_wrapper_receives_its_code_in_the_wrapper() {
    let (_dir, mut e, vpn) = setup("openvpn-client");
    let front = add(
        &mut e,
        "Front",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":1081}),
    );
    e.store.library.profiles[0].config["password"] = json!("pw-{otp}");
    e.store.library.profiles[0].group_id = "g".into();
    e.store.library.groups.push(crate::store::Group {
        id: "g".into(),
        name: "Group".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        subscription: None,
        proxy_chain: crate::group_chains::GroupChain {
            front: Some(front),
            landing: None,
        },
    });
    e.store.commit(e.store.library.clone()).unwrap();
    let hotp = otp_entry(&mut e, crate::otp::Kind::Hotp);
    bind(
        &mut e,
        &vpn,
        &hotp,
        crate::vpn_otp_bindings::Mode::AutoStart,
    );
    let profile = e.profile(&vpn).unwrap();
    assert!(
        vpn::wrapped(&e.store.library, &profile),
        "the group wraps it"
    );
    let run = e.start_ping(vec![vpn.clone()]).unwrap();
    let probe = e.next_url_test(&run.id).expect("the wrapper is issued");
    assert_eq!(counter(&e, &hotp.0), "1");
    let Request::Http(request) = &probe.request else {
        panic!("HTTP probe expected");
    };
    let core: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    let expected = code_at_counter(&e, &hotp.0, "1");
    let endpoints = core["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0]["password"], format!("pw-{expected}"));
    assert_eq!(
        e.profile(&vpn).unwrap().config["password"],
        "pw-{otp}",
        "the copy carried the code, never the stored profile"
    );
    assert!(!everything_visible(&mut e).contains(&expected));
}
