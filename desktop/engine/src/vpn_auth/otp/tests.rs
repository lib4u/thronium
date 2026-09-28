use super::*;
use prost::Message;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn field(value: &Value) -> proto::VpnChallengeField {
    let s = |k: &str| value[k].as_str().unwrap_or("").to_string();
    proto::VpnChallengeField {
        submission_key: Some(s("key")),
        name: Some(s("name")),
        label: Some(s("label")),
        kind: Some(value["kind"].as_str().unwrap_or("text").into()),
        value: Some(s("value")),
        options: value["options"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|a| proto::VpnChallengeChoice {
                value: Some(a[0].as_str().unwrap_or("").into()),
                label: Some(a[1].as_str().unwrap_or("").into()),
            })
            .collect(),
    }
}
#[test]
fn actual_qt_form_golden_matches_valid_inputs_and_rejects_known_unsafe_cases() {
    let golden: Value = serde_json::from_str(include_str!("qt-form-golden.json")).unwrap();
    let mut compared = 0;
    let mut strict = 0;
    // Explicit, source-reviewed Qt cases: these put an OTP in AnyConnect's
    // stable username/password cache. Other failures must not become skips.
    const CACHE_UNSUPPORTED: &[&str] = &[
        "token-label-token",
        "token-label-otp",
        "token-label-passcode",
        "token-label-one-time",
        "token-label-onetime",
        "token-label-second",
        "token-label-challenge",
        "token-label-verification",
        "token-label-authenticator",
        "password-empty-account-uses-code",
        "both-credentials-placeholder",
    ];
    let mut cache_cases = HashSet::new();
    for case in golden["cases"].as_array().unwrap() {
        let mut merged = case["input"].clone();
        if let Some(first) = case["input"]["steps"]
            .as_array()
            .and_then(|steps| steps.first())
            .and_then(Value::as_object)
        {
            merged.as_object_mut().unwrap().extend(first.clone());
        }
        let input = &merged;
        if input["protocol"].as_str().unwrap_or("openconnect") != "openconnect"
            || input["kind"].as_str().unwrap_or("form") != "form"
        {
            continue;
        }
        let entries=input["entries"].as_array().into_iter().flatten().filter(|e|!e.is_null()).map(|e|json!({"submission_key":e["key"].as_str().unwrap_or(""),"name":e["name"].as_str().unwrap_or(""),"value":e["value"].as_str().unwrap_or(""),"promote":e["promote"].as_bool().unwrap_or(false),"form_id":e["formId"].as_str().unwrap_or("")})).collect();
        let source = planner::Source {
            profile_id: "source".into(),
            placement: planner::Placement::None,
            protocol: "openconnect".into(),
            flavor: String::new(),
            username: input["username"].as_str().unwrap_or("account-user").into(),
            password: input["password"]
                .as_str()
                .unwrap_or("account-password")
                .into(),
            entries,
        };
        let challenge = proto::VpnChallenge {
            id: Some("1".into()),
            endpoint_tag: Some("proxy".into()),
            kind: Some("form".into()),
            fields: input["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .map(field)
                .collect(),
            ..Default::default()
        };
        let identity = ChallengeRequest {
            session_id: "session".into(),
            endpoint_tag: "proxy".into(),
            challenge_id: "1".into(),
        };
        let code = input["code"].as_str().unwrap_or("654321");
        let result = planner::answer(&source, &challenge, &identity, code);
        let id = input["id"].as_str().unwrap();
        if CACHE_UNSUPPORTED.contains(&id) {
            assert_eq!(
                result.as_ref().err().map(String::as_str),
                Some("vpn_otp_form_cache_unsupported"),
                "{id}"
            );
            assert!(cache_cases.insert(id.to_owned()));
            strict += 1;
            continue;
        }
        assert_ne!(
            result.as_ref().err().map(String::as_str),
            Some("vpn_otp_form_cache_unsupported"),
            "unexpected cache refusal: {id}"
        );
        if validate::details(&challenge, "openconnect").is_err() || code.is_empty() {
            assert!(result.is_err(), "{}", input["id"]);
            strict += 1;
            continue;
        }
        let qt = &case["actualQt"][0];
        if qt["directBuildAccepted"] == true {
            let proposed = SubmitRequest {
                session_id: "session".into(),
                endpoint_tag: "proxy".into(),
                challenge_id: "1".into(),
                username: String::new(),
                password: String::new(),
                secret: String::new(),
                form_values: serde_json::from_value(qt["directBuildValues"].clone()).unwrap(),
            };
            if validate::answer(&challenge, "openconnect", &proposed).is_err() {
                assert!(result.is_err(), "{}", input["id"]);
                strict += 1;
                continue;
            }
        }
        if qt["directBuildAccepted"] == true {
            assert_eq!(
                json!(
                    result
                        .unwrap_or_else(|e| panic!("{}: {e}", input["id"]))
                        .request
                        .form_values
                ),
                qt["directBuildValues"],
                "{}",
                input["id"]
            );
        } else {
            assert!(result.is_err(), "{}", input["id"]);
        }
        compared += 1;
    }
    assert!(compared >= 45, "compared {compared}");
    assert!(strict >= 7, "strict {strict}");
    assert_eq!(cache_cases.len(), CACHE_UNSUPPORTED.len());
}

#[derive(Default)]
struct Wire {
    seq: u32,
    reject: bool,
    connected: bool,
    clear_error: bool,
    malformed: bool,
    cached_field: bool,
    answers: Vec<proto::SubmitVpnChallengeRequest>,
    observed_counters: Vec<String>,
    queries: usize,
    generation: u64,
    change_after_query: bool,
}
fn challenge(seq: u32, rejected: bool, malformed: bool) -> proto::VpnChallenge {
    let mut fields = vec![proto::VpnChallengeField {
        submission_key: Some("exact:otp".into()),
        name: Some("answer".into()),
        kind: Some("password".into()),
        label: Some("OTP".into()),
        ..Default::default()
    }];
    if malformed {
        fields.push(proto::VpnChallengeField {
            submission_key: Some("unknown".into()),
            kind: Some("text".into()),
            ..Default::default()
        });
    }
    proto::VpnChallenge {
        id: Some(seq.to_string()),
        endpoint_tag: Some("proxy".into()),
        kind: Some("form".into()),
        error: rejected.then(|| "Rejected synthetic answer".into()),
        fields,
        ..Default::default()
    }
}
async fn fixture(kind: Kind) -> (tempfile::TempDir, Engine, Arc<Mutex<Wire>>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("never-spawn")).unwrap();
    let p=e.save_profile(crate::ProfileDraft{ vpn_policy: Default::default(),id:None,name:"Synthetic VPN".into(),group_id:"personal".into(),kind:crate::store::ProfileKind::SingBoxOutbound,config:json!({"type":"openconnect","server":"https://vpn.fixture.invalid","username":"account-user","password":"account-password"})}).unwrap();
    let m = e
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                kind,
                ..Default::default()
            },
        )
        .unwrap();
    let otp_id = m["id"].as_str().unwrap().to_owned();
    let view = e.get_vpn_otp_binding(&p).unwrap();
    e.save_vpn_otp_binding(crate::vpn_otp_bindings::SaveRequest {
        profile_id: p.clone(),
        edit_token: view.edit_token,
        otp_id: Some(otp_id.clone()),
        otp_revision: Some(m["revision"].as_str().unwrap().into()),
        mode: None,
    })
    .unwrap();
    let profile = e.profile(&p).unwrap();
    let (request, bindings) =
        Engine::build_with_vpn_sources(&profile, &e.store.library, dir.path(), Intent::Start)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    let wire = Arc::new(Mutex::new(Wire {
        seq: 1,
        generation: 9007199254740993,
        ..Default::default()
    }));
    let remote = wire.clone();
    let path = dir.path().join("library.json");
    let rpc = crate::transport::Rpc::scripted_vpn_test_rpc(move |method, payload| {
        let mut w = remote.lock().unwrap();
        if method == "ManagedTunStatus" {
            return proto::ManagedTunStatus {
                phase: Some("connected".into()),
                generation: Some(w.generation),
                vpn_auth_version: Some(1),
                ..Default::default()
            }
            .encode_to_vec();
        }
        assert_eq!(method, "ManagedVPN");
        let req = proto::ManagedVpnRequest::decode(payload).unwrap();
        let mut reply = proto::ManagedVpnResponse {
            version: Some(1),
            generation: Some(w.generation),
            ..Default::default()
        };
        if req.generation != Some(w.generation) {
            reply.error_code = Some("managed_vpn_stale_generation".into());
            return reply.encode_to_vec();
        }
        match req.operation.unwrap() {
            proto::managed_vpn_request::Operation::Query(_) => {
                w.queries += 1;
                reply.result = Some(proto::managed_vpn_response::Result::Status(
                    proto::VpnStatusResponse {
                        results: vec![proto::VpnEndpointStatus {
                            tag: Some("proxy".into()),
                            state: Some(
                                if w.connected {
                                    "connected"
                                } else {
                                    "auth-pending"
                                }
                                .into(),
                            ),
                            connected: Some(w.connected),
                            challenge: (!w.connected).then(|| {
                                let mut challenge =
                                    challenge(w.seq, w.seq > 1 && !w.clear_error, w.malformed);
                                if w.cached_field {
                                    challenge.fields[0].name = Some("password".into());
                                }
                                challenge
                            }),
                            ..Default::default()
                        }],
                    },
                ));
                if w.change_after_query && w.queries.is_multiple_of(2) {
                    w.generation += 1;
                    w.change_after_query = false;
                }
            }
            proto::managed_vpn_request::Operation::Submit(answer) => {
                let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                w.observed_counters
                    .push(stored["otp"][0]["counter"].as_str().unwrap().into());
                w.answers.push(answer);
                if w.reject {
                    w.seq += 1;
                } else {
                    w.connected = true;
                }
                reply.result = Some(proto::managed_vpn_response::Result::Action(
                    proto::ErrorResp::default(),
                ));
            }
            proto::managed_vpn_request::Operation::Cancel(_) => {
                w.connected = true;
                reply.result = Some(proto::managed_vpn_response::Result::Action(
                    proto::ErrorResp::default(),
                ));
            }
        }
        reply.encode_to_vec()
    });
    e.rpc = Some(rpc);
    e.running = Some(p.clone());
    e.active_connection = Some(crate::connection::ActiveConnection {
        id: p,
        profiles: HashSet::new(),
        groups: HashSet::new(),
        request,
        routing_revision: 0,
        system_port: None,
        tun: true,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: bindings,
        vpn_otp_start: Default::default(),
    });
    e.reset_vpn_session();
    (dir, e, wire, otp_id)
}
async fn tick(e: &mut Engine) {
    e.vpn.last_query = None;
    e.vpn_tick().await;
}

#[tokio::test]
async fn hotp_persists_c_plus_one_before_wire_then_stops_after_three_rejected_retries() {
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    wire.lock().unwrap().reject = true;
    for _ in 0..8 {
        tick(&mut e).await;
    }
    {
        let w = wire.lock().unwrap();
        assert_eq!(w.answers.len(), 4);
        assert_eq!(w.observed_counters, vec!["1", "2", "3", "4"]);
        assert_eq!(w.answers[0].form_values["exact:otp"], "287082");
    }
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "4");
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "limited"
    );
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn invalid_form_never_spends_and_totp_same_window_does_not_replay() {
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    wire.lock().unwrap().malformed = true;
    tick(&mut e).await;
    tick(&mut e).await;
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "0");
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    let (_dir, mut e, wire, id) = fixture(Kind::Totp).await;
    wire.lock().unwrap().reject = true;
    // A long supported window avoids a timing-dependent boundary fixture.
    e.store.library.otp[0].value.period = 3600;
    e.active_connection
        .as_mut()
        .unwrap()
        .vpn_otp
        .get_mut("proxy")
        .unwrap()
        .identity
        .value
        .period = 3600;
    for _ in 0..5 {
        tick(&mut e).await;
    }
    assert_eq!(wire.lock().unwrap().answers.len(), 1);
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "0");
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "waiting"
    );
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn generation_change_after_query_does_not_retarget_consumed_hotp() {
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    wire.lock().unwrap().change_after_query = true;
    tick(&mut e).await;
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "1");
    // New session only consumes the next code for a newly observed form.
    tick(&mut e).await;
    assert_eq!(wire.lock().unwrap().answers.len(), 1);
    assert_eq!(wire.lock().unwrap().observed_counters, vec!["2"]);
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn manual_session_credentials_preserve_frozen_library_identity_and_rollback_source() {
    let (dir, mut engine, wire, _) = fixture(Kind::Hotp).await;
    let bytes = std::fs::read(dir.path().join("library.json")).unwrap();
    let old = engine.active_connection.as_ref().unwrap().vpn_otp["proxy"].clone();
    let mut candidate = old.clone();
    assert!(candidate.credentials_supported());
    candidate.session_credentials(" transient user ", " transient password ");
    assert_eq!(old.source.username, "account-user");
    assert_eq!(old.source.password, "account-password");
    assert_eq!(candidate.original_config, old.original_config);
    assert_eq!(candidate.binding_revision, old.binding_revision);
    assert!(candidate.current(&engine.store.library).is_some());
    let challenge = proto::VpnChallenge {
        endpoint_tag: Some("proxy".into()),
        id: Some("credentials-form".into()),
        kind: Some("form".into()),
        fields: vec![
            field(&json!({"key":"u","name":"username","kind":"text"})),
            field(&json!({"key":"p","name":"password","kind":"password"})),
        ],
        ..Default::default()
    };
    let identity = ChallengeRequest {
        session_id: "session".into(),
        endpoint_tag: "proxy".into(),
        challenge_id: "credentials-form".into(),
    };
    assert!(!planner::dependency(&candidate.source, &challenge, &identity).unwrap());
    let answer =
        planner::answer(&candidate.source, &challenge, &identity, "must-not-appear").unwrap();
    assert_eq!(answer.request.form_values["u"], " transient user ");
    assert_eq!(answer.request.form_values["p"], " transient password ");
    candidate.source.entries = vec![json!({"name":"answer","value":"{otp}"})];
    assert!(
        !candidate.credentials_supported(),
        "withheld Start entries still block credential replacement"
    );
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        bytes
    );
    engine.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn binding_and_otp_edits_disable_frozen_auto_until_reconnect_and_check_is_pure() {
    let (dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let active = e.active_connection.as_ref().unwrap().clone();
    let profile = e.profile(&active.id).unwrap();
    let _ = Engine::build_with_vpn_sources(&profile, &e.store.library, dir.path(), Intent::Start)
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        before
    );
    let entry = e
        .store
        .library
        .otp
        .iter()
        .find(|x| x.id == id)
        .unwrap()
        .clone();
    let mut draft = entry.value.clone();
    draft.secret = "MZXW6YTBOI".into();
    e.otp_save(&id, &entry.revision, draft).unwrap();
    tick(&mut e).await;
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "disabled"
    );
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn durable_failure_cancel_and_explicit_counter_edit_never_send_an_auto_answer() {
    for fault in [
        crate::store::CommitFault::BeforeRename,
        crate::store::CommitFault::AfterRename,
        crate::store::CommitFault::DirectorySync,
    ] {
        let (_dir, mut e, wire, _) = fixture(Kind::Hotp).await;
        e.store.fail_next_commit(fault);
        tick(&mut e).await;
        tick(&mut e).await;
        assert!(wire.lock().unwrap().answers.is_empty());
        assert_eq!(
            e.snapshot().vpn.endpoints[0]
                .otp
                .as_ref()
                .unwrap()
                .error
                .as_deref(),
            Some("vpn_otp_save_failed")
        );
        e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    let old = e.store.library.otp[0].clone();
    let mut next = old.value.clone();
    next.counter = "20".into();
    e.otp_save(&id, &old.revision, next).unwrap();
    // Returning to the previous value before a tick must not re-enable auto.
    let changed = e.store.library.otp[0].clone();
    e.otp_save(&id, &changed.revision, old.value).unwrap();
    tick(&mut e).await;
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "disabled"
    );
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    e.observe_tun().await;
    e.query_vpn().await.unwrap();
    let request = ChallengeRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    e.cancel_vpn_challenge(request).await.unwrap();
    wire.lock().unwrap().connected = false;
    wire.lock().unwrap().seq = 2;
    tick(&mut e).await;
    assert!(wire.lock().unwrap().answers.is_empty());
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "0");
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn explicit_emission_preserves_aux_origin_and_full_json_cannot_claim_a_binding() {
    let (dir, mut e, _, id) = fixture(Kind::Hotp).await;
    let vpn = e.active_connection.as_ref().unwrap().id.clone();
    let p = e
        .save_profile(crate::ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Direct".into(),
            group_id: "personal".into(),
            kind: crate::store::ProfileKind::SingBoxOutbound,
            config: json!({"type":"direct"}),
        })
        .unwrap();
    let mut routing = e.routing();
    let selected = routing.active.clone();
    let active = routing
        .profiles
        .iter_mut()
        .find(|p| p.id == selected)
        .unwrap();
    active.route["final"] = json!(format!("profile:{vpn}"));
    e.save_routing(routing).unwrap();
    let direct = e.profile(&p).unwrap();
    let (request, bindings) = Engine::build_with_vpn_sources(
        &direct,
        &e.store.library,
        dir.path(),
        crate::vpn_auth::otp::Intent::Start,
    )
    .unwrap();
    let tag = format!("thronium-route-{vpn}");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[&tag].source.profile_id, vpn);
    assert_eq!(bindings[&tag].identity.id, id);
    let full = Profile {
        kind: crate::store::ProfileKind::SingBoxConfig,
        config: serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap(),
        ..direct
    };
    assert!(Engine::build_with_vpn_sources(
        &full,
        &e.store.library,
        dir.path(),
        crate::vpn_auth::otp::Intent::Start
    )
    .unwrap()
    .1
    .is_empty());
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[test]
fn exact_otp_dependency_allows_credentials_at_hotp_max_and_rejected_history_survives_clock_rollback(
) {
    let source = planner::Source {
        profile_id: "id".into(),
        placement: planner::Placement::None,
        protocol: "openconnect".into(),
        flavor: String::new(),
        username: "123456".into(),
        password: "123456".into(),
        entries: Vec::new(),
    };
    let challenge = proto::VpnChallenge {
        kind: Some("form".into()),
        fields: vec![
            field(&json!({"key":"user","name":"username","kind":"text"})),
            field(&json!({"key":"pass","name":"password","kind":"password"})),
        ],
        ..Default::default()
    };
    let identity = ChallengeRequest {
        session_id: "session".into(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    assert!(!planner::dependency(&source, &challenge, &identity).unwrap());
    let entry = Entry {
        id: "otp".into(),
        revision: "revision".into(),
        value: crate::otp::Draft {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            kind: Kind::Hotp,
            counter: i64::MAX.to_string(),
            ..Default::default()
        },
    };
    assert_eq!(candidate_code(&entry, false, 59).unwrap(), "");
    assert_eq!(
        candidate_code(&entry, true, 59).unwrap_err(),
        "vpn_otp_counter_exhausted"
    );
    let plan = planner::answer(&source, &challenge, &identity, "").unwrap();
    assert!(!plan.uses_otp);
    assert_eq!(plan.request.form_values["pass"], "123456");
    let mut state = State {
        last_code: Some("111111".into()),
        ..Default::default()
    };
    assert!(state.wait_for_new_code("111111", true));
    assert!(!state.wait_for_new_code("222222", true));
    state.last_code = Some("222222".into());
    assert!(state.wait_for_new_code("111111", true));
    assert_eq!(state.rejected_codes.len(), 2);
    state.rejects = 0;
    assert!(
        state.wait_for_new_code("111111", false),
        "connected does not replay earlier rejected digits"
    );
}

#[tokio::test]
async fn manual_shape_fallback_allows_next_challenge_and_connected_resets_retry_budget() {
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    wire.lock().unwrap().malformed = true;
    tick(&mut e).await;
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "manual"
    );
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "0");
    e.submit_vpn_challenge(SubmitRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::from([
            ("exact:otp".into(), "manual answer".into()),
            ("unknown".into(), "operator".into()),
        ]),
    })
    .await
    .unwrap();
    {
        let mut w = wire.lock().unwrap();
        w.connected = false;
        w.malformed = false;
        w.seq = 2;
    }
    tick(&mut e).await;
    assert_eq!(wire.lock().unwrap().answers.len(), 2);
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "1");
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
    wire.lock().unwrap().reject = true;
    for _ in 0..5 {
        tick(&mut e).await;
    }
    assert_eq!(wire.lock().unwrap().answers.len(), 4);
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "limited"
    );
    // A manual successful answer replenishes only the endpoint retry budget.
    wire.lock().unwrap().reject = false;
    e.submit_vpn_challenge(SubmitRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "5".into(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::from([("exact:otp".into(), "operator answer".into())]),
    })
    .await
    .unwrap();
    tick(&mut e).await;
    assert_eq!(
        e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
        "ready"
    );
    {
        let mut w = wire.lock().unwrap();
        w.connected = false;
        w.reject = false;
        w.seq = 6;
    }
    tick(&mut e).await;
    assert_eq!(wire.lock().unwrap().answers.len(), 6);
    assert_eq!(e.otp_get(&id).unwrap()["counter"], "5");
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn last_rejected_totp_at_limit_or_bad_shape_is_not_replayed_after_connected_reset() {
    for malformed in [false, true] {
        let (dir, mut e, wire, _) = fixture(Kind::Totp).await;
        // Choose a validated window with at least a minute remaining, including
        // when this test starts in the final second of an hour.
        let at = now();
        let period = (1800..=3600).find(|p| p - at % p >= 60).unwrap() as u16;
        e.store.library.otp[0].value.period = period;
        e.active_connection
            .as_mut()
            .unwrap()
            .vpn_otp
            .get_mut("proxy")
            .unwrap()
            .identity
            .value
            .period = period;
        e.observe_tun().await;
        let last = candidate_code(&e.store.library.otp[0], true, at).unwrap();
        let before = std::fs::read(dir.path().join("library.json")).unwrap();
        let state = e.vpn.otp.entry("proxy".into()).or_default();
        state.rejects = if malformed { 1 } else { 3 };
        state.last_code = Some(last.clone());
        state
            .attempted
            .extend(["1", "2", "3", "4"].map(str::to_owned));
        state
            .rejected_codes
            .extend(["A", "B", "C"].map(str::to_owned));
        {
            let mut w = wire.lock().unwrap();
            w.seq = 5;
            w.malformed = malformed;
        }
        tick(&mut e).await;
        assert_eq!(
            e.snapshot().vpn.endpoints[0].otp.as_ref().unwrap().state,
            if malformed { "manual" } else { "limited" }
        );
        assert!(wire.lock().unwrap().answers.is_empty());
        assert!(
            e.vpn.otp["proxy"].rejected_codes.contains(&last),
            "every observed refusal must remember D before an early return"
        );

        wire.lock().unwrap().connected = true;
        tick(&mut e).await;
        assert_eq!(e.vpn.otp["proxy"].rejects, 0);
        assert!(e.vpn.otp["proxy"].rejected_codes.contains(&last));
        {
            let mut w = wire.lock().unwrap();
            w.connected = false;
            w.clear_error = true;
            w.malformed = false;
            w.seq = 6;
        }
        tick(&mut e).await;
        assert!(wire.lock().unwrap().answers.is_empty());
        assert_eq!(
            e.vpn.status.endpoints[0].otp.as_ref().unwrap().state,
            "waiting"
        );
        assert_eq!(
            std::fs::read(dir.path().join("library.json")).unwrap(),
            before
        );
        e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}

#[tokio::test]
async fn shadowed_form_templates_refuse_binding_and_old_bound_build_without_side_effects() {
    let (dir, mut e, wire, otp_id) = fixture(Kind::Hotp).await;
    let active = e.active_connection.as_ref().unwrap().clone();
    let mut profile = e.profile(&active.id).unwrap();
    let invalid = [
        json!([{"submission_key":"same","value":"fixed"},{"submission_key":"same","value":"{otp}"}]),
        json!([{"name":"same","form_id":"first","value":"{otp}"},{"name":"same","form_id":"second","value":"fixed"}]),
        json!([{"submission_key":"actual:key","value":"fixed"},{"name":"otp","value":"prefix-{otp}"}]),
        json!([{"name":"otp","value":"fixed"},{"submission_key":"actual:key","value":"{otp}"}]),
    ];
    for entries in invalid {
        profile.config["form_entries"] = entries;
        let source = profile.config.clone();
        assert_eq!(support(&profile).unwrap_err(), "vpn_otp_form_shadowed");
        let mut library = e.store.library.clone();
        library
            .profiles
            .iter_mut()
            .find(|p| p.id == profile.id)
            .unwrap()
            .config = source.clone();
        assert_eq!(
            Engine::build_with_vpn_sources(
                &profile,
                &library,
                dir.path(),
                crate::vpn_auth::otp::Intent::Start
            )
            .err()
            .as_deref(),
            Some("vpn_otp_form_shadowed")
        );
        assert_eq!(profile.config, source);
        // A prior v3 backup remains readable; build refuses before Core traffic.
        assert!(crate::vpn_otp_bindings::validate(&library).is_ok());
    }
    for entries in [
        json!([{"name":"answer","value":"{otp}"},{"name":"answer","value":"last-{otp}"}]),
        json!([{"name":"realm","value":"fixed"},{"name":"otp","value":"{otp}"}]),
        json!([{"name":"answer","promote":true},{"name":"answer","value":"{otp}"}]),
    ] {
        profile.config["form_entries"] = entries;
        assert!(support(&profile).is_ok());
    }
    profile.config["form_entries"] = json!([{"submission_key":"same","value":"fixed"},{"submission_key":"same","value":"{otp}"}]);
    let new_id = e
        .save_profile(crate::ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Shadowed synthetic".into(),
            group_id: "personal".into(),
            kind: profile.kind,
            config: profile.config,
        })
        .unwrap();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let entry = e
        .store
        .library
        .otp
        .iter()
        .find(|entry| entry.id == otp_id)
        .unwrap()
        .clone();
    let view = e.get_vpn_otp_binding(&new_id).unwrap();
    assert!(!view.supported);
    assert_eq!(view.reason.as_deref(), Some("vpn_otp_form_shadowed"));
    assert_eq!(
        e.save_vpn_otp_binding(crate::vpn_otp_bindings::SaveRequest {
            profile_id: new_id,
            edit_token: view.edit_token,
            otp_id: Some(otp_id),
            otp_revision: Some(entry.revision),
            mode: None,
        })
        .err()
        .as_deref(),
        Some("vpn_otp_form_shadowed")
    );
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        before
    );
    assert_eq!(
        e.active_connection.as_ref().unwrap().request.core_config,
        active.request.core_config
    );
    assert!(wire.lock().unwrap().answers.is_empty());
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[test]
fn templates_that_could_become_core_cached_credentials_are_explicitly_unsupported() {
    let base = Profile {
        vpn_policy: None,
        id: "source".into(),
        name: "Synthetic".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: crate::store::ProfileKind::SingBoxOutbound,
        config: json!({"type":"openconnect","server":"https://vpn.fixture.invalid","username":"account","password":"account-password"}),
    };
    for name in [
        "password",
        "username",
        "UserName",
        "user_id",
        "uname",
        "UNAME_ID",
        "group_list",
        "secondary_username",
        "",
    ] {
        let mut p = base.clone();
        p.config["form_entries"] = json!([{"name":name,"value":"{otp}"}]);
        assert_eq!(
            support(&p).err().as_deref(),
            Some("vpn_otp_form_cache_unsupported"),
            "{name}"
        );
    }
    for patch in [
        json!({"form_entries":[{"submission_key":"untrusted:key","value":"{otp}"}]}),
        json!({"flavor":"pulse","form_entries":[{"name":"answer","value":"{otp}"}]}),
        json!({"token":{"type":"stoken"},"form_entries":[{"name":"answer","value":"{otp}"}]}),
    ] {
        let mut p = base.clone();
        p.config
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert_eq!(
            support(&p).err().as_deref(),
            Some("vpn_otp_form_cache_unsupported")
        );
    }
    for name in ["custom_challenge", "answer", "secondary_password"] {
        let mut p = base.clone();
        p.config["form_entries"] = json!([{"name":name,"value":"prefix-{otp}"}]);
        assert!(support(&p).is_ok(), "{name}");
    }
    assert!(
        support(&base).is_ok(),
        "ordinary credential-only login keeps support"
    );
}

#[test]
fn promote_entries_with_ignored_placeholder_value_remain_exact_in_compiled_config() {
    let config = json!({"type":"openconnect","server":"https://fixture.invalid","form_entries":[
        {"submission_key":"hidden:key","promote":true,"value":"ignored-{otp}","unknown":"preserved"},
        {"name":"custom_challenge","value":"prefix-{otp}"}
    ]});
    let p = Profile {
        vpn_policy: None,
        id: "id".into(),
        name: "name".into(),
        group_id: "personal".into(),
        favorite: false,
        kind: crate::store::ProfileKind::SingBoxOutbound,
        config: config.clone(),
    };
    assert!(support(&p).is_ok());
    let mut compiled = config.clone();
    planner::withhold(&mut compiled);
    assert_eq!(
        compiled["form_entries"],
        json!([config["form_entries"][0].clone()])
    );
    assert_eq!(p.config, config);
    let only_promote = json!({"type":"openconnect","token":{"type":"stoken"},"form_entries":[{"submission_key":"opaque:key","promote":true,"value":"{otp}"}]});
    let mut p = p;
    p.config = only_promote.clone();
    assert!(
        support(&p).is_ok(),
        "ignored promote value is not an OTP template"
    );
    planner::withhold(&mut p.config);
    assert_eq!(p.config, only_promote);
}

#[tokio::test]
async fn otp_answer_to_cached_or_unknown_flavor_field_is_manual_before_reservation() {
    for unknown_flavor in [false, true] {
        let (_dir, mut e, wire, id) = fixture(Kind::Hotp).await;
        if unknown_flavor {
            e.active_connection
                .as_mut()
                .unwrap()
                .vpn_otp
                .get_mut("proxy")
                .unwrap()
                .source
                .flavor = "pulse".into();
        } else {
            wire.lock().unwrap().cached_field = true;
        }
        tick(&mut e).await;
        tick(&mut e).await;
        assert!(wire.lock().unwrap().answers.is_empty());
        assert_eq!(e.otp_get(&id).unwrap()["counter"], "0");
        let endpoint = &e.vpn.status.endpoints[0];
        assert_eq!(endpoint.otp.as_ref().unwrap().state, "manual");
        assert_eq!(
            endpoint.otp.as_ref().unwrap().error.as_deref(),
            Some("vpn_otp_form_cache_unsupported")
        );
        e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
    }
}
