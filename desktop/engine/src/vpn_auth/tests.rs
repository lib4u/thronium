use super::*;
use serde_json::json;

#[cfg(target_os = "linux")]
mod managed;
#[cfg(target_os = "linux")]
mod managed_runtime;
mod runtime;

fn request() -> proto::LoadConfigReq {
    proto::LoadConfigReq { core_config: Some(json!({"endpoints":[{"type":"openconnect","tag":"proxy","server":"https://private-token.invalid"},{"type":"openvpn-client","tag":"secondary"}],"route":{"final":"direct"}}).to_string()), ..Default::default() }
}
fn challenge(kind: &str) -> proto::VpnChallenge {
    proto::VpnChallenge {
        endpoint_tag: Some("proxy".into()),
        id: Some("1".into()),
        kind: Some(kind.into()),
        username: Some("private-user".into()),
        message: Some("private-message".into()),
        banner: Some("private-banner".into()),
        error: Some("private-error".into()),
        url: Some("https://fixture.invalid/path?secret=private-url".into()),
        ..Default::default()
    }
}
fn status(challenge: Option<proto::VpnChallenge>, tag: &str) -> proto::VpnEndpointStatus {
    proto::VpnEndpointStatus {
        tag: Some(tag.into()),
        state: Some(
            if challenge.is_some() {
                "auth-pending"
            } else {
                "connecting"
            }
            .into(),
        ),
        challenge,
        ..Default::default()
    }
}
fn form() -> proto::VpnChallenge {
    let mut c = challenge("form");
    c.fields = vec![
        proto::VpnChallengeField {
            submission_key: Some("exact:user:1".into()),
            name: Some("user".into()),
            kind: Some("text".into()),
            ..Default::default()
        },
        proto::VpnChallengeField {
            submission_key: Some("exact:password:2".into()),
            name: Some("password".into()),
            kind: Some("password".into()),
            value: Some("private-prefill".into()),
            ..Default::default()
        },
        proto::VpnChallengeField {
            submission_key: Some("exact:realm:3".into()),
            name: Some("realm".into()),
            kind: Some("select".into()),
            options: vec![
                proto::VpnChallengeChoice {
                    value: Some("one".into()),
                    label: Some("First label".into()),
                },
                proto::VpnChallengeChoice {
                    value: Some("two".into()),
                    label: Some("Second label".into()),
                },
            ],
            ..Default::default()
        },
    ];
    c
}
fn answer() -> SubmitRequest {
    SubmitRequest {
        session_id: "session".into(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::new(),
    }
}

#[test]
fn metadata_contains_only_safe_fields_and_core_tags_from_frozen_request() {
    let mut session = Session::start(&request(), false, Some(1));
    let c = form();
    session
        .update(&proto::VpnStatusResponse {
            results: vec![status(Some(c), "proxy"), status(None, "secondary")],
        })
        .unwrap();
    let public = serde_json::to_string(&session.snapshot()).unwrap();
    for secret in [
        "private-user",
        "private-message",
        "private-banner",
        "private-error",
        "private-url",
        "private-prefill",
        "private-token",
    ] {
        assert!(!public.contains(secret), "{secret}");
    }
    assert_eq!(
        session.status.endpoints[0].challenge_id.as_deref(),
        Some("1")
    );
    assert!(
        session.phase().is_none(),
        "full JSON has independent endpoint states"
    );
    session.primary = true;
    assert_eq!(session.phase(), Some("auth-pending"));
}

#[test]
fn an_acknowledged_message_stops_asking_but_other_challenges_still_do() {
    let mut session = Session::start(&request(), true, Some(1));
    let message = |id: &str| {
        let mut c = challenge("message");
        c.endpoint_tag = Some("secondary".into());
        c.id = Some(id.into());
        c
    };
    let update = |session: &mut Session, c: proto::VpnChallenge| {
        session
            .update(&proto::VpnStatusResponse {
                results: vec![status(None, "proxy"), status(Some(c), "secondary")],
            })
            .unwrap();
    };
    update(&mut session, message("1"));
    assert_eq!(
        session.status.endpoints[1].challenge_id.as_deref(),
        Some("1")
    );
    session.acknowledge("secondary", "1");
    assert_eq!(session.status.endpoints[1].challenge_id, None);
    // The core keeps reporting the message it cannot complete.
    update(&mut session, message("1"));
    assert_eq!(session.status.endpoints[1].challenge_id, None);
    assert_eq!(session.status.endpoints[1].state, "auth-pending");
    // A new message, or a challenge of another kind with the same ID, still asks.
    update(&mut session, message("2"));
    assert_eq!(
        session.status.endpoints[1].challenge_kind.as_deref(),
        Some("message")
    );
    let mut secret = challenge("secret");
    secret.endpoint_tag = Some("secondary".into());
    update(&mut session, secret);
    assert_eq!(
        session.status.endpoints[1].challenge_id.as_deref(),
        Some("1")
    );
}

#[test]
fn session_epoch_changes_even_for_same_request_process_and_reused_challenge_id() {
    let a = Session::start(&request(), true, Some(7));
    let b = Session::start(&request(), true, Some(7));
    assert_ne!(a.status.session_id, b.status.session_id);
    assert_eq!(a.phase(), Some("connecting"));
    assert_eq!(Session::default().snapshot().session_id, None);
    assert!(Session::start(
        &proto::LoadConfigReq {
            core_config: Some("{}".into()),
            ..Default::default()
        },
        false,
        Some(7)
    )
    .status
    .session_id
    .is_none());
}

#[test]
fn response_identity_and_state_ambiguities_fail_atomically() {
    let mut session = Session::start(&request(), true, Some(1));
    let good = proto::VpnStatusResponse {
        results: vec![status(Some(form()), "proxy"), status(None, "secondary")],
    };
    session.update(&good).unwrap();
    let before = serde_json::to_value(session.snapshot()).unwrap();
    let mut variants = vec![];
    let mut v = good.clone();
    v.results.pop();
    variants.push(v);
    let mut v = good.clone();
    v.results[1].tag = Some("proxy".into());
    variants.push(v);
    let mut v = good.clone();
    v.results[1].tag = Some("unrequested".into());
    variants.push(v);
    let mut v = good.clone();
    v.results[0].challenge.as_mut().unwrap().endpoint_tag = Some("secondary".into());
    variants.push(v);
    let mut v = good.clone();
    v.results[0].state = Some("connected".into());
    v.results[0].connected = Some(true);
    variants.push(v);
    let mut v = good.clone();
    v.results[1].state = Some("connected".into());
    variants.push(v);
    for variant in variants {
        assert!(session.update(&variant).is_err());
        assert_eq!(serde_json::to_value(session.snapshot()).unwrap(), before);
    }
}

#[test]
fn endpoint_inventory_overflow_and_unknown_tags_are_not_silently_truncated() {
    for endpoints in [
        json!([{"type":"openconnect"}]),
        json!([{"type":"openconnect","tag":"x"},{"type":"openconnect","tag":"x"}]),
        json!((0..129)
            .map(|i| json!({"type":"openconnect","tag":format!("e{i}")}))
            .collect::<Vec<_>>()),
    ] {
        let mut req = request();
        req.core_config = Some(json!({"endpoints":endpoints}).to_string());
        let s = Session::start(&req, true, Some(1));
        assert_eq!(s.status.error.as_deref(), Some("vpn_status_unsupported"));
        assert!(s.status.endpoints.is_empty());
        assert_eq!(s.phase(), Some("unknown"));
    }
}

#[test]
fn form_answers_use_exact_submission_keys_and_option_values() {
    let c = form();
    let mut a = answer();
    a.form_values = BTreeMap::from([
        ("exact:user:1".into(), "fixture-user".into()),
        ("exact:password:2".into(), "".into()),
        ("exact:realm:3".into(), "two".into()),
    ]);
    validate::answer(&c, "openconnect", &a).unwrap();
    a.form_values
        .insert("exact:realm:3".into(), "Second label".into());
    assert!(validate::answer(&c, "openconnect", &a).is_err());
    a.form_values.insert("exact:realm:3".into(), "two".into());
    a.form_values.remove("exact:user:1");
    a.form_values.insert("user".into(), "fixture-user".into());
    assert!(validate::answer(&c, "openconnect", &a).is_err());
    a.form_values
        .insert("exact:user:1".into(), "fixture-user".into());
    assert!(validate::answer(&c, "openconnect", &a).is_err());
}

#[test]
fn malformed_and_oversize_forms_remain_visible_for_cancel_but_cannot_be_answered() {
    let mut variants = vec![];
    let mut c = form();
    c.fields.push(c.fields[0].clone());
    variants.push(c);
    let mut c = form();
    c.fields[0].kind = Some("hidden-custom".into());
    variants.push(c);
    let mut c = form();
    c.fields[0].submission_key = Some("".into());
    variants.push(c);
    let mut c = form();
    c.fields[2].options.clear();
    variants.push(c);
    let mut c = form();
    let duplicate = c.fields[2].options[0].clone();
    c.fields[2].options.push(duplicate);
    variants.push(c);
    let mut c = form();
    c.fields[2].value = Some("unlisted".into());
    variants.push(c);
    let mut c = form();
    c.fields.clear();
    variants.push(c);
    let mut c = form();
    c.message = Some("a".repeat(4097));
    variants.push(c);
    let mut c = form();
    c.deadline = Some(-1);
    variants.push(c);
    let mut c = form();
    c.deadline = Some(9_007_199_254_740_992);
    variants.push(c);
    let mut c = form();
    c.fields[0].value = Some("a\0b".into());
    variants.push(c);
    let mut c = form();
    c.fields = (0..129)
        .map(|i| proto::VpnChallengeField {
            submission_key: Some(format!("f{i}")),
            kind: Some("text".into()),
            ..Default::default()
        })
        .collect();
    variants.push(c);
    for c in variants {
        assert_eq!(
            validate::details(&c, "openconnect").err().as_deref(),
            Some("vpn_auth_unsupported")
        );
        let mut s = Session::start(&request(), true, Some(1));
        s.update(&proto::VpnStatusResponse {
            results: vec![status(Some(c), "proxy"), status(None, "secondary")],
        })
        .unwrap();
        assert_eq!(s.status.endpoints[0].challenge_id.as_deref(), Some("1"));
        assert_eq!(
            s.status.endpoints[0].error.as_deref(),
            Some("vpn_auth_unsupported")
        );
    }
}

#[test]
fn message_secret_credentials_and_browser_keep_distinct_response_contracts() {
    let mut a = answer();
    a.username = "user".into();
    a.password = "password".into();
    a.secret = "answer".into();
    validate::answer(&challenge("credentials"), "openvpn", &a).unwrap();
    assert!(validate::answer(&challenge("secret"), "openvpn", &a).is_err());
    a.username.clear();
    a.password.clear();
    validate::answer(&challenge("secret"), "openvpn", &a).unwrap();
    assert!(validate::answer(&challenge("message"), "openvpn", &a).is_err());
    a.secret.clear();
    validate::answer(&challenge("message"), "openvpn", &a).unwrap();
    for (protocol, kind) in [
        ("openconnect", "browser"),
        ("openvpn", "open-url"),
        ("openvpn", "unknown"),
    ] {
        assert_eq!(
            validate::answer(&challenge(kind), protocol, &a)
                .err()
                .as_deref(),
            Some("vpn_auth_unsupported")
        );
    }
    a.secret = "a".repeat(4097);
    assert_eq!(
        validate::answer_size(&a).err().as_deref(),
        Some("vpn_auth_invalid_response")
    );
}

#[test]
fn url_preserves_token_without_allowing_non_web_or_credential_handlers() {
    let exact = "https://vpn.fixture.invalid/path?token=synthetic%2Bvalue#fragment";
    assert_eq!(validate::url(exact).unwrap(), exact);
    for raw in [
        "file:///tmp/a",
        "javascript:alert(1)",
        "data:text/plain,a",
        "https://user:password@fixture.invalid/",
        "https://fixture.invalid/\n",
        " https://fixture.invalid/",
        "//fixture.invalid/",
    ] {
        assert_eq!(
            validate::url(raw).err().as_deref(),
            Some("vpn_auth_url_invalid")
        );
    }
}

#[tokio::test]
async fn idle_actions_are_stale_and_do_not_spawn_save_or_log_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
    let before = serde_json::to_value(&e.store.library).unwrap();
    let r = ChallengeRequest {
        session_id: "old".into(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    assert_eq!(
        e.vpn_challenge(r.clone()).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    assert_eq!(
        e.cancel_vpn_challenge(r.clone()).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    assert_eq!(
        e.vpn_challenge_url(r).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    let mut a = answer();
    a.secret = "private-answer-never-saved".into();
    assert_eq!(
        e.submit_vpn_challenge(a).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    e.vpn_tick().await;
    assert!(e.rpc.is_none());
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    assert!(!serde_json::to_string(&e.snapshot())
        .unwrap()
        .contains("private-answer-never-saved"));
}

#[test]
fn request_shapes_reject_unknown_fields_duplicate_answer_keys_and_non_strings() {
    for raw in [
        r#"{"sessionId":"s","endpointTag":"p","challengeId":"1","formValues":{"key":"a","key":"b"}}"#,
        r#"{"sessionId":"s","endpointTag":"p","challengeId":"1","formValues":{"key":1}}"#,
        r#"{"sessionId":"s","endpointTag":"p","challengeId":"1","password":null}"#,
        r#"{"sessionId":"s","endpointTag":"p","challengeId":"1","unknown":"answer"}"#,
    ] {
        assert!(serde_json::from_str::<SubmitRequest>(raw).is_err());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn managed_actions_refuse_before_query_and_missed_generation_resets_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("missing-core")).unwrap();
    e.rpc = Some(crate::transport::Rpc::managed_vpn_test_rpc());
    e.running = Some("active".into());
    e.active_connection = Some(crate::connection::ActiveConnection {
        id: "active".into(),
        profiles: HashSet::new(),
        groups: HashSet::new(),
        request: request(),
        routing_revision: 0,
        system_port: None,
        tun: true,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    e.reset_vpn_session();
    let id = e.vpn.status.session_id.clone();
    e.tun_generation = 7;
    e.observe_vpn_generation(7, 0);
    assert_eq!(e.vpn.status.session_id, id);
    e.observe_vpn_generation(8, 0);
    assert_ne!(
        e.vpn.status.session_id, id,
        "no intermediate reconnecting was observed"
    );
    let r = ChallengeRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    assert_eq!(
        e.vpn_challenge(r.clone()).await.err().as_deref(),
        Some("vpn_auth_managed_unsupported")
    );
    assert_eq!(
        e.cancel_vpn_challenge(r.clone()).await.err().as_deref(),
        Some("vpn_auth_managed_unsupported")
    );
    assert_eq!(
        e.vpn_challenge_url(r).await.err().as_deref(),
        Some("vpn_auth_managed_unsupported")
    );
    assert_eq!(
        e.submit_vpn_challenge(answer()).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    let mut current = answer();
    current.session_id = e.vpn.status.session_id.clone().unwrap();
    assert_eq!(
        e.submit_vpn_challenge(current).await.err().as_deref(),
        Some("vpn_auth_managed_unsupported")
    );
    // Fixture drops its IPC peer at the FIRST incoming frame. A live stream
    // proves all four refusals happened before either Query or Submit/Cancel.
    assert!(e.rpc.as_mut().unwrap().is_alive());
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[test]
fn metadata_unavailable_never_claims_that_the_tunnel_failed() {
    let mut s = Session::start(&request(), true, Some(1));
    s.unavailable();
    assert_eq!(s.phase(), Some("unknown"));
    assert!(s.status.endpoints.iter().all(|e| e.state == "unknown"));
    s.managed_unsupported();
    assert_eq!(s.phase(), Some("unknown"));
    assert_eq!(
        s.status.error.as_deref(),
        Some("vpn_auth_managed_unsupported")
    );
    s.primary = false;
    assert!(s.phase().is_none());
}

#[test]
fn deadline_is_server_defined_and_checked_at_submission_boundary() {
    let mut c = challenge("secret");
    for deadline in [None, Some(0), Some(101)] {
        c.deadline = deadline;
        unexpired(&c, 100).unwrap();
    }
    for deadline in [1, 99, 100] {
        c.deadline = Some(deadline);
        assert_eq!(
            unexpired(&c, 100).err().as_deref(),
            Some("vpn_auth_expired")
        );
    }
    c.deadline = Some(-1);
    assert!(validate::details(&c, "openvpn").is_err());
}

#[test]
fn field_and_total_payload_boundaries_are_explicit_not_partial() {
    let mut c = form();
    c.fields = (0..128)
        .map(|i| proto::VpnChallengeField {
            submission_key: Some(format!("f{i}")),
            kind: Some("password".into()),
            value: Some("exact-default".into()),
            ..Default::default()
        })
        .collect();
    validate::details(&c, "openconnect").unwrap();
    assert!(c
        .fields
        .iter()
        .all(|f| f.value.as_deref() == Some("exact-default")));
    let mut a = answer();
    a.form_values = (0..128)
        .map(|i| (format!("f{i}"), "value".into()))
        .collect();
    validate::answer(&c, "openconnect", &a).unwrap();
    for field in &mut c.fields {
        field.value = Some("x".repeat(1024));
    }
    assert!(validate::details(&c, "openconnect").is_err());
    for value in a.form_values.values_mut() {
        *value = "x".repeat(1024);
    }
    assert!(validate::answer_size(&a).is_err());
}

#[test]
fn a_connected_tunnel_reports_its_own_details_bounded_and_without_control_characters() {
    let mut session = Session::start(&request(), false, Some(1));
    let connected = proto::VpnEndpointStatus {
        tag: Some("proxy".into()),
        state: Some("connected".into()),
        connected: Some(true),
        server: Some("vpn.fixture.invalid:1194".into()),
        network: Some("udp".into()),
        cipher: Some("AES-256-GCM".into()),
        mtu: Some(1420),
        connected_since: Some(1_700_000_000),
        ipv4: vec!["10.8.0.6".into()],
        ipv6: vec!["fd00:9::6".into()],
        dns: vec!["10.8.0.1".into(), "quiet\ndns".into(), String::new()],
        routes: (0..200).map(|index| format!("10.{index}.0.0/16")).collect(),
        excluded_routes: vec!["192.0.2.0/24".into()],
        search_domains: vec!["fixture.invalid".into()],
        ..Default::default()
    };
    session
        .update(&proto::VpnStatusResponse {
            results: vec![connected, status(None, "secondary")],
        })
        .unwrap();
    let tunnel = session.status.endpoints[0].tunnel.as_ref().unwrap();
    assert_eq!(tunnel.server, "vpn.fixture.invalid:1194");
    assert_eq!((tunnel.cipher.as_str(), tunnel.mtu), ("AES-256-GCM", 1420));
    assert_eq!(tunnel.ipv4, ["10.8.0.6"]);
    assert_eq!(tunnel.ipv6, ["fd00:9::6"]);
    // A newline never reaches the window, and an empty value is not a row.
    assert_eq!(tunnel.dns, ["10.8.0.1", "quietdns"]);
    // A server that pushes more routes than a window can show is bounded.
    assert_eq!(tunnel.routes.len(), 64);
    assert_eq!(tunnel.excluded_routes, ["192.0.2.0/24"]);
    assert_eq!(tunnel.search_domains, ["fixture.invalid"]);
    // An endpoint that is not up reports no tunnel at all.
    assert!(session.status.endpoints[1].tunnel.is_none());
    let public = serde_json::to_string(&session.snapshot()).unwrap();
    assert!(public.contains("AES-256-GCM") && !public.contains("quiet\\ndns"));
}
