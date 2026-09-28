use super::*;
use prost::Message;
use std::sync::{Arc, Mutex};

struct Script {
    generation: u64,
    change_after_query: bool,
    pending: bool,
    cancelled: bool,
    queries: Vec<u64>,
    attempted: Vec<(bool, u64)>,
    applied: Vec<proto::SubmitVpnChallengeRequest>,
}

async fn generation_race(cancel: bool) {
    let script = Arc::new(Mutex::new(Script {
        generation: (1u64 << 53) + 1,
        change_after_query: false,
        pending: true,
        cancelled: false,
        queries: Vec::new(),
        attempted: Vec::new(),
        applied: Vec::new(),
    }));
    let remote = script.clone();
    let rpc = crate::transport::Rpc::scripted_vpn_test_rpc(move |method, payload| {
        let mut state = remote.lock().unwrap();
        if method == "ManagedTunStatus" {
            return proto::ManagedTunStatus {
                phase: Some("connected".into()),
                generation: Some(state.generation),
                vpn_auth_version: Some(1),
                ..Default::default()
            }
            .encode_to_vec();
        }
        assert_eq!(method, "ManagedVPN", "never fall back to unguarded methods");
        let request = proto::ManagedVpnRequest::decode(payload).unwrap();
        assert_eq!(request.version, Some(1));
        let mut reply = proto::ManagedVpnResponse {
            version: Some(1),
            generation: Some(state.generation),
            ..Default::default()
        };
        match request.operation.unwrap() {
            proto::managed_vpn_request::Operation::Query(query) => {
                assert_eq!(query.timeout_ms, Some(0));
                assert_eq!(query.endpoint_tags, vec!["proxy", "secondary"]);
                state.queries.push(request.generation.unwrap());
                assert_eq!(request.generation, Some(state.generation));
                let mut primary = status(state.pending.then(form), "proxy");
                if !state.pending {
                    primary.state = Some(
                        if state.cancelled {
                            "error"
                        } else {
                            "connected"
                        }
                        .into(),
                    );
                    primary.connected = Some(!state.cancelled);
                }
                reply.result = Some(proto::managed_vpn_response::Result::Status(
                    proto::VpnStatusResponse {
                        results: vec![primary, status(None, "secondary")],
                    },
                ));
                if state.change_after_query {
                    state.generation += 1;
                    state.change_after_query = false;
                }
            }
            operation => {
                let (was_cancel, answer) = match operation {
                    proto::managed_vpn_request::Operation::Submit(v) => (false, v),
                    proto::managed_vpn_request::Operation::Cancel(v) => (true, v),
                    _ => unreachable!(),
                };
                state
                    .attempted
                    .push((was_cancel, request.generation.unwrap()));
                if request.generation != Some(state.generation) {
                    reply.error_code = Some("managed_vpn_stale_generation".into());
                } else {
                    assert_eq!(answer.endpoint_tag.as_deref(), Some("proxy"));
                    assert_eq!(answer.challenge_id.as_deref(), Some("1"));
                    state.applied.push(answer);
                    state.pending = false;
                    state.cancelled = was_cancel;
                    reply.result = Some(proto::managed_vpn_response::Result::Action(
                        proto::ErrorResp::default(),
                    ));
                }
            }
        }
        reply.encode_to_vec()
    });
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), &dir.path().join("never-spawn-core")).unwrap();
    e.rpc = Some(rpc);
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
    e.vpn_tick().await;
    assert_eq!(e.snapshot().phase, "auth-pending");
    let old = ChallengeRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    assert_eq!(
        e.vpn_challenge(old.clone()).await.unwrap().fields[1].value,
        "private-prefill"
    );
    let before = serde_json::to_value(&e.store.library).unwrap();
    let submit = |identity: &ChallengeRequest| SubmitRequest {
        session_id: identity.session_id.clone(),
        endpoint_tag: identity.endpoint_tag.clone(),
        challenge_id: identity.challenge_id.clone(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::from([
            ("exact:user:1".into(), "synthetic-user".into()),
            ("exact:password:2".into(), "transient-secret".into()),
            ("exact:realm:3".into(), "two".into()),
        ]),
    };
    script.lock().unwrap().change_after_query = true;
    let result = if cancel {
        e.cancel_vpn_challenge(old.clone()).await
    } else {
        e.submit_vpn_challenge(submit(&old)).await
    };
    assert_eq!(result.err().as_deref(), Some("vpn_auth_stale"));
    assert_ne!(e.vpn.status.session_id.as_ref(), Some(&old.session_id));
    assert_eq!(e.snapshot().phase, "unknown");
    assert!(script.lock().unwrap().applied.is_empty());
    assert_eq!(
        script.lock().unwrap().attempted,
        vec![(cancel, (1u64 << 53) + 1)]
    );
    let queries = script.lock().unwrap().queries.len();
    assert_eq!(
        e.cancel_vpn_challenge(old.clone()).await.err().as_deref(),
        Some("vpn_auth_stale")
    );
    assert_eq!(
        script.lock().unwrap().queries.len(),
        queries,
        "old session rejected before another query"
    );
    e.vpn_tick().await;
    assert_eq!(e.snapshot().phase, "auth-pending");
    let current = ChallengeRequest {
        session_id: e.vpn.status.session_id.clone().unwrap(),
        endpoint_tag: "proxy".into(),
        challenge_id: "1".into(),
    };
    assert_ne!(current.session_id, old.session_id);
    if cancel {
        e.cancel_vpn_challenge(current).await.unwrap();
    } else {
        e.submit_vpn_challenge(submit(&current)).await.unwrap();
    }
    {
        let state = script.lock().unwrap();
        assert_eq!(state.applied.len(), 1);
        assert_eq!(
            state.attempted,
            vec![(cancel, (1u64 << 53) + 1), (cancel, (1u64 << 53) + 2)]
        );
        if !cancel {
            assert_eq!(
                state.applied[0]
                    .form_values
                    .get("exact:password:2")
                    .map(String::as_str),
                Some("transient-secret")
            );
        }
    }
    assert_eq!(serde_json::to_value(&e.store.library).unwrap(), before);
    assert!(!serde_json::to_string(&e.snapshot())
        .unwrap()
        .contains("transient-secret"));
    e.rpc.as_mut().unwrap().kill_for_recovery_test().await;
}

#[tokio::test]
async fn submit_retains_original_generation_across_query_and_never_replays_on_replacement() {
    generation_race(false).await;
}
#[tokio::test]
async fn cancel_retains_original_generation_and_cannot_cancel_replacement_challenge() {
    generation_race(true).await;
}
