use super::*;

fn sample() -> Value {
    json!({"id":"ignored-account","token":"must-not-escape","config":{
        "client_id":STANDARD.encode([0,128,255]),
        "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8c5a::2"}},
        "peers":[{"public_key":STANDARD.encode([3;32]),"endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}})
}
fn parsed(value: Value) -> Result<Config, String> {
    parse(
        &serde_json::to_vec(&value).unwrap(),
        &STANDARD.encode([1; 32]),
        &STANDARD.encode([2; 32]),
    )
}
#[test]
fn complete_response_has_only_needed_parameters_and_correct_prefixes() {
    let config = parsed(sample()).unwrap();
    assert_eq!(
        config.addresses,
        vec!["172.16.0.2/32", "2606:4700:110:8c5a::2/128"]
    );
    assert_eq!(config.reserved, vec![0, 128, 255]);
    assert_eq!(config.host, "engage.cloudflareclient.com");
    assert_eq!(config.port, 2408);
    assert_eq!(config.private_key, STANDARD.encode([1; 32]));
    assert_eq!(config.client_public_key, STANDARD.encode([2; 32]));
    assert_eq!(config.peer_public_key, STANDARD.encode([3; 32]));
    let out = serde_json::to_string(&config).unwrap();
    assert!(!out.contains("must-not-escape") && !out.contains("ignored-account"));
}
#[test]
fn missing_endpoint_uses_qt_fallback_and_ipv6_is_not_split_at_the_wrong_colon() {
    for value in [Value::Null, json!({}), json!({"host":""})] {
        let mut source = sample();
        source["config"]["peers"][0]["endpoint"] = value;
        assert_eq!(
            parsed(source).unwrap().endpoint,
            "engage.cloudflareclient.com:2408"
        );
    }
    let mut source = sample();
    source["config"]["peers"][0]["endpoint"] = json!({"host":"[2606:4700:d0::a29f:c001]:2408"});
    let config = parsed(source).unwrap();
    assert_eq!(config.host, "2606:4700:d0::a29f:c001");
    assert_eq!(config.endpoint, "[2606:4700:d0::a29f:c001]:2408");
}
#[test]
fn malformed_responses_never_return_raw_provider_data() {
    let bad = vec![
        ("/config", json!(null)),
        ("/config/peers", json!([])),
        ("/config/peers/0", json!(false)),
        (
            "/config/peers/0/public_key",
            json!("PRIVATE RESPONSE CANARY"),
        ),
        (
            "/config/peers/0/public_key",
            json!(STANDARD.encode([0; 32])),
        ),
        ("/config/client_id", json!("PRIVATE RESPONSE CANARY")),
        ("/config/client_id", json!(STANDARD.encode([1, 2]))),
        ("/config/interface/addresses", json!({})),
        ("/config/interface/addresses/v4", json!("::1")),
        ("/config/interface/addresses/v6", json!("1.1.1.1")),
        ("/config/interface/addresses/v4", json!("0.0.0.0")),
        ("/config/interface/addresses/v6", json!("ff02::1")),
        ("/config/peers/0/endpoint", json!(17)),
        ("/config/peers/0/endpoint/host", json!(false)),
    ];
    for (path, value) in bad {
        let mut source = sample();
        *source.pointer_mut(path).unwrap() = value;
        assert_eq!(
            parsed(source).err().as_deref(),
            Some("warp_invalid_response"),
            "{path}"
        );
    }
    assert_eq!(
        parse(&vec![b' '; LIMIT + 1], "bad", "bad").err().as_deref(),
        Some("warp_invalid_response")
    );
    assert_eq!(
        parse(b"provider-secret-malformed-response", "bad", "bad")
            .err()
            .as_deref(),
        Some("warp_invalid_response")
    );
}
#[test]
fn endpoint_rejects_paths_credentials_controls_and_invalid_ports() {
    for raw in [
        "host",
        "host:0",
        "host:65536",
        "http://host:2408",
        "user:password@host:2408",
        "host:2408/path",
        "host:2408?key=secret",
        "host:2408#secret",
        " host:2408",
        "host:\n2408",
        "0.0.0.0:2408",
        "[ff02::1]:2408",
        "-invalid.test:2408",
    ] {
        assert!(endpoint(raw).is_err(), "{raw}");
    }
    for raw in ["example.test:2408", "127.0.0.1:51820", "[::1]:51820"] {
        assert!(endpoint(raw).is_ok(), "{raw}");
    }
}
#[test]
fn registration_payload_never_contains_private_key_or_unrelated_settings() {
    let registration = Registration {
        client: reqwest::Client::new(),
        private_key: STANDARD.encode([1; 32]),
        public_key: STANDARD.encode([2; 32]),
        accepted_at: "2026-09-13T00:00:00.000+00:00".into(),
    };
    let payload = registration.payload();
    let out = serde_json::to_string(&payload).unwrap();
    assert!(!out.contains(&registration.private_key));
    assert_eq!(payload.as_object().unwrap().len(), 6);
    assert_eq!(payload["key"], registration.public_key);
    assert_eq!(payload["install_id"], "");
    assert_eq!(payload["warp_enabled"], true);
    assert_eq!(payload["locale"], "en_US");
    #[cfg(target_os = "linux")]
    assert_eq!(payload["type"], "Linux");
}
fn request(id: &str) -> StartRequest {
    StartRequest {
        request_id: id.into(),
        accept_terms: true,
    }
}
#[test]
fn registration_jobs_require_terms_and_reject_busy_duplicates_and_late_cancelled_starts() {
    let mut jobs = Jobs::default();
    assert_eq!(
        jobs.begin(&StartRequest {
            request_id: "one".into(),
            accept_terms: false
        })
        .err()
        .as_deref(),
        Some("warp_terms_required")
    );
    let cancelled = jobs.begin(&request("one")).unwrap();
    assert_eq!(
        jobs.begin(&request("two")).err().as_deref(),
        Some("warp_busy")
    );
    jobs.cancel("two").unwrap();
    assert!(!*cancelled.borrow());
    jobs.cancel("one").unwrap();
    assert!(*cancelled.borrow());
    jobs.finish("unrelated");
    assert!(jobs.is_active());
    jobs.finish("one");
    for id in ["one", "two"] {
        assert_eq!(
            jobs.begin(&request(id)).err().as_deref(),
            Some("warp_request_finished")
        );
    }
    assert!(jobs.begin(&request("three")).is_ok());
    jobs.finish("three");
    assert_eq!(
        jobs.begin(&request("three")).err().as_deref(),
        Some("warp_request_finished")
    );
}
#[test]
fn cancellation_registry_and_wire_payloads_are_bounded_and_strict() {
    let mut jobs = Jobs::default();
    for id in ["", "../one", "one two", "ключ"] {
        assert!(jobs.cancel(id).is_err());
        assert!(jobs.begin(&request(id)).is_err());
    }
    assert!(jobs.cancel(&"x".repeat(129)).is_err());
    for i in 0..300 {
        jobs.cancel(&format!("view-{i}")).unwrap();
    }
    for value in [
        json!({"requestId":"one","acceptTerms":true,"url":"http://example.test"}),
        json!({"requestId":"one"}),
        json!({"requestId":42,"acceptTerms":true}),
    ] {
        assert!(serde_json::from_value::<StartRequest>(value).is_err());
    }
}
#[tokio::test]
async fn cancelled_execution_and_missing_requested_proxy_never_spawn_or_send() {
    let (send, mut receive) = watch::channel(true);
    let registration = Registration {
        client: reqwest::Client::new(),
        private_key: STANDARD.encode([1; 32]),
        public_key: STANDARD.encode([2; 32]),
        accepted_at: "unused".into(),
    };
    assert_eq!(
        registration.execute(&mut receive).await.err().as_deref(),
        Some("warp_cancelled")
    );
    drop(send);
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &dir.path().join("must-not-start")).unwrap();
    engine
        .store
        .library
        .settings
        .insert("net_use_proxy".into(), json!(true));
    assert_eq!(
        engine.prepare_warp_registration().await.err().as_deref(),
        Some("warp_proxy_unavailable")
    );
    assert!(engine.owned_core_process().is_none());
    assert!(engine.running.is_none());
}
