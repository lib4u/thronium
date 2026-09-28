//! Independent real TLS ClientHello/HTTP acceptance using public Engine APIs.
//! Run with the owned fixture through desktop/tests/profile_tls_review.py.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::{net::TcpListener, path::PathBuf, time::Duration};
use thronium_engine::{
    exports::Format, store::ProfileKind, system_proxy::ConnectionMode, vless::Core, Engine,
    ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(
        exe.file_name().unwrap(),
        "Thronium",
        "use pinned-core runner"
    );
    exe.with_file_name("ThroniumCore")
}
fn input(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(std::env::var(name).unwrap()).unwrap()).unwrap()
}
fn events(fixture: &Value) -> Vec<Value> {
    std::fs::read_to_string(fixture["events"].as_str().unwrap())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn report(value: Value) {
    println!("PROFILE_TLS_REVIEW_JSON {value}");
}
struct App {
    engine: Engine,
    _directory: tempfile::TempDir,
    port: u16,
}
impl App {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(directory.path(), &core()).unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        engine
            .connection_settings(ConnectionMode::Local, port)
            .unwrap();
        drop(reservation);
        Self {
            engine,
            _directory: directory,
            port,
        }
    }
    async fn defaults(&mut self, mixed: bool, spoof: bool, fragment: bool) {
        let previous = self.engine.settings()["presets"].clone();
        let mut next = previous.clone();
        next["tls_tricks_default_on"] = json!(mixed);
        next["tls_spoof_default_on"] = json!(spoof);
        next["tls_spoof"] = json!("spoof.fixture.invalid");
        next["tls_spoof_method"] = json!("wrong-checksum");
        next["fragment_default_on"] = json!(fragment);
        next["fragment_implementation"] = json!("built-in");
        self.engine
            .save_settings("presets", previous, next)
            .await
            .unwrap();
    }
    fn add(&mut self, name: &str, kind: ProfileKind, config: Value) -> String {
        self.engine
            .save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: name.into(),
                group_id: "personal".into(),
                kind,
                config,
            })
            .unwrap()
    }
    fn unchanged(&self, id: &str, original: &Value) {
        assert_eq!(&self.engine.profile(id).unwrap().config, original);
        let exported: Value = serde_json::from_str(
            &self
                .engine
                .export_profiles(vec![id.into()], Format::Configurations)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            &exported, original,
            "explicit export keeps exact saved JSON"
        );
    }
    async fn close(&mut self) {
        self.engine.shutdown().await;
        assert!(self.engine.owned_core_process().is_none());
        assert!(TcpListener::bind(("127.0.0.1", self.port)).is_ok());
    }
}
async fn get(port: u16, origin: u16, path: &str) {
    let mut stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(format!("GET http://127.0.0.1:{origin}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(12), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response.ends_with(format!("tls-fixture:/{path}").as_bytes()),
        "owned HTTP response body"
    );
}
fn tls(fixture: &Value) -> Value {
    json!({"enabled":true, "server_name":fixture["serverName"], "alpn":["http/1.1"]})
}
fn outbound(fixture: &Value, tls: Value) -> Value {
    json!({"type":"http", "server":"127.0.0.1", "server_port":fixture["proxyPort"], "tls":tls})
}

#[tokio::test]
#[ignore = "real pinned core and owned TLS fixture required"]
async fn actual_clienthello_and_http_preserve_profile_and_explicit_defaults() {
    let fixture = input("THRONIUM_TLS_FIXTURE");
    let imported = input("THRONIUM_TLS_URI_FIXTURES");
    let mut cases: Vec<(String, Value, bool, bool, bool, bool)> = vec![];
    for item in imported.as_array().unwrap() {
        let name = item["name"].as_str().unwrap();
        let config = item["draft"]["config"].clone();
        cases.push((
            format!("{name}-default-off"),
            config.clone(),
            false,
            false,
            false,
            name == "uri-true",
        ));
        cases.push((
            format!("{name}-default-on"),
            config,
            true,
            true,
            false,
            name != "uri-false",
        ));
    }
    for (name, tricks, mixed) in [
        ("legacy-true", json!(true), true),
        ("legacy-false", json!(false), false),
        ("empty-object", json!({}), true),
    ] {
        let mut t = tls(&fixture);
        t["tls_tricks"] = tricks;
        t["spoof_enabled"] = json!(false);
        cases.push((name.into(), outbound(&fixture, t), true, true, false, mixed));
    }
    for enabled in [false, true] {
        let mut t = tls(&fixture);
        t["tls_tricks"] = json!({"mixedcase_sni":false});
        t["fragment"] = json!(enabled);
        t["spoof_enabled"] = json!(false);
        t["spoof"] = json!("own-disabled.fixture.invalid");
        cases.push((
            format!("fragment-{enabled}"),
            outbound(&fixture, t),
            true,
            true,
            true,
            false,
        ));
    }
    // Previous additive Throne imports represented explicit Off using empty
    // strings. This saved representation must remain Off under new defaults.
    let mut sentinel = tls(&fixture);
    sentinel["tls_tricks"] = json!({"mixedcase_sni":false});
    sentinel["spoof"] = json!("");
    sentinel["spoof_method"] = json!("");
    cases.push((
        "legacy-spoof-off-sentinel".into(),
        outbound(&fixture, sentinel),
        true,
        true,
        false,
        false,
    ));
    for (name, config, mixed_default, spoof_default, fragment_default, expected_mixed) in cases {
        let mut app = App::new();
        app.defaults(mixed_default, spoof_default, fragment_default)
            .await;
        let id = app.add(&name, ProfileKind::SingBoxOutbound, config.clone());
        let before = events(&fixture).len();
        app.engine
            .check(&app.engine.profile(&id).unwrap())
            .await
            .unwrap();
        assert_eq!(
            events(&fixture).len(),
            before,
            "Check never sends a ClientHello"
        );
        app.unchanged(&id, &config);
        app.engine.connect(&id).await.unwrap();
        get(
            app.port,
            fixture["originPort"].as_u64().unwrap() as u16,
            &name,
        )
        .await;
        app.engine.disconnect().await.unwrap();
        app.unchanged(&id, &config);
        app.close().await;
        let rows = events(&fixture);
        let observed = &rows[before..];
        let hellos: Vec<_> = observed
            .iter()
            .filter(|v| v["event"] == "client-hello")
            .collect();
        assert_eq!(hellos.len(), 1);
        let sni = hellos[0]["rawSni"].as_str().unwrap();
        let base = fixture["serverName"].as_str().unwrap();
        assert_eq!(hellos[0]["sni"], sni);
        assert!(sni.eq_ignore_ascii_case(base));
        if expected_mixed {
            assert!(
                sni.bytes().any(|b| b.is_ascii_uppercase()),
                "48-letter randomized SNI must contain uppercase"
            );
        } else {
            assert_eq!(sni, base, "explicit false/default false wire SNI");
        }
        assert_eq!(
            observed
                .iter()
                .filter(|v| v["event"] == "handshake")
                .count(),
            1
        );
        assert_eq!(
            observed
                .iter()
                .filter(|v| v["event"] == "http" && v["path"] == format!("/{name}"))
                .count(),
            1
        );
        report(
            json!({"scenario":name,"actualTlsHttp":true,"mixed":expected_mixed,"wireSni":sni,"sourceExact":true,"spoofDefault":spoof_default}),
        );
    }
}

#[tokio::test]
#[ignore = "real pinned core and owned TLS fixture required"]
async fn check_only_spoof_invalid_types_and_cross_core_refusal() {
    let fixture = input("THRONIUM_TLS_FIXTURE");
    let before = events(&fixture).len();
    let mut app = App::new();
    app.defaults(false, false, false).await;
    let positive = [
        json!({"spoof_enabled":true}),
        json!({"spoof_enabled":true,"spoof":"own.fixture.invalid"}),
        json!({"spoof":"own.fixture.invalid"}),
        json!({"spoof_enabled":false,"spoof":"own.fixture.invalid","spoof_method":"wrong-checksum"}),
    ];
    for (i, fields) in positive.into_iter().enumerate() {
        let mut t = tls(&fixture);
        t.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let config = outbound(&fixture, t);
        let id = app.add(
            &format!("spoof-check-{i}"),
            ProfileKind::SingBoxOutbound,
            config.clone(),
        );
        app.engine
            .check(&app.engine.profile(&id).unwrap())
            .await
            .unwrap();
        app.unchanged(&id, &config);
    }
    app.defaults(false, true, false).await;
    let config = outbound(&fixture, tls(&fixture));
    let id = app.add(
        "inherited-spoof-check",
        ProfileKind::SingBoxOutbound,
        config.clone(),
    );
    app.engine
        .check(&app.engine.profile(&id).unwrap())
        .await
        .unwrap();
    app.unchanged(&id, &config);
    app.defaults(false, false, false).await;
    // The pinned decoder accepts an empty array for this object-shaped field.
    // Compare the ordinary path with an untouched full-config control instead
    // of claiming that acceptance means our compiler removed the input.
    let mut array_tls = tls(&fixture);
    array_tls["tls_tricks"] = json!([]);
    let array_config = outbound(&fixture, array_tls);
    let array_id = app.add(
        "empty-array-core-control",
        ProfileKind::SingBoxOutbound,
        array_config.clone(),
    );
    app.engine
        .check(&app.engine.profile(&array_id).unwrap())
        .await
        .unwrap();
    app.unchanged(&array_id, &array_config);
    let raw_config = json!({"inbounds":[],"outbounds":[array_config]});
    let raw_id = app.add(
        "empty-array-full-core-control",
        ProfileKind::SingBoxConfig,
        raw_config.clone(),
    );
    app.engine
        .check(&app.engine.profile(&raw_id).unwrap())
        .await
        .unwrap();
    app.unchanged(&raw_id, &raw_config);
    let invalid = [
        json!({"tls_tricks":"true"}),
        json!({"tls_tricks":{"mixedcase_sni":true,"future":1}}),
        json!({"tls_tricks":{"mixedcase_sni":"false"}}),
        json!({"spoof_enabled":7}),
        json!({"spoof_enabled":false,"spoof":7}),
        json!({"spoof_enabled":false,"spoof_method":7}),
    ];
    for (i, fields) in invalid.into_iter().enumerate() {
        let mut t = tls(&fixture);
        t.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let config = outbound(&fixture, t);
        let id = app.add(
            &format!("invalid-{i}"),
            ProfileKind::SingBoxOutbound,
            config.clone(),
        );
        assert!(
            app.engine
                .check(&app.engine.profile(&id).unwrap())
                .await
                .is_err(),
            "invalid TLS types/unknown siblings must not disappear: {fields}"
        );
        app.unchanged(&id, &config);
    }
    for (i, fields) in [
        json!({"tls_tricks":{"mixedcase_sni":false}}),
        json!({"tls_tricks":{"mixedcase_sni":true}}),
        json!({"spoof_enabled":false}),
        json!({"spoof_enabled":true}),
        json!({"spoof":"own.fixture.invalid"}),
        json!({"spoof_method":"wrong-checksum"}),
        json!({"curve_preferences":["X25519"]}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut t = tls(&fixture);
        t.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let config = json!({"type":"vless","server":"127.0.0.1","server_port":fixture["proxyPort"],"uuid":"bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1","tls":t});
        let id = app.add(
            &format!("cross-core-{i}"),
            ProfileKind::SingBoxOutbound,
            config.clone(),
        );
        assert_eq!(
            app.engine
                .check_vless_choice(app.engine.profile(&id).unwrap(), Some(Core::Xray))
                .await
                .unwrap_err(),
            "vless_core_conversion_unsupported"
        );
        app.unchanged(&id, &config);
    }
    app.close().await;
    assert_eq!(
        events(&fixture).len(),
        before,
        "spoof and invalid configuration checks never send traffic"
    );
    report(
        json!({"scenario":"check-only","spoofAccepted":5,"invalidRejected":6,"xrayConversionRefused":7,"coreEmptyArrayAcceptedUnchanged":2,"networkEvents":0,"sourceExact":true}),
    );
}

#[tokio::test]
#[ignore = "real pinned core and owned TLS fixture required"]
async fn full_client_json_stays_opaque_under_enabled_global_presets() {
    let fixture = input("THRONIUM_TLS_FIXTURE");
    let mut app = App::new();
    app.defaults(true, true, true).await;
    let mut t = tls(&fixture);
    t["tls_tricks"] = json!({"mixedcase_sni":false});
    let mut proxy = outbound(&fixture, t);
    proxy["tag"] = json!("owned-proxy");
    let config = json!({"log":{"level":"error"},"dns":{"servers":[{"type":"hosts","tag":"source-dns","predefined":{"unused.fixture.invalid":"127.0.0.9"}}],"final":"source-dns"},"inbounds":[{"type":"mixed","tag":"source-in","listen":"127.0.0.1","listen_port":app.port}],"outbounds":[proxy],"route":{"rules":[{"domain":["never.fixture.invalid"],"action":"reject"}],"final":"owned-proxy"}});
    let id = app.add("full-sb", ProfileKind::SingBoxConfig, config.clone());
    let before = events(&fixture).len();
    app.engine
        .check(&app.engine.profile(&id).unwrap())
        .await
        .unwrap();
    assert_eq!(events(&fixture).len(), before);
    app.unchanged(&id, &config);
    app.engine.connect(&id).await.unwrap();
    get(
        app.port,
        fixture["originPort"].as_u64().unwrap() as u16,
        "full-sb",
    )
    .await;
    app.engine.disconnect().await.unwrap();
    app.unchanged(&id, &config);
    let rows = events(&fixture);
    let hellos: Vec<_> = rows[before..]
        .iter()
        .filter(|v| v["event"] == "client-hello")
        .collect();
    assert_eq!(hellos.len(), 1);
    assert_eq!(hellos[0]["rawSni"], fixture["serverName"]);
    let xray = json!({"dns":{"hosts":{"source.fixture.invalid":"127.0.0.9"},"queryStrategy":"UseIPv4"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"source-direct"},{"protocol":"blackhole","tag":"source-block"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["domain:never.fixture.invalid"],"outboundTag":"source-block"}]}});
    let xid = app.add("full-xray", ProfileKind::XrayConfig, xray.clone());
    app.engine
        .check(&app.engine.profile(&xid).unwrap())
        .await
        .unwrap();
    app.unchanged(&xid, &xray);
    assert_eq!(events(&fixture).len(), rows.len());
    app.close().await;
    report(
        json!({"scenario":"full-json","singboxActualTlsHttp":1,"xrayCheck":1,"dnsRoutingSourceExact":true,"globalMixedSpoofFragmentNotInjected":true}),
    );
}
