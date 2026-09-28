//! Independent public API acceptance; only the dedicated owned-fixture runner.
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    time::{Duration, Instant},
};
use thronium_engine::{
    store::ProfileKind,
    system_proxy::ConnectionMode,
    vpn_auth::{Challenge, ChallengeRequest, SubmitRequest},
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("THRONIUM_AUTH_FIXTURE").expect("explicit owned runner required"),
        )
        .unwrap(),
    )
    .unwrap()
}
fn core() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    assert_eq!(exe.file_name().unwrap(), "Thronium");
    exe.with_file_name("ThroniumCore").canonicalize().unwrap()
}
fn listener(port: u16) -> TcpListener {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .unwrap();
    socket.listen(16).unwrap()
}
struct App {
    engine: Engine,
    directory: tempfile::TempDir,
    port: u16,
}
impl App {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(directory.path(), &core()).unwrap();
        let reservation = listener(0);
        let port = reservation.local_addr().unwrap().port();
        engine
            .connection_settings(ConnectionMode::Local, port)
            .unwrap();
        Self {
            engine,
            directory,
            port,
        }
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
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.directory.path().join("library.json")).unwrap()
    }
    fn privacy(&mut self, id: &str, config: &Value) {
        assert_eq!(self.engine.profile(id).unwrap().config, *config);
        let snapshot = serde_json::to_string(&self.engine.snapshot()).unwrap();
        let backup = self.engine.export_backup().unwrap();
        let library = String::from_utf8(self.bytes()).unwrap();
        let ready = fixture();
        for key in [
            "USER",
            "PASSWORD",
            "ANSWER",
            "FORM_USER",
            "FORM_PASSWORD",
            "FORM_ANSWER",
        ] {
            let secret = ready["answers"][key].as_str().unwrap();
            for output in [&snapshot, &backup, &library] {
                assert!(
                    !output.contains(secret),
                    "transient answer leaked into persistent/snapshot output: {key}"
                );
            }
        }
        for body in [
            "Synthetic VPN <b>plain text</b>",
            "Answer local form",
            "First realm label",
            "submissionKey",
            "formValues",
        ] {
            assert!(
                !snapshot.contains(body),
                "snapshot leaked on-demand challenge body"
            );
            assert!(
                !backup.contains(body),
                "backup persisted on-demand challenge body"
            );
        }
    }
    async fn close(&mut self) {
        self.engine.shutdown().await;
        assert!(self.engine.owned_core_process().is_none());
        assert_eq!(self.engine.snapshot().phase, "disconnected");
        assert!(self.engine.snapshot().vpn.session_id.is_none());
        drop(listener(self.port));
    }
}
fn oc(path: &str) -> Value {
    let ready = fixture();
    json!({"type":"openconnect","server":format!("https://127.0.0.1:{}/form/{path}",ready["openconnectPort"].as_u64().unwrap()),"flavor":"anyconnect","system":false,"no_udp":true,"tls":{"certificate_authority_path":ready["certificate"]}})
}
fn request(engine: &mut Engine, tag: &str) -> ChallengeRequest {
    let status = engine.snapshot().vpn;
    let endpoint = status.endpoints.iter().find(|e| e.tag == tag).unwrap();
    ChallengeRequest {
        session_id: status.session_id.unwrap(),
        endpoint_tag: tag.into(),
        challenge_id: endpoint.challenge_id.clone().unwrap(),
    }
}
async fn wait(
    engine: &mut Engine,
    tag: &str,
    state: &str,
    previous: Option<&str>,
) -> ChallengeRequest {
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        engine.vpn_tick().await;
        let view = engine.snapshot().vpn;
        if let Some(endpoint) = view
            .endpoints
            .iter()
            .find(|e| e.tag == tag && e.state == state)
        {
            if previous.is_none()
                || endpoint
                    .challenge_id
                    .as_deref()
                    .is_some_and(|id| Some(id) != previous)
            {
                return ChallengeRequest {
                    session_id: view.session_id.unwrap(),
                    endpoint_tag: tag.into(),
                    challenge_id: endpoint.challenge_id.clone().unwrap_or_default(),
                };
            }
        }
        assert!(
            Instant::now() < until,
            "endpoint {tag} did not reach {state}; safe view {}",
            serde_json::to_string(&view).unwrap()
        );
        sleep(Duration::from_millis(35)).await;
    }
}
fn response(id: &ChallengeRequest) -> SubmitRequest {
    SubmitRequest {
        session_id: id.session_id.clone(),
        endpoint_tag: id.endpoint_tag.clone(),
        challenge_id: id.challenge_id.clone(),
        username: String::new(),
        password: String::new(),
        secret: String::new(),
        form_values: BTreeMap::new(),
    }
}
fn form_response(id: &ChallengeRequest, details: &Challenge) -> SubmitRequest {
    let mut output = response(id);
    let ready = fixture();
    for field in &details.fields {
        let value = match field.name.as_str() {
            "username" => ready["answers"]["FORM_USER"].as_str().unwrap(),
            "password" => ready["answers"]["FORM_PASSWORD"].as_str().unwrap(),
            "realm" => "two",
            "answer" => ready["answers"]["FORM_ANSWER"].as_str().unwrap(),
            _ => panic!("unexpected fixture field"),
        };
        assert!(output
            .form_values
            .insert(field.submission_key.clone(), value.into())
            .is_none());
    }
    output
}
async fn stale_all(engine: &mut Engine, old: &ChallengeRequest) {
    assert_eq!(
        engine.vpn_challenge(old.clone()).await.err().unwrap(),
        "vpn_auth_stale"
    );
    assert_eq!(
        engine
            .submit_vpn_challenge(response(old))
            .await
            .err()
            .unwrap(),
        "vpn_auth_stale"
    );
    assert_eq!(
        engine
            .cancel_vpn_challenge(old.clone())
            .await
            .err()
            .unwrap(),
        "vpn_auth_stale"
    );
    assert_eq!(
        engine.vpn_challenge_url(old.clone()).await.err().unwrap(),
        "vpn_auth_stale"
    );
}
async fn old_session_current_id(
    engine: &mut Engine,
    old: &ChallengeRequest,
    current: &ChallengeRequest,
) {
    assert_ne!(old.session_id, current.session_id);
    let mut forged = current.clone();
    forged.session_id = old.session_id.clone();
    stale_all(engine, &forged).await;
    let still = request(engine, &current.endpoint_tag);
    assert_eq!(still.session_id, current.session_id);
    assert_eq!(still.challenge_id, current.challenge_id);
}
fn events(path: &str) -> Vec<Value> {
    let ready = fixture();
    std::fs::read_to_string(ready["events"].as_str().unwrap())
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["path"] == format!("/form/{path}"))
        .collect()
}
fn report(name: &str, evidence: Value) {
    println!(
        "VPN_AUTH_PUBLIC_JSON {}",
        json!({"scenario":name,"evidence":evidence})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "dedicated pinned-core owned userspace VPN fixture required"]
async fn ordinary_openvpn_authenticates_to_real_server_without_persisting_answers() {
    let mut app = App::new();
    let ready = fixture();
    let config = json!({"type":"openvpn-client","server":"127.0.0.1","server_port":ready["openvpnPort"],"network":"udp","system":false,"static_challenge":"Synthetic answer","tls":{"certificate_path":ready["certificate"],"server_name":ready["serverName"]}});
    let id = app.add(
        "Actual OpenVPN public",
        ProfileKind::SingBoxOutbound,
        config.clone(),
    );
    app.engine
        .check(&app.engine.profile(&id).unwrap())
        .await
        .unwrap();
    assert!(app.engine.snapshot().vpn.session_id.is_none());
    app.engine.connect(&id).await.unwrap();
    let pending = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    assert_eq!(app.engine.snapshot().phase, "auth-pending");
    let details = app.engine.vpn_challenge(pending.clone()).await.unwrap();
    assert_eq!(details.kind, "credentials");
    assert_eq!(details.message, "Synthetic answer");
    assert!(!details.echo);
    assert_eq!(details.deadline, 0);
    assert_eq!(
        app.engine
            .vpn_challenge_url(pending.clone())
            .await
            .err()
            .unwrap(),
        "vpn_auth_unsupported"
    );
    let bytes = app.bytes();
    let mut submit = response(&pending);
    submit.username = ready["answers"]["USER"].as_str().unwrap().into();
    submit.password = ready["answers"]["PASSWORD"].as_str().unwrap().into();
    submit.secret = ready["answers"]["ANSWER"].as_str().unwrap().into();
    app.engine.submit_vpn_challenge(submit).await.unwrap();
    wait(&mut app.engine, "proxy", "connected", None).await;
    assert_eq!(app.engine.snapshot().phase, "connected");
    app.privacy(&id, &config);
    assert_eq!(app.bytes(), bytes);
    app.engine.disconnect().await.unwrap();
    stale_all(&mut app.engine, &pending).await;
    assert!(app.engine.snapshot().vpn.session_id.is_none());
    app.engine.connect(&id).await.unwrap();
    let next = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    // OpenVPN identifiers are random: use the current real identifier with the
    // old session, without forcing or claiming a random-ID collision.
    old_session_current_id(&mut app.engine, &pending, &next).await;
    app.engine.cancel_vpn_challenge(next).await.unwrap();
    wait(&mut app.engine, "proxy", "error", None).await;
    assert_eq!(app.engine.snapshot().phase, "error");
    app.privacy(&id, &config);
    app.close().await;
    report(
        "openvpn-actual-auth",
        json!({"userspaceServerConnected":true,"tlsCertificateVerified":true,"credentialsAndStaticAnswer":true,"ordinaryPhaseAccurate":true,"noSessionFromCheck":true,"transientAnswersAbsentFromLibraryBackupSnapshot":true,"libraryExactAfterSubmit":true,"staleOperationsRefused":8,"oldSessionWithCurrentRandomIdRefused":true,"randomCollisionForced":false,"openUrlRefused":true,"newOpenvpnCancellationTerminal":true}),
    );
}

struct Held {
    stream: TcpStream,
    task: JoinHandle<()>,
    exchanges: usize,
}
impl Held {
    async fn new(port: u16) -> Self {
        let server = listener(0);
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, peer) = server.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            let mut buffer = [0u8; 256];
            loop {
                let n = stream.read(&mut buffer).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buffer[..n]).await.unwrap();
            }
        });
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut header = vec![];
        timeout(Duration::from_secs(4), async {
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(header.starts_with(b"HTTP/1.1 200"));
        Self {
            stream,
            task,
            exchanges: 0,
        }
    }
    async fn echo(&mut self) {
        let message = format!("held-auth-public-{}", self.exchanges);
        self.stream.write_all(message.as_bytes()).await.unwrap();
        let mut received = vec![0; message.len()];
        timeout(
            Duration::from_secs(3),
            self.stream.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, message.as_bytes());
        self.exchanges += 1;
    }
    async fn close(self) {
        drop(self.stream);
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "dedicated pinned-core owned userspace VPN fixture required"]
async fn two_openconnect_forms_cancel_in_isolation_while_direct_connect_survives() {
    let mut app = App::new();
    let mut alpha = oc("public-alpha");
    alpha["tag"] = json!("alpha");
    let mut beta = oc("public-beta");
    beta["tag"] = json!("beta");
    let config = json!({"log":{"disabled":true},"endpoints":[alpha,beta],"inbounds":[{"type":"mixed","tag":"owned-in","listen":"127.0.0.1","listen_port":app.port}],"outbounds":[{"type":"direct","tag":"control","udp_fragment":true}],"route":{"final":"control"}});
    let id = app.add(
        "Two independent OC forms",
        ProfileKind::SingBoxConfig,
        config.clone(),
    );
    app.engine
        .check(&app.engine.profile(&id).unwrap())
        .await
        .unwrap();
    app.engine.connect(&id).await.unwrap();
    let first = wait(&mut app.engine, "alpha", "auth-pending", None).await;
    let second = wait(&mut app.engine, "beta", "auth-pending", None).await;
    assert_eq!(app.engine.snapshot().phase, "connected");
    let owner = app.engine.owned_core_process().unwrap();
    let mut held = Held::new(app.port).await;
    held.echo().await;
    let bytes = app.bytes();
    let details = app.engine.vpn_challenge(first.clone()).await.unwrap();
    assert_eq!(details.kind, "form");
    assert_eq!(details.banner, "Synthetic VPN <b>plain text</b>");
    assert_eq!(
        details
            .fields
            .iter()
            .map(|field| field.kind.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["password", "select", "text"].into_iter().collect()
    );
    let realm = details
        .fields
        .iter()
        .find(|field| field.name == "realm")
        .unwrap();
    assert!(realm
        .options
        .iter()
        .any(|choice| choice.value == "two" && choice.label == "Second realm label"));
    assert_eq!(
        app.engine
            .vpn_challenge_url(first.clone())
            .await
            .err()
            .unwrap(),
        "vpn_auth_unsupported"
    );
    for mode in ["missing", "extra", "display-label"] {
        let mut invalid = form_response(&first, &details);
        match mode {
            "missing" => {
                invalid.form_values.remove(&realm.submission_key);
            }
            "extra" => {
                invalid
                    .form_values
                    .insert("extra-injected".into(), "value".into());
            }
            _ => {
                invalid
                    .form_values
                    .insert(realm.submission_key.clone(), "Second realm label".into());
            }
        }
        assert_eq!(
            app.engine
                .submit_vpn_challenge(invalid)
                .await
                .err()
                .unwrap(),
            "vpn_auth_invalid_response"
        );
        assert_eq!(
            request(&mut app.engine, "alpha").challenge_id,
            first.challenge_id
        );
        assert_eq!(events("public-alpha").len(), 1);
    }
    let mut cross = first.clone();
    cross.endpoint_tag = "beta".into();
    stale_all(&mut app.engine, &cross).await;
    held.echo().await;
    app.engine
        .submit_vpn_challenge(form_response(&first, &details))
        .await
        .unwrap();
    let otp = wait(
        &mut app.engine,
        "alpha",
        "auth-pending",
        Some(&first.challenge_id),
    )
    .await;
    assert!(events("public-alpha")
        .iter()
        .any(|row| row["formExact"] == true));
    stale_all(&mut app.engine, &first).await;
    let otp_details = app.engine.vpn_challenge(otp.clone()).await.unwrap();
    assert_eq!(otp_details.fields.len(), 1);
    assert_eq!(otp_details.fields[0].name, "answer");
    assert_eq!(otp_details.fields[0].kind, "password");
    app.engine
        .submit_vpn_challenge(form_response(&otp, &otp_details))
        .await
        .unwrap();
    let third = wait(
        &mut app.engine,
        "alpha",
        "auth-pending",
        Some(&otp.challenge_id),
    )
    .await;
    assert!(events("public-alpha")
        .iter()
        .any(|row| row["otpExact"] == true));
    held.echo().await;
    app.engine
        .cancel_vpn_challenge(third.clone())
        .await
        .unwrap();
    wait(&mut app.engine, "alpha", "error", None).await;
    let count = events("public-alpha").len();
    let until = Instant::now() + Duration::from_millis(2200);
    let mut polls = 0;
    while Instant::now() < until {
        app.engine.vpn_tick().await;
        let view = app.engine.snapshot();
        assert_eq!(view.phase, "connected");
        let endpoint = view
            .vpn
            .endpoints
            .iter()
            .find(|e| e.tag == "alpha")
            .unwrap();
        assert_eq!(endpoint.state, "error");
        assert!(!endpoint.auth_failed);
        assert!(endpoint.challenge_id.is_none());
        assert_eq!(
            request(&mut app.engine, "beta").challenge_id,
            second.challenge_id
        );
        assert_eq!(events("public-alpha").len(), count);
        polls += 1;
        sleep(Duration::from_millis(70)).await;
    }
    stale_all(&mut app.engine, &third).await;
    held.echo().await;
    let beta_details = app.engine.vpn_challenge(second.clone()).await.unwrap();
    app.engine
        .submit_vpn_challenge(form_response(&second, &beta_details))
        .await
        .unwrap();
    let beta_otp = wait(
        &mut app.engine,
        "beta",
        "auth-pending",
        Some(&second.challenge_id),
    )
    .await;
    assert!(events("public-beta")
        .iter()
        .any(|row| row["formExact"] == true));
    app.engine.cancel_vpn_challenge(beta_otp).await.unwrap();
    wait(&mut app.engine, "beta", "error", None).await;
    held.echo().await;
    assert_eq!(app.engine.owned_core_process(), Some(owner));
    app.privacy(&id, &config);
    assert_eq!(app.bytes(), bytes);
    let exchanges = held.exchanges;
    held.close().await;
    app.close().await;
    assert_eq!(events("public-alpha").len(), 3);
    assert_eq!(events("public-beta").len(), 2);
    report(
        "openconnect-form-otp-cancel-isolation",
        json!({"actualTlsFormRequests":5,"formValuesExact":true,"otpValueExact":true,"invalidFormsRefused":3,"staleAndCrossEndpointOperationsRefused":12,"cancelQuietMs":2200,"cancelStatusPolls":polls,"cancelAuthFailed":false,"heldConnectExchanges":exchanges,"sameCoreInstance":true,"fullJsonExact":true,"snapshotBackupPrivacy":true}),
    );
}

fn kill_own(engine: &Engine) {
    let owner = engine.owned_core_process().unwrap();
    assert_ne!(
        u64::from(owner.pid),
        fixture()["serverCorePid"].as_u64().unwrap()
    );
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, owner.pid, 0) };
    assert!(fd >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", owner.pid)).unwrap();
    let end = stat.rfind(')').unwrap();
    let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
    assert_eq!(fields[1].parse::<u32>().unwrap(), std::process::id());
    assert_eq!(Some(fields[19].parse::<u64>().unwrap()), owner.start_time);
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/exe", owner.pid)).unwrap(),
        core()
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "dedicated pinned-core owned userspace VPN fixture required"]
async fn session_guards_survive_manual_restart_failed_start_rollback_and_actual_recovery() {
    let mut app = App::new();
    let config = oc("public-generations");
    let id = app.add(
        "Actual OC session generations",
        ProfileKind::SingBoxOutbound,
        config.clone(),
    );
    app.engine.connect(&id).await.unwrap();
    let initial = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    assert_eq!(
        initial.challenge_id, "1",
        "single first OC in a fresh real core"
    );
    let owner1 = app.engine.owned_core_process().unwrap();
    app.engine.disconnect().await.unwrap();
    stale_all(&mut app.engine, &initial).await;
    app.engine.connect(&id).await.unwrap();
    let manual = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    assert_eq!(app.engine.owned_core_process(), Some(owner1));
    assert_ne!(manual.challenge_id, initial.challenge_id);
    old_session_current_id(&mut app.engine, &initial, &manual).await;
    let foreign = listener(0);
    let foreign_port = foreign.local_addr().unwrap().port();
    let bad=app.add("Owned foreign busy port candidate",ProfileKind::SingBoxConfig,json!({"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":foreign_port}],"outbounds":[{"type":"direct","tag":"control"}],"route":{"final":"control"}}));
    app.engine
        .check(&app.engine.profile(&bad).unwrap())
        .await
        .unwrap();
    let error = app
        .engine
        .connect(&bad)
        .await
        .expect_err("real Start must fail at the occupied listener");
    assert!(!error.is_empty());
    assert_eq!(app.engine.snapshot().running.as_deref(), Some(id.as_str()));
    let restored = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    assert_eq!(
        restored.challenge_id, initial.challenge_id,
        "rollback has a fresh OC counter"
    );
    let owner2 = app.engine.owned_core_process().unwrap();
    assert_ne!(owner1, owner2);
    old_session_current_id(&mut app.engine, &manual, &restored).await;
    stale_all(&mut app.engine, &initial).await;
    assert_eq!(foreign.local_addr().unwrap().port(), foreign_port);
    drop(foreign);
    let bytes = app.bytes();
    kill_own(&app.engine);
    let deadline = Instant::now() + Duration::from_secs(4);
    while app.engine.owned_core_process().is_some() {
        app.engine.snapshot();
        assert!(Instant::now() < deadline);
        sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(app.engine.snapshot().phase, "reconnecting");
    assert!(app.engine.snapshot().vpn.session_id.is_none());
    stale_all(&mut app.engine, &restored).await;
    sleep(Duration::from_millis(330)).await;
    app.engine.vpn_tick().await;
    app.engine.snapshot();
    assert!(
        app.engine.owned_core_process().is_none(),
        "VPN metadata must not launch recovery"
    );
    app.engine.recovery_tick().await;
    let recovered = wait(&mut app.engine, "proxy", "auth-pending", None).await;
    assert_eq!(
        recovered.challenge_id, initial.challenge_id,
        "new process reproduces actual literal OC ID"
    );
    let owner3 = app.engine.owned_core_process().unwrap();
    assert_ne!(owner2, owner3);
    old_session_current_id(&mut app.engine, &restored, &recovered).await;
    stale_all(&mut app.engine, &initial).await;
    app.privacy(&id, &config);
    assert_eq!(app.bytes(), bytes);
    app.engine
        .cancel_vpn_challenge(recovered.clone())
        .await
        .unwrap();
    wait(&mut app.engine, "proxy", "error", None).await;
    app.engine.disconnect().await.unwrap();
    stale_all(&mut app.engine, &recovered).await;
    let count = events("public-generations").len();
    for _ in 0..4 {
        sleep(Duration::from_millis(100)).await;
        app.engine.recovery_tick().await;
        app.engine.vpn_tick().await;
        assert_eq!(app.engine.snapshot().phase, "disconnected");
        assert!(app.engine.snapshot().vpn.session_id.is_none());
    }
    assert_eq!(events("public-generations").len(), count);
    assert_eq!(count, 4);
    app.close().await;
    report(
        "session-restart-rollback-owned-recovery",
        json!({"actualStarts":4,"actualCoreInstances":3,"sessionIdsChangedOnEveryStart":true,"actualRepeatedOpenconnectId":"1","oldSessionCurrentIdRefused":12,"literalOldIdOperationsRefused":8,"staleAfterDisconnectAndDeathRefused":12,"failedCandidateCheckSucceeded":true,"actualFailedStartRestoredPrevious":true,"foreignListenerPreserved":true,"ownedCrashPidStarttimePidfdVerified":true,"metadataNeverSpawns":true,"sourceAndLibraryExact":true,"cancelDisconnectNoDelayedRestart":true}),
    );
}
