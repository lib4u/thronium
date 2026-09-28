//! Before-Start OTP: placement rules, durable HOTP reservation between
//! CheckConfig and Start, no code in views, and no replay of a spent request.
use super::*;
#[cfg(target_os = "linux")]
use crate::transport::Rpc;
use crate::{store::ProfileKind, vpn_otp_bindings::SaveRequest, ProfileDraft};
use base64::{engine::general_purpose::STANDARD, Engine as _};
#[cfg(target_os = "linux")]
use prost::Message;
use serde_json::json;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn openvpn(password: &str, extra: Value) -> Value {
    let mut config = json!({"type":"openvpn-client","server":"127.0.0.1","server_port":31194,"network":"udp","system":false,"username":"fixture-user","password":password});
    if let Some(object) = extra.as_object() {
        config.as_object_mut().unwrap().extend(object.clone());
    }
    config
}
fn engine() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), &dir.path().join("never-spawn")).unwrap();
    (dir, e)
}
fn profile(e: &mut Engine, config: Value) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Synthetic OpenVPN".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config,
    })
    .unwrap()
}
fn otp(e: &mut Engine, kind: Kind) -> (String, String) {
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
fn bind(e: &mut Engine, profile: &str, otp: &(String, String), mode: Mode) -> Result<(), String> {
    let view = e.get_vpn_otp_binding(profile).unwrap();
    e.save_vpn_otp_binding(SaveRequest {
        profile_id: profile.into(),
        edit_token: view.edit_token,
        otp_id: Some(otp.0.clone()),
        otp_revision: Some(otp.1.clone()),
        mode: Some(mode),
    })
    .map(|_| ())
}
fn expected_code(e: &Engine, otp_id: &str, counter: &str) -> String {
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
    value.code_at(now() as u64).unwrap().code
}
fn endpoint(request: &proto::LoadConfigReq) -> Value {
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    core["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|endpoint| endpoint["tag"] == "proxy")
        .unwrap()
        .clone()
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

#[test]
fn placement_follows_qt_credentials_static_challenge_and_retry_rules() {
    let (_dir, mut e) = engine();
    for (config, live, start) in [
        (
            openvpn("{otp}", json!({})),
            Some("vpn_otp_start_mode_required"),
            None,
        ),
        (
            openvpn("pass-{otp}", json!({"static_challenge":"Owned"})),
            Some("vpn_otp_start_mode_required"),
            None,
        ),
        (
            openvpn("fixed", json!({})),
            None,
            Some("vpn_otp_start_unsupported"),
        ),
        (
            openvpn("fixed", json!({"static_challenge":"Owned"})),
            None,
            Some("vpn_otp_start_unsupported"),
        ),
        (
            openvpn("{otp}", json!({"auth_retry":"interact"})),
            Some("vpn_otp_start_retry_unsupported"),
            Some("vpn_otp_start_retry_unsupported"),
        ),
        (
            openvpn("{otp}", json!({"auth_retry":"none"})),
            Some("vpn_otp_start_mode_required"),
            None,
        ),
        (
            json!({"type":"openconnect","server":"https://vpn.fixture.invalid","username":"u","password":"{otp}"}),
            Some("vpn_otp_start_placeholder_unsupported"),
            Some("vpn_otp_start_placeholder_unsupported"),
        ),
    ] {
        let id = profile(&mut e, config.clone());
        let view = e.get_vpn_otp_binding(&id).unwrap();
        assert_eq!(view.reason.as_deref(), live, "{config}");
        assert_eq!(view.supported, live.is_none());
        assert_eq!(view.start_reason.as_deref(), start, "{config}");
        assert_eq!(view.start_supported, start.is_none());
    }
}

#[test]
fn bake_substitutes_packs_scrv1_and_pins_auth_retry_none() {
    let mut credentials = openvpn("pre-{otp}-post", json!({"username":"{otp}@example"}));
    planner::bake(&mut credentials, "123456", planner::Placement::Credentials).unwrap();
    assert_eq!(credentials["username"], "123456@example");
    assert_eq!(credentials["password"], "pre-123456-post");
    assert_eq!(credentials["auth_retry"], "none");
    assert_eq!(credentials["single_use_auth"], true);
    let mut packed = openvpn(
        "pass-{otp}",
        json!({"static_challenge":"Owned","static_challenge_echo":true}),
    );
    planner::bake(&mut packed, "654321", planner::Placement::StaticChallenge).unwrap();
    assert_eq!(
        packed["password"],
        format!(
            "SCRV1:{}:{}",
            STANDARD.encode("pass-654321"),
            STANDARD.encode("654321")
        )
    );
    assert!(
        packed.get("static_challenge").is_none() && packed.get("static_challenge_echo").is_none()
    );
    assert_eq!(packed["auth_retry"], "none");
    let mut explicit = openvpn("{otp}", json!({"auth_retry":"none"}));
    planner::bake(&mut explicit, "1", planner::Placement::Credentials).unwrap();
    assert_eq!(explicit["auth_retry"], "none");
    let mut interact = openvpn("{otp}", json!({"auth_retry":"interact"}));
    assert_eq!(
        planner::bake(&mut interact, "1", planner::Placement::Credentials).unwrap_err(),
        "vpn_otp_start_retry_unsupported"
    );
    let mut untouched = openvpn("{otp}", json!({}));
    assert_eq!(
        planner::bake(&mut untouched, "", planner::Placement::Credentials).unwrap_err(),
        "vpn_otp_manual_required"
    );
    assert_eq!(untouched["password"], "{otp}");
    planner::bake(&mut untouched, "1", planner::Placement::None).unwrap();
    assert_eq!(untouched["password"], "{otp}");
}

#[test]
fn saving_a_start_binding_needs_a_placeholder_and_raises_the_library_to_v4() {
    let (dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let fixed = profile(&mut e, openvpn("fixed", json!({})));
    assert_eq!(
        bind(&mut e, &fixed, &hotp, Mode::AutoStart).unwrap_err(),
        "vpn_otp_start_unsupported"
    );
    let templated = profile(&mut e, openvpn("{otp}", json!({})));
    assert_eq!(
        bind(&mut e, &templated, &hotp, Mode::AutoLive).unwrap_err(),
        "vpn_otp_start_mode_required"
    );
    assert_eq!(e.store.library.version, 2, "OTP entries alone need v2");
    bind(&mut e, &templated, &hotp, Mode::AutoStart).unwrap();
    assert_eq!(e.store.library.version, 4);
    assert_eq!(
        e.store.library.vpn_otp_bindings[&templated].mode,
        Mode::AutoStart
    );
    let stored: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("library.json")).unwrap()).unwrap();
    assert_eq!(stored["vpnOtpBindings"][&templated]["mode"], "auto-start");
    assert_eq!(stored["version"], 4);
    let mut downgraded = e.store.library.clone();
    downgraded.version = 3;
    assert_eq!(
        crate::store::validate_library(&downgraded).unwrap_err(),
        "library_version_unsupported"
    );
}

#[test]
fn check_intent_never_reserves_and_start_intent_reserves_c_plus_one_before_baking() {
    let (dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let selected = e.profile(&id).unwrap();
    let checked = Engine::build_with_library(&selected, &e.store.library, dir.path()).unwrap();
    assert_eq!(endpoint(&checked)["password"], "{otp}");
    assert_eq!(endpoint(&checked)["single_use_auth"], true);
    assert!(endpoint(&checked).get("auth_retry").is_none());
    assert_eq!(counter(&e, &hotp.0), "0");
    let (mut request, bindings) =
        Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Start)
            .unwrap();
    assert_eq!(
        endpoint(&request)["password"],
        "{otp}",
        "prepare does not mint"
    );
    assert_eq!(bindings["proxy"].mode, Mode::AutoStart);
    let expected = expected_code(&e, &hotp.0, "1");
    let marks = e.commit_start_codes(&mut request, &bindings).unwrap();
    assert_eq!(counter(&e, &hotp.0), "1");
    let stored: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("library.json")).unwrap()).unwrap();
    assert_eq!(stored["otp"][0]["counter"], "1", "durable before Start");
    assert_eq!(endpoint(&request)["password"], expected);
    assert_eq!(endpoint(&request)["auth_retry"], "none");
    assert_eq!(
        marks["proxy"],
        StartMark {
            otp_id: hotp.0.clone(),
            counter: Some("1".into())
        }
    );
    assert!(!json!(marks).to_string().contains(&expected));
    // A TOTP binding bakes without writing the library.
    let totp = otp(&mut e, Kind::Totp);
    let timed = profile(
        &mut e,
        openvpn("pass-{otp}", json!({"static_challenge":"Owned"})),
    );
    bind(&mut e, &timed, &totp, Mode::AutoStart).unwrap();
    let before = std::fs::read(dir.path().join("library.json")).unwrap();
    let timed_profile = e.profile(&timed).unwrap();
    let (mut request, bindings) =
        Engine::build_with_vpn_sources(&timed_profile, &e.store.library, dir.path(), Intent::Start)
            .unwrap();
    let marks = e.commit_start_codes(&mut request, &bindings).unwrap();
    assert_eq!(marks["proxy"].counter, None);
    assert_eq!(
        std::fs::read(dir.path().join("library.json")).unwrap(),
        before
    );
    let packed = endpoint(&request);
    assert!(packed["password"].as_str().unwrap().starts_with("SCRV1:"));
    assert!(packed.get("static_challenge").is_none());
}

#[test]
fn start_bindings_allow_connection_modes_but_require_explicit_primary_connects() {
    let (dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let selected = e.profile(&id).unwrap();
    assert_eq!(
        Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Background)
            .map(|_| ())
            .unwrap_err(),
        "vpn_otp_start_background_unsupported"
    );
    for mode in [
        crate::system_proxy::ConnectionMode::Tun,
        crate::system_proxy::ConnectionMode::SystemProxy,
    ] {
        let mut library = e.store.library.clone();
        library.preferences.connection_mode = mode;
        let (request, bindings) =
            Engine::build_with_vpn_sources(&selected, &library, dir.path(), Intent::Start).unwrap();
        assert_eq!(endpoint(&request)["password"], "{otp}");
        assert_eq!(bindings["proxy"].mode, Mode::AutoStart);
    }
    // A selected profile that carries the bound one — a hop of its chain or an
    // endpoint one of its routes uses — spends its code on an explicit Connect,
    // because that node needs it to come up at all.
    let other = profile(&mut e, openvpn("fixed", json!({})));
    let mut compiled = e.store.library.clone();
    let mut chosen = e.profile(&other).unwrap();
    let needed: HashSet<String> = [id.clone(), other.clone()].into_iter().collect();
    let prepared = Build::prepare(
        &mut compiled,
        &mut chosen,
        &needed,
        &e.store.library,
        Intent::Start,
    )
    .unwrap();
    assert!(prepared.candidates.contains_key(&id));
    // A background rebuild still never spends one.
    let mut compiled = e.store.library.clone();
    let mut chosen = e.profile(&other).unwrap();
    assert_eq!(
        Build::prepare(
            &mut compiled,
            &mut chosen,
            &needed,
            &e.store.library,
            Intent::Background
        )
        .map(|_| ())
        .unwrap_err(),
        "vpn_otp_start_background_unsupported"
    );
    // Preparing is not spending: the counter moves only when Start commits.
    assert_eq!(counter(&e, &hotp.0), "0");
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Core {
    fail_start: bool,
    starts: Vec<Value>,
    tun_recovery: Vec<bool>,
}
#[cfg(target_os = "linux")]
fn scripted(core: Arc<Mutex<Core>>) -> Rpc {
    scripted_mode(core, false)
}
#[cfg(target_os = "linux")]
fn scripted_mode(core: Arc<Mutex<Core>>, managed: bool) -> Rpc {
    let handler = move |method: &str, payload: &[u8]| {
        let mut core = core.lock().unwrap();
        let mut reply = proto::ErrorResp::default();
        if method == "Start" {
            let request = proto::LoadConfigReq::decode(payload).unwrap();
            core.starts.push(endpoint(&request));
            if core.fail_start {
                reply.error = Some("synthetic start failure".into());
            }
        }
        if method == "ManagedTunReady" {
            let options = proto::ManagedTunOptions::decode(payload).unwrap();
            core.tun_recovery.push(options.auto_reconnect.unwrap());
        }
        reply.encode_to_vec()
    };
    if managed {
        Rpc::scripted_vpn_test_rpc(handler)
    } else {
        Rpc::scripted_local_test_rpc(handler)
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn start_spends_one_code_hides_it_from_the_active_view_and_never_replays_the_request() {
    let (dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let core = Arc::new(Mutex::new(Core::default()));
    e.rpc = Some(scripted(core.clone()));
    let first = expected_code(&e, &hotp.0, "1");
    e.connect(&id).await.unwrap();
    assert_eq!(counter(&e, &hotp.0), "1");
    assert_eq!(core.lock().unwrap().starts.len(), 1);
    assert_eq!(core.lock().unwrap().starts[0]["password"], first);
    assert_eq!(core.lock().unwrap().starts[0]["auth_retry"], "none");
    let active = e.active_connection.as_ref().unwrap();
    assert_eq!(active.vpn_otp_start["proxy"].counter.as_deref(), Some("1"));
    let view = e.connection_configuration(&id, true).await.unwrap();
    let text = view.to_string();
    assert!(
        !text.contains(&first) && text.contains("{otp}"),
        "active view is redacted"
    );
    assert!(!std::fs::read_to_string(dir.path().join("library.json"))
        .unwrap()
        .contains(&first));
    // The next explicit Connect mints C2; when its Start fails, the previous
    // request with C1 is not replayed and the counter stays spent.
    core.lock().unwrap().fail_start = true;
    let second = expected_code(&e, &hotp.0, "2");
    assert_eq!(e.connect(&id).await.unwrap_err(), "vpn_otp_start_stale");
    assert_eq!(counter(&e, &hotp.0), "2");
    let starts = core.lock().unwrap().starts.clone();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[1]["password"], second);
    assert!(e.active_connection.is_none() && e.running.is_none());
    assert_eq!(e.error.as_deref(), Some("vpn_otp_start_stale"));
    // Without a previous baked request, a failed Start reports its own error.
    // The aborted attempt reaped the scripted core, so attach a fresh one.
    e.rpc = Some(scripted(core.clone()));
    assert_eq!(e.connect(&id).await.unwrap_err(), "synthetic start failure");
    assert_eq!(counter(&e, &hotp.0), "3");
    assert_eq!(core.lock().unwrap().starts.len(), 3);
    let logs = e.logs.view(crate::logs::Filter::default()).unwrap();
    assert!(logs
        .entries
        .iter()
        .all(|line| !line.text.contains(&first) && !line.text.contains(&second)));
}

/// The selection commit after a successful Start can fail only in the directory
/// sync, when the new selection is already in memory and on disk. That must not
/// tear the working session down and restore the previous one.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_unconfirmed_sync_after_start_keeps_the_new_session() {
    let (_dir, mut e) = engine();
    let id = profile(&mut e, openvpn("fixed", json!({})));
    let core = Arc::new(Mutex::new(Core::default()));
    e.rpc = Some(scripted(core.clone()));
    e.store
        .fail_next_commit(crate::store::CommitFault::DirectorySync);
    e.connect(&id).await.expect("the running session is kept");
    assert_eq!(e.running.as_deref(), Some(id.as_str()));
    assert_eq!(e.store.library.selected.as_deref(), Some(id.as_str()));
    assert!(e.store.durability_uncertain());
    assert_eq!(
        core.lock().unwrap().starts.len(),
        1,
        "no restart or rollback"
    );
    assert!(e
        .logs
        .view(crate::logs::Filter::default())
        .unwrap()
        .entries
        .iter()
        .any(|line| line.text == crate::store::Store::WRITTEN_UNCERTAIN));
}

/// Accepted TOTP digits stay spent for their whole step: a Start retry, a new VPN
/// session and a manual test in that step must not send them again.
#[test]
fn a_totp_step_is_spent_once_across_start_retries_sessions_and_tests() {
    let (dir, mut e) = engine();
    // An hour-long step keeps the test from crossing a boundary between calls.
    let meta = e
        .otp_save(
            "",
            "",
            crate::otp::Draft {
                secret: SECRET.into(),
                kind: Kind::Totp,
                period: 3600,
                ..Default::default()
            },
        )
        .unwrap();
    let totp = (
        meta["id"].as_str().unwrap().to_owned(),
        meta["revision"].as_str().unwrap().to_owned(),
    );
    let id = profile(&mut e, openvpn("pass-{otp}", json!({})));
    bind(&mut e, &id, &totp, Mode::AutoStart).unwrap();
    let selected = e.profile(&id).unwrap();
    let start = |e: &mut Engine| {
        let (mut request, bindings) =
            Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Start)
                .unwrap();
        e.commit_start_codes(&mut request, &bindings)
    };
    start(&mut e).expect("the first Start spends the current step");
    assert_eq!(start(&mut e).unwrap_err(), "vpn_otp_code_spent");
    e.vpn = crate::vpn_auth::Session::default();
    assert_eq!(
        start(&mut e).unwrap_err(),
        "vpn_otp_code_spent",
        "a new VPN session keeps the spent step"
    );
    let entry = e
        .store
        .library
        .otp
        .iter()
        .find(|o| o.id == totp.0)
        .unwrap()
        .clone();
    let at = u64::try_from(now()).unwrap();
    assert_eq!(
        e.reserve_vpn_totp(&entry, at).unwrap_err(),
        "vpn_otp_code_spent",
        "a manual test in the same step is refused by the same owner"
    );
    let next_step = (at / 3600 + 1) * 3600;
    assert!(!e.totp_step_spent(&entry, next_step));
    e.reserve_vpn_totp(&entry, next_step)
        .expect("the next step brings a new code");
}

#[test]
fn recovery_does_not_restart_a_connection_that_carried_a_code() {
    let (dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let selected = e.profile(&id).unwrap();
    let (mut request, bindings) =
        Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Start)
            .unwrap();
    let marks = e.commit_start_codes(&mut request, &bindings).unwrap();
    let previous = crate::connection::ActiveConnection {
        id: id.clone(),
        profiles: HashSet::new(),
        groups: HashSet::new(),
        request,
        routing_revision: 0,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: true,
        vpn_otp: bindings,
        vpn_otp_start: marks,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(e.recover_connection(Some(previous), "start_failed".into()));
    assert_eq!(result, "vpn_otp_start_stale");
    assert_eq!(e.error.as_deref(), Some("vpn_otp_start_stale"));
    assert!(e.active_connection.is_none());
    assert_eq!(
        counter(&e, &hotp.0),
        "1",
        "the spent step is never rolled back"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn managed_tun_start_otp_disables_core_recovery_only_for_the_spent_session() {
    use crate::system_proxy::ConnectionMode;
    let (_dir, mut e) = engine();
    e.store.library.preferences.connection_mode = ConnectionMode::Tun;
    e.store
        .library
        .settings
        .insert("vpn_tun_ipv4_cidr".into(), json!("10.239.204.1/30"));
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let core = Arc::new(Mutex::new(Core::default()));
    e.rpc = Some(scripted_mode(core.clone(), true));
    e.connect(&id).await.unwrap();
    assert!(e.active_connection.as_ref().unwrap().tun);
    assert_eq!(counter(&e, &hotp.0), "1");
    assert_eq!(core.lock().unwrap().tun_recovery, [false, false]);
    assert!(e.store.library.preferences.tun.auto_reconnect);
    // A different explicit Connect must replace the previous session policy.
    let plain = profile(&mut e, openvpn("fixed", json!({})));
    e.connect(&plain).await.unwrap();
    assert_eq!(core.lock().unwrap().tun_recovery, [false, false, true]);
    assert_eq!(core.lock().unwrap().starts.len(), 2);
    assert_eq!(counter(&e, &hotp.0), "1");
    e.disconnect().await.unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn system_proxy_start_otp_reserves_once_and_restores_private_proxy_settings() {
    // Spawn a separate test process before GLib initialization. Never change
    // process-wide environment in a parallel test or touch desktop settings.
    const ISOLATED: &str = "_THRONIUM_OTP_START_PROXY_TEST";
    if std::env::var_os(ISOLATED).is_none() {
        let directory = tempfile::Builder::new()
            .prefix("thronium-start-otp-proxy-")
            .tempdir()
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "vpn_auth::otp::start_tests::system_proxy_start_otp_reserves_once_and_restores_private_proxy_settings", "--nocapture"])
            .env(ISOLATED, directory.path())
            .env("XDG_CONFIG_HOME", directory.path())
            .env("XDG_CURRENT_DESKTOP", "GNOME")
            .env("GSETTINGS_BACKEND", "keyfile")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let directory = std::env::var_os(ISOLATED).unwrap();
    assert_eq!(std::env::var_os("XDG_CONFIG_HOME").unwrap(), directory);
    assert!(std::path::Path::new(&directory)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("thronium-start-otp-proxy-"));
    assert_eq!(std::env::var("GSETTINGS_BACKEND").unwrap(), "keyfile");
    use gio::prelude::*;
    let proxy = gio::Settings::new("org.gnome.system.proxy");
    proxy.set_string("mode", "none").unwrap();
    gio::Settings::sync();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (_dir, mut e) = engine();
        e.initialize_system_proxy();
        e.store.library.preferences.connection_mode =
            crate::system_proxy::ConnectionMode::SystemProxy;
        let hotp = otp(&mut e, Kind::Hotp);
        let id = profile(&mut e, openvpn("{otp}", json!({})));
        bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
        let core = Arc::new(Mutex::new(Core::default()));
        e.rpc = Some(scripted(core.clone()));
        e.connect(&id).await.unwrap();
        assert_eq!(counter(&e, &hotp.0), "1");
        assert_eq!(proxy.string("mode"), "manual");
        assert!(e.active_connection.as_ref().unwrap().system_port.is_some());
        core.lock().unwrap().fail_start = true;
        assert_eq!(e.connect(&id).await.unwrap_err(), "vpn_otp_start_stale");
        assert_eq!(counter(&e, &hotp.0), "2");
        assert_eq!(core.lock().unwrap().starts.len(), 2);
        assert_eq!(proxy.string("mode"), "none");
        assert!(!std::path::Path::new(&directory)
            .join("thronium-system-proxy/recovery.json")
            .exists());
    });
}

/// A bound endpoint keeps its live automation when it is a chain hop or a
/// group proxy: the compiler announces it under the tag it actually emits,
/// also when the wrapper compiles it as a renamed copy.
#[test]
fn live_bindings_follow_vpn_hops_into_chains_and_group_wrappers() {
    let (dir, mut e) = engine();
    let vpn = profile(&mut e, openvpn("fixture-password", json!({})));
    let totp = otp(&mut e, Kind::Totp);
    bind(&mut e, &vpn, &totp, Mode::AutoLive).unwrap();
    let socks = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Socks".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"socks","server":"127.0.0.1","server_port":1080}),
        })
        .unwrap();
    let chain = |name: &str, hops: Value| ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::Chain,
        config: json!({"type":"chain","hops":hops}),
    };
    let exit = e.save_profile(chain("Exit", json!([socks, vpn]))).unwrap();
    let entry = e.save_profile(chain("Entry", json!([vpn, socks]))).unwrap();
    for (id, tag) in [(&exit, "proxy"), (&entry, "thronium-chain-proxy-0")] {
        let selected = e.profile(id).unwrap();
        let (request, bindings) =
            Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Start)
                .unwrap();
        assert_eq!(bindings.keys().collect::<Vec<_>>(), [tag]);
        assert_eq!(bindings[tag].mode, Mode::AutoLive);
        let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
        let hop = core["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["tag"] == tag)
            .unwrap();
        assert_eq!(hop["type"], "openvpn-client");
    }
    // Group front proxy: the VPN is compiled as a renamed copy and stays the exit.
    e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
        front: Some(socks.clone()),
        landing: None,
    };
    e.store.commit(e.store.library.clone()).unwrap();
    let selected = e.profile(&vpn).unwrap();
    let (_, bindings) =
        Engine::build_with_vpn_sources(&selected, &e.store.library, dir.path(), Intent::Start)
            .unwrap();
    assert_eq!(bindings.keys().collect::<Vec<_>>(), ["proxy"]);
}

/// A disposable test has no challenge channel: `Intent::Probe` keeps live
/// templates in place and the planner bakes them like Qt's test build.
#[test]
fn probe_intent_bakes_live_templates_and_packs_a_static_challenge() {
    let (_dir, mut e) = engine();
    let live = profile(
        &mut e,
        openvpn("fixture-password", json!({"static_challenge":"Enter code"})),
    );
    let totp = otp(&mut e, Kind::Totp);
    bind(&mut e, &live, &totp, Mode::AutoLive).unwrap();
    let selected = e.profile(&live).unwrap();
    let mut library = e.store.library.clone();
    let mut chosen = selected.clone();
    let needed: HashSet<String> = [live.clone()].into_iter().collect();
    let mut build = Build::prepare(
        &mut library,
        &mut chosen,
        &needed,
        &e.store.library,
        Intent::Probe,
    )
    .unwrap();
    assert_eq!(
        chosen.config["static_challenge"], "Enter code",
        "probe intent withholds nothing"
    );
    let frozen = build.take(&live).unwrap();
    let mut baked = chosen.config.clone();
    assert!(planner::bake_probe(&mut baked, "123456", &frozen.source).unwrap());
    assert!(baked["password"].as_str().unwrap().starts_with("SCRV1:"));
    assert!(baked.get("static_challenge").is_none());
    assert_eq!(baked["single_use_auth"], true);
    // A live-only profile without any template needs no code and spends none.
    let plain = profile(&mut e, openvpn("fixture-password", json!({})));
    let mut untouched = e.profile(&plain).unwrap().config;
    let source = planner::Source::from_profile(&e.profile(&plain).unwrap()).unwrap();
    assert!(!planner::bake_probe(&mut untouched, "123456", &source).unwrap());
    assert_eq!(untouched, e.profile(&plain).unwrap().config);
    // OpenConnect: credentials, token and live form entries are substituted.
    let oc = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "OpenConnect".into(),
            group_id: "personal".into(),
            kind: ProfileKind::SingBoxOutbound,
            config: json!({"type":"openconnect","server":"vpn.fixture.invalid","username":"user","password":"fixed",
                "form_entries":[{"name":"otp","value":"{otp}"},{"name":"hidden","value":"{otp}","promote":true}]}),
        })
        .unwrap();
    let profile = e.profile(&oc).unwrap();
    let source = planner::Source::from_profile(&profile).unwrap();
    let mut baked = profile.config.clone();
    assert!(planner::bake_probe(&mut baked, "654321", &source).unwrap());
    assert_eq!(baked["form_entries"][0]["value"], "654321");
    assert_eq!(
        baked["form_entries"][1]["value"], "{otp}",
        "promoted entries keep their placeholder"
    );
    assert_eq!(baked["password"], "fixed");
}

/// Qt starts the connection again with a code of its own when the server
/// refuses the one baked before Start. Nothing here answers a challenge: this
/// mode has none.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_refused_start_code_is_followed_by_a_fresh_one_until_the_budget_runs_out() {
    let (_dir, mut e) = engine();
    let hotp = otp(&mut e, Kind::Hotp);
    let id = profile(&mut e, openvpn("{otp}", json!({})));
    bind(&mut e, &id, &hotp, Mode::AutoStart).unwrap();
    let core = Arc::new(Mutex::new(Core::default()));
    e.rpc = Some(scripted(core.clone()));
    e.connect(&id).await.unwrap();
    assert_eq!(core.lock().unwrap().starts.len(), 1);
    assert_eq!(counter(&e, &hotp.0), "1");
    let refused = proto::VpnStatusResponse {
        results: vec![proto::VpnEndpointStatus {
            tag: Some("proxy".into()),
            state: Some("error".into()),
            connected: Some(false),
            auth_failed: Some(true),
            ..Default::default()
        }],
    };
    for attempt in 2..=4 {
        e.auto_vpn_otp(&refused).await;
        assert_eq!(
            core.lock().unwrap().starts.len(),
            attempt,
            "attempt {attempt}"
        );
        assert_eq!(counter(&e, &hotp.0), attempt.to_string());
        // Every restart carries digits of its own.
        let starts = core.lock().unwrap().starts.clone();
        assert_ne!(
            starts[attempt - 1]["password"],
            starts[attempt - 2]["password"]
        );
    }
    // The budget is spent: the refusal is reported instead of a fourth code.
    e.auto_vpn_otp(&refused).await;
    assert_eq!(core.lock().unwrap().starts.len(), 4);
    assert_eq!(counter(&e, &hotp.0), "4");
    let endpoint = e
        .vpn
        .status
        .endpoints
        .iter()
        .find(|endpoint| endpoint.tag == "proxy")
        .unwrap();
    let otp_state = endpoint.otp.as_ref().unwrap();
    assert_eq!(
        serde_json::to_value(otp_state).unwrap()["error"],
        json!("vpn_otp_retry_limited")
    );
    // Asking for this connection again starts the budget over.
    e.connect(&id).await.unwrap();
    assert_eq!(core.lock().unwrap().starts.len(), 5);
    e.auto_vpn_otp(&refused).await;
    assert_eq!(core.lock().unwrap().starts.len(), 6);
    // A code the server accepted clears the budget as well.
    let connected = proto::VpnStatusResponse {
        results: vec![proto::VpnEndpointStatus {
            tag: Some("proxy".into()),
            state: Some("connected".into()),
            connected: Some(true),
            ..Default::default()
        }],
    };
    e.auto_vpn_otp(&connected).await;
    assert!(e.vpn_start_restarts.is_empty());
}
