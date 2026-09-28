//! Every Throne protocol the backup import converts is accepted by the real core.
//! Synthetic rows in Qt's ExportToJson shape; the runner renames this process to Thronium.
use serde_json::{json, Value};
use thronium_engine::{
    legacy_backup::{profiles, SourceDatabase, SourceGroup, SourceProfile, SourceValue},
    Engine,
};

const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn server(extra: Value) -> Value {
    let mut value = json!({"server":"192.0.2.10","server_port":443});
    for (key, item) in extra.as_object().unwrap() {
        value[key] = item.clone();
    }
    value
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let executable = std::env::current_exe().unwrap();
    let core = executable.parent().unwrap().join(if cfg!(windows) {
        "ThroniumCore.exe"
    } else {
        "ThroniumCore"
    });
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &core)?;
    let tls = json!({"enabled":true,"server_name":"example.test"});
    let rows = [
        (
            "hysteria",
            server(
                json!({"type":"hysteria","up_mbps":10,"down_mbps":50,"obfs":"obfs-fixture","auth_str":"auth-fixture","tls":tls}),
            ),
        ),
        (
            "hysteria2",
            json!({"type":"hysteria2","server":"192.0.2.11","server_ports":["20000:30000"],"hop_interval":"10s","hop_interval_max":"30s","bbr_profile":"invented","password":"fixture","obfs":{"type":"future","password":"o","min_packet_size":0,"max_packet_size":0},"tls":tls}),
        ),
        (
            "hysteria2",
            json!({"type":"hysteria2","password":"fixture","realm":{"server_url":"https://realm.example.test","realm_id":"fixture"},"tls":tls}),
        ),
        (
            "tuic",
            server(
                json!({"type":"tuic","uuid":UUID,"password":"fixture","congestion_control":"bbr","tls":{"enabled":true,"server_name":"example.test","utls":{"enabled":true,"fingerprint":"chrome"}}}),
            ),
        ),
        (
            "juicity",
            server(json!({"type":"juicity","uuid":UUID,"password":"fixture","tls":tls})),
        ),
        (
            "anytls",
            server(json!({"type":"anytls","password":"fixture","min_idle_session":2,"tls":tls})),
        ),
        (
            "trusttunnel",
            server(
                json!({"type":"trusttunnel","username":"fixture","password":"fixture","quic":true,"quic_congestion_control":"bbr","tls":tls}),
            ),
        ),
        (
            "naive",
            server(json!({"type":"naive","username":"fixture","password":"fixture","tls":tls})),
        ),
        (
            "shadowtls",
            server(json!({"type":"shadowtls","version":3,"password":"fixture","tls":tls})),
        ),
        (
            "mieru",
            json!({"type":"mieru","server":"192.0.2.12","server_ports":["2000-2010"],"transport":"TCP","username":"fixture","password":"fixture"}),
        ),
        (
            "snell",
            server(
                json!({"type":"snell","version":4,"psk":"fixture","obfs_mode":"tls","obfs_host":"example.test"}),
            ),
        ),
        (
            "ssh",
            server(
                json!({"type":"ssh","user":"fixture","password":"fixture","client_version":"SSH-2.0-fixture"}),
            ),
        ),
        (
            "tailscale",
            json!({"type":"tailscale","tag":"Tailnet","auth_key":"tskey-fixture","accept_routes":true,"globalDNS":true}),
        ),
        (
            "direct",
            json!({"type":"direct","tag":"Direct fixture","tcp_fast_open":true}),
        ),
    ];
    let ids: Vec<i64> = (1..=rows.len() as i64).collect();
    let db = SourceDatabase {
        groups: vec![SourceGroup {
            id: 0,
            name: "Protocols".into(),
            columns: [(
                "profiles_json".to_owned(),
                SourceValue::Text(json!(ids).to_string()),
            )]
            .into(),
        }],
        profiles: rows
            .iter()
            .zip(&ids)
            .map(|((kind, outbound), id)| SourceProfile {
                id: *id,
                kind: (*kind).into(),
                name: Some(format!("{kind} {id}")),
                group_id: 0,
                outbound: outbound.clone(),
                columns: [(
                    "outbound_json".to_owned(),
                    SourceValue::Text(outbound.to_string()),
                )]
                .into(),
            })
            .collect(),
        ..Default::default()
    };
    let plan = profiles::convert(&db).map_err(|issues| {
        issues
            .into_iter()
            .map(|issue| issue.code)
            .collect::<Vec<_>>()
            .join(", ")
    })?;
    if plan.profiles.len() != rows.len() {
        return Err("not every protocol row converted".into());
    }
    for profile in &plan.profiles {
        engine
            .check(profile)
            .await
            .map_err(|error| format!("{}: {error}", profile.name))?;
        println!(
            "PASS imported {} is accepted by the core: {}",
            profile.config["type"].as_str().unwrap_or(""),
            profile.name
        );
    }
    // The normalizations matter: rows as Qt exported them are refused. (Qt also
    // drops uTLS on QUIC classes; the core's check accepts that one either way.)
    for (name, raw) in [
        (
            "unknown obfs type",
            json!({"type":"hysteria2","server":"192.0.2.11","server_port":443,"password":"fixture","obfs":{"type":"future","password":"o"},"tls":{"enabled":true,"server_name":"example.test"}}),
        ),
        (
            "unknown BBR profile",
            json!({"type":"hysteria2","server":"192.0.2.11","server_port":443,"password":"fixture","bbr_profile":"invented","tls":{"enabled":true,"server_name":"example.test"}}),
        ),
    ] {
        let mut profile = plan.profiles[0].clone();
        profile.config = raw;
        if engine.check(&profile).await.is_ok() {
            return Err(format!("the core accepted an unconverted {name}"));
        }
        println!("PASS the core refuses the unconverted row with an {name}");
    }
    engine.shutdown().await;
    Ok(())
}
