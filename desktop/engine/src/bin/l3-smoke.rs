//! Real L3 forwarding. The runner supplies a private veth peer with HTTP origins.
use serde_json::json;
use thronium_engine::{store::ProfileKind, system_proxy::ConnectionMode, Engine, ProfileDraft};
#[tokio::main]
async fn main() -> Result<(), String> {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), &exe.parent().unwrap().join("ThroniumCore"))?;
    let id = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Private fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    engine.select(&id)?;
    engine.store.library.preferences.connection_mode = ConnectionMode::Tun;
    engine.store.library.preferences.tun.ipv6 = true;
    engine.store.library.preferences.tun.auto_reconnect = false;
    engine
        .store
        .library
        .settings
        .insert("vpn_l3_bridge".into(), json!(true));
    engine
        .store
        .library
        .settings
        .insert("log_level".into(), json!("debug"));
    engine.store.library.routing.profiles[0].mode = "direct".into();
    for redirect in [false, true] {
        engine
            .store
            .library
            .settings
            .insert("vpn_auto_redirect".into(), json!(redirect));
        engine.connect(&id).await?;
        for address in [
            "http://198.18.0.80:18080/",
            "http://[2001:db8:ff::80]:18080/",
        ] {
            let result = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .unwrap()
                .get(address)
                .send()
                .await;
            let response = match result {
                Ok(response) => response,
                Err(_) => {
                    for line in engine.logs.view(Default::default()).unwrap().entries {
                        eprintln!("{}", line.text);
                    }
                    for args in [
                        vec!["-4", "rule"],
                        vec!["-4", "route", "show", "table", "all"],
                    ] {
                        let o = std::process::Command::new("ip")
                            .args(args)
                            .output()
                            .unwrap();
                        eprintln!("{}", String::from_utf8_lossy(&o.stdout));
                    }
                    for path in [
                        "/proc/sys/net/ipv4/ip_forward",
                        "/proc/sys/net/ipv4/conf/thronium-br0/forwarding",
                        "/proc/sys/net/ipv4/conf/uplink/rp_filter",
                    ] {
                        eprintln!("{}: {:?}", path, std::fs::read_to_string(path));
                    }
                    engine.disconnect().await?;
                    return Err("l3_http_failed".into());
                }
            };
            assert_eq!(response.text().await.unwrap(), "fixture-l3");
        }
        engine.disconnect().await?;
        println!("PASS L3 bridge forwards real IPv4 and IPv6 HTTP through a veth peer, auto_redirect={redirect}");
    }
    engine.shutdown().await;
    Ok(())
}
