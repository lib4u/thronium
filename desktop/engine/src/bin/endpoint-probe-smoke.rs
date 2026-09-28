//! Run only in the private namespace supplied by test_endpoint_probes.py.
use serde_json::json;
use thronium_engine::{
    probes::Method, store::ProfileKind, system_proxy::ConnectionMode, Engine, ProfileDraft,
};

async fn measure(engine: &mut Engine) -> Result<(), String> {
    let ids = engine
        .store
        .library
        .profiles
        .iter()
        .filter(|p| p.name == "Direct probe fixture")
        .map(|p| p.id.clone())
        .collect();
    let mut run = engine.start_ping(ids)?;
    while let Some(probe) = engine.next_url_test(&run.id) {
        let id = probe.id.clone();
        let result = if let Some(job) = engine.start_managed_probe(&probe).await? {
            loop {
                match engine.query_managed_probe(&job).await {
                    Ok(Some(ms)) => break Ok(ms),
                    Err(error) => break Err(error),
                    Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
                }
            }
        } else {
            probe.execute(&mut run.cancelled).await
        };
        engine.finish_url_test(&run.id, &id, result);
    }
    Ok(())
}

fn nft(script: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

#[tokio::main]
async fn main() -> Result<(), String> {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_string_lossy(),
        std::env::var("THRONIUM_TEST_ORIGINAL_NETNS").unwrap()
    );
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut engine = Engine::open(dir.path(), &exe.parent().unwrap().join("ThroniumCore"))?;
    let blocked = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Blocked VPN fixture".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks", "server":"127.0.0.1", "server_port":9}),
    })?;
    let mut ids = vec![];
    for host in ["198.18.0.80", "2001:db8:ff::80"] {
        for port in [18080, 18081] {
            ids.push(engine.save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Direct probe fixture".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"socks", "server":host, "server_port":port}),
            })?);
        }
    }
    for mode in ["local", "tun", "redirect"] {
        if mode != "local" {
            engine.store.library.preferences.connection_mode = ConnectionMode::Tun;
            engine.store.library.preferences.tun.ipv6 = true;
            engine.store.library.preferences.tun.auto_reconnect = false;
            engine
                .store
                .library
                .settings
                .insert("vpn_auto_redirect".into(), json!(mode == "redirect"));
            engine.store.library.routing.profiles[0].mode = "all".into();
            engine.connect(&blocked).await?;
        }
        for method in [Method::Tcp, Method::Icmp] {
            engine.store.library.preferences.ping.method = method;
            engine.store.library.preferences.ping.timeout_ms = 500;
            measure(&mut engine).await?;
            for (i, entry) in engine
                .snapshot()
                .url_tests
                .unwrap()
                .entries
                .iter()
                .enumerate()
            {
                let expected = if method == Method::Tcp && i % 2 == 1 {
                    Some("probe_connection_refused")
                } else {
                    None
                };
                assert_eq!(
                    entry.error.as_deref(),
                    expected,
                    "{mode} {method:?} case {i}"
                );
            }
            println!("PASS direct {method:?} IPv4/IPv6 and closed-port detection with {mode}");
        }
        nft("add table inet ping_fixture\nadd chain inet ping_fixture input { type filter hook input priority -200; policy accept; }\nadd rule inet ping_fixture input icmp type echo-reply drop\nadd rule inet ping_fixture input icmpv6 type echo-reply drop\n");
        engine.store.library.preferences.ping.timeout_ms = 100;
        measure(&mut engine).await?;
        let no_reply = engine.snapshot().url_tests.unwrap();
        assert!(
            no_reply.entries.iter().all(
                |e| e.error.as_deref() == Some("probe_icmp_no_reply") && e.latency_ms.is_none()
            ),
            "{mode}: {}",
            serde_json::to_string(&no_reply).unwrap()
        );
        println!("PASS blocked ICMP produces no-reply without an invented latency with {mode}");
        if mode != "local" {
            engine.store.library.preferences.ping.timeout_ms = 10000;
            let run = engine.start_ping(vec![ids[0].clone()])?;
            let probe = engine.next_url_test(&run.id).unwrap();
            let start = std::time::Instant::now();
            let job = engine.start_managed_probe(&probe).await?.unwrap();
            assert!(engine.query_managed_probe(&job).await?.is_none());
            assert_eq!(
                engine.poll().await.running.as_deref(),
                Some(blocked.as_str())
            );
            engine.cancel_url_tests();
            engine.cancel_managed_probe(&job).await;
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            assert_eq!(
                engine.query_managed_probe(&job).await.unwrap_err(),
                "probe_direct_unavailable"
            );
            println!("PASS managed ICMP cancellation and status polling do not wait for network timeout with {mode}");
        }
        nft("delete table inet ping_fixture\n");
        if mode != "local" {
            assert_eq!(engine.snapshot().running.as_deref(), Some(blocked.as_str()));
            engine.disconnect().await?;
        }
    }
    engine.shutdown().await;
    Ok(())
}
