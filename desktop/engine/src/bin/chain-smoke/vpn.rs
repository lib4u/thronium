//! Real OpenVPN endpoints as chain hops, proven against an owned sing-box
//! openvpn-server in a second pinned Core: the tunnel exit carries HTTP, a hop
//! behind the tunnel is reached through it, the exit's VPN policy gates traffic
//! and an isolated URL probe waits for the hop's readiness.
use super::{add, counts, exchange};
use serde_json::{json, Value};
use std::{path::Path, process::Stdio};
use thronium_engine::{
    probes,
    store::ProfileKind,
    vpn_policy::{Edit, Policy},
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
    time::{timeout, Duration},
};

async fn tunnel_http(proxy: u16, url: &str) -> Result<String, String> {
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .ok_or("fixture URL")?;
    let mut client = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    client
        .write_all(
            format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut response = String::new();
    timeout(Duration::from_secs(6), client.read_to_string(&mut response))
        .await
        .map_err(|_| "tunnel HTTP timeout")?
        .map_err(|e| e.to_string())?;
    Ok(response)
}

pub(crate) async fn vpn_hops(
    e: &mut Engine,
    nodes: &mut [Engine],
    ports: &[u16],
    proxy: u16,
    origin_port: u16,
    root: &Path,
) -> Result<(), String> {
    let (mut server, info) = spawn_server(root).await?;
    let tunnel = info["tunnel"].as_str().ok_or("fixture tunnel")?.to_owned();
    let http = info["httpUrl"].as_str().ok_or("fixture URL")?.to_owned();
    let vpn = add(
        e,
        "OpenVPN hop",
        ProfileKind::SingBoxOutbound,
        info["profile"].clone(),
    )?;
    let sing0 = add(
        e,
        "sing-box hop before OpenVPN",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":ports[0],"version":"5"}),
    )?;
    // Hops behind the tunnel are addressed by the server's tunnel address.
    let through = add(
        e,
        "sing-box hop behind OpenVPN",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":tunnel,"server_port":ports[1],"version":"5"}),
    )?;
    let xray_through = add(
        e,
        "Xray hop behind OpenVPN",
        ProfileKind::XrayOutbound,
        json!({"protocol":"socks","settings":{"address":tunnel,"port":ports[2]}}),
    )?;
    for (pattern, hops, node, exit_local) in [
        ("SV", vec![sing0.clone(), vpn.clone()], 0usize, false),
        ("VS", vec![vpn.clone(), through.clone()], 1, true),
        ("VX", vec![vpn.clone(), xray_through.clone()], 2, true),
        (
            "SVS",
            vec![sing0.clone(), vpn.clone(), through.clone()],
            1,
            true,
        ),
    ] {
        let id = add(
            e,
            pattern,
            ProfileKind::Chain,
            json!({"type":"chain","hops":hops}),
        )?;
        e.check(&e.profile(&id)?)
            .await
            .map_err(|err| format!("{pattern} validation: {err}"))?;
        let before = counts(nodes).await;
        e.connect(&id)
            .await
            .map_err(|err| format!("{pattern} start: {err}"))?;
        // Start returns before the tunnel is up: the VPN status session, polled
        // through the hop's emitted tag, says when traffic may flow.
        wait_connected(e)
            .await
            .map_err(|states| format!("{pattern}: the VPN hop never connected: {states:?}"))?;
        if exit_local {
            exchange(proxy, origin_port)
                .await
                .map_err(|err| format!("{pattern}: {err}"))?;
        } else {
            let response = tunnel_http(proxy, &http)
                .await
                .map_err(|err| format!("{pattern}: {err}"))?;
            if !response.ends_with("chained") {
                return Err(format!(
                    "{pattern}: tunnel HTTP did not reach the fixture origin: {response}"
                ));
            }
        }
        let after = timeout(Duration::from_secs(2), async {
            loop {
                let after = counts(nodes).await;
                if after[node].0 > before[node].0 && after[node].1 > before[node].1 {
                    break after;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| format!("{pattern}: traffic counters did not reach hop {node}"))?;
        assert!(after[node].0 > before[node].0);
        e.disconnect().await?;
        println!("PASS {pattern}: real OpenVPN endpoint hop carries HTTP with the local hop counters growing");
    }
    // The exit hop's policy gates the chain: only the advertised tunnel route
    // passes, everything else is rejected before leaving the device.
    let gated = e.save_profile(ProfileDraft {
        vpn_policy: Edit::Set(Some(Policy {
            only_advertised_routes: true,
            use_tunnel_dns: false,
            block_outside_dns: false,
        })),
        id: None,
        name: "Gated OpenVPN hop".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: info["profile"].clone(),
    })?;
    let id = add(
        e,
        "SV gated",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing0.clone(), gated]}),
    )?;
    e.connect(&id)
        .await
        .map_err(|err| format!("SV gated start: {err}"))?;
    // Gating admits the advertised route only once the tunnel has pushed it.
    wait_connected(e)
        .await
        .map_err(|states| format!("SV gated: endpoint never connected: {states:?}"))?;
    let response = tunnel_http(proxy, &http)
        .await
        .map_err(|err| format!("SV gated: {err}"))?;
    assert!(response.ends_with("chained"), "SV gated: {response}");
    assert!(
        exchange(proxy, origin_port).await.is_err(),
        "SV gated: a destination outside the advertised routes must be rejected"
    );
    e.disconnect().await?;
    println!(
        "PASS SV gated: the exit hop's VPN policy admits advertised routes and rejects the rest"
    );
    // An isolated URL probe of the chain waits for the hop's readiness first.
    let id = add(
        e,
        "SV probed",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing0, vpn]}),
    )?;
    let mut run = e.start_url_tests(probes::Options {
        ids: vec![id.clone()],
        url: http.clone(),
        timeout_ms: 5000,
        concurrency: None,
    })?;
    let probe = e.next_url_test(&run.id).ok_or("SV probe not queued")?;
    let result = probe.execute(&mut run.cancelled).await;
    assert!(result.is_ok(), "SV probe: {result:?}");
    e.finish_url_test(&run.id, &id, result);
    println!(
        "PASS SV probe: the isolated URL test waits for the OpenVPN hop and measures through it"
    );
    // The device-side VPN hop is not the measured outbound: the core still waits
    // for it before dialing (dependency readiness), so the probe succeeds instead
    // of failing on an endpoint that is not ready yet.
    let entry = add(
        e,
        "VS probed",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[vpn.clone(), through]}),
    )?;
    let mut run = e.start_url_tests(probes::Options {
        ids: vec![entry.clone()],
        url: format!("http://127.0.0.1:{origin_port}/probe"),
        timeout_ms: 5000,
        concurrency: None,
    })?;
    let probe = e.next_url_test(&run.id).ok_or("VS probe not queued")?;
    let result = probe.execute(&mut run.cancelled).await;
    assert!(result.is_ok(), "VS probe: {result:?}");
    e.finish_url_test(&run.id, &entry, result);
    println!("PASS VS probe: the URL test waits for the device-side OpenVPN hop as a dependency endpoint");
    // A complete sing-box JSON that carries its own OpenVPN endpoint is tested
    // as a whole client: its endpoint is a readiness dependency as well.
    let mut endpoint = info["profile"].clone();
    endpoint["tag"] = json!("user-vpn");
    let full = add(
        e,
        "Complete client with OpenVPN",
        ProfileKind::SingBoxConfig,
        json!({"log":{"level":"warn"},
               "endpoints":[endpoint],
               "outbounds":[{"type":"direct","tag":"direct"}],
               "route":{"final":"user-vpn"}}),
    )?;
    let mut run = e.start_url_tests(probes::Options {
        ids: vec![full.clone()],
        url: http.clone(),
        timeout_ms: 5000,
        concurrency: None,
    })?;
    let probe = e.next_url_test(&run.id).ok_or_else(|| {
        format!(
            "full-client probe not queued: {:?}; supported {:?}; groups {:?}; profile {}",
            e.snapshot().url_tests.map(|b| b
                .entries
                .iter()
                .map(|x| (x.status, x.error.clone()))
                .collect::<Vec<_>>()),
            e.snapshot()
                .profiles
                .iter()
                .find(|p| p["id"] == full)
                .map(|p| p["ipSpeedSupported"].clone()),
            e.store
                .library
                .groups
                .iter()
                .map(|g| (g.id.clone(), g.proxy_chain.clone()))
                .collect::<Vec<_>>(),
            e.profile(&full)
                .map(|p| p.config.to_string())
                .unwrap_or_default()
        )
    })?;
    assert!(
        probe.is_disposable_vpn(),
        "a full client with a VPN endpoint takes the VPN admission slot"
    );
    let result = probe.execute(&mut run.cancelled).await;
    assert!(result.is_ok(), "full-client probe: {result:?}");
    e.finish_url_test(&run.id, &full, result);
    println!("PASS full-client probe: a complete sing-box JSON with its own OpenVPN endpoint waits for it and measures through it");
    drop(server.stdin.take());
    let _ = timeout(Duration::from_secs(10), server.wait()).await;
    Ok(())
}

/// Starts the owned server through the copied interpreter named Thronium (the
/// pinned Core checks its parent's name) and returns its readiness record.
async fn spawn_server(root: &Path) -> Result<(Child, Value), String> {
    let mut server = Command::new(root.join("Thronium"))
        .kill_on_drop(true)
        .arg(root.join("fixture.py"))
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(server.stdout.take().unwrap()).lines();
    let ready = timeout(Duration::from_secs(30), lines.next_line())
        .await
        .map_err(|_| "OpenVPN fixture readiness timeout")?
        .map_err(|e| e.to_string())?
        .ok_or("OpenVPN fixture exited")?;
    let info: Value = serde_json::from_str(ready.trim()).map_err(|e| e.to_string())?;
    Ok((server, info))
}

/// The host tick refreshes VPN status; the stand has no host loop, so poll it
/// here until an endpoint reports connected (or give up after 10 s).
async fn wait_connected(e: &mut Engine) -> Result<(), Vec<(String, String)>> {
    let mut states = vec![];
    for _ in 0..50 {
        e.vpn_tick().await;
        states = e
            .snapshot()
            .vpn
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.tag.clone(), endpoint.state.clone()))
            .collect();
        if states.iter().any(|(_, state)| state == "connected") {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(states)
}
