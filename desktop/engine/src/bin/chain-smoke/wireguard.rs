//! Real WireGuard endpoints as chain hops, proven by an independent
//! wireguard-go peer relaying in-tunnel connections to the local hops.
use super::{add, counts, exchange};
use serde_json::{json, Value};
use std::process::Stdio;
use thronium_engine::{store::ProfileKind, Engine};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

/// An independent wireguard-go peer relays in-tunnel connections to the local
/// hops, so a chain can enter or leave through a real WireGuard endpoint.
pub(crate) async fn wireguard_hops(
    e: &mut Engine,
    nodes: &mut [Engine],
    ports: &[u16],
    proxy: u16,
    origin_port: u16,
    fixture: &std::ffi::OsStr,
) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let (mut peer, info) = spawn_peer(fixture, dir.path(), json!({"forwardPorts": ports})).await?;
    let tunnel = info["tunnel4"].as_str().unwrap().to_owned();
    let stats = info["stats"].as_str().unwrap().to_owned();
    let wg = add(
        e,
        "WireGuard hop",
        ProfileKind::SingBoxOutbound,
        info["profile"].clone(),
    )?;
    // Hops behind the tunnel are addressed by the peer's tunnel address.
    let through: Vec<_> = ports
        .iter()
        .map(|p| {
            add(
                e,
                "sing-box hop behind WireGuard",
                ProfileKind::SingBoxOutbound,
                json!({"type":"socks","server":tunnel,"server_port":p,"version":"5"}),
            )
        })
        .collect::<Result<_, _>>()?;
    let sing0 = add(
        e,
        "sing-box hop before WireGuard",
        ProfileKind::SingBoxOutbound,
        json!({"type":"socks","server":"127.0.0.1","server_port":ports[0],"version":"5"}),
    )?;
    let xray_through = add(
        e,
        "Xray hop behind WireGuard",
        ProfileKind::XrayOutbound,
        json!({"protocol":"socks","settings":{"address":tunnel,"port":ports[2]}}),
    )?;
    let forwarded = |stats: &str| -> Result<Value, String> {
        Ok(serde_json::from_str::<Value>(
            &std::fs::read_to_string(stats).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?["forwarded"]
            .clone())
    };
    for (pattern, hops, node, port) in [
        ("SW", vec![sing0.clone(), wg.clone()], 0usize, None),
        (
            "WS",
            vec![wg.clone(), through[1].clone()],
            1,
            Some(ports[1]),
        ),
        (
            "WX",
            vec![wg.clone(), xray_through.clone()],
            2,
            Some(ports[2]),
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
        let relayed = forwarded(&stats)?;
        e.connect(&id)
            .await
            .map_err(|err| format!("{pattern} start: {err}"))?;
        if let Some(port) = port {
            // The tunnel exit is a local hop: the origin answers as usual.
            exchange(proxy, origin_port)
                .await
                .map_err(|err| format!("{pattern}: {err}"))?;
            // The peer flushes its statistics every 100 ms.
            let key = port.to_string();
            timeout(Duration::from_secs(2), async {
                loop {
                    if forwarded(&stats).is_ok_and(|now| {
                        now[&key].as_i64().unwrap_or(0) > relayed[&key].as_i64().unwrap_or(0)
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .map_err(|_| {
                let now = forwarded(&stats).unwrap_or_default();
                let raw = std::fs::read_to_string(&stats).unwrap_or_default();
                format!("{pattern}: the hop behind the tunnel was not reached through the peer (before {relayed}, after {now}, stats {raw})")
            })?;
        } else {
            // WireGuard is the exit: only the peer's own HTTP answers inside the tunnel.
            let mut client = TcpStream::connect(("127.0.0.1", proxy))
                .await
                .map_err(|e| e.to_string())?;
            let http4 = info["http4"].as_str().unwrap();
            client.write_all(format!("GET {http4}/fixture/chain HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", &http4[7..]).as_bytes()).await.unwrap();
            let mut response = String::new();
            timeout(Duration::from_secs(4), client.read_to_string(&mut response))
                .await
                .map_err(|_| format!("{pattern}: tunnel HTTP timeout"))?
                .map_err(|e| e.to_string())?;
            assert!(
                response.ends_with("wg43:/fixture/chain"),
                "{pattern}: {response}"
            );
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
        println!("PASS {pattern}: real WireGuard endpoint hop carries HTTP with the local hop counters growing");
    }
    let mut fixed = info["profile"].clone();
    fixed["listen_port"] = json!(51999);
    let fixed = add(
        e,
        "WireGuard fixed port",
        ProfileKind::SingBoxOutbound,
        fixed,
    )?;
    assert_eq!(
        add(
            e,
            "SF",
            ProfileKind::Chain,
            json!({"type":"chain","hops":[sing0.clone(), fixed]})
        )
        .unwrap_err(),
        "chain_endpoint_listen_port_unsupported"
    );
    println!("PASS a fixed WireGuard port behind another hop is refused at save time");
    warp_hop(e, proxy, &sing0, fixture).await?;
    super::warp_routes::run(e, proxy, &sing0, origin_port, fixture).await?;
    drop(peer.stdin.take());
    let _ = timeout(Duration::from_secs(10), peer.wait()).await;
    Ok(())
}

/// Spawns one independent wireguard-go peer with the given options and returns
/// it with the readiness info it prints. The caller owns the peer's lifetime.
pub(super) async fn spawn_peer(
    fixture: &std::ffi::OsStr,
    dir: &std::path::Path,
    options: Value,
) -> Result<(Child, Value), String> {
    let options_path = dir.join("peer.options.json");
    std::fs::write(&options_path, options.to_string()).map_err(|e| e.to_string())?;
    let mut peer = Command::new(fixture)
        .kill_on_drop(true)
        .arg(dir.join("peer"))
        .arg("127.0.0.1")
        .arg(&options_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(peer.stdout.take().unwrap()).lines();
    let ready = timeout(Duration::from_secs(10), lines.next_line())
        .await
        .map_err(|_| "WG peer readiness timeout")?
        .map_err(|e| e.to_string())?
        .ok_or("WG peer exited")?;
    let info: Value =
        serde_json::from_str(&std::fs::read_to_string(ready.trim()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    Ok((peer, info))
}

/// WARP fills an ordinary WireGuard profile whose single peer carries three
/// reserved bytes and a keepalive. It is therefore a chain hop like any other
/// endpoint: the peer stamps and strips the reserved bytes, and HTTP still
/// exits through the tunnel.
async fn warp_hop(
    e: &mut Engine,
    proxy: u16,
    sing0: &str,
    fixture: &std::ffi::OsStr,
) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let (mut peer, info) = spawn_peer(
        fixture,
        dir.path(),
        json!({"subnet": 46, "reserved": [1, 2, 3]}),
    )
    .await?;
    let stats = info["stats"].as_str().unwrap().to_owned();
    let mut profile = info["profile"].clone();
    profile["mtu"] = json!(1280);
    profile["peers"][0]["reserved"] = json!([1, 2, 3]);
    profile["peers"][0]["persistent_keepalive_interval"] = json!(30);
    let warp = add(e, "WARP endpoint", ProfileKind::SingBoxOutbound, profile)?;
    let id = add(
        e,
        "SWARP",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[sing0, warp]}),
    )?;
    e.check(&e.profile(&id)?)
        .await
        .map_err(|err| format!("WARP chain validation: {err}"))?;
    e.connect(&id)
        .await
        .map_err(|err| format!("WARP chain start: {err}"))?;
    let http4 = info["http4"].as_str().unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    client
        .write_all(
            format!(
                "GET {http4}/fixture/warp HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                &http4[7..]
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(4), client.read_to_string(&mut response))
        .await
        .map_err(|_| "WARP tunnel HTTP timeout")?
        .map_err(|e| e.to_string())?;
    assert!(response.ends_with("wg43:/fixture/warp"), "WARP: {response}");
    let seen: Value =
        serde_json::from_str(&std::fs::read_to_string(&stats).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    assert!(
        seen["reservedSeen"]["010203"].as_i64().unwrap_or(0) > 0,
        "WARP reserved bytes were not seen on the wire: {}",
        seen["reservedSeen"]
    );
    e.disconnect().await?;
    drop(peer.stdin.take());
    let _ = timeout(Duration::from_secs(10), peer.wait()).await;
    println!(
        "PASS WARP-shaped endpoint with reserved bytes carries HTTP as a chain hop behind another hop"
    );
    Ok(())
}
