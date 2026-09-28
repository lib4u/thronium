//! Independent raw-core oracle; no routing UI/model/compiler is used.
//! Explicit runner preserves the release parent check and supplies a pinned core.
#![cfg(target_os = "linux")]
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use thronium_engine::{
    proto::{EmptyReq, ErrorResp, LoadConfigReq},
    transport::Rpc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{timeout, Duration},
};

fn materialize(value: &Value, port: u16) -> Value {
    match value {
        Value::String(text) if text == "$destinationPort" => json!(port),
        Value::String(text) if text == "$destinationRange" => json!(format!("{port}:{port}")),
        Value::Array(values) => json!(values
            .iter()
            .map(|v| materialize(v, port))
            .collect::<Vec<_>>()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(k, v)| (k.clone(), materialize(v, port)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn dns_question(packet: &[u8]) -> (u16, usize) {
    assert!(packet.len() >= 17 && packet[4..6] == [0, 1]);
    let mut pos = 12;
    let mut labels = vec![];
    loop {
        let size = packet[pos] as usize;
        pos += 1;
        if size == 0 {
            break;
        }
        assert!(size <= 63 && pos + size <= packet.len());
        labels.push(std::str::from_utf8(&packet[pos..pos + size]).unwrap());
        pos += size;
    }
    assert!(labels.join(".").ends_with(".oracle.invalid"));
    assert!(pos + 4 <= packet.len());
    (u16::from_be_bytes([packet[pos], packet[pos + 1]]), pos + 4)
}

fn dns_data(kind: u16, marker: u8) -> Vec<u8> {
    match kind {
        1 => vec![192, 0, 2, marker],
        28 => {
            let mut value = vec![0; 16];
            value[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            value[15] = marker;
            value
        }
        _ => panic!("nonfixture query type"),
    }
}

async fn dns_origin(
    marker: u8,
) -> (
    u16,
    Arc<std::sync::Mutex<Vec<Value>>>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let observations = Arc::new(std::sync::Mutex::new(vec![]));
    let seen = observations.clone();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert!(peer.ip().is_loopback());
            let query = &buffer[..length];
            let (kind, end) = dns_question(query);
            let data = dns_data(kind, marker);
            let mut reply = query[..end].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x80;
            reply[6..12].fill(0);
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 0x0c]);
            reply.extend_from_slice(&kind.to_be_bytes());
            reply.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&(data.len() as u16).to_be_bytes());
            reply.extend_from_slice(&data);
            seen.lock()
                .unwrap()
                .push(json!({"type":kind,"marker":marker}));
            socket.send_to(&reply, peer).await.unwrap();
        }
    });
    (port, observations, task)
}

async fn dns_exchange(port: u16, kind: u16, id: u16) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(("127.0.0.1", port)).await.unwrap();
    let mut request = vec![0; 12];
    request[..2].copy_from_slice(&id.to_be_bytes());
    request[2] = 1;
    request[5] = 1;
    for label in format!("q{id}.oracle.invalid").split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&kind.to_be_bytes());
    request.extend_from_slice(&[0, 1]);
    socket.send(&request).await.unwrap();
    let mut response = [0; 4096];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .expect("owned DNS timeout")
        .unwrap();
    let response = &response[..length];
    assert_eq!(&response[..2], &id.to_be_bytes());
    assert_eq!(response[3] & 15, 0);
    assert_eq!(&response[6..8], &[0, 1]);
    let (query_type, mut pos) = dns_question(response);
    assert_eq!(query_type, kind);
    if response[pos] & 0xc0 == 0xc0 {
        pos += 2;
    } else {
        while response[pos] != 0 {
            pos += response[pos] as usize + 1;
        }
        pos += 1;
    }
    assert_eq!(u16::from_be_bytes([response[pos], response[pos + 1]]), kind);
    pos += 8;
    let length = u16::from_be_bytes([response[pos], response[pos + 1]]) as usize;
    pos += 2;
    response[pos..pos + length].to_vec()
}

fn dns_request(rules: Value, inbound: u16, matched: u16, fallback: u16) -> LoadConfigReq {
    LoadConfigReq {
        core_config: Some(json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"direct","tag":"dns-in","listen":"127.0.0.1","listen_port":inbound,"network":"udp"}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct","rule_set":[{"type":"inline","tag":"fixture","rules":rules}],"rules":[{"inbound":["dns-in"],"action":"hijack-dns"}]},
            "dns":{"disable_cache":true,"servers":[{"type":"udp","tag":"matched","server":"127.0.0.1","server_port":matched},{"type":"udp","tag":"fallback","server":"127.0.0.1","server_port":fallback}],"final":"fallback","rules":[{"rule_set":["fixture"],"action":"route","server":"matched"}]}
        }).to_string()),
        need_extra_process:Some(false),extra_no_out:Some(true),need_xray:Some(false),disable_stats:Some(true),..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned-core runner; owned loopback DNS only"]
async fn pinned_core_inline_dns_query_types() {
    let executable = std::env::current_exe().unwrap();
    assert_eq!(executable.file_name().unwrap(), "Thronium");
    let route_before = std::fs::read("/proc/net/route").unwrap();
    let interfaces_before = interface_names();
    let (matched, matched_seen, matched_task) = dns_origin(10).await;
    let (fallback, fallback_seen, fallback_task) = dns_origin(20).await;
    let guard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inbound = guard.local_addr().unwrap().port();
    drop(guard);
    let working = tempfile::tempdir().unwrap();
    let mut rpc = Rpc::spawn(
        &executable.parent().unwrap().join("ThroniumCore"),
        working.path(),
    )
    .await
    .unwrap();
    let matrix: Value =
        serde_json::from_str(include_str!("fixtures/inline-ruleset/oracle-contract.json")).unwrap();
    let mut observations = vec![];
    for (index, case) in matrix["dns"].as_array().unwrap().iter().enumerate() {
        let request = dns_request(case["rules"].clone(), inbound, matched, fallback);
        assert_eq!(
            error(&mut rpc, "CheckConfig", request.clone()).await,
            "",
            "DNS Check {}",
            case["name"]
        );
        assert_eq!(
            error(&mut rpc, "Start", request).await,
            "",
            "DNS Start {}",
            case["name"]
        );
        for (kind, key) in [(1, "expectedA"), (28, "expectedAAAA")] {
            let wanted = if case[key] == true { 10 } else { 20 };
            let observed = dns_exchange(
                inbound,
                kind,
                (index * 2 + usize::from(kind == 28) + 1) as u16,
            )
            .await;
            assert_eq!(
                observed,
                dns_data(kind, wanted),
                "{} type{kind}",
                case["name"]
            );
            observations.push(
                json!({"name":case["name"],"queryType":kind,"marker":wanted,"response":observed}),
            );
            println!(
                "PASS DNS {} type{kind} marker{wanted}",
                case["name"].as_str().unwrap()
            );
        }
        stop(&mut rpc).await;
    }
    rpc.terminate().await;
    assert!(!rpc.is_alive());
    matched_task.abort();
    fallback_task.abort();
    let _ = matched_task.await;
    let _ = fallback_task.await;
    let matched_observed = matched_seen.lock().unwrap().clone();
    let fallback_observed = fallback_seen.lock().unwrap().clone();
    assert_eq!(matched_observed.len(), 8);
    assert_eq!(fallback_observed.len(), 6);
    assert_eq!(std::fs::read("/proc/net/route").unwrap(), route_before);
    assert_eq!(interface_names(), interfaces_before);
    println!(
        "INLINE_DNS_ORACLE_JSON {}",
        json!({"queryCases":observations,"matchedQueries":matched_observed,"fallbackQueries":fallback_observed,"responses":14,"coreExited":true,"hostRoutesUnchanged":true,"interfaceNamesUnchanged":true,"scope":"Literal loopback UDP DNS to two owned responders; actual A/AAAA packets, no external resolver/network or UI model."})
    );
}
fn request(condition: Value, proxy: u16, matched: u16, _omit_action: bool) -> LoadConfigReq {
    let rule = json!({"rule_set":["fixture"],"outbound":"direct","override_port":matched,"action":"route"});
    LoadConfigReq {
        core_config:Some(json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"mixed","tag":"oracle-in","listen":"127.0.0.1","listen_port":proxy}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct","rule_set":[{"type":"inline","tag":"fixture","rules":condition}],"rules":[rule]},
            "dns":{"servers":[{"type":"local","tag":"local"}],"final":"local"}
        }).to_string()),
        need_extra_process:Some(false),extra_no_out:Some(true),need_xray:Some(false),disable_stats:Some(true),
        ..Default::default()
    }
}
async fn origin(label: &'static str) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let read = timeout(Duration::from_secs(3), async {
                let mut chunk = [0; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0 && request.len() + n <= 8192, "unexpected HTTP input");
                    request.extend_from_slice(&chunk[..n]);
                }
            })
            .await;
            assert!(read.is_ok());
            assert!(String::from_utf8_lossy(&request).starts_with("GET /oracle/"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{label}",
                        label.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, count, task)
}
async fn exchange(proxy: u16, destination: u16, id: usize) -> String {
    timeout(Duration::from_secs(5),async {
        let mut client=TcpStream::connect(("127.0.0.1",proxy)).await.unwrap();
        client.write_all(format!("GET http://127.0.0.1:{destination}/oracle/{id} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response=String::new();client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"),"{response}");
        response.split_once("\r\n\r\n").unwrap().1.to_owned()
    }).await.expect("owned local HTTP exchange timed out")
}

async fn held_connect(proxy: u16) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut peer, address) = listener.accept().await.unwrap();
        assert!(address.ip().is_loopback());
        let mut buffer = [0; 128];
        loop {
            let size = peer.read(&mut buffer).await.unwrap();
            if size == 0 {
                break;
            }
            peer.write_all(&buffer[..size]).await.unwrap();
        }
    });
    let mut client = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let header = timeout(Duration::from_secs(5), async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(client.read_u8().await.unwrap());
            assert!(header.len() < 4096);
        }
        header
    })
    .await
    .expect("CONNECT header timeout");
    assert!(header.starts_with(b"HTTP/1.1 200"));
    (client, task)
}

async fn held_echo(client: &mut TcpStream, sequence: u64) {
    timeout(Duration::from_secs(5), async {
        client.write_u64(sequence).await.unwrap();
        assert_eq!(client.read_u64().await.unwrap(), sequence);
    })
    .await
    .expect("same held CONNECT stopped forwarding");
}
async fn error(rpc: &mut Rpc, method: &str, request: LoadConfigReq) -> String {
    rpc.call::<_, ErrorResp>(method, request)
        .await
        .unwrap()
        .error
        .unwrap_or_default()
}
async fn stop(rpc: &mut Rpc) {
    let response: ErrorResp = rpc.call("Stop", EmptyReq {}).await.unwrap();
    assert!(response.error.unwrap_or_default().is_empty());
}
fn interface_names() -> Vec<String> {
    let mut names = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|v| v.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit pinned-core runner; real owned loopback HTTP only"]
async fn pinned_core_inline_rule_truth_table() {
    let executable = std::env::current_exe().unwrap();
    assert_eq!(
        executable.file_name().unwrap(),
        "Thronium",
        "use inline_ruleset_core_oracle.py to preserve release parent authentication"
    );
    let core = executable.parent().unwrap().join("ThroniumCore");
    let matrix: Value =
        serde_json::from_str(include_str!("fixtures/inline-ruleset/oracle-contract.json")).unwrap();
    let route_before = std::fs::read("/proc/net/route").unwrap();
    let interfaces_before = interface_names();
    let (matched, matched_count, matched_task) = origin("MATCHED").await;
    let (fallback, fallback_count, fallback_task) = origin("FALLBACK").await;
    let guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = guard.local_addr().unwrap().port();
    drop(guard);
    let working = tempfile::tempdir().unwrap();
    let mut rpc = Rpc::spawn(&core, working.path()).await.unwrap();
    let mut observations = vec![];
    for (index, case) in matrix["http"].as_array().unwrap().iter().enumerate() {
        let condition = materialize(&case["rules"], fallback);
        let request = request(
            condition.clone(),
            proxy,
            matched,
            case["omitAction"] == true,
        );
        assert_eq!(
            error(&mut rpc, "CheckConfig", request.clone()).await,
            "",
            "check {}",
            case["name"]
        );
        assert_eq!(
            error(&mut rpc, "Start", request).await,
            "",
            "start {}",
            case["name"]
        );
        let observed = exchange(proxy, fallback, index).await;
        let wanted = if case["expectedMatched"] == true {
            "MATCHED"
        } else {
            "FALLBACK"
        };
        assert_eq!(observed, wanted, "{}: {condition}", case["name"]);
        stop(&mut rpc).await;
        observations.push(json!({"name":case["name"],"condition":condition,"observed":observed,"expectedMatched":case["expectedMatched"]}));
        println!("PASS HTTP {} => {observed}", case["name"].as_str().unwrap());
    }
    // Keep a known forwarding configuration alive while invalid nested edits
    // are checked. CheckConfig must neither silently accept nor replace it.
    let baseline = request(json!([{"network":"udp"}]), proxy, matched, false);
    assert_eq!(error(&mut rpc, "Start", baseline).await, "");
    assert_eq!(exchange(proxy, fallback, 1000).await, "FALLBACK");
    let (mut held, held_task) = held_connect(proxy).await;
    held_echo(&mut held, 0).await;
    let mut rejected = vec![];
    for (index, case) in matrix["invalidCheck"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let condition = materialize(&case["rules"], fallback);
        let problem = error(
            &mut rpc,
            "CheckConfig",
            request(condition.clone(), proxy, matched, false),
        )
        .await;
        assert!(
            !problem.is_empty(),
            "invalid headless edit accepted: {}",
            case["name"]
        );
        assert_eq!(exchange(proxy, fallback, 1001 + index).await, "FALLBACK");
        held_echo(&mut held, (index + 1) as u64).await;
        rejected.push(json!({"name":case["name"],"error":problem}));
        println!(
            "PASS invalid {} rejected, current HTTP survives",
            case["name"].as_str().unwrap()
        );
    }
    held.shutdown().await.unwrap();
    drop(held);
    timeout(Duration::from_secs(5), held_task)
        .await
        .expect("owned CONNECT peer cleanup")
        .unwrap();
    stop(&mut rpc).await;
    rpc.terminate().await;
    assert!(!rpc.is_alive());
    matched_task.abort();
    fallback_task.abort();
    let _ = matched_task.await;
    let _ = fallback_task.await;
    assert_eq!(std::fs::read("/proc/net/route").unwrap(), route_before);
    assert_eq!(interface_names(), interfaces_before);
    let packets = matched_count.load(Ordering::SeqCst) + fallback_count.load(Ordering::SeqCst);
    assert_eq!(packets, 20 + 1 + 33);
    println!(
        "INLINE_HTTP_ORACLE_JSON {}",
        json!({"httpCases":observations,"invalidCases":rejected,
        "httpResponses":packets,"matchedResponses":matched_count.load(Ordering::SeqCst),"fallbackResponses":fallback_count.load(Ordering::SeqCst),
        "currentConfigurationSurvivedInvalidChecks":33,"heldCONNECTSurvivedInvalidChecks":33,"heldEchoExchanges":34,"coreExited":true,"hostRoutesUnchanged":true,"interfaceNamesUnchanged":true,
        "scope":"Raw LoadConfigReq and literal loopback HTTP; no UI model, Engine routing compiler, TUN, DNS queries or external network."})
    );
}
