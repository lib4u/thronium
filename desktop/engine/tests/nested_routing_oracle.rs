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
    net::{TcpListener, TcpStream},
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
fn request(condition: Value, proxy: u16, matched: u16, omit_action: bool) -> LoadConfigReq {
    let mut rule = condition;
    rule["outbound"] = json!("direct");
    rule["override_port"] = json!(matched);
    if !omit_action {
        rule["action"] = json!("route");
    }
    LoadConfigReq {
        core_config:Some(json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"mixed","tag":"oracle-in","listen":"127.0.0.1","listen_port":proxy}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct","rules":[rule]},
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
async fn pinned_core_nested_rule_truth_table() {
    let executable = std::env::current_exe().unwrap();
    assert_eq!(
        executable.file_name().unwrap(),
        "Thronium",
        "use test_nested_routing.py to preserve release parent authentication"
    );
    let core = executable.parent().unwrap().join("ThroniumCore");
    let matrix: Value =
        serde_json::from_str(include_str!("fixtures/nested-routing/matrix.json")).unwrap();
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
        let condition = materialize(&case["condition"], fallback);
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
    let baseline = request(json!({"network":"udp"}), proxy, matched, false);
    assert_eq!(error(&mut rpc, "Start", baseline).await, "");
    assert_eq!(exchange(proxy, fallback, 1000).await, "FALLBACK");
    let mut rejected = vec![];
    for (index, case) in matrix["invalid"].as_array().unwrap().iter().enumerate() {
        let condition = materialize(&case["condition"], fallback);
        let problem = error(
            &mut rpc,
            "CheckConfig",
            request(condition.clone(), proxy, matched, false),
        )
        .await;
        assert!(
            !problem.is_empty(),
            "invalid nested edit accepted: {}",
            case["name"]
        );
        let fragment = case["expectedErrorContains"].as_str().unwrap();
        assert!(problem.contains(fragment), "{}: {problem}", case["name"]);
        assert_eq!(exchange(proxy, fallback, 1001 + index).await, "FALLBACK");
        rejected.push(json!({"name":case["name"],"error":problem}));
        println!(
            "PASS invalid {} rejected, current HTTP survives",
            case["name"].as_str().unwrap()
        );
    }
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
    assert_eq!(packets, 32 + 1 + 13);
    println!(
        "NESTED_ORACLE_JSON {}",
        json!({"httpCases":observations,"invalidCases":rejected,
        "httpResponses":packets,"matchedResponses":matched_count.load(Ordering::SeqCst),"fallbackResponses":fallback_count.load(Ordering::SeqCst),
        "currentConfigurationSurvivedInvalidChecks":13,"coreExited":true,"hostRoutesUnchanged":true,"interfaceNamesUnchanged":true,
        "scope":"Raw LoadConfigReq and literal loopback HTTP; no UI model, Engine routing compiler, TUN, DNS queries or external network."})
    );
}
