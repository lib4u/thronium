//! Real routing assertions. The runner renames this process to Thronium.
use serde_json::json;
use thronium_engine::{
    routing::{RoutingProfile, Rule},
    store::ProfileKind,
    Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

async fn exchange(proxy: u16, allowed: bool) -> Result<(), String> {
    exchange_host(proxy, allowed, false).await
}
async fn exchange_host(proxy: u16, allowed: bool, domain: bool) -> Result<(), String> {
    let origin = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let address = origin.local_addr().unwrap();
    let target = if domain {
        format!("routing.test:{}", address.port())
    } else {
        address.to_string()
    };
    let mut client = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    client
        .write_all(
            format!(
                "GET http://{target}/route HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    if allowed {
        let (mut socket, _) = timeout(Duration::from_secs(3), origin.accept())
            .await
            .map_err(|_| "routed_connection_did_not_reach_origin")?
            .unwrap();
        let mut buf = [0; 4096];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET /route"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nrouted")
            .await
            .unwrap();
        drop(socket);
        let mut response = String::new();
        timeout(Duration::from_secs(3), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with("routed"));
    } else {
        let mut response = Vec::new();
        let _ = timeout(Duration::from_secs(2), client.read_to_end(&mut response)).await;
        assert!(
            timeout(Duration::from_millis(200), origin.accept())
                .await
                .is_err(),
            "blocked traffic reached its destination"
        );
        assert!(!String::from_utf8_lossy(&response).contains("200 OK"));
    }
    Ok(())
}
/// A SOCKS client that resolved the name itself: it connects to the address and
/// names the site only in its HTTP request, as TUN traffic arrives.
async fn exchange_sniffed(proxy: u16, host: &str, allowed: bool) -> Result<(), String> {
    let origin = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = origin.local_addr().unwrap().port();
    let mut client = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend(port.to_be_bytes());
    client.write_all(&connect).await.unwrap();
    client
        .write_all(
            format!("GET /route HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    if allowed {
        let (mut socket, _) = timeout(Duration::from_secs(3), origin.accept())
            .await
            .map_err(|_| "sniffed_connection_did_not_reach_origin")?
            .unwrap();
        let mut buf = [0; 4096];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains(&format!("Host: {host}")));
    } else {
        let mut response = Vec::new();
        let _ = timeout(Duration::from_secs(2), client.read_to_end(&mut response)).await;
        assert!(
            timeout(Duration::from_millis(200), origin.accept())
                .await
                .is_err(),
            "an unmatched host reached its destination"
        );
    }
    Ok(())
}
fn rule(id: &str, config: serde_json::Value) -> Rule {
    Rule {
        id: id.into(),
        name: id.into(),
        enabled: true,
        simple: None,
        config,
    }
}
async fn change(engine: &mut Engine, r: RoutingProfile, apply: bool) -> Result<(), String> {
    engine.check_routing(r.clone()).await?;
    let mut next = engine.routing();
    let index = next.profiles.iter().position(|p| p.id == r.id).unwrap();
    next.profiles[index] = r;
    engine.save_routing(next)?;
    if apply {
        engine.apply_routing().await?;
    }
    Ok(())
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
    if let Some(path) = std::env::args().nth(1) {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let fixtures: Vec<RoutingProfile> =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let mut failures = Vec::new();
        let live = std::env::args().any(|s| s == "--start");
        let selected = if live {
            let guard = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut prefs = engine.store.library.preferences.clone();
            prefs.inbound_port = guard.local_addr().unwrap().port();
            engine.preferences(prefs)?;
            drop(guard);
            Some(engine.save_profile(ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: "Catalog validation".into(),
                group_id: "personal".into(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"direct"}),
            })?)
        } else {
            None
        };
        for fixture in fixtures {
            let name = fixture.name.clone();
            match engine.check_routing(fixture.clone()).await {
                Ok(()) => {
                    if let Some(id) = selected.as_ref() {
                        let mut next = engine.routing();
                        next.active = fixture.id.clone();
                        next.profiles = vec![fixture];
                        engine.save_routing(next)?;
                        match engine.connect(id).await {
                            Ok(()) => {
                                println!("PASS live routing sources and core start: {name}");
                                engine.disconnect().await?;
                            }
                            Err(error) => failures.push(format!("{name}: {error}")),
                        }
                    } else {
                        println!("PASS routing schema: {name}");
                    }
                }
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }
        engine.shutdown().await;
        return if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n"))
        };
    }
    let guard = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = guard.local_addr().unwrap().port();
    let mut prefs = engine.store.library.preferences.clone();
    prefs.inbound_port = port;
    engine.preferences(prefs)?;
    drop(guard);
    let primary = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Unavailable selected SOCKS".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks", "server":"127.0.0.1", "server_port":1, "version":"5"}),
    })?;
    let aux = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Auxiliary direct".into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
    })?;
    let xray = engine.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Auxiliary Xray".into(),
        group_id: "personal".into(),
        kind: ProfileKind::XrayOutbound,
        config: json!({"protocol":"freedom", "settings":{}}),
    })?;
    let mut routing = engine.routing().active()?.clone();
    routing.rules = vec![rule(
        "loopback",
        json!({"ip_cidr":["127.0.0.0/8"], "action":"route", "outbound":"direct"}),
    )];
    change(&mut engine, routing.clone(), false).await?;
    engine.connect(&primary).await?;
    exchange(port, true).await?;
    println!("PASS direct rule bypasses an unavailable selected proxy");
    routing.rules[0].config["outbound"] = json!(format!("profile:{aux}"));
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    assert!(engine.delete(&aux).is_err());
    println!("PASS rule selects a separate sing-box profile and protects its reference");
    routing.rules[0].config["outbound"] = json!(format!("profile:{xray}"));
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS rule selects an auxiliary Xray profile through its own bridge");
    routing.rules.insert(
        0,
        rule(
            "block",
            json!({"ip_cidr":["127.0.0.0/8"], "action":"reject", "method":"default"}),
        ),
    );
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, false).await?;
    println!("PASS earlier reject rule blocks actual traffic");
    routing.rules.swap(0, 1);
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS moving route before reject changes real forwarding");
    routing.rules[0].enabled = false;
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, false).await?;
    println!("PASS disabled route is omitted from active configuration");
    routing.mode = "direct".into();
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS Direct mode bypasses stored reject rules");
    routing.mode = "all".into();
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, false).await?;
    println!("PASS All traffic mode uses the selected proxy rather than a stored direct rule");
    routing.mode = "rules".into();
    routing.rules[0].enabled = true;
    change(&mut engine, routing.clone(), true).await?;
    let before = engine.snapshot().since;
    let mut invalid = routing.clone();
    invalid.rules[0].config = json!({"domain_regex":["["], "action":"reject"});
    assert!(engine.check_routing(invalid.clone()).await.is_err());
    // Even an invalid candidate staged by a caller cannot tear down a valid session on apply.
    let mut staged = engine.routing();
    staged.profiles[0] = invalid;
    engine.save_routing(staged)?;
    assert!(engine.snapshot().routing["pending"].as_bool().unwrap());
    assert!(engine.apply_routing().await.is_err());
    assert_eq!(engine.snapshot().since, before);
    exchange(port, true).await?;
    println!("PASS invalid routing preserves the running connection and remains visibly pending");
    change(&mut engine, routing.clone(), true).await?;
    let stale = engine.routing();
    engine.save_routing(stale.clone())?;
    assert!(engine.save_routing(stale).is_err());
    println!("PASS stale routing saves are rejected instead of overwriting a newer revision");
    routing.rules = vec![rule(
        "hosts",
        json!({"domain":["routing.test"], "action":"route", "outbound":"direct"}),
    )];
    routing.dns = json!({"servers":[{"type":"hosts", "tag":"test-hosts", "predefined":{"routing.test":"127.0.0.1"}}], "final":"test-hosts"});
    routing.route["default_domain_resolver"] = json!("test-hosts");
    change(&mut engine, routing.clone(), true).await?;
    exchange_host(port, true, true).await?;
    println!("PASS DNS hosts resolution directs an actual domain request to the local origin");
    // The sniff every structured route starts with gives a connection made to an
    // address its HTTP host, so a domain rule decides it instead of the final proxy.
    routing.rules = vec![rule(
        "sniffed",
        json!({"domain":["sniffed.test"], "action":"route", "outbound":"direct"}),
    )];
    change(&mut engine, routing.clone(), true).await?;
    exchange_sniffed(port, "sniffed.test", true).await?;
    exchange_sniffed(port, "other.test", false).await?;
    println!("PASS a domain rule matches a connection to an address by its sniffed host");
    routing.route["rule_set"] =
        json!([{"type":"inline", "tag":"local-test", "rules":[{"ip_cidr":["127.0.0.0/8"]}]}]);
    routing.rules = vec![rule(
        "set",
        json!({"rule_set":["local-test"], "action":"route", "outbound":"direct"}),
    )];
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS inline rule-set matches actual traffic");
    let file = dir.path().join("rules.json");
    let rule_set_data = json!({"version":3, "rules":[{"ip_cidr":["127.0.0.0/8"]}]}).to_string();
    std::fs::write(&file, &rule_set_data).unwrap();
    routing.route["rule_set"] =
        json!([{"type":"local", "tag":"local-test", "format":"source", "path":file}]);
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS local rule-set file is loaded and applied by the core");
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = server.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let _ = socket.read(&mut buffer).await;
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", rule_set_data.len(), rule_set_data);
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    routing.route["rule_set"] = json!([{"type":"remote", "tag":"local-test", "format":"source", "url":format!("http://{addr}/rules.json"), "download_detour":"direct"}]);
    change(&mut engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    server_task.abort();
    println!("PASS remote rule-set is fetched from an isolated loopback server and applied");
    geodata_checks(&mut engine, &mut routing, port, &xray).await?;
    engine.disconnect().await?;
    engine.shutdown().await;
    let saved = serde_json::to_value(engine.routing()).unwrap();
    drop(engine);
    let engine = Engine::open(dir.path(), &core)?;
    assert_eq!(serde_json::to_value(engine.routing()).unwrap(), saved);
    println!("PASS routing survives native storage restart");
    Ok(())
}

async fn geodata_checks(
    engine: &mut Engine,
    routing: &mut RoutingProfile,
    port: u16,
    xray: &str,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = std::sync::Arc::new(std::sync::Mutex::new(
        STANDARD
            .decode("ChgKBFRFU1QSEAgDEgxyb3V0aW5nLnRlc3Q=")
            .unwrap(),
    ));
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let current = bytes.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = server.accept().await.unwrap();
            let mut request = [0; 2048];
            let _ = socket.read(&mut request).await;
            let data = current.lock().unwrap().clone();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                data.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&data).await;
        }
    });
    let url = format!("http://{address}/geosite.dat");
    engine
        .load_geodata(json!({"kind":"geosite","url":url}))
        .await?;
    routing.route["rule_set"] =
        json!([{"type":"geodata","tag":"site","kind":"geosite","url":url,"category":"test"}]);
    routing.rules = vec![rule(
        "site",
        json!({"rule_set":["site"],"action":"route","outbound":"direct"}),
    )];
    change(engine, routing.clone(), true).await?;
    exchange_host(port, true, true).await?;
    println!("PASS downloaded GeoSite category routes real domain traffic with sing-box");
    routing.rules[0].config["outbound"] = json!(format!("profile:{xray}"));
    change(engine, routing.clone(), true).await?;
    exchange_host(port, true, true).await?;
    println!("PASS GeoSite category forwards actual traffic through the Xray bridge");
    *bytes.lock().unwrap() = STANDARD.decode("ChYKBFRFU1QSDggDEgpvdGhlci50ZXN0").unwrap();
    engine
        .load_geodata(json!({"kind":"geosite","url":url,"force":true}))
        .await?;
    assert_eq!(engine.snapshot().routing["pending"], true);
    exchange_host(port, true, true).await?;
    engine.apply_routing().await?;
    exchange_host(port, false, true).await?;
    println!(
        "PASS source update preserves the running rules until reconnect and then uses new data"
    );
    *bytes.lock().unwrap() = b"not a database".to_vec();
    assert!(engine
        .load_geodata(json!({"kind":"geosite","url":url,"force":true}))
        .await
        .is_err());
    assert!(engine
        .geodata_category(json!({"kind":"geosite","url":url,"category":"test"}))?
        .to_string()
        .contains("other.test"));
    task.abort();
    println!("PASS broken source update leaves the last valid database available offline");
    let ip = engine
        .load_geodata(
            json!({"kind":"geoip","data":"ChQKCExPT1BCQUNLEggKBH8AAAAQCA==","name":"local-ip.dat"}),
        )
        .await?;
    routing.route["rule_set"] =
        json!([{"type":"geodata","tag":"ip","kind":"geoip","url":ip["url"],"category":"loopback"}]);
    routing.rules = vec![rule("ip", json!({"rule_set":["ip"],"action":"reject"}))];
    change(engine, routing.clone(), false).await?;
    engine.connect(xray).await?;
    exchange(port, false).await?;
    routing.rules[0].config = json!({"rule_set":["ip"],"action":"route","outbound":"proxy"});
    change(engine, routing.clone(), true).await?;
    exchange(port, true).await?;
    println!("PASS local GeoIP category blocks and permits real traffic with Xray selected");
    let exported = engine.export_routing_profile(&routing.id)?;
    assert_eq!(
        exported["profile"]["route"]["rule_set"][0]["type"],
        "inline"
    );
    let copied: RoutingProfile = serde_json::from_value(exported["profile"].clone()).unwrap();
    engine.check_routing(copied).await?;
    println!("PASS exporting local .dat categories produces portable editable rule sets accepted by the core");
    Ok(())
}
