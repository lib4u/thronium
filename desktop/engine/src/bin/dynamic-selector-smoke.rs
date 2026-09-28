//! Dynamic pool membership through the production core and loopback-only fixtures.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use thronium_engine::{
    exports, routing::Rule, store::ProfileKind, subscriptions::GroupDraft, Engine, ProfileDraft,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
type Seen = Arc<Mutex<Vec<(usize, u16)>>>;
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn draft(
    id: Option<String>,
    group: &str,
    name: &str,
    kind: ProfileKind,
    config: Value,
) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id,
        name: name.into(),
        group_id: group.into(),
        kind,
        config,
    }
}
fn add(
    e: &mut Engine,
    group: &str,
    name: &str,
    kind: ProfileKind,
    config: Value,
) -> Result<String, String> {
    e.save_profile(draft(None, group, name, kind, config))
}
fn group(e: &mut Engine, name: &str) -> Result<String, String> {
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        id: None,
        name: name.into(),
        subscription: None,
        proxy_chain: None,
    })
}
async fn socks(
    index: usize,
    seen: Seen,
    allowed: Arc<Mutex<Vec<u16>>>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            let allowed = allowed.clone();
            tokio::spawn(async move {
                let result: std::io::Result<()> = async {
                    let mut hello = [0; 2];
                    client.read_exact(&mut hello).await?;
                    if hello[0] != 5 {
                        return Err(std::io::Error::other("unexpected SOCKS version"));
                    }
                    let mut methods = vec![0; hello[1] as usize];
                    client.read_exact(&mut methods).await?;
                    client.write_all(&[5, 0]).await?;
                    let mut request = [0; 4];
                    client.read_exact(&mut request).await?;
                    if request != [5, 1, 0, 1] {
                        return Err(std::io::Error::other(
                            "only local IPv4 CONNECT is permitted",
                        ));
                    }
                    let mut address = [0; 4];
                    client.read_exact(&mut address).await?;
                    let target = client.read_u16().await?;
                    if address != [127, 0, 0, 1] || !allowed.lock().unwrap().contains(&target) {
                        return Err(std::io::Error::other("outside fixture"));
                    }
                    seen.lock().unwrap().push((index, target));
                    let mut upstream = TcpStream::connect(("127.0.0.1", target)).await?;
                    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok(())
                }
                .await;
                let _ = result;
            });
        }
    });
    (port, task)
}
async fn tunnel(proxy: u16, echo: u16) -> Result<TcpStream, String> {
    let mut socket = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    socket
        .write_all(
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nHost: 127.0.0.1:{echo}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut response = vec![];
    timeout(Duration::from_secs(5), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(socket.read_u8().await?);
            if response.len() > 8192 {
                return Err(std::io::Error::other("large CONNECT response"));
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| "CONNECT timeout")?
    .map_err(|e| e.to_string())?;
    assert!(
        String::from_utf8_lossy(&response).contains("200"),
        "{response:?}"
    );
    Ok(socket)
}
async fn echo(socket: &mut TcpStream, text: &str) -> Result<(), String> {
    socket
        .write_all(text.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut response = vec![0; text.len()];
    timeout(Duration::from_secs(4), socket.read_exact(&mut response))
        .await
        .map_err(|_| "echo timeout")?
        .map_err(|e| e.to_string())?;
    assert_eq!(response, text.as_bytes());
    Ok(())
}
async fn wait(e: &mut Engine, predicate: impl Fn(&Value) -> bool) -> Result<Value, String> {
    for _ in 0..120 {
        let groups = e.auto_selectors().await?;
        if let Some(g) = groups.as_array().unwrap().iter().find(|g| predicate(g)) {
            return Ok(g.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "dynamic pool status timeout: {}",
        e.auto_selectors().await?
    ))
}
fn member_ids(status: &Value) -> Vec<String> {
    status["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["profileId"].as_str().unwrap().to_string())
        .collect()
}
fn route_seen(seen: &Seen, ports: &[u16], member: usize, echo_port: u16) {
    let seen = seen.lock().unwrap();
    for item in [(0, ports[member]), (member, ports[3]), (3, echo_port)] {
        assert!(seen.contains(&item), "missing {item:?} from {seen:?}");
    }
}
#[tokio::main]
async fn main() -> Result<(), String> {
    let core = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "ThroniumCore.exe"
        } else {
            "ThroniumCore"
        });
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let http_task = tokio::spawn(async move {
        loop {
            let (mut s, _) = http.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                let _ = s.read(&mut buffer).await;
                let _=s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            });
        }
    });
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut s, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = s.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let seen: Seen = Default::default();
    let allowed = Arc::new(Mutex::new(vec![http_port, echo_port]));
    let mut ports = vec![];
    let mut tasks = vec![];
    for i in 0..4 {
        let (p, t) = socks(i, seen.clone(), allowed.clone()).await;
        ports.push(p);
        tasks.push(t);
        allowed.lock().unwrap().push(p);
    }
    let directory = tempfile::tempdir().unwrap();
    let mut e = Engine::open(directory.path(), &core)?;
    let proxy = port();
    let mut preferences = e.store.library.preferences.clone();
    preferences.inbound_port = proxy;
    e.preferences(preferences)?;
    let source = group(&mut e, "Dynamic source")?;
    let owner = group(&mut e, "Dynamic owner")?;
    let sing_config = |index: usize| json!({"type":"socks","server":"127.0.0.1","server_port":ports[index],"version":"5"});
    let front = add(
        &mut e,
        "personal",
        "Front",
        ProfileKind::SingBoxOutbound,
        sing_config(0),
    )?;
    let landing = add(
        &mut e,
        "personal",
        "Landing",
        ProfileKind::SingBoxOutbound,
        sing_config(3),
    )?;
    e.save_group(serde_json::from_value(json!({"id":owner,"name":"Dynamic owner","proxyChain":{"front":front,"landing":landing}})).unwrap())?;
    let a = add(
        &mut e,
        &source,
        "Match Alpha",
        ProfileKind::SingBoxOutbound,
        sing_config(1),
    )?;
    let b = add(
        &mut e,
        &source,
        "Match Beta",
        ProfileKind::XrayOutbound,
        json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":ports[2]}}),
    )?;
    let skipped = add(
        &mut e,
        &source,
        "Match Skip",
        ProfileKind::SingBoxOutbound,
        sing_config(1),
    )?;
    add(
        &mut e,
        "personal",
        "Match other group",
        ProfileKind::SingBoxOutbound,
        sing_config(1),
    )?;
    add(
        &mut e,
        &source,
        "Match opaque",
        ProfileKind::SingBoxConfig,
        json!({"outbounds":[{"type":"direct"}]}),
    )?;
    add(
        &mut e,
        &source,
        "Match chain",
        ProfileKind::Chain,
        json!({"type":"chain","hops":[skipped]}),
    )?;
    let config = json!({"type":"auto-selector","member_source":{"group_id":source,"name_regex":"^Match ","exclude_regex":"Skip"},"url":format!("http://127.0.0.1:{http_port}/health"),"interval":"1s","bench_interval":"2s","watch_interval":"500ms","timeout":"800ms","sampling":2,"expected":2,"active_size":5,"concurrency":5,"interrupt_exist_connections":false});
    let id = add(
        &mut e,
        &owner,
        "Dynamic fixture",
        ProfileKind::AutoSelector,
        config.clone(),
    )?;
    e.check(&e.profile(&id)?).await?;
    e.connect(&id).await?;
    let ready = wait(&mut e, |g| g["membersAlive"] == 2).await?;
    assert_eq!(member_ids(&ready), vec![a.clone(), b.clone()]);
    println!("PASS group and include/exclude regex resolve only ordinary sing-box/Xray profiles in library order");
    for (member, index) in [(&a, 1), (&b, 2)] {
        let tag = thronium_engine::auto_selector::member_tag("proxy", member);
        e.auto_selector_action("proxy", "select", &tag).await?;
        wait(&mut e, |g| g["selected"] == tag).await?;
        seen.lock().unwrap().clear();
        let mut socket = tunnel(proxy, echo_port).await?;
        echo(&mut socket, "mixed-dynamic").await?;
        route_seen(&seen, &ports, index, echo_port);
    }
    println!("PASS dynamic sing-box and Xray members carry real traffic through group front and landing proxies");
    let since = e.snapshot().since;
    let mut open = tunnel(proxy, echo_port).await?;
    echo(&mut open, "before-edit").await?;
    let c = add(
        &mut e,
        &source,
        "Match Gamma",
        ProfileKind::SingBoxOutbound,
        sing_config(1),
    )?;
    let d = add(
        &mut e,
        &source,
        "Dormant Delta",
        ProfileKind::XrayOutbound,
        json!({"protocol":"socks","settings":{"address":"127.0.0.1","port":ports[2]}}),
    )?;
    let old = e.profile(&d)?;
    e.save_profile(draft(
        Some(d.clone()),
        &source,
        "Match Delta",
        old.kind,
        old.config,
    ))?;
    echo(&mut open, "after-add-and-rename").await?;
    assert_eq!(e.snapshot().since, since);
    assert_eq!(
        member_ids(&e.auto_selectors().await?[0]),
        vec![a.clone(), b.clone()]
    );
    assert_eq!(
        e.delete_profiles(vec![a.clone()]).unwrap_err(),
        "stop_before_editing"
    );
    println!("PASS additions and renaming unused candidates preserve the open socket and frozen live membership; running members remain protected");
    let library = serde_json::to_value(&e.store.library).unwrap();
    for (key, value, error) in [
        (
            "member_source",
            json!({"group_id":source,"name_regex":"[","exclude_regex":""}),
            "selector_invalid_regex",
        ),
        ("members", json!([a]), "invalid_selector_source"),
        ("pinned_profile", json!(a), "invalid_selector_pin"),
    ] {
        let mut invalid = config.clone();
        invalid[key] = value;
        assert_eq!(
            add(
                &mut e,
                &owner,
                "Invalid dynamic",
                ProfileKind::AutoSelector,
                invalid
            )
            .unwrap_err(),
            error
        );
        assert_eq!(serde_json::to_value(&e.store.library).unwrap(), library);
        echo(&mut open, "invalid-stays-live").await?;
    }
    assert_eq!(
        e.delete_group(&source, true).unwrap_err(),
        "selector_source_in_use"
    );
    println!("PASS invalid regex, ambiguous sources, persisted dynamic pin and referenced group deletion fail atomically without disturbing traffic");
    let mut empty_config = config.clone();
    empty_config["member_source"]["name_regex"] = json!("^No candidate$");
    let empty = add(
        &mut e,
        "personal",
        "Empty dynamic",
        ProfileKind::AutoSelector,
        empty_config,
    )?;
    assert_eq!(e.connect(&empty).await.unwrap_err(), "selector_empty_pool");
    assert_eq!(e.snapshot().running.as_ref(), Some(&id));
    assert_eq!(e.snapshot().since, since);
    echo(&mut open, "empty-stays-live").await?;
    println!("PASS empty dynamic pool can be saved but connecting rejects it before closing the existing listener or CONNECT socket");
    let large_source = group(&mut e, "Growing subscription")?;
    let mut large_config = config.clone();
    large_config["member_source"] =
        json!({"group_id":large_source,"name_regex":"","exclude_regex":""});
    let large_pool = add(
        &mut e,
        "personal",
        "Growing dynamic pool",
        ProfileKind::AutoSelector,
        large_config.clone(),
    )?;
    let batch = (0..501)
        .map(|index| {
            draft(
                None,
                &large_source,
                &format!("Candidate {index}"),
                ProfileKind::SingBoxOutbound,
                sing_config(1),
            )
        })
        .collect();
    let imported_candidates = e.import_profiles(batch)?;
    assert_eq!(imported_candidates.len(), 501);
    assert_eq!(
        e.preview_selector(draft(
            Some(large_pool.clone()),
            "personal",
            "Growing dynamic pool",
            ProfileKind::AutoSelector,
            large_config
        ))
        .unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(
        e.connect(&large_pool).await.unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(e.snapshot().running.as_ref(), Some(&id));
    assert_eq!(e.snapshot().since, since);
    echo(&mut open, "oversized-stays-live").await?;
    println!("PASS a subscription can grow beyond 500 candidates while oversized preview and connect fail explicitly without truncation or interrupting live traffic");
    e.delete_profiles(vec![large_pool])?;
    e.delete_group(&large_source, true)?;
    e.disconnect().await?;
    drop(open);
    let old = e.profile(&b)?;
    e.save_profile(draft(
        Some(b.clone()),
        &source,
        "No longer matches",
        old.kind,
        old.config,
    ))?;
    e.delete_profiles(vec![a.clone()])?;
    e.connect(&id).await?;
    let ready = wait(&mut e, |g| g["membersAlive"] == 2).await?;
    assert_eq!(member_ids(&ready), vec![c.clone(), d.clone()]);
    let mut socket = tunnel(proxy, echo_port).await?;
    echo(&mut socket, "refreshed").await?;
    println!("PASS reconnect refreshes added, renamed and removed candidates and forwards through the new fixed runtime pool");
    e.disconnect().await?;
    let direct = add(
        &mut e,
        "personal",
        "Routing root",
        ProfileKind::SingBoxOutbound,
        json!({"type":"direct"}),
    )?;
    let mut routing = e.routing();
    routing.profiles[0].rules = vec![Rule {
        id: "dynamic-route".into(),
        name: "Dynamic target".into(),
        enabled: true,
        simple: None,
        config: json!({"ip_cidr":["127.0.0.0/8"],"action":"route","outbound":format!("profile:{id}")}),
    }];
    e.check_routing(routing.profiles[0].clone()).await?;
    e.save_routing(routing)?;
    e.connect(&direct).await?;
    let route_tag = format!("thronium-route-{id}");
    let ready = wait(&mut e, |g| g["tag"] == route_tag && g["membersAlive"] == 2).await?;
    assert_eq!(member_ids(&ready), vec![c.clone(), d.clone()]);
    let pinned = thronium_engine::auto_selector::member_tag(&route_tag, &d);
    e.auto_selector_action(&route_tag, "select", &pinned)
        .await?;
    wait(&mut e, |g| g["selected"] == pinned).await?;
    seen.lock().unwrap().clear();
    let mut socket = tunnel(proxy, echo_port).await?;
    echo(&mut socket, "routed-dynamic").await?;
    route_seen(&seen, &ports, 2, echo_port);
    println!("PASS routing targets resolve dynamic pools with mixed-core runtime controls and group proxy order");
    let text = e.export_profiles(vec![id.clone()], exports::Format::Profiles)?;
    let mut bundle: Value = serde_json::from_str(&text).unwrap();
    assert!(!text.contains("member_source"));
    assert!(!text.contains(&source));
    for old in [&id, &c, &d, &front, &landing] {
        assert!(!text.contains(old));
    }
    let index = bundle["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .position(|p| p["kind"] == "auto-selector")
        .unwrap();
    assert_eq!(
        bundle["profiles"][index]["config"]["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for profile in bundle["profiles"].as_array_mut().unwrap() {
        profile["groupId"] = json!("personal");
    }
    let imported_dir = tempfile::tempdir().unwrap();
    let mut imported = Engine::open(imported_dir.path(), &core)?;
    let imported_port = port();
    let mut preferences = imported.store.library.preferences.clone();
    preferences.inbound_port = imported_port;
    imported.preferences(preferences)?;
    let count = imported.store.library.profiles.len();
    imported
        .check_import_profile(
            serde_json::from_value(bundle["profiles"].clone()).unwrap(),
            index,
        )
        .await?;
    assert_eq!(imported.store.library.profiles.len(), count);
    let ids = imported
        .import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())?;
    e.disconnect().await?;
    let mut routing = e.routing();
    routing.profiles[0].rules.clear();
    e.save_routing(routing)?;
    e.delete_profiles(vec![id, empty])?;
    e.delete_group(&source, true)?;
    imported.connect(&ids[index]).await?;
    wait(&mut imported, |g| g["membersAlive"] == 2).await?;
    seen.lock().unwrap().clear();
    let mut socket = tunnel(imported_port, echo_port).await?;
    echo(&mut socket, "portable").await?;
    assert!(seen.lock().unwrap().contains(&(3, echo_port)));
    println!("PASS portable export freezes current members and wrappers, remaps all references, previews without saving and works after deleting its original source group");
    imported.shutdown().await;
    let vless_dir = tempfile::tempdir().unwrap();
    let mut vless_server = Engine::open(vless_dir.path(), &core)?;
    let vless_port = port();
    allowed.lock().unwrap().push(vless_port);
    let uuid = "00000000-0000-0000-0000-000000000007";
    let server_id = add(
        &mut vless_server,
        "personal",
        "Loopback VLESS service",
        ProfileKind::SingBoxConfig,
        json!({
            "log":{"level":"warn"},
            "inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":vless_port,"users":[{"uuid":uuid}]}],
            "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}
        }),
    )?;
    vless_server.connect(&server_id).await?;
    let vless_source = group(&mut e, "VLESS dynamic source")?;
    let member = add(
        &mut e,
        &vless_source,
        "VLESS candidate",
        ProfileKind::SingBoxOutbound,
        json!({"type":"vless","server":"127.0.0.1","server_port":vless_port,"uuid":uuid}),
    )?;
    let mut vless_config = config.clone();
    vless_config["member_source"] =
        json!({"group_id":vless_source,"name_regex":"","exclude_regex":""});
    let vless_pool = add(
        &mut e,
        &owner,
        "Dynamic VLESS core choice",
        ProfileKind::AutoSelector,
        vless_config,
    )?;
    for choice in [
        thronium_engine::vless::Core::SingBox,
        thronium_engine::vless::Core::Xray,
    ] {
        e.vless_core(&member, Some(choice))?;
        e.connect(&vless_pool).await?;
        wait(&mut e, |g| g["membersAlive"] == 1).await?;
        seen.lock().unwrap().clear();
        let mut socket = tunnel(proxy, echo_port).await?;
        echo(&mut socket, "dynamic-vless-core-choice").await?;
        assert!(seen.lock().unwrap().contains(&(0, vless_port)));
        assert!(seen.lock().unwrap().contains(&(3, echo_port)));
        e.disconnect().await?;
    }
    println!("PASS the same dynamic VLESS member forwards through real sing-box and Xray core choices with front and landing proxies");
    vless_server.shutdown().await;
    e.shutdown().await;
    http_task.abort();
    echo_task.abort();
    for task in tasks {
        task.abort();
    }
    Ok(())
}
