//! Two distinct paths with settings-owned WARP, including DNS over the tunnel.
use super::{exchange, wireguard::spawn_peer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use thronium_engine::{
    backups::legacy::{self, Scopes, SettingsScopes},
    legacy_backup::{
        Parts, SourceArchive, SourceDatabase, SourceRoute, SourceSetting, SourceValue,
    },
    routing::Rule,
    settings, Engine,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

pub(super) async fn run(
    e: &mut Engine,
    proxy: u16,
    selected: &str,
    origin: u16,
    fixture: &std::ffi::OsStr,
) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let (mut peer, info) = spawn_peer(
        fixture,
        dir.path(),
        json!({"subnet":47,"noPresharedKey":true,"dns":true}),
    )
    .await?;
    let previous = settings::section(&e.store.library, "intercept");
    let previous_routing = e.routing();
    e.select(selected)?;
    let import_only = std::env::args().any(|arg| arg == "--warp-import");
    for global in [false, true].into_iter().filter(|_| !import_only) {
        let current = settings::section(&e.store.library, "intercept");
        let mut next = current.clone();
        next["enable_warp"] = json!(global);
        next["warp_private_key"] = info["profile"]["private_key"].clone();
        next["warp_public_key"] = info["profile"]["peers"][0]["public_key"].clone();
        next["warp_ep"] = info["endpoint"].clone();
        next["warp_ifc_addrs"] = info["profile"]["address"].clone();
        next["warp_reserved"] = json!([]);
        e.save_settings("intercept", current, next).await?;
        for mode in ["domain", "process", "default"] {
            let mut routing = e.routing();
            let active = routing
                .profiles
                .iter_mut()
                .find(|p| p.id == routing.active)
                .unwrap();
            active.mode = "rules".into();
            active.route = json!({"final":if mode == "default" { "warp" } else { "direct" },"find_process":true,"auto_detect_interface":true,"default_domain_resolver":"warp-dns"});
            active.dns = json!({"servers":[{"tag":"warp-dns","type":"udp","server":info["tunnel4"],"server_port":53,"detour":"warp"}],"final":"warp-dns","strategy":"ipv4_only","disable_cache":true});
            let mut rules = vec![json!({"ip_cidr":["127.0.0.1/32"],"outbound":"warp-bypass"})];
            if mode == "domain" {
                rules.push(json!({"domain":["warp.fixture.test"],"outbound":"warp"}));
            }
            if mode == "process" {
                rules.push(json!({"process_name":["Thronium"],"outbound":"warp"}));
            }
            active.rules = rules
                .into_iter()
                .enumerate()
                .map(|(i, config)| Rule {
                    id: format!("warp-rule-{i}"),
                    name: mode.into(),
                    enabled: true,
                    simple: None,
                    config,
                })
                .collect();
            e.check_routing(active.clone()).await?;
            e.save_routing(routing)?;
            e.connect(selected).await?;
            warp_http(proxy)
                .await
                .map_err(|error| format!("WARP {mode}/{global}: {error}"))?;
            exchange(proxy, origin)
                .await
                .map_err(|e| format!("WARP bypass {mode}/{global}: {e}"))?;
            e.disconnect().await?;
            println!("PASS WARP {mode}, global={global}: DNS and HTTP reach the independent peer; bypass reaches the loopback origin through the selected SOCKS server");
        }
    }
    imported_routes(e, proxy, selected, origin, &info).await?;
    let seen: Value = serde_json::from_str(
        &std::fs::read_to_string(info["stats"].as_str().unwrap()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    assert!(
        seen["dnsRequests"].as_u64().unwrap_or(0) >= if import_only { 1 } else { 7 },
        "DNS was not carried by WARP: {seen}"
    );
    let mut routing = previous_routing;
    routing.revision = e.routing().revision;
    e.save_routing(routing)?;
    let current = settings::section(&e.store.library, "intercept");
    e.save_settings("intercept", current, previous).await?;
    drop(peer.stdin.take());
    timeout(Duration::from_secs(10), peer.wait())
        .await
        .map_err(|_| "WARP fixture exit timeout")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn warp_http(proxy: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .map_err(|e| e.to_string())?;
    let url = "http://warp.fixture.test:18080/fixture/warp-routes";
    stream
        .write_all(
            format!(
                "GET {url} HTTP/1.1\r\nHost: warp.fixture.test:18080\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut response = String::new();
    timeout(Duration::from_secs(6), stream.read_to_string(&mut response))
        .await
        .map_err(|_| "WARP HTTP timeout")?
        .map_err(|e| e.to_string())?;
    if !response.ends_with("wg43:/fixture/warp-routes") {
        return Err(format!("unexpected WARP response: {response}"));
    }
    Ok(())
}

async fn imported_routes(
    e: &mut Engine,
    proxy: u16,
    selected: &str,
    origin: u16,
    info: &Value,
) -> Result<(), String> {
    let before = json!(e.store.library);
    let settings = [
        ("enable_warp", json!(true)),
        ("warp_private_key", info["profile"]["private_key"].clone()),
        ("warp_public_key", info["profile"]["peers"][0]["public_key"].clone()),
        ("warp_ep", info["endpoint"].clone()),
        ("warp_ifc_addrs", info["profile"]["address"].clone()),
        ("warp_reserved", json!([])),
        ("use_dns_object", json!(true)),
        ("dns_object", json!({"servers":[{"type":"udp","tag":"dns-direct","server":info["tunnel4"],"detour":"proxy"}],"final":"dns-direct","strategy":"ipv4_only","disable_cache":true})),
    ].into_iter().map(|(key, value)| {
        let value = value.as_str().map_or_else(|| value.to_string(), str::to_owned);
        SourceSetting { key: key.into(), columns: BTreeMap::from([("key".into(), SourceValue::Text(key.into())), ("value".into(), SourceValue::Text(value.clone()))]), value }
    }).collect();
    let archive = SourceArchive {
        container_version: 2, content_version: Some(2), metadata: json!({}), created_at: None,
        parts: Parts { routes: true, settings: true, ..Default::default() }, files: BTreeMap::new(),
        database: Some(SourceDatabase { settings, routes: vec![SourceRoute { id: 1, name: "Imported WARP routes".into(), columns: BTreeMap::from([
            ("is_raw".into(), SourceValue::Integer(1)),
            ("raw_route".into(), SourceValue::Text(json!({"final":-1,"auto_detect_interface":false,"rules":[{"ip_cidr":["127.0.0.1/32"],"outbound":-5},{"domain":["warp.fixture.test"],"outbound":-1}]}).to_string())),
        ]) }], ..Default::default() }),
    };
    let preview = e.preview_legacy_import(legacy::prepare(&archive))?;
    let scopes = Scopes {
        profiles: false,
        routes: true,
        ..Default::default()
    };
    let blocked = e.legacy_backup_scopes(&preview.token, scopes)?;
    assert_eq!(json!(blocked)["legacy"]["canApply"], false);
    assert!(e.restore_backup(&blocked.token).is_err());
    assert_eq!(json!(e.store.library), before);
    let accepted = e.legacy_backup_scopes(
        &blocked.token,
        Scopes {
            settings: SettingsScopes {
                warp: true,
                ..Default::default()
            },
            ..scopes
        },
    )?;
    assert_eq!(
        json!(accepted)["legacy"]["canApply"],
        true,
        "{}",
        json!(accepted)
    );
    e.restore_backup(&accepted.token)?;
    let mut routing = e.routing();
    routing.active = routing
        .profiles
        .iter()
        .find(|p| p.name == "Imported WARP routes")
        .unwrap()
        .id
        .clone();
    e.save_routing(routing)?;
    e.connect(selected).await?;
    warp_http(proxy).await?;
    exchange(proxy, origin).await?;
    e.disconnect().await?;
    let undo = e.preview_previous_backup()?;
    e.restore_backup(&undo.token)?;
    assert_eq!(json!(e.store.library), before);
    println!("PASS imported WARP routes: explicit archive dependency, encrypted DNS/HTTP, bypass traffic and exact Undo");
    Ok(())
}
