//! Exercise the wrapped pool's real RPC identities without public WARP traffic.
use super::*;

pub(super) async fn run(e: &mut Engine, id: &str, preferred: &str) -> Result<(), String> {
    e.disconnect().await?;
    let mut routing = e.routing();
    routing.profiles[0].rules.clear();
    e.save_routing(routing)?;
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let previous = thronium_engine::settings::section(&e.store.library, "intercept");
    let mut next = previous.clone();
    next["enable_warp"] = json!(true);
    next["warp_ep"] = json!(peer.local_addr().unwrap().to_string());
    next["warp_private_key"] = json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
    next["warp_public_key"] = json!("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
    next["warp_ifc_addrs"] = json!(["10.77.0.2/32"]);
    e.save_settings("intercept", previous.clone(), next.clone())
        .await?;
    e.connect(id).await?;
    let pool = wait(e, |g| g["membersAlive"] == 2).await?;
    assert_eq!(pool["tag"], "settings-warp-base");
    assert_eq!(pool["profileId"], id);
    assert_eq!(pool["name"], "Balanced");
    assert!(pool["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["profileId"].is_string()
            && !m["name"]
                .as_str()
                .unwrap()
                .starts_with("thronium-selector-")));
    let member = thronium_engine::auto_selector::member_tag("proxy", preferred);
    let since = e.snapshot().since;
    e.auto_selector_action("settings-warp-base", "select", &member)
        .await?;
    wait(e, |g| g["selected"] == member && g["pinned"] == member).await?;
    let round = e.auto_selectors().await?[0]["roundsCompleted"]
        .as_i64()
        .unwrap_or(0);
    e.auto_selector_action("settings-warp-base", "recheck", "")
        .await?;
    wait(e, |g| g["roundsCompleted"].as_i64().unwrap_or(0) > round).await?;
    assert_eq!(e.snapshot().since, since);
    // Settings now describe the NEXT connection; the running WARP tag still
    // has to resolve until disconnect has completed.
    e.save_settings("intercept", next, previous).await?;
    let pool = e.auto_selectors().await?[0].clone();
    assert_eq!(pool["tag"], "settings-warp-base");
    assert_eq!(pool["profileId"], id);
    e.disconnect().await?;
    e.connect(id).await?;
    let pool = wait(e, |g| g["membersAlive"] == 2).await?;
    assert_eq!(pool["tag"], "proxy");
    assert_eq!(pool["profileId"], id);
    println!("PASS WARP wraps the pool while real Core status, member names, pin, recheck and the next WARP-off connection retain their identities");
    Ok(())
}
