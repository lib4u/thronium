use super::*;
use crate::subscriptions::provider_routing::ProviderRouting;

fn provider(config: Value) -> ProviderRouting {
    ProviderRouting {
        action: "add".into(),
        config,
        error: None,
    }
}
fn build(provider: &ProviderRouting) -> Result<Value, String> {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path(), None);
    let mut req = LoadConfigReq {
        core_config: Some(
            json!({"route":{"rules":[]},"outbounds":[{"type":"direct","tag":"direct"}]})
                .to_string(),
        ),
        ..Default::default()
    };
    apply(&mut req, provider, &assets)?;
    Ok(serde_json::from_str(req.core_config.as_ref().unwrap()).unwrap())
}

#[test]
fn provider_rules_preserve_order_dns_detours_and_ignore_unknown_keys() {
    let mut provider = provider(
        json!({"DirectSites":["domain:example.test"],"DirectIp":["192.0.2.0/24"],"ProxySites":["full:private.example.test"],"RemoteDNSType":"DoH","DomesticDNSType":"DoU"}),
    );
    let c = build(&provider).unwrap();
    assert_eq!(c["route"]["rules"][1]["outbound"], "proxy");
    assert_eq!(c["route"]["rules"][4]["action"], "resolve");
    assert_eq!(c["dns"]["servers"][1]["detour"], "proxy");
    // An unknown extension keeps the policy; the summary reports the name.
    provider.config["FuturePolicy"] = json!(true);
    assert_eq!(build(&provider).unwrap(), c);
    assert_eq!(
        provider.unsupported(),
        (vec!["FuturePolicy".to_string()], 1)
    );
}
#[test]
fn an_unknown_provider_key_keeps_the_policy_and_is_reported_instead_of_refusing_it() {
    let provider = provider(json!({"RouteOrder":"block-proxy-direct",
        "DirectSites":["domain:example.test"],"GlobalProxy":false,
        "SplitTunnelingV2":true,"Расширение":1}));
    let c = build(&provider).unwrap();
    assert_eq!(c["route"]["final"], "direct");
    assert_eq!(
        c["route"]["rules"],
        json!([{"action":"sniff"},
            {"domain_suffix":["example.test"],"action":"route","outbound":"direct"}])
    );
    // Both extensions are counted; only the plain identifier may be named.
    assert_eq!(
        provider.unsupported(),
        (vec!["SplitTunnelingV2".to_string()], 2)
    );
}

#[test]
fn fake_dns_becomes_fake_ip_after_hosts_and_before_site_rules() {
    let fake = provider(
        json!({"FakeDNS":"true","DnsHosts":{"pinned.example.test":"192.0.2.7"},"DirectSites":["domain:example.test"]}),
    );
    let c = build(&fake).unwrap();
    let servers = c["dns"]["servers"].as_array().unwrap();
    assert_eq!(servers[2]["tag"], "dns-hosts");
    assert_eq!(servers[3]["type"], "fakeip");
    assert_eq!(servers[3]["inet4_range"], "198.18.0.0/15");
    let rules = c["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["server"], "dns-hosts");
    assert_eq!(rules[1]["server"], "dns-fake");
    assert_eq!(rules[1]["query_type"], json!(["A", "AAAA"]));
    assert_eq!(rules[2]["server"], "dns-direct");
    assert_eq!(c["dns"]["independent_cache"], true);
    assert_eq!(c["route"]["rules"][0]["action"], "sniff");
    assert_eq!(fake.summary()["fakeDns"], true);
    let plain = build(&provider(json!({"FakeDNS":false}))).unwrap();
    assert!(plain["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["type"] != "fakeip"));
    assert!(plain["dns"].get("independent_cache").is_none());
}

#[test]
fn domain_strategies_position_resolve_and_unknown_values_stay_refused() {
    let base = json!({"RouteOrder":"proxy-direct-block","ProxySites":["domain:proxy.test"],"ProxyIp":["198.51.100.0/24"],"DirectSites":["domain:direct.test"],"DirectIp":["192.0.2.0/24"]});
    let mut demand = base.clone();
    demand["DomainStrategy"] = json!("IPOnDemand");
    let c = build(&provider(demand)).unwrap();
    let actions: Vec<_> = c["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["action"]
                .as_str()
                .map(|a| {
                    if a == "route" {
                        r["outbound"].as_str().unwrap().to_owned()
                            + if r.get("ip_cidr").is_some() {
                                "-ip"
                            } else {
                                ""
                            }
                    } else {
                        a.to_owned()
                    }
                })
                .unwrap()
        })
        .collect();
    assert_eq!(
        actions,
        [
            "sniff",
            "proxy",
            "resolve",
            "proxy-ip",
            "direct",
            "direct-ip"
        ]
    );
    let mut as_is = base.clone();
    as_is["DomainStrategy"] = json!("AsIs");
    let c = build(&provider(as_is)).unwrap();
    assert!(c["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["action"] != "resolve"));
    let mut non_match = base.clone();
    non_match["DomainStrategy"] = json!("IPIfNonMatch");
    let c = build(&provider(non_match)).unwrap();
    let rules = c["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[5]["action"], "resolve");
    assert_eq!(rules.len(), 8);
    let mut unknown = base;
    unknown["DomainStrategy"] = json!("IPOnDemandPlus");
    assert_eq!(
        build(&provider(unknown)).unwrap_err(),
        "subscription_domain_strategy_unsupported"
    );
}

#[test]
fn chunk_files_are_a_loading_hint_that_changes_no_rule() {
    let lists = json!({"DirectSites":["domain:example.test"]});
    let mut chunked = lists.clone();
    chunked["UseChunkFiles"] = json!("true");
    assert_eq!(
        build(&provider(chunked)).unwrap(),
        build(&provider(lists)).unwrap()
    );
    let invalid = provider(json!({"UseChunkFiles":"sometimes"}));
    assert!(build(&invalid).is_err());
}
