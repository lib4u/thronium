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

/// The Routing page lists exactly what a connection runs: the same rules in
/// the same order, the same final outbound and the same DNS, for every
/// resolution timing and order a provider may send.
#[test]
fn the_routing_page_lists_the_rules_and_dns_a_connection_applies() {
    for strategy in ["AsIs", "IPIfNonMatch", "IPOnDemand"] {
        for order in [
            "block-proxy-direct",
            "direct-proxy-block",
            "proxy-block-direct",
        ] {
            let provider = provider(json!({
                "Name":"Fixture policy","DomainStrategy":strategy,"RouteOrder":order,
                "GlobalProxy":false,"FakeDNS":true,"DnsHosts":{"hosts.example.test":"192.0.2.9"},
                "DirectSites":["domain:a.example.test","full:b.example.test","keyword:c","regexp:^d\\.","plain"],
                "DirectIp":["192.0.2.0/24"],"ProxySites":["domain:p.example.test"],
                "ProxyIp":["2001:db8::/32"],"BlockSites":["domain:ads.example.test"],
                "BlockIp":["198.51.100.1"],"RemoteDNSType":"DoH","DomesticDNSType":"DoU"}));
            let applied = build(&provider).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let view = profile(
                "subscription:g",
                "Fixture policy",
                &provider,
                &Assets::new(dir.path(), Some(&provider)),
            )
            .unwrap();
            let rules: Vec<Value> = view.rules.iter().map(|r| r.config.clone()).collect();
            assert_eq!(
                json!(rules),
                applied["route"]["rules"],
                "{strategy} {order}"
            );
            assert_eq!(view.route["final"], applied["route"]["final"]);
            assert_eq!(view.dns, applied["dns"]);
            assert_eq!(view.name, "Fixture policy");
            assert!(view.rules.iter().any(|r| r.name == "domain:a.example.test"));
            // What the page shows is a valid profile, so a copy of it saves.
            crate::routing::Routing {
                active: view.id.clone(),
                profiles: vec![view],
                revision: 0,
            }
            .validate()
            .unwrap();
        }
    }
}

/// Geo categories become category databases of the provider's own lists, or
/// of the default source where the provider names none; no file is needed.
#[test]
fn geo_categories_on_the_page_are_sources_of_the_provider_lists() {
    let policy = provider(json!({
        "Geositeurl":"https://provider.example.test/geosite.dat",
        "DirectSites":["geosite:category-ru","geosite:category-ru"],"DirectIp":["geoip:ru"]}));
    let dir = tempfile::tempdir().unwrap();
    let library = crate::store::Library::default();
    let assets = Assets::new(dir.path(), Some(&policy)).with_library(&library);
    let view = profile("subscription:g", "Policy", &policy, &assets).unwrap();
    assert_eq!(
        view.route["rule_set"],
        json!([
            {"type":"geodata","tag":"geosite:category-ru","kind":"geosite",
                "url":"https://provider.example.test/geosite.dat","category":"category-ru"},
            {"type":"geodata","tag":"geoip:ru","kind":"geoip",
                "url":crate::geodata::default_url(false),"category":"ru"}
        ])
    );
    assert_eq!(
        view.rules[1].config,
        json!({"rule_set":["geosite:category-ru"],"action":"route","outbound":"direct"})
    );
    // A policy a connection refuses is refused here with the same code.
    let refused = provider(json!({"DomainStrategy":"UseIP"}));
    assert_eq!(
        profile("subscription:g", "Policy", &refused, &assets)
            .err()
            .unwrap(),
        build(&refused).unwrap_err()
    );
}
