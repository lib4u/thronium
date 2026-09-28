use super::*;
fn preset() -> RoutingProfile {
    let db = SourceDatabase::default();
    let row = SourceRoute {
        id: 1,
        name: "Keep my name".into(),
        columns: BTreeMap::from([
            ("is_remote".into(), SourceValue::Integer(1)),
            ("auto_update".into(), SourceValue::Integer(1)),
            (
                "remote_url".into(),
                SourceValue::Text("http://127.0.0.1:12345/routes".into()),
            ),
        ]),
    };
    let dns = generated_dns::build(&db, &row, &mut vec![]).unwrap();
    let inbounds = super::super::inbounds::Inbounds::parse(&db).unwrap();
    convert_one(&row, &db, &dns, None, &inbounds, &mut vec![], None).unwrap()
}
fn remote(domain: &str) -> Value {
    json!({"kind":"throne-route-profile","v":1,"name":"Provider name","default_outbound":"direct","rules":[{"type":"simple_address_bypass","name":"Local domains","domain_suffix":[domain],"outbound":"direct"}]})
}
#[test]
fn remote_refresh_rebuilds_dns_projection_and_retains_local_identity() {
    let old = preset();
    let before = json!(old);
    let next = refresh(
        &old,
        remote("changed.fixture.invalid").to_string().as_bytes(),
        900,
    )
    .unwrap();
    assert_eq!(next.id, old.id);
    assert_eq!(next.name, old.name);
    assert_eq!(next.route["final"], "direct");
    assert!(next.dns["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |rule| rule["domain_suffix"] == json!(["changed.fixture.invalid"])
                && rule["server"] == "dns-direct"
        ));
    assert_eq!(next.source.as_ref().unwrap()["importedAt"], 900);
    assert_eq!(next.source.as_ref().unwrap()["autoUpdate"], true);
    assert_eq!(json!(old), before);
    let encoded = format!(
        "throne://route/{}",
        general_purpose::URL_SAFE_NO_PAD.encode(remote("encoded.invalid").to_string())
    );
    assert!(refresh(&next, encoded.as_bytes(), 901)
        .unwrap()
        .rules
        .iter()
        .any(|r| r.config["domain_suffix"] == json!(["encoded.invalid"])));
}
/// What an update leaves out stays visible beside the source instead of
/// being dropped with the conversion report.
#[test]
fn a_remote_update_keeps_its_omission_notes_on_the_source() {
    let clean = refresh(
        &preset(),
        remote("clean.invalid").to_string().as_bytes(),
        900,
    )
    .unwrap();
    assert!(clean.source.as_ref().unwrap().get("updateNotes").is_none());
    let with_empty = json!({"kind":"throne-route-profile","v":1,"rules":[
        {"type":"simple_address_bypass","name":"Empty placeholder","outbound":"direct"},
        {"type":"simple_address_bypass","name":"Real","domain_suffix":["real.invalid"],"outbound":"direct"}
    ]});
    let next = refresh(&clean, with_empty.to_string().as_bytes(), 901).unwrap();
    let notes = next.source.as_ref().unwrap()["updateNotes"]
        .as_array()
        .unwrap()
        .clone();
    assert!(!notes.is_empty(), "{notes:?}");
    crate::routing::source::Source::parse(next.source.as_ref().unwrap()).unwrap();
    let again = refresh(&next, remote("clean.invalid").to_string().as_bytes(), 902).unwrap();
    assert!(
        again.source.as_ref().unwrap().get("updateNotes").is_none(),
        "a later clean update clears the notes"
    );
}
#[test]
fn manual_dns_and_route_resolver_edits_survive_remote_refresh() {
    let old = preset();
    let mut routing = Routing {
        revision: 0,
        active: old.id.clone(),
        profiles: vec![old],
    };
    let before = routing.clone();
    let current = &mut routing.profiles[0];
    current.dns = json!({"servers":[{"type":"local","tag":"my-local"}],"final":"my-local"});
    current.route["default_domain_resolver"] = json!("my-local");
    crate::routing::source::retain_dns_edit(&before, &mut routing).unwrap();
    let current = &routing.profiles[0];
    let next = refresh(current, remote("new.invalid").to_string().as_bytes(), 900).unwrap();
    assert_eq!(next.dns, current.dns);
    assert_eq!(next.route["default_domain_resolver"], "my-local");
    assert_eq!(next.source.as_ref().unwrap()["dnsCustomized"], true);
}
#[test]
fn refreshed_sets_follow_new_rules_and_keep_only_referenced_old_dependencies() {
    let old = preset();
    let first = refresh(&old, json!({"kind":"throne-route-profile","v":1,"rules":[{"type":"simple_address_bypass","rule_set":["geosite-openai"],"outbound":"direct"}]}).to_string().as_bytes(), 1).unwrap();
    assert_eq!(first.route["rule_set"].as_array().unwrap().len(), 1);
    let next = refresh(&first, json!({"kind":"throne-route-profile","v":1,"rules":[{"type":"custom","rule_set":["geoip-private"],"outbound":"direct"}]}).to_string().as_bytes(), 2).unwrap();
    assert_eq!(next.route["rule_set"].as_array().unwrap().len(), 1);
    assert_eq!(next.route["rule_set"][0]["tag"], "geoip-private");
    assert!(!next.dns.to_string().contains("geosite-openai"));
    assert_eq!(first.route["rule_set"][0]["tag"], "geosite-openai");
}
#[test]
fn remote_content_cannot_materialize_endpoints_or_guess_local_profiles() {
    let current = preset();
    for content in [
        json!([]),
        json!({"kind":"throne-route-profile","v":1,"raw":true,"rules":[]}),
        json!({"kind":"throne-route-profile","v":1,"rules":[],"endpoints":[{"private_key":"secret"}]}),
        json!({"kind":"throne-route-profile","v":1,"rules":[{"outbound":"profile:private-id","domain":["x.invalid"]}]}),
        json!({"kind":"throne-route-profile","v":1,"rules":[{"type":"endpoint_preferred_by","outbound":5}]}),
        json!({"kind":"throne-route-profile","v":2,"rules":[]}),
    ] {
        let error = refresh(&current, content.to_string().as_bytes(), 900)
            .err()
            .unwrap();
        assert!(!error.contains("private"));
        assert!(!error.contains("secret"));
    }
}
#[test]
fn a_first_import_uses_the_update_converter_and_keeps_the_source() {
    let link = format!(
        "throne://route/{}",
        general_purpose::URL_SAFE_NO_PAD.encode(
            json!({"kind":"throne-route-profile","v":1,"name":"Russia","default_outbound":"direct","rules":[
                {"type":"custom","name":"Blocked","rule_set":["geosite-openai","geoip-private"],"outbound":"proxy"},
                {"type":"simple_address_bypass","name":"Local","domain_suffix":["local.invalid"],"outbound":"direct"}
            ]})
            .to_string()
        )
    );
    let imported = import(&link, "Fallback", Some("https://example.test/profile"), 7).unwrap();
    assert_eq!(imported.name, "Russia");
    assert_eq!(imported.route["final"], "direct");
    // Qt's generated sniff and DNS hijack rules come first, then the document's rules in order.
    let names: Vec<_> = imported
        .rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect();
    assert_eq!(names[names.len() - 2..], ["Blocked", "Local"]);
    let sets = imported.route["rule_set"].as_array().unwrap();
    assert_eq!(sets.len(), 2);
    assert!(sets.iter().all(|set| set["type"] == "remote"
        && set["url"].as_str().is_some_and(|url| url.ends_with(".srs"))));
    let source = Source::parse(imported.source.as_ref().unwrap()).unwrap();
    assert_eq!(
        (source.url.as_str(), source.imported_at),
        ("https://example.test/profile", 7)
    );
    // The update of the same source produces the same profile.
    let updated = refresh(&imported, link.as_bytes(), 8).unwrap();
    assert_eq!(updated.rules.len(), imported.rules.len());
    assert_eq!(updated.route, imported.route);

    let pasted = import(
        &json!({"kind":"throne-route-profile","v":1,"rules":[]}).to_string(),
        "Pasted",
        None,
        7,
    )
    .unwrap();
    assert_eq!(pasted.name, "Pasted");
    assert!(pasted.source.is_none());
}
#[test]
fn an_import_reports_version_and_unknown_fields_as_routing_errors() {
    let error = |value: Value| import(&value.to_string(), "x", None, 1).err().unwrap();
    assert_eq!(
        error(json!({"kind":"throne-route-profile","v":2,"rules":[]})),
        "routing_import_version"
    );
    assert_eq!(
        error(json!({"kind":"throne-route-profile","v":1,"rules":[],"unknown":true})),
        "routing_import_unsupported"
    );
    assert_eq!(
        error(json!({"kind":"other","v":1,"rules":[]})),
        "routing_import_unsupported"
    );
}
