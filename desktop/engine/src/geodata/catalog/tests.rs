use super::*;
use crate::geodata::{Attr, Cidr, Domain, Ip, Site};
fn database(code: &str, value: &str) -> Vec<u8> {
    SiteList {
        entry: vec![Site {
            code: code.into(),
            domain: vec![
                Domain {
                    kind: 2,
                    value: value.into(),
                    attribute: vec![Attr { key: "ads".into() }],
                },
                Domain {
                    kind: 3,
                    value: format!("exact.{value}"),
                    attribute: vec![],
                },
            ],
        }],
    }
    .encode_to_vec()
}
fn library() -> Library {
    Library::default()
}
fn selected(library: &mut Library, url: &str) {
    library.routing.profiles[0].route["rule_set"] =
        json!([{ "type":"geodata","tag":"test","kind":"geosite","url":url,"category":"test@ads" }]);
}
#[test]
fn categories_and_updates_preserve_attributes_references_and_running_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut library = library();
    let url = "https://example.test/geosite.dat";
    let first = install(
        dir.path(),
        &library,
        "geosite",
        url,
        "Example",
        &database("TEST", "old.test"),
    )
    .unwrap();
    assert_eq!(first.categories[0].attributes, vec!["ads"]);
    selected(&mut library, url);
    let stored = serde_json::to_value(&library.routing).unwrap();
    let compiled = resolve(library.routing.active().unwrap(), dir.path()).unwrap();
    let path = compiled.route["rule_set"][0]["path"].as_str().unwrap();
    let before = std::fs::read(path).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&before).unwrap()["rules"],
        json!([{"domain_suffix":["old.test"]}])
    );
    assert!(install(
        dir.path(),
        &library,
        "geosite",
        url,
        "Example",
        &database("MISSING", "bad.test")
    )
    .is_err());
    assert_eq!(load(dir.path(), "geosite", url).unwrap().hash, first.hash);
    install(
        dir.path(),
        &library,
        "geosite",
        url,
        "Example",
        &database("TEST", "new.test"),
    )
    .unwrap();
    let next = resolve(library.routing.active().unwrap(), dir.path()).unwrap();
    assert_ne!(
        next.route["rule_set"][0]["path"],
        compiled.route["rule_set"][0]["path"]
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(serde_json::to_value(&library.routing).unwrap(), stored);
}
#[test]
fn invalid_files_do_not_replace_cache_and_geoip_preserves_ipv6_and_reverse_match() {
    let dir = tempfile::tempdir().unwrap();
    let library = library();
    let data = IpList {
        entry: vec![Ip {
            code: "IP".into(),
            cidr: vec![Cidr {
                ip: vec![0; 16],
                prefix: 128,
            }],
            reverse_match: true,
        }],
    }
    .encode_to_vec();
    install(
        dir.path(),
        &library,
        "geoip",
        "https://example.test/ip.dat",
        "IP",
        &data,
    )
    .unwrap();
    assert_eq!(
        convert(&data, false, "ip").unwrap(),
        vec![json!({"ip_cidr":["::/128"],"invert":true})]
    );
    assert!(categories(&data, "geosite").is_err());
    assert!(categories(&database("TEST", "x.test"), "geoip").is_err());
    assert!(install(
        dir.path(),
        &library,
        "geoip",
        "https://example.test/ip.dat",
        "IP",
        b"<html>error</html>"
    )
    .is_err());
    assert_eq!(
        source_bytes(
            dir.path(),
            &load(dir.path(), "geoip", "https://example.test/ip.dat").unwrap()
        )
        .unwrap(),
        data
    );
}
#[test]
fn source_identity_separates_providers_and_rejects_bad_descriptors() {
    let dir = tempfile::tempdir().unwrap();
    let mut library = library();
    for (host, value) in [("one", "one.test"), ("two", "two.test")] {
        let url = format!("https://{host}.test/site.dat");
        install(
            dir.path(),
            &library,
            "geosite",
            &url,
            host,
            &database("TEST", value),
        )
        .unwrap();
        selected(&mut library, &url);
        let resolved = resolve(library.routing.active().unwrap(), dir.path()).unwrap();
        let data = std::fs::read_to_string(resolved.route["rule_set"][0]["path"].as_str().unwrap())
            .unwrap();
        assert!(data.contains(value));
    }
    library.routing.profiles[0].route["rule_set"][0]["unexpected"] = json!(true);
    assert!(resolve(library.routing.active().unwrap(), dir.path()).is_err());
    for url in [
        "file:///etc/passwd",
        "http://example.test/data",
        "https://user:password@example.test/data",
    ] {
        assert!(valid_url(url).is_err());
    }
    assert!(valid_url("https://github.com/example/release/site.dat").is_ok());
    assert!(valid_url("http://127.0.0.1:8080/site.dat").is_ok());
}
