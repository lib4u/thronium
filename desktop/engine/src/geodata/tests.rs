use super::*;
/// A usable cache must not depend on the download proxy: "download through
/// the tunnel" is on, nothing is connected, so no proxy address exists.
#[tokio::test]
async fn a_valid_cache_is_used_without_a_download_proxy_even_when_stale() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path(), None);
    let mut library = Library::default();
    library.settings.insert("net_use_proxy".into(), json!(true));
    let rule = json!({"rules":[{"domain":["geosite:test"]}]});
    assert_eq!(
        assets
            .prepare(&[&rule], &library, None, Fetch::Download)
            .await
            .unwrap_err(),
        "subscription_proxy_unavailable",
        "without a cache the missing proxy is still reported"
    );
    std::fs::create_dir_all(&assets.directory).unwrap();
    let bytes = SiteList {
        entry: vec![Site {
            code: "TEST".into(),
            domain: vec![Domain {
                kind: 2,
                value: "example.test".into(),
                attribute: vec![],
            }],
        }],
    }
    .encode_to_vec();
    let hash = digest(&bytes);
    write(&assets.directory.join(format!("{hash}.dat")), &bytes).unwrap();
    write(&assets.manifest(true), hash.as_bytes()).unwrap();
    assets
        .prepare(&[&rule], &library, None, Fetch::Download)
        .await
        .unwrap();
    let old = std::time::SystemTime::now() - Duration::from_secs(30 * 24 * 3600);
    std::fs::File::options()
        .write(true)
        .open(assets.manifest(true))
        .unwrap()
        .set_modified(old)
        .unwrap();
    assets
        .prepare(&[&rule], &library, None, Fetch::Download)
        .await
        .expect("a stale but valid cache survives a refresh that cannot run");
    assert_eq!(
        assets.cached(true).unwrap(),
        assets.directory.join(format!("{hash}.dat"))
    );
}
#[test]
fn xray_references_to_absent_categories_are_refused_before_the_core_starts() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path(), None);
    std::fs::create_dir_all(&assets.directory).unwrap();
    let sites = SiteList {
        entry: vec![Site {
            code: "TEST".into(),
            domain: vec![Domain {
                kind: 2,
                value: "example.test".into(),
                attribute: vec![Attr { key: "ads".into() }],
            }],
        }],
    }
    .encode_to_vec();
    let ips = IpList {
        entry: vec![Ip {
            code: "PRIVATE".into(),
            cidr: vec![Cidr {
                ip: vec![192, 0, 2, 0],
                prefix: 24,
            }],
            reverse_match: false,
        }],
    }
    .encode_to_vec();
    for (bytes, kind) in [(&sites, true), (&ips, false)] {
        let hash = digest(bytes);
        write(&assets.directory.join(format!("{hash}.dat")), bytes).unwrap();
        write(&assets.manifest(kind), hash.as_bytes()).unwrap();
    }
    let mut config =
        json!({"routing":{"rules":[{"domain":["geosite:test@ads"],"ip":["geoip:!private"]}]}});
    assets.rewrite_xray(&mut config).unwrap();
    assert!(config["routing"]["rules"][0]["domain"][0]
        .as_str()
        .unwrap()
        .ends_with(".dat:test@ads"));
    let index = assets
        .cached(true)
        .unwrap()
        .with_extension("categories.json");
    assert!(
        index.is_file(),
        "the category index is kept for later builds"
    );
    for reference in [
        json!({"domain":["geosite:missing"]}),
        json!({"ip":["geoip:!cn"]}),
    ] {
        let mut config = json!({"routing":{"rules":[reference]}});
        assert_eq!(
            assets.rewrite_xray(&mut config).unwrap_err(),
            "geodata_category_missing",
            "{reference}"
        );
    }
    let mut dns =
        json!({"dns":{"servers":[{"address":"192.0.2.53","domains":["geosite:absent"]}]}});
    assert_eq!(
        assets.rewrite_xray(&mut dns).unwrap_err(),
        "geodata_category_missing"
    );
}
#[test]
fn xray_resource_rewrite_does_not_touch_opaque_values() {
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::new(dir.path(), None);
    let mut config = json!({"remarks":"geosite:private","outbounds":[{"tag":"ext:ordinary-tag"}],"dns":{"hosts":{"literal.test":"127.0.0.1"}}});
    let original = config.clone();
    assets.rewrite_xray(&mut config).unwrap();
    assert_eq!(config, original);
    assert_eq!(xray_references(&config), json!([]));
    config["routing"] = json!({"rules":[{"domain":["ext:foreign.dat:test"]}]});
    assert_eq!(
        assets.rewrite_xray(&mut config).unwrap_err(),
        "geodata_external_file_unsupported"
    );
}
#[test]
fn conversion_preserves_or_attributes_ipv6_and_inversion() {
    let data = SiteList {
        entry: vec![Site {
            code: "TEST".into(),
            domain: vec![
                Domain {
                    kind: 2,
                    value: "example.test".into(),
                    attribute: vec![Attr { key: "ads".into() }],
                },
                Domain {
                    kind: 3,
                    value: "exact.test".into(),
                    attribute: vec![],
                },
            ],
        }],
    }
    .encode_to_vec();
    assert_eq!(convert(&data, true, "test").unwrap().len(), 2);
    assert_eq!(
        convert(&data, true, "test@ads").unwrap(),
        vec![json!({"domain_suffix":["example.test"]})]
    );
    assert!(convert(&data, true, "test@missing").is_err());
    let data = IpList {
        entry: vec![Ip {
            code: "TEST".into(),
            cidr: vec![Cidr {
                ip: vec![0; 16],
                prefix: 128,
            }],
            reverse_match: true,
        }],
    }
    .encode_to_vec();
    assert_eq!(
        convert(&data, false, "!test").unwrap(),
        vec![json!({"ip_cidr":["::/128"],"invert":false})]
    );
}

fn fixture_sites() -> Vec<u8> {
    SiteList {
        entry: vec![Site {
            code: "TEST".into(),
            domain: vec![Domain {
                kind: 2,
                value: "example.test".into(),
                attribute: vec![],
            }],
        }],
    }
    .encode_to_vec()
}
/// The shipped pair stands in for the first download of the default source,
/// offline and under the Engine lock alike, and needs no refresh before a
/// connection; a provider's own source is never replaced by it.
#[tokio::test]
async fn the_shipped_default_list_replaces_a_first_download() {
    let dir = tempfile::tempdir().unwrap();
    let shipped = tempfile::tempdir().unwrap();
    write(&shipped.path().join(bundled::SITE_FILE), &fixture_sites()).unwrap();
    let library = Library::default();
    let rule = json!({"rules":[{"domain":["geosite:test"]}]});
    let assets = Assets::new(dir.path(), None)
        .with_library(&library)
        .with_bundled(shipped.path());
    assert_eq!(assets.url(true), default_url(true));
    assets
        .prepare(&[&rule], &library, None, Fetch::Cached { stale: true })
        .await
        .expect("no download is needed");
    assert!(assets.rule_set("geosite:test").is_ok());
    assets
        .prepare(&[&rule], &library, None, Fetch::Cached { stale: false })
        .await
        .expect("a connection does not wait for a refresh of the shipped copy");
    let provider = ProviderRouting {
        action: "add".into(),
        config: json!({"Geositeurl":"https://provider.example.test/geosite.dat"}),
        error: None,
    };
    let other = tempfile::tempdir().unwrap();
    let assets = Assets::new(other.path(), Some(&provider))
        .with_library(&library)
        .with_bundled(shipped.path());
    assert_eq!(
        assets
            .prepare(&[&rule], &library, None, Fetch::Cached { stale: true })
            .await
            .unwrap_err(),
        deferral::DOWNLOAD_REQUIRED
    );
    // Not a list of its kind: the shipped file is ignored.
    write(&shipped.path().join(bundled::IP_FILE), b"not a list").unwrap();
    assert!(bundled::bytes(Some(shipped.path()), false, default_url(false)).is_none());
}
/// The shipped pair is the first publisher the settings and the routing
/// category databases offer, and the settings catalog's default.
#[test]
fn the_default_publisher_is_the_shipped_pair() {
    let first = &manager::PROVIDERS[0];
    assert_eq!(first.id, "v2fly");
    assert_eq!(first.geosite, default_url(true));
    assert_eq!(first.geoip, default_url(false));
}
