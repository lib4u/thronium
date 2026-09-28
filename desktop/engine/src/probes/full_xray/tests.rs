use super::*;

fn profile() -> Profile {
    Profile {
        id: "full".into(),
        name: "Client policy".into(),
        group_id: "personal".into(),
        kind: ProfileKind::XrayConfig,
        config: json!({"log":{"access":"/must/not/write","error":"/must/not/write-e"},"dns":{"servers":["1.1.1.1"]},
            "inbounds":[{"tag":"socks","protocol":"socks","port":1234,"sniffing":{"enabled":true,"destOverride":["tls"]}},{"tag":"http","protocol":"http","port":1235}],
            "outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],
            "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["socks"],"domain":["domain:block.test"],"outboundTag":"block"}]}}),
        favorite: false,
        vpn_policy: None,
    }
}

#[test]
fn complete_client_request_keeps_dns_routes_sniffing_and_owns_only_fresh_inbounds() {
    let p = profile();
    let before = p.config.clone();
    let library = Library::default();
    assert!(supported(&library, &p));
    let request =
        crate::probes::prepared_request(&library, &p, "http://target.test/", 3000).unwrap();
    assert_eq!(p.config, before);
    let xray: Value = serde_json::from_str(request.xray_config.as_ref().unwrap()).unwrap();
    assert_eq!(xray["dns"], before["dns"]);
    assert_eq!(xray["routing"]["domainStrategy"], "IPIfNonMatch");
    assert!(xray["routing"]["rules"]
        .as_array()
        .unwrap()
        .contains(&before["routing"]["rules"][0]));
    assert_eq!(xray["inbounds"][0]["tag"], "socks");
    assert_eq!(
        xray["inbounds"][0]["sniffing"],
        before["inbounds"][0]["sniffing"]
    );
    assert_eq!(xray["inbounds"][0]["listen"], "127.0.0.1");
    assert_ne!(xray["inbounds"][0]["port"], 1234);
    assert_ne!(xray["inbounds"][0]["port"], 1235);
    assert_eq!(xray["log"], json!({"loglevel":"warning"}));
    let sing: Value = serde_json::from_str(request.config.as_ref().unwrap()).unwrap();
    assert_eq!(sing["inbounds"], json!([]));
    assert_eq!(sing["services"], json!([]));
    assert_eq!(request.test_current, Some(false));
    assert_eq!(request.outbound_tags, vec!["proxy"]);
}

#[test]
fn full_client_background_unsupported_inbounds_and_case_variants_are_refused() {
    for key in [
        "api",
        "API",
        "reverse",
        "metrics",
        "env",
        "Env",
        "geodata",
        "observatory",
        "burstObservatory",
        "browserForwarder",
        "unknownFutureListener",
    ] {
        let mut p = profile();
        p.config[key] = json!({});
        assert!(!supported(&Library::default(), &p), "{key}");
        assert_eq!(
            crate::probes::prepared_request(&Library::default(), &p, "http://target.test/", 1000)
                .unwrap_err(),
            "probe_full_config_unsupported"
        );
    }
    for protocol in ["wireguard", "dokodemo-door", "vless"] {
        let mut p = profile();
        p.config["inbounds"][0]["protocol"] = json!(protocol);
        assert!(!client_shape(&p.config));
    }
    let mut p = profile();
    p.config["routing"]["rules"][0]["inboundTag"] = json!(["http"]);
    assert!(!client_shape(&p.config));
    let mut p = profile();
    p.config["routing"]["rules"][0]["INBOUNDTAG"] = json!(["http"]);
    assert!(!client_shape(&p.config));
    let mut p = profile();
    p.config["outbounds"][0]["protocol"] = json!("wireguard");
    assert!(!client_shape(&p.config));
    let mut p = profile();
    p.config["routing"]["Balancers"] = json!([{ "tag":"bal" }]);
    assert!(!client_shape(&p.config));
}

#[tokio::test]
async fn geodata_staging_uses_verified_owned_copy_and_removes_failed_directory() {
    use sha2::{Digest, Sha256};
    let source = tempfile::tempdir().unwrap();
    let bytes = b"fixture immutable data";
    let name = format!("{:x}.dat", Sha256::digest(bytes));
    let path = source.path().join(&name);
    std::fs::write(&path, bytes).unwrap();
    let destination = tempfile::tempdir().unwrap();
    let root = destination.path().to_path_buf();
    let stage = Assets {
        files: vec![(path.clone(), name.clone())],
        ..Default::default()
    }
    .stage(destination)
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(root.join("xray-assets").join(&name)).unwrap(),
        bytes
    );
    std::fs::write(&path, b"changed").unwrap();
    assert_eq!(
        std::fs::read(root.join("xray-assets").join(&name)).unwrap(),
        bytes
    );
    drop(stage);
    assert!(!root.exists());
    let bad = tempfile::tempdir().unwrap();
    let bad_path = bad.path().to_path_buf();
    assert_eq!(
        Assets {
            files: vec![(path, name)],
            ..Default::default()
        }
        .stage(bad)
        .await
        .unwrap_err(),
        "geodata_invalid"
    );
    assert!(!bad_path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn geodata_staging_rejects_symlink_fifo_and_oversized_files() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    let source = tempfile::tempdir().unwrap();
    let normal = source.path().join("normal");
    std::fs::write(&normal, b"data").unwrap();
    let link = source.path().join("link");
    symlink(&normal, &link).unwrap();
    let fifo = source.path().join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let huge = source.path().join("huge");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(LIMIT + 1)
        .unwrap();
    for path in [link, fifo, huge] {
        let destination = tempfile::tempdir().unwrap();
        let root = destination.path().to_path_buf();
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Assets {
                files: vec![(path, format!("{}.dat", "0".repeat(64)))],
                ..Default::default()
            }
            .stage(destination)
        )
        .await
        .unwrap()
        .is_err());
        assert!(!root.exists());
    }
}

#[test]
fn canceling_geodata_staging_reaps_its_directory_after_pending_io_unblocks() {
    use std::{future::Future, task::Poll, time::Duration};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (started, observed) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let occupant = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let root = destination.path().to_path_buf();
        let assets = Assets {
            files: vec![(PathBuf::from("/must/not/open"), "0".repeat(64) + ".dat")],
            ..Default::default()
        };
        let mut operation = Box::pin(assets.stage(destination));
        std::future::poll_fn(|cx| {
            assert!(operation.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(operation);
        release.send(()).unwrap();
        occupant.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while root.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    });
}

#[tokio::test]
async fn cached_category_selection_is_captured_and_new_source_invalidates_pending_result() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("xray-assets");
    std::fs::create_dir(&cache).unwrap();
    let mut library = Library::default();
    let url = "https://assets.probe.test/geosite.dat";
    library
        .settings
        .insert("xray_geosite_url".into(), json!(url));
    let mut p = profile();
    p.config["routing"]["rules"][0]["domain"] = json!(["geosite:TEST"]);
    // A credential that happens to start with ext: is not a geodata reference.
    p.config["outbounds"][0]["settings"] = json!({"password":"ext:private-opaque-value"});
    let mut request =
        crate::probes::prepared_request(&library, &p, "http://target.test/", 1000).unwrap();
    assert_eq!(
        Assets::prepare(&mut request, root.path(), &library, &p)
            .err()
            .as_deref(),
        Some("geodata_missing")
    );
    let data = crate::geodata::site_list_fixture("TEST", "independent.staging.test");
    let hash = format!("{:x}", Sha256::digest(&data));
    let manifest = cache.join(format!(
        "{:x}.ref",
        Sha256::digest(format!("{url}:null").as_bytes())
    ));
    std::fs::write(cache.join(format!("{hash}.dat")), &data).unwrap();
    std::fs::write(&manifest, &hash).unwrap();
    let assets = Assets::prepare(&mut request, root.path(), &library, &p).unwrap();
    assert_eq!(assets.files.len(), 1);
    let context = assets.context.clone().unwrap();
    assert!(context.matches(&library, &p));
    let xray: Value = serde_json::from_str(request.xray_config.as_ref().unwrap()).unwrap();
    assert!(xray.to_string().contains(&format!("ext:{hash}.dat:TEST")));
    assert!(xray.to_string().contains("ext:private-opaque-value"));
    let original = library.clone();
    library.settings.insert(
        "xray_geosite_url".into(),
        json!("https://other.probe.test/geosite.dat"),
    );
    assert!(!context.matches(&library, &p));
    std::fs::write(&manifest, "1".repeat(64)).unwrap();
    assert!(!context.matches(&original, &p));
    // An in-flight probe owns the selected immutable version; it must not read
    // the newly selected manifest into its runtime directory after planning.
    let staged = assets.stage(tempfile::tempdir().unwrap()).await.unwrap();
    assert_eq!(
        std::fs::read(
            staged
                .path()
                .join("xray-assets")
                .join(format!("{hash}.dat"))
        )
        .unwrap(),
        data
    );
    assert_eq!(
        p.config["routing"]["rules"][0]["domain"],
        json!(["geosite:TEST"])
    );
}

#[test]
fn malformed_or_nonregular_cache_references_fail_before_staging() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("xray-assets");
    std::fs::create_dir(&cache).unwrap();
    let library = Library::default();
    let mut p = profile();
    p.config["routing"]["rules"][0]["domain"] = json!(["geosite:TEST"]);
    let url = crate::settings::value(&library, "xray_geosite_url");
    use sha2::{Digest, Sha256};
    let manifest = cache.join(format!(
        "{:x}.ref",
        Sha256::digest(format!("{}:null", url.as_str().unwrap()).as_bytes())
    ));
    for bytes in [
        vec![b'a'; 63],
        vec![b'a'; 65],
        vec![b'!'; 64],
        vec![b'a'; 65536],
    ] {
        std::fs::write(&manifest, bytes).unwrap();
        let mut request =
            crate::probes::prepared_request(&library, &p, "http://target.test/", 1000).unwrap();
        assert_eq!(
            Assets::prepare(&mut request, root.path(), &library, &p)
                .err()
                .as_deref(),
            Some("geodata_invalid")
        );
    }
}
