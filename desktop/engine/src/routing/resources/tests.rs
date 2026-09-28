use super::*;
use serde_json::json;

#[test]
fn portable_pack_checks_formats_hashes_limits_and_shared_bytes() {
    let hosts = Resource::parse(Kind::Hosts, b"127.0.0.1 fixture.invalid\n".to_vec()).unwrap();
    let cloned = hosts.clone();
    assert!(Arc::ptr_eq(&hosts.0, &cloned.0));
    let mut pack = Pack::default();
    let reference = pack.insert(hosts).unwrap();
    let wire = serde_json::to_value(&pack).unwrap();
    let decoded: Pack = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        decoded.get(&reference, Kind::Hosts).unwrap().0.bytes,
        cloned.0.bytes
    );
    assert!(decoded.get(&reference, Kind::RuleSetSource).is_err());
    let mut invalid = wire.as_object().unwrap().clone();
    let key = invalid.keys().next().unwrap().clone();
    let value = invalid.remove(&key).unwrap();
    invalid.insert("0".repeat(64), value);
    assert!(serde_json::from_value::<Pack>(json!(invalid)).is_err());
    for (kind, bytes) in [
        (Kind::Hosts, b"not-a-hosts-file".to_vec()),
        (Kind::Hosts, vec![0xff]),
        (
            Kind::RuleSetSource,
            br#"{"version":3,"version":4,"rules":[]}"#.to_vec(),
        ),
        (Kind::RuleSetSource, br#"{"version":6,"rules":[]}"#.to_vec()),
        (
            Kind::RuleSetSource,
            br#"{"version":3,"rules":[],"ignored":true}"#.to_vec(),
        ),
        (Kind::RuleSetBinary, b"SRS\x05bad-zlib".to_vec()),
        (Kind::RuleSetBinary, b"SRS\x06".to_vec()),
    ] {
        assert!(Resource::parse(kind, bytes).is_err());
    }
    assert!(Resource::parse(Kind::Hosts, vec![b' '; MAX_FILE_BYTES + 1]).is_err());
    let binary = include_bytes!("../../../../tests/fixtures/tray-controls/loopback.srs").to_vec();
    assert!(Resource::parse(Kind::RuleSetBinary, binary).is_ok());
    let mut compressor = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    compressor.write_all(&vec![0; MAX_PACK_BYTES + 1]).unwrap();
    let mut bomb = b"SRS\x05".to_vec();
    bomb.extend(compressor.finish().unwrap());
    assert!(Resource::parse(Kind::RuleSetBinary, bomb).is_err());
}

#[test]
fn runtime_materialization_is_immutable_bounded_and_regenerates_from_a_backup() {
    let root = tempfile::tempdir().unwrap();
    let resource = Resource::parse(Kind::Hosts, b"127.0.0.1 fixture.invalid\n".to_vec()).unwrap();
    let target = materialize(root.path(), &resource).unwrap();
    assert_eq!(materialize(root.path(), &resource).unwrap(), target);
    std::fs::write(&target, b"127.0.0.2 changed.invalid\n").unwrap();
    assert!(materialize(root.path(), &resource).is_err());
    std::fs::remove_file(&target).unwrap();
    assert_eq!(materialize(root.path(), &resource).unwrap(), target);
    assert_eq!(std::fs::read(&target).unwrap(), resource.0.bytes);
    #[cfg(unix)]
    {
        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &target).unwrap();
        assert!(materialize(root.path(), &resource).is_err());
    }
}

#[test]
fn reader_boundary_and_broken_references_fail_before_runtime_writes() {
    let resource = Resource::parse(Kind::Hosts, b"127.0.0.1 fixture.invalid\n".to_vec()).unwrap();
    let mut library = crate::store::Library::default();
    let reference = library.routing_resources.insert(resource).unwrap();
    library.routing.profiles[0].dns =
        json!({"servers":[{"type":"hosts","tag":"custom","path":[reference]}],"final":"custom"});
    assert!(crate::store::validate_library(&library).is_err());
    library.version = 6;
    crate::store::validate_library(&library).unwrap();
    library.routing_resources = Pack::default();
    assert_eq!(
        crate::store::validate_library(&library).err().as_deref(),
        Some("routing_resource_missing")
    );
}

#[test]
fn empty_policy_and_unrelated_http_paths_are_not_changed_by_the_resource_walker() {
    let root = tempfile::tempdir().unwrap();
    let mut profile = super::super::Routing::default().profiles.remove(0);
    profile.dns = json!({"servers":[{"type":"https","path":"/dns-query"}]});
    profile.route = json!({});
    let before = json!(profile);
    resolve(&mut profile, &Pack::default(), root.path()).unwrap();
    assert_eq!(json!(profile), before);
    assert!(!root.path().join("routing-resources").exists());
}
