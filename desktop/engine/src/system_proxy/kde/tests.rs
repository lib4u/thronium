use super::*;

#[test]
fn local_entries_restore_spelling_markers_and_unrelated_sections() {
    let original = "# comment\n[Proxy Settings]\nhttpProxy[$e]=http://$PROXY_HOST 3128\nhttpsProxy[$d]\nNoProxyFor=intranet.test\n[Other]\nhttpProxy=untouched\n";
    let mut applied = original.to_owned();
    for (key, value) in [
        ("httpProxy", "http://127.0.0.1 2080"),
        ("httpsProxy", "http://127.0.0.1 2080"),
    ] {
        applied = replace(&applied, key, &[format!("{key}={value}")]);
    }
    assert!(applied.contains("NoProxyFor=intranet.test\n[Other]\nhttpProxy=untouched\n"));
    for key in ["httpsProxy", "httpProxy"] {
        applied = replace(&applied, key, &entries(original, key));
    }
    assert_eq!(applied, original);
}

#[test]
fn absent_entries_are_removed_without_hiding_system_defaults() {
    for original in [
        "",
        "[Proxy Settings]\nNoProxyFor=intranet\n",
        "[Other]\nvalue=x",
    ] {
        let applied = replace(
            original,
            "httpProxy",
            &["httpProxy=http://127.0.0.1 2080".into()],
        );
        assert_eq!(
            entries(&applied, "httpProxy"),
            ["httpProxy=http://127.0.0.1 2080"]
        );
        let restored = replace(&applied, "httpProxy", &[]);
        assert!(entries(&restored, "httpProxy").is_empty());
        assert!(!restored.contains("[$d]"));
    }
}

#[test]
fn repeated_groups_and_duplicate_keys_have_one_effective_replacement() {
    let original =
        "[Proxy Settings]\nhttpProxy=first\n[Other]\nx=1\n[Proxy Settings]\nhttpProxy=last\n";
    let applied = replace(original, "httpProxy", &["httpProxy=ours".into()]);
    assert_eq!(entries(&applied, "httpProxy"), ["httpProxy=ours"]);
    let restored = replace(&applied, "httpProxy", &entries(original, "httpProxy"));
    assert_eq!(
        entries(&restored, "httpProxy"),
        ["httpProxy=first", "httpProxy=last"]
    );
    assert!(restored.contains("[Other]\nx=1\n"));
}

#[test]
fn kiosk_immutability_covers_global_group_and_owned_entry_flags() {
    for text in [
        "[$i]\n",
        "[Proxy Settings][$i]\n",
        "[Proxy Settings]\nhttpProxy[$i]=x\n",
        "[Proxy Settings]\n  httpProxy [$i] =x\n",
    ] {
        assert!(immutable(text), "{text}");
    }
    for text in [
        "[Other][$i]\nhttpProxy=x\n",
        "[Proxy Settings]\nUnrelated[$i]=x\n",
        "[Proxy Settings]\nhttpProxy=value[$i]\n",
    ] {
        assert!(!immutable(text), "{text}");
    }
}

#[test]
fn key_prefixes_nested_groups_and_comments_are_not_owned() {
    let original = "[Proxy Settings]\n# httpProxy=comment\nhttpProxyExtra=extra\nhttpProxy =old\n[Proxy Settings][Nested]\nhttpProxy=nested\n";
    let applied = replace(original, "httpProxy", &["httpProxy=ours".into()]);
    assert!(applied.contains("# httpProxy=comment\nhttpProxyExtra=extra\nhttpProxy=ours"));
    assert!(applied.ends_with("[Proxy Settings][Nested]\nhttpProxy=nested\n"));
}

#[test]
fn legacy_journal_defaults_to_gnome_and_kde_has_its_own_schema() {
    let legacy: super::super::Journal =
        serde_json::from_value(serde_json::json!({"version":1,"port":2080,"before":[]})).unwrap();
    assert_eq!(legacy.backend, BackendKind::Gnome);
    assert_eq!(legacy.desired().len(), BackendKind::Gnome.len());
    let kde = super::super::Journal {
        backend: BackendKind::Kde,
        ..legacy
    };
    assert_eq!(kde.desired().len(), KEYS.len());
    assert_eq!(kde.desired().last().unwrap(), "1");
    assert_eq!(kde.desired()[3], "socks://127.0.0.1 2080");
}

#[test]
fn atomic_writes_preserve_a_config_symlink_and_restore_the_target() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    fs::create_dir(&config).unwrap();
    let target = root.path().join("dotfiles-kioslaverc");
    let original =
        "[Proxy Settings]\nhttpProxy=http://previous.invalid 3128\n[Other]\nvalue=keep\n";
    fs::write(&target, original).unwrap();
    std::os::unix::fs::symlink(&target, config.join("kioslaverc")).unwrap();
    let backend = Kde {
        config: config.clone(),
        defaults: vec![],
        reader: PathBuf::new(),
        cache: Mutex::new(None),
    };
    backend.write(0, Some("http://127.0.0.1 2080")).unwrap();
    assert!(config.join("kioslaverc").is_symlink());
    assert!(fs::read_to_string(&target)
        .unwrap()
        .contains("httpProxy=http://127.0.0.1 2080"));
    backend
        .write(
            0,
            Some(&serde_json::to_string(&entries(original, "httpProxy")).unwrap()),
        )
        .unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), original);
    fs::remove_file(target).unwrap();
    assert_eq!(
        backend.write(0, Some("http://127.0.0.1 2080")).unwrap_err(),
        "system_proxy_not_writable"
    );
    assert!(config.join("kioslaverc").is_symlink());
}
