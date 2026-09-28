use super::*;
use crate::store::ProfileKind;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn settings(url: &str) -> Settings {
    Settings {
        name_rules: Default::default(),
        inherit_defaults: Some(false),
        allow_insecure: false,
        timeout_seconds: 30,
        url: url.into(),
        headers: BTreeMap::new(),
        user_agent: user_agent(),
        via_proxy: false,
        use_provider_routing: false,
        interval_minutes: 0,
    }
}
fn setup() -> (tempfile::TempDir, Engine, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let id = engine
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: None,
            name: "Provider".into(),
            subscription: Some(settings("https://example.test/token-secret")),
        })
        .unwrap();
    (dir, engine, id)
}
fn draft(group: &str, name: &str, port: u16, password: &str) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: group.into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"example.test","server_port":port,"username":"user","password":password}),
    }
}
fn ticket(e: &mut Engine, group: &str) -> String {
    let request = e.subscription_request(group).unwrap();
    e.subscription_downloaded(
        request,
        Download {
            metadata: Default::default(),
            body: "fixture".into(),
            usage: Usage::parse("upload=10; download=20; total=100; expire=2000000000"),
        },
    )
    .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .into()
}
fn apply(e: &mut Engine, group: &str, profiles: Vec<ProfileDraft>) -> Vec<Change> {
    let token = ticket(e, group);
    e.preview_subscription(&token, profiles).unwrap();
    e.apply_subscription(&token).unwrap()
}
fn state(e: &Engine) -> Value {
    serde_json::to_value(&e.store.library).unwrap()
}

#[test]
fn external_core_remote_batch_is_rejected_before_filters_and_never_reuses_old_plan() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "Keep", 1080, "old")]);
    let mut group = e.group(&g).unwrap();
    group
        .subscription
        .as_mut()
        .unwrap()
        .settings
        .name_rules
        .include = "Keep".into();
    *e.store
        .library
        .groups
        .iter_mut()
        .find(|group| group.id == g)
        .unwrap() = group;
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Keep", 1080, "valid-preview")])
        .unwrap();
    let before = state(&e);
    let mut external = draft(&g, "Excluded by filter", 1081, "private-command");
    external.kind = ProfileKind::ExternalCore;
    external.config = json!({"type":"extracore","socks_address":"127.0.0.1","socks_port":1081,"extra_core_path":"/tmp/private-command","extra_core_args":"--config %s","extra_core_conf":"private-config","no_logs":true});
    assert_eq!(
        e.preview_subscription(&token, vec![draft(&g, "Keep", 1080, "new"), external])
            .err()
            .as_deref(),
        Some("external_remote_import_unsupported")
    );
    assert_eq!(state(&e), before);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_preview_required")
    );
    assert_eq!(state(&e), before);
}

#[test]
fn updates_preserve_identity_favorites_selection_and_local_profiles() {
    let (dir, mut e, g) = setup();
    let initial = apply(
        &mut e,
        &g,
        vec![draft(&g, "One", 1080, "old"), draft(&g, "Two", 1081, "two")],
    );
    let id = initial[0].id.clone();
    e.favorite(&id).unwrap();
    e.select(&id).unwrap();
    let local = e.save_profile(draft(&g, "Local", 1090, "local")).unwrap();
    let token = ticket(&mut e, &g);
    let before = state(&e);
    let preview = e
        .preview_subscription(
            &token,
            vec![
                draft(&g, "New", 1082, "new"),
                draft(&g, "Renamed", 1080, "rotated"),
            ],
        )
        .unwrap();
    assert_eq!(state(&e), before, "preview must not write the library");
    assert_eq!(
        preview
            .iter()
            .map(|c| c.action.as_str())
            .collect::<Vec<_>>(),
        ["added", "updated", "removed"]
    );
    assert_eq!(preview[1].id, id);
    e.apply_subscription(&token).unwrap();
    assert_eq!(
        e.store
            .library
            .profiles
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["New", "Renamed", "Local"]
    );
    assert_eq!(e.store.library.selected.as_deref(), Some(id.as_str()));
    assert!(e.profile(&id).unwrap().favorite);
    assert_eq!(e.profile(&id).unwrap().config["password"], "rotated");
    assert!(e.profile(&local).is_ok());
    assert!(e.profile(&initial[1].id).is_err());
    let subscription = e.group(&g).unwrap().subscription.unwrap();
    assert!(subscription.updated_at.is_some());
    assert_eq!(subscription.usage.unwrap().total, Some(100));
    let expected = state(&e);
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(state(&reopened), expected);
}

#[test]
fn duplicates_are_matched_once_and_reordered_without_swapping_favorites() {
    let (_dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "A", 1080, "a"),
            draft(&g, "B", 1080, "b"),
            draft(&g, "C", 1080, "a"),
        ],
    );
    e.favorite(&first[1].id).unwrap();
    let second = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "B", 1080, "b"),
            draft(&g, "A", 1080, "a"),
            draft(&g, "C", 1080, "a"),
            draft(&g, "D", 1080, "a"),
        ],
    );
    assert_eq!(second[0].id, first[1].id);
    assert_eq!(second[1].id, first[0].id);
    assert_eq!(second[2].id, first[2].id);
    assert_eq!(second[3].action, "added");
    assert_eq!(
        e.store
            .library
            .profiles
            .iter()
            .filter(|p| p.favorite)
            .count(),
        1
    );
    assert!(e.profile(&second[0].id).unwrap().favorite);
}

#[test]
fn active_changes_and_removed_routing_targets_are_kept() {
    let (_dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Active", 1080, "old"),
            draft(&g, "Routed", 1081, "old"),
            draft(&g, "Gone", 1082, "old"),
        ],
    );
    e.running = Some(first[0].id.clone());
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{}", first[1].id));
    let next = apply(&mut e, &g, vec![draft(&g, "Active", 1080, "new")]);
    assert_eq!(
        next.iter()
            .map(|c| (c.action.as_str(), c.reason.as_deref()))
            .collect::<Vec<_>>(),
        [
            ("kept", Some("running")),
            ("kept", Some("running")),
            ("removed", None)
        ]
    );
    assert_eq!(e.profile(&first[0].id).unwrap().config["password"], "old");
    assert!(e.profile(&first[1].id).is_ok());
    e.running = None;
    apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Active", 1080, "new"),
            draft(&g, "Routed", 1081, "new"),
        ],
    );
    assert_eq!(e.profile(&first[0].id).unwrap().config["password"], "new");
    e.running = Some(first[0].id.clone());
    let result = apply(&mut e, &g, vec![draft(&g, "Only new", 9999, "new")]);
    assert!(result
        .iter()
        .any(|c| c.id == first[0].id && c.reason.as_deref() == Some("running")));
}

#[test]
fn stale_downloads_and_previews_never_overwrite_edits() {
    let (_dir, mut e, g) = setup();
    let request = e.subscription_request(&g).unwrap();
    e.save_profile(draft(&g, "Manual", 1234, "secret")).unwrap();
    assert_eq!(
        e.subscription_downloaded(
            request,
            Download {
                metadata: Default::default(),
                body: "anything".into(),
                usage: None
            }
        )
        .unwrap_err(),
        "subscription_changed"
    );
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Remote", 1080, "remote")])
        .unwrap();
    e.save_profile(draft(&g, "Another manual", 1235, "secret"))
        .unwrap();
    let before = state(&e);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(state(&e), before);
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Remote", 1080, "remote")])
        .unwrap();
    let unrelated = e
        .save_profile(draft("personal", "Unrelated", 4321, "local"))
        .unwrap();
    e.select(&unrelated).unwrap();
    e.apply_subscription(&token).unwrap();
    assert!(e.profile(&unrelated).is_ok());
    assert_eq!(e.store.library.selected, Some(unrelated));
}

#[test]
fn invalid_empty_unreviewed_expired_and_cancelled_updates_are_non_destructive() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "One", 1080, "old")]);
    let before = state(&e);
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "One", 1080, "new")])
        .unwrap();
    assert!(e.preview_subscription(&token, vec![]).is_err());
    assert!(e
        .preview_subscription(&token, vec![draft("personal", "Wrong group", 1080, "old")])
        .is_err());
    let mut invalid = draft(&g, "Bad", 1080, "old");
    invalid.config = json!(null);
    assert!(e.preview_subscription(&token, vec![invalid]).is_err());
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_preview_required")
    );
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "One", 1080, "new")])
        .unwrap();
    e.discard_subscription(&token);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_expired")
    );
    let token = ticket(&mut e, &g);
    e.subscription_tickets.get_mut(&token).unwrap().used =
        Instant::now() - Duration::from_secs(601);
    assert!(e
        .preview_subscription(&token, vec![draft(&g, "One", 1080, "new")])
        .is_err());
    assert_eq!(state(&e), before);
}

#[test]
fn group_changes_preserve_profiles_and_protect_referenced_deletions() {
    let (_dir, mut e, g) = setup();
    let first = apply(&mut e, &g, vec![draft(&g, "One", 1080, "old")]);
    let id = &first[0].id;
    e.move_group(&g, -1).unwrap();
    assert_eq!(e.store.library.groups[0].id, g);
    assert!(e.move_group(&g, -1).is_err());
    assert!(e.delete_group("personal", false).is_err());
    e.running = Some(id.clone());
    assert_eq!(
        e.delete_group(&g, true).err().as_deref(),
        Some("stop_before_editing")
    );
    e.running = None;
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{id}"));
    assert_eq!(
        e.delete_group(&g, true).err().as_deref(),
        Some("profile_used_in_routing")
    );
    e.favorite(id).unwrap();
    e.delete_group(&g, false).unwrap();
    assert_eq!(e.profile(id).unwrap().group_id, "personal");
    assert!(e.profile(id).unwrap().favorite);
    assert!(e.group(&g).is_err());
}

#[test]
fn changing_sources_resets_usage_and_detaching_keeps_profiles_local() {
    let (_dir, mut e, g) = setup();
    let first = apply(&mut e, &g, vec![draft(&g, "One", 1080, "old")]);
    let id = &first[0].id;
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Changed".into(),
        subscription: Some(settings("https://example.test/other")),
    })
    .unwrap();
    let subscription = e.group(&g).unwrap().subscription.unwrap();
    assert!(subscription.usage.is_none());
    assert!(subscription.updated_at.is_none());
    assert!(subscription.managed_ids.contains(id));
    let mut moved = draft("personal", "One", 1080, "old");
    moved.id = Some(id.clone());
    e.save_profile(moved).unwrap();
    let mut back = draft(&g, "One", 1080, "old");
    back.id = Some(id.clone());
    e.save_profile(back).unwrap();
    assert!(e
        .group(&g)
        .unwrap()
        .subscription
        .unwrap()
        .managed_ids
        .is_empty());
    apply(&mut e, &g, vec![draft(&g, "Remote", 1081, "new")]);
    assert!(e.profile(id).is_ok());
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Local".into(),
        subscription: None,
    })
    .unwrap();
    assert!(e.subscription_request(&g).is_err());
    assert_eq!(e.store.library.profiles.len(), 2);
    e.delete_group(&g, true).unwrap();
    assert!(e.store.library.profiles.is_empty());
    assert!(e.store.library.selected.is_none());
}

#[test]
fn snapshots_redact_sources_and_legacy_groups_remain_readable() {
    let (dir, mut e, g) = setup();
    let mut config = settings("https://example.test/token-secret");
    config
        .headers
        .insert("Authorization".into(), "Bearer header-secret".into());
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(config),
    })
    .unwrap();
    let snapshot = serde_json::to_string(&e.snapshot()).unwrap();
    assert!(!snapshot.contains("token-secret"));
    assert!(!snapshot.contains("header-secret"));
    assert!(serde_json::to_string(&e.group(&g).unwrap())
        .unwrap()
        .contains("header-secret"));
    assert!(e.group("personal").unwrap().subscription.is_none());
    let legacy = serde_json::from_value::<Group>(json!({"id":"old","name":"Old group"})).unwrap();
    assert!(legacy.subscription.is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("library.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[cfg(not(unix))]
    let _ = &dir;
}

#[test]
fn invalid_settings_and_unavailable_proxies_are_rejected_without_echoing_secrets() {
    for url in [
        "file:///secret",
        "https://user:secret@example.test",
        "https://example.test/#secret",
        "garbage-secret",
    ] {
        assert_eq!(
            settings(url).validate().err().as_deref(),
            Some("invalid_subscription_url")
        );
    }
    for key in [
        "Host",
        "Connection",
        "Content-Length",
        "Proxy-Authorization",
        "bad\r\n",
    ] {
        let mut s = settings("https://example.test");
        s.headers.insert(key.into(), "secret".into());
        assert_eq!(
            s.validate().err().as_deref(),
            Some("invalid_subscription_headers")
        );
    }
    let (_dir, mut e, g) = setup();
    let mut s = settings("https://example.test");
    s.via_proxy = true;
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Proxy".into(),
        subscription: Some(s),
    })
    .unwrap();
    assert_eq!(
        e.subscription_request(&g).err().as_deref(),
        Some("subscription_proxy_unavailable")
    );
    let id = e
        .save_profile(draft("personal", "Proxy", 1080, "secret"))
        .unwrap();
    e.running = Some(id);
    // A remembered running id alone cannot prove that a usable HTTP listener exists.
    assert_eq!(
        e.subscription_request(&g).err().as_deref(),
        Some("subscription_proxy_unavailable")
    );
    assert_eq!(
        Usage::parse("upload=-1; download=NaN; total=18446744073709551615; expire=bad"),
        None
    );
    assert_eq!(
        Usage::parse("UPLOAD = 12; download=20; total=0").unwrap(),
        Usage {
            upload: Some(12),
            download: Some(20),
            total: Some(0),
            expire: None
        }
    );
}

async fn server(response: Vec<u8>) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut part = [0; 1024];
        loop {
            let count = socket.read(&mut part).await.unwrap();
            request.extend_from_slice(&part[..count]);
            if count == 0 || request.windows(4).any(|s| s == b"\r\n\r\n") {
                break;
            }
        }
        let _ = socket.write_all(&response).await;
        String::from_utf8(request).unwrap()
    });
    (url, task)
}
fn response(body: &[u8], extra: &str) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

#[tokio::test]
async fn download_sends_configured_headers_and_reads_quota() {
    let (url, task) = server(response(
        b"socks://example.test:1080",
        "Subscription-Userinfo: upload=10; download=20; total=30\r\n",
    ))
    .await;
    let mut s = settings(&url);
    s.user_agent = "Thronium-test".into();
    s.headers
        .insert("Authorization".into(), "Bearer fixture".into());
    let download = Downloads::default()
        .fetch(&uuid::Uuid::new_v4().to_string(), &s, None)
        .await
        .unwrap();
    assert_eq!(download.body, "socks://example.test:1080");
    assert_eq!(download.usage.unwrap().total, Some(30));
    let request = task.await.unwrap().to_ascii_lowercase();
    assert!(request.contains("user-agent: thronium-test\r\n"));
    assert!(request.contains("authorization: bearer fixture\r\n"));
}

/// Custom headers (tokens, cookies) never reach another origin; the
/// User-Agent names the client, as in Qt, so the provider's mirror still
/// serves the format chosen for it.
#[tokio::test]
async fn cross_origin_redirects_strip_custom_headers_but_keep_the_user_agent() {
    let (target, target_task) = server(response(b"socks://example.test:1080", "")).await;
    let (url,source_task)=server(format!("HTTP/1.1 302 Found\r\nLocation: {target}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()).await;
    let mut s = settings(&url);
    s.user_agent = "Provider-Client/1.0".into();
    s.headers.insert("X-Token".into(), "secret-header".into());
    s.headers.insert("Cookie".into(), "secret-cookie".into());
    fetch(&s, None).await.unwrap();
    assert!(source_task.await.unwrap().contains("secret-header"));
    let received = target_task.await.unwrap();
    assert!(!received.contains("secret"));
    assert!(received.starts_with("GET /next HTTP/1.1"));
    assert!(received
        .to_ascii_lowercase()
        .contains("user-agent: provider-client/1.0\r\n"));
}

#[test]
fn a_download_is_bounded_by_the_network_timeout_setting() {
    let mut s = settings("https://example.test/");
    for (setting, expected) in [(0, 30), (5, 5), (120, 120), (300, 300)] {
        s.timeout_seconds = setting;
        assert_eq!(s.timeout(), Duration::from_secs(expected), "{setting}");
    }
}

#[tokio::test]
async fn bad_status_invalid_utf8_empty_and_large_responses_fail_safely() {
    let cases = vec![
        (
            b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\n\r\npart".to_vec(),
            "subscription_http_206",
        ),
        (
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nsecret".to_vec(),
            "subscription_http_403",
        ),
        (
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            "subscription_http_404",
        ),
        (
            b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n".to_vec(),
            "subscription_http_error",
        ),
        (response(b" \n", ""), "subscription_empty"),
        (response(&[0xff], ""), "subscription_invalid_text"),
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_BYTES + 1
            )
            .into_bytes(),
            "subscription_too_large",
        ),
        (
            response(&vec![b'x'; MAX_BYTES + 1], ""),
            "subscription_too_large",
        ),
    ];
    for (response, error) in cases {
        let (url, task) = server(response).await;
        assert_eq!(
            fetch(&settings(&(url + "/secret")), None)
                .await
                .err()
                .as_deref(),
            Some(error)
        );
        task.await.unwrap();
    }
    let mut chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        MAX_BYTES + 1
    )
    .into_bytes();
    chunked.extend(vec![b'x'; MAX_BYTES + 1]);
    chunked.extend(b"\r\n0\r\n\r\n");
    let (url, task) = server(chunked).await;
    assert_eq!(
        fetch(&settings(&url), None).await.err().as_deref(),
        Some("subscription_too_large")
    );
    task.await.unwrap();
}

#[tokio::test]
async fn downloads_are_cancellable_while_waiting_for_the_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s = settings(&format!("http://{}", listener.local_addr().unwrap()));
    let downloads = Downloads::default();
    let id = uuid::Uuid::new_v4().to_string();
    let download = downloads.fetch(&id, &s, None);
    let cancel = async {
        let (_socket, _) = listener.accept().await.unwrap();
        downloads.cancel(&id).await;
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(download, cancel)
    })
    .await
    .unwrap();
    assert_eq!(result.err().as_deref(), Some("subscription_cancelled"));
    assert!(downloads.active.lock().await.is_empty());
}

#[tokio::test]
async fn configured_proxy_is_used_without_system_proxy_settings() {
    let (proxy, task) = server(response(b"socks://example.test:1080", "")).await;
    let mut s = settings("http://unresolvable.invalid/subscription");
    s.via_proxy = true;
    assert_eq!(
        fetch(&s, Some(&proxy)).await.unwrap().body,
        "socks://example.test:1080"
    );
    assert!(task
        .await
        .unwrap()
        .starts_with("GET http://unresolvable.invalid/subscription HTTP/1.1"));
}

#[test]
fn group_metadata_commits_atomically_and_collapse_does_not_invalidate_review() {
    let (dir, mut e, g) = setup();
    let request = e.subscription_request(&g).unwrap();
    let token = e
        .subscription_downloaded(
            request,
            Download {
                body: "fixture".into(),
                usage: Usage::parse("download=10; total=100"),
                metadata: Metadata {
                    title: Some("Provider title".into()),
                    announcement: Some("First announcement".into()),
                    ..Default::default()
                },
            },
        )
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        e.group(&g).unwrap().subscription.unwrap().metadata,
        Metadata::default()
    );
    e.collapse_group(&g, true).unwrap();
    e.preview_subscription(&token, vec![draft(&g, "A", 443, "test-secret")])
        .unwrap();
    e.apply_subscription(&token).unwrap();
    assert!(e.group(&g).unwrap().collapsed);
    assert_eq!(
        e.group(&g)
            .unwrap()
            .subscription
            .unwrap()
            .metadata
            .announcement
            .as_deref(),
        Some("First announcement")
    );
    let profile_id = e.store.library.profiles[0].id.clone();
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert!(e.group(&g).unwrap().collapsed);
    assert_eq!(
        e.group(&g)
            .unwrap()
            .subscription
            .unwrap()
            .metadata
            .title
            .as_deref(),
        Some("Provider title")
    );
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "A", 443, "test-secret")])
        .unwrap();
    e.apply_subscription(&token).unwrap();
    assert_eq!(
        e.group(&g).unwrap().subscription.unwrap().metadata,
        Metadata::default()
    );
    assert_eq!(e.store.library.profiles[0].id, profile_id);
}

#[test]
fn metadata_is_preserved_on_stale_review_and_cleared_when_source_changes() {
    let (_dir, mut e, g) = setup();
    e.store
        .library
        .groups
        .iter_mut()
        .find(|v| v.id == g)
        .unwrap()
        .subscription
        .as_mut()
        .unwrap()
        .metadata
        .announcement = Some("Cached announcement".into());
    let token = ticket(&mut e, &g);
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Renamed".into(),
        subscription: Some(settings("https://example.test/token-secret")),
    })
    .unwrap();
    assert_eq!(
        e.preview_subscription(&token, vec![draft(&g, "A", 443, "secret")])
            .err()
            .as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(
        e.group(&g)
            .unwrap()
            .subscription
            .unwrap()
            .metadata
            .announcement
            .as_deref(),
        Some("Cached announcement")
    );
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Renamed".into(),
        subscription: Some(settings("https://example.test/other-token")),
    })
    .unwrap();
    assert_eq!(
        e.group(&g).unwrap().subscription.unwrap().metadata,
        Metadata::default()
    );
    let old: Group = serde_json::from_value(json!({"id":"old", "name":"Old group"})).unwrap();
    assert!(!old.collapsed);
}

#[test]
fn reorder_groups_preserves_contents_and_persists_one_move() {
    let (dir, mut e, provider) = setup();
    let first = apply(
        &mut e,
        &provider,
        vec![draft(&provider, "One", 1080, "old")],
    );
    e.favorite(&first[0].id).unwrap();
    e.select(&first[0].id).unwrap();
    e.running = Some(first[0].id.clone());
    e.collapse_group(&provider, true).unwrap();
    let mut groups = vec!["personal".to_string(), provider.clone()];
    for name in ["Hidden", "Last"] {
        groups.push(
            e.save_group(GroupDraft {
                auto_clear_unavailable: None,
                proxy_chain: None,
                id: None,
                name: name.into(),
                subscription: None,
            })
            .unwrap(),
        );
    }
    let before = state(&e);
    e.reorder_group(&groups[3], "personal", false).unwrap();
    assert_eq!(
        e.store
            .library
            .groups
            .iter()
            .map(|g| &g.id)
            .collect::<Vec<_>>(),
        vec![&groups[3], &groups[0], &groups[1], &groups[2]]
    );
    // A filtered UI supplies a target ID, not a replacement list of visible IDs.
    e.reorder_group("personal", &groups[2], true).unwrap();
    let after = state(&e);
    assert_eq!(after["profiles"], before["profiles"]);
    assert_eq!(after["selected"], before["selected"]);
    assert_eq!(after["preferences"], before["preferences"]);
    assert_eq!(after["routing"], before["routing"]);
    for group in before["groups"].as_array().unwrap() {
        assert!(after["groups"].as_array().unwrap().contains(group));
    }
    assert_eq!(e.running.as_deref(), Some(first[0].id.as_str()));
    e.running = None;
    drop(e);
    let reopened = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(state(&reopened), after);
}

#[test]
fn reorder_groups_validates_ids_and_does_not_publish_a_failed_write() {
    let (dir, mut e, group) = setup();
    let before = state(&e);
    for (source, target) in [("missing", group.as_str()), (group.as_str(), "missing")] {
        assert_eq!(
            e.reorder_group(source, target, false).err().as_deref(),
            Some("group_not_found")
        );
    }
    e.reorder_group(&group, &group, true).unwrap();
    e.reorder_group(&group, "personal", true).unwrap();
    assert_eq!(state(&e), before);
    let file = dir.path().join("library.json");
    let saved = dir.path().join("saved-library.json");
    std::fs::rename(&file, &saved).unwrap();
    std::fs::create_dir(&file).unwrap();
    assert!(e.reorder_group(&group, "personal", false).is_err());
    assert_eq!(state(&e), before);
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&saved, &file).unwrap();
}

#[test]
fn name_rules_filter_original_names_and_rename_without_changing_identity() {
    let (dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "DE old", 1080, "one"),
            draft(&g, "US old", 1081, "two"),
        ],
    );
    e.favorite(&first[0].id).unwrap();
    let mut settings = e.group(&g).unwrap().subscription.unwrap().settings;
    settings.name_rules = serde_json::from_value(json!({"include":"^(DE|US)","exclude":"US","rename":[{"pattern":"^DE (.*)$","replacement":"🇩🇪 ${1}"},{"pattern":"old$","replacement":"new"}]})).unwrap();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings),
    })
    .unwrap();
    let before = state(&e);
    let token = ticket(&mut e, &g);
    let preview = e
        .preview_subscription(
            &token,
            vec![
                draft(&g, "DE old", 1080, "one"),
                draft(&g, "US old", 1081, "two"),
            ],
        )
        .unwrap();
    assert_eq!(state(&e), before);
    assert!(preview
        .iter()
        .any(|c| c.id == first[0].id && c.name == "🇩🇪 new" && c.action == "updated"));
    assert!(preview
        .iter()
        .any(|c| c.id == first[1].id && c.action == "removed"));
    assert_eq!(e.subscription_check_index(&token, &first[0].id).unwrap(), 0);
    assert!(e.subscription_check_index(&token, &first[1].id).is_err());
    e.apply_subscription(&token).unwrap();
    let saved = e.profile(&first[0].id).unwrap();
    assert!(saved.favorite);
    assert_eq!(saved.config, draft(&g, "", 1080, "one").config);
    let again = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "DE old", 1080, "one"),
            draft(&g, "US old", 1081, "two"),
        ],
    );
    assert_eq!(again[0].action, "unchanged");
    assert_eq!(again[0].id, first[0].id);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        e.group(&g)
            .unwrap()
            .subscription
            .unwrap()
            .settings
            .name_rules
            .rename
            .len(),
        2
    );
}
#[test]
fn name_rules_errors_are_atomic_and_invalidate_old_previews() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "Keep", 1080, "secret")]);
    let mut settings = e.group(&g).unwrap().subscription.unwrap().settings;
    settings.name_rules.exclude = ".*".into();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings.clone()),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    let before = state(&e);
    assert_eq!(
        e.preview_subscription(&token, vec![draft(&g, "Keep", 1080, "secret")])
            .err()
            .as_deref(),
        Some("subscription_filtered_empty")
    );
    assert!(e.apply_subscription(&token).is_err());
    assert_eq!(state(&e), before);
    settings.name_rules.exclude.clear();
    settings.name_rules.rename = vec![name_rules::Rename {
        pattern: ".*".into(),
        replacement: String::new(),
    }];
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings.clone()),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    let before = state(&e);
    assert_eq!(
        e.preview_subscription(&token, vec![draft(&g, "Keep", 1080, "secret")])
            .err()
            .as_deref(),
        Some("subscription_invalid_renamed_name")
    );
    assert_eq!(state(&e), before);
    settings.name_rules.include = "(?=invalid)".into();
    assert_eq!(
        e.save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: Some(g.clone()),
            name: "Provider".into(),
            subscription: Some(settings)
        })
        .err()
        .as_deref(),
        Some("subscription_invalid_name_rules")
    );
    assert_eq!(state(&e), before);
}
#[test]
fn name_rules_keep_protected_and_local_profiles_and_reject_stale_policy() {
    let (_dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![draft(&g, "DE", 1080, "one"), draft(&g, "US", 1081, "two")],
    );
    let local = e.save_profile(draft(&g, "Local", 1082, "local")).unwrap();
    e.running = Some(first[1].id.clone());
    let mut settings = e.group(&g).unwrap().subscription.unwrap().settings;
    settings.name_rules.include = "DE".into();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings.clone()),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    let changes = e
        .preview_subscription(
            &token,
            vec![draft(&g, "DE", 1080, "one"), draft(&g, "US", 1081, "two")],
        )
        .unwrap();
    assert!(changes
        .iter()
        .any(|c| c.id == first[1].id && c.reason.as_deref() == Some("running")));
    e.apply_subscription(&token).unwrap();
    assert!(e.profile(&local).is_ok());
    assert!(e.profile(&first[1].id).is_ok());
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "DE", 1080, "one")])
        .unwrap();
    settings.name_rules.include = "US".into();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings),
    })
    .unwrap();
    let before = state(&e);
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
    assert_eq!(state(&e), before);
}
#[test]
fn name_rule_limits_and_invalid_input_cannot_bypass_validation() {
    let (_dir, mut e, g) = setup();
    let mut settings = e.group(&g).unwrap().subscription.unwrap().settings;
    settings.name_rules.include = "a".repeat(2049);
    assert_eq!(
        settings.validate().err().as_deref(),
        Some("subscription_invalid_name_rules")
    );
    settings.name_rules.include.clear();
    settings.name_rules.rename = vec![
        name_rules::Rename {
            pattern: "x".into(),
            replacement: "y".into()
        };
        17
    ];
    assert!(settings.validate().is_err());
    settings.name_rules.rename = vec![name_rules::Rename {
        pattern: "x".into(),
        replacement: "я".repeat(256),
    }];
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings.clone()),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    let before = state(&e);
    assert_eq!(
        e.preview_subscription(&token, vec![draft(&g, "xx", 1080, "secret")])
            .err()
            .as_deref(),
        Some("subscription_invalid_renamed_name")
    );
    assert_eq!(state(&e), before);
    settings.name_rules.rename.clear();
    settings.name_rules.exclude = "Excluded".into();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: None,
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    assert!(e
        .preview_subscription(
            &token,
            vec![
                draft(&g, "Keep", 1080, "secret"),
                draft("personal", "Excluded", 1081, "secret")
            ]
        )
        .is_err());
}
#[test]
fn filtering_identical_connections_retains_the_named_occurrence_with_its_favorite() {
    for password in ["same", "rotated"] {
        let (_dir, mut e, g) = setup();
        let first = apply(
            &mut e,
            &g,
            vec![
                draft(&g, "DE First", 1080, "same"),
                draft(&g, "US Second", 1080, "same"),
            ],
        );
        e.favorite(&first[1].id).unwrap();
        e.select(&first[1].id).unwrap();
        let mut settings = e.group(&g).unwrap().subscription.unwrap().settings;
        settings.name_rules.include = "^US".into();
        settings.name_rules.rename = vec![name_rules::Rename {
            pattern: "^US".into(),
            replacement: "🇺🇸".into(),
        }];
        e.save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: Some(g.clone()),
            name: "Provider".into(),
            subscription: Some(settings),
        })
        .unwrap();
        let changes = apply(
            &mut e,
            &g,
            vec![
                draft(&g, "DE First", 1080, password),
                draft(&g, "US Second", 1080, password),
            ],
        );
        assert_eq!(changes[0].id, first[1].id);
        assert_eq!(changes[0].name, "🇺🇸 Second");
        assert!(e.profile(&first[1].id).unwrap().favorite);
        assert_eq!(
            e.store.library.selected.as_deref(),
            Some(first[1].id.as_str())
        );
        assert!(changes
            .iter()
            .any(|c| c.id == first[0].id && c.action == "removed"));
    }
}

#[test]
fn group_proxies_are_retained_on_subscription_removal_and_protect_active_credentials() {
    let (_dir, mut e, g) = setup();
    let first = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Entry", 1080, "old"),
            draft(&g, "Keep", 1081, "keep"),
        ],
    );
    let target = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: Some(crate::group_chains::GroupChain {
                front: Some(first[0].id.clone()),
                landing: None,
            }),
            id: None,
            name: "Target".into(),
            subscription: None,
        })
        .unwrap();
    let selected = e
        .save_profile(draft(&target, "Selected", 1090, "local"))
        .unwrap();
    let result = apply(&mut e, &g, vec![draft(&g, "Keep", 1081, "keep")]);
    assert!(result.iter().any(|c| c.id == first[0].id
        && c.action == "kept"
        && c.reason.as_deref() == Some("chain")));
    e.running = Some(selected);
    let result = apply(
        &mut e,
        &g,
        vec![
            draft(&g, "Entry", 1080, "rotated"),
            draft(&g, "Keep", 1081, "keep"),
        ],
    );
    assert_eq!(result[0].action, "kept");
    assert_eq!(result[0].reason.as_deref(), Some("running"));
    assert_eq!(e.profile(&first[0].id).unwrap().config["password"], "old");
    e.running = None;
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Keep", 1081, "keep")])
        .unwrap();
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: Some(Default::default()),
        id: Some(target),
        name: "Target".into(),
        subscription: None,
    })
    .unwrap();
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
}

#[test]
fn changed_external_group_proxy_invalidates_subscription_validation() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "Keep", 1081, "keep")]);
    let external = e
        .save_profile(draft("personal", "Entry", 1090, "old"))
        .unwrap();
    let settings = e.group(&g).unwrap().subscription.unwrap().settings;
    e.save_group(GroupDraft {
        auto_clear_unavailable: None,
        proxy_chain: Some(crate::group_chains::GroupChain {
            front: Some(external.clone()),
            landing: None,
        }),
        id: Some(g.clone()),
        name: "Provider".into(),
        subscription: Some(settings),
    })
    .unwrap();
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Keep", 1081, "keep")])
        .unwrap();
    let mut changed: ProfileDraft =
        serde_json::from_value(json!(e.profile(&external).unwrap())).unwrap();
    changed.config["password"] = json!("new");
    e.save_profile(changed).unwrap();
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
    let token = ticket(&mut e, &g);
    e.preview_subscription(&token, vec![draft(&g, "Keep", 1081, "keep")])
        .unwrap();
    let mut prefs = e.store.library.preferences.clone();
    prefs.vless_core = crate::vless::Core::SingBox;
    e.preferences(prefs).unwrap();
    assert_eq!(
        e.apply_subscription(&token).err().as_deref(),
        Some("subscription_changed")
    );
}

#[test]
fn vpn_policy_remote_omission_preserves_local_policy_and_explicit_payload_cannot_replace_it() {
    let (directory, mut engine, group) = setup();
    let remote = |password: &str| {
        let mut p = draft(&group, "VPN", 443, password);
        p.config["type"] = json!("openconnect");
        p
    };
    let id = apply(&mut engine, &group, vec![remote("old")])[0]
        .id
        .clone();
    let policy = crate::vpn_policy::Policy {
        only_advertised_routes: true,
        use_tunnel_dns: false,
        block_outside_dns: true,
    };
    let mut local = remote("old");
    local.id = Some(id.clone());
    local.vpn_policy = crate::vpn_policy::Edit::Set(Some(policy));
    engine.save_profile(local).unwrap();
    let changes = apply(&mut engine, &group, vec![remote("new")]);
    assert_eq!(changes[0].id, id);
    assert_eq!(changes[0].action, "updated");
    assert_eq!(engine.profile(&id).unwrap().vpn_policy, Some(policy));
    assert_eq!(engine.profile(&id).unwrap().config["password"], "new");
    let before = std::fs::read(directory.path().join("library.json")).unwrap();
    let token = ticket(&mut engine, &group);
    engine
        .preview_subscription(&token, vec![remote("later")])
        .unwrap();
    let mut explicit = remote("remote override");
    explicit.vpn_policy = crate::vpn_policy::Edit::Set(None);
    assert_eq!(
        engine
            .preview_subscription(&token, vec![explicit])
            .err()
            .as_deref(),
        Some("vpn_policy_context_unsupported")
    );
    assert_eq!(
        engine.apply_subscription(&token).err().as_deref(),
        Some("subscription_preview_required")
    );
    assert_eq!(
        std::fs::read(directory.path().join("library.json")).unwrap(),
        before
    );
    assert!(engine.owned_core_process().is_none());
}

mod recreation;

/// "Auto-select" is a virtual entry, never a stored profile: an update of any
/// subscription or deleting an unrelated group must not replace it.
#[test]
fn applying_a_subscription_or_deleting_a_group_keeps_auto_select_selected() {
    let (_dir, mut e, g) = setup();
    apply(&mut e, &g, vec![draft(&g, "First", 1080, "one")]);
    e.store.library.selected = Some(crate::auto_selector::AUTO_SELECT_ID.into());
    apply(
        &mut e,
        &g,
        vec![
            draft(&g, "First", 1080, "one"),
            draft(&g, "Second", 1081, "two"),
        ],
    );
    assert_eq!(
        e.store.library.selected.as_deref(),
        Some(crate::auto_selector::AUTO_SELECT_ID)
    );
    let other = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            proxy_chain: None,
            id: None,
            name: "Other".into(),
            subscription: None,
        })
        .unwrap();
    e.delete_group(&other, true).unwrap();
    assert_eq!(
        e.store.library.selected.as_deref(),
        Some(crate::auto_selector::AUTO_SELECT_ID)
    );
    e.store.library.selected = None;
    apply(&mut e, &g, vec![draft(&g, "Third", 1082, "three")]);
    assert!(
        e.store.library.selected.is_some(),
        "an empty selection still picks the updated group's server"
    );
}

#[test]
fn every_named_http_status_crosses_the_ipc_boundary() {
    for status in HTTP_STATUSES {
        let code = format!("subscription_http_{status}");
        assert_eq!(crate::ipc::BoundaryError::legacy(&code).code, code);
    }
    assert_eq!(
        crate::ipc::BoundaryError::legacy("subscription_http_error").code,
        "subscription_http_error"
    );
}
