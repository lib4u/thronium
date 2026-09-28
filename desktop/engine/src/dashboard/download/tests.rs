use super::*;
use serde_json::json;
use std::path::Path;

#[test]
fn job_registry_handles_early_foreign_active_and_late_cancellation() {
    let mut jobs = Jobs::default();
    jobs.cancel("early").unwrap();
    assert_eq!(
        jobs.begin("early").err().as_deref(),
        Some("dashboard_request_finished")
    );
    let active = jobs.begin("active").unwrap();
    assert_eq!(jobs.begin("other").err().as_deref(), Some("dashboard_busy"));
    jobs.cancel("foreign").unwrap();
    jobs.finish("foreign");
    assert!(!*active.borrow());
    assert_eq!(jobs.begin("other").err().as_deref(), Some("dashboard_busy"));
    jobs.cancel("active").unwrap();
    assert!(*active.borrow());
    assert_eq!(jobs.begin("other").err().as_deref(), Some("dashboard_busy"));
    jobs.finish("active");
    assert_eq!(
        jobs.begin("active").err().as_deref(),
        Some("dashboard_request_finished")
    );
    let next = jobs.begin("next").unwrap();
    assert!(!*next.borrow());
    jobs.finish("next");
    for n in 0..150 {
        jobs.cancel(&format!("done-{n}")).unwrap();
    }
    for id in ["", "with/slash", "x y", "юникод"] {
        assert!(jobs.begin(id).is_err());
        assert!(jobs.cancel(id).is_err());
    }
    assert!(jobs.begin(&"a".repeat(129)).is_err());
    assert!(serde_json::from_value::<Request>(
        json!({"requestId":"owned","url":"https://custom.invalid"})
    )
    .is_err());
}
#[test]
fn download_redirects_are_limited_to_official_https_hosts() {
    for url in [
        URL,
        "https://codeload.github.com/SagerNet/sing-box-dashboard/zip/refs/heads/gh-pages",
    ] {
        assert!(allowed_redirect(&reqwest::Url::parse(url).unwrap()));
    }
    for url in [
        "http://github.com/file",
        "https://github.com.evil.invalid/file",
        "https://untrusted.invalid/file",
        "https://u:p@github.com/file",
        "https://codeload.github.com:8443/file",
    ] {
        assert!(!allowed_redirect(&reqwest::Url::parse(url).unwrap()));
    }
}
#[tokio::test]
async fn cancellation_and_missing_requested_proxy_do_not_contact_the_download_server_or_start_core()
{
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("/missing-core")).unwrap();
    engine
        .store
        .library
        .settings
        .insert("net_use_proxy".into(), json!(true));
    assert_eq!(
        engine.prepare_dashboard_download().err().as_deref(),
        Some("dashboard_proxy_unavailable")
    );
    assert!(engine.rpc.is_none());
    assert!(!dir.path().join("web-dashboard").exists());
    let (_send, receive) = watch::channel(true);
    let download = Download {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        assets: Assets::new(dir.path()),
    };
    assert_eq!(
        download.execute(receive).await.err().as_deref(),
        Some("dashboard_cancelled")
    );
    assert!(!dir.path().join("web-dashboard").exists());
}
