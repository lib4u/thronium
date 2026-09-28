use super::journal::{Entry, Journal};
use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, name: &str, port: u16) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":port}),
    })
    .unwrap()
}
fn entry(kind: &str, status: &str) -> Entry {
    Entry {
        id: 0,
        at: 0,
        kind: kind.into(),
        source: "single".into(),
        profile_id: "p1".into(),
        profile_name: "Profile".into(),
        member_id: None,
        member_name: None,
        member_origin: None,
        transport: Some("isolated-core".into()),
        status: status.into(),
        latency_ms: Some(42),
        ip: None,
        country_code: None,
        download: None,
        upload: None,
        error: None,
    }
}

#[test]
fn journal_keeps_bounded_recent_history_and_reloads_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::default();
    for i in 0..620 {
        let id = journal.record(entry("ip", if i % 2 == 0 { "ok" } else { "error" }));
        assert_eq!(id, i + 1);
    }
    assert_eq!(journal.len(), 500, "count bound");
    journal.save(dir.path()).unwrap();
    let mut reloaded = Journal::load(dir.path());
    assert_eq!(reloaded.view(), journal.view());
    assert_eq!(reloaded.len(), journal.len());
    let view = reloaded.view();
    assert_eq!(view["total"], 500);
    assert_eq!(view["limit"], 500);
    assert_eq!(view["retentionDays"], 7);
    assert_eq!(view["entries"][0]["id"], 620, "newest first");
    let next = reloaded.record(entry("speed", "ok"));
    assert_eq!(next, 621, "ids continue after reload");
}

#[test]
fn journal_rejects_foreign_or_unsafe_files_and_stays_usable() {
    let dir = tempfile::tempdir().unwrap();
    for text in [
        "not json",
        r#"{"version":2,"next_id":1,"entries":[]}"#,
        r#"{"version":1,"next_id":2,"entries":[{"id":1,"at":1,"kind":"ip","source":"single","profileId":"p","profileName":"n","status":"ok","error":"contains space and CAPS"}]}"#,
        r#"{"version":1,"next_id":1,"entries":[{"id":5,"at":1,"kind":"ip","source":"single","profileId":"p","profileName":"n","status":"ok"}]}"#,
        r#"{"version":1,"next_id":2,"entries":[{"id":1,"at":1,"kind":"other","source":"single","profileId":"p","profileName":"n","status":"ok"}]}"#,
    ] {
        std::fs::write(dir.path().join("measurement-journal-v1.json"), text).unwrap();
        let journal = Journal::load(dir.path());
        assert_eq!(journal.len(), 0, "{text}");
    }
    let aged = format!(
        r#"{{"version":1,"next_id":3,"entries":[{{"id":1,"at":1,"kind":"ip","source":"single","profileId":"p","profileName":"n","status":"ok"}},{{"id":2,"at":{},"kind":"ip","source":"batch","profileId":"p","profileName":"n","status":"ok"}}]}}"#,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    std::fs::write(dir.path().join("measurement-journal-v1.json"), aged).unwrap();
    let journal = Journal::load(dir.path());
    assert_eq!(
        journal.len(),
        1,
        "entries older than the retention window are dropped on load"
    );
    assert_eq!(journal.view()["entries"][0]["id"], 2);
}

#[test]
fn batch_completion_journals_each_finished_row_with_its_member_and_code() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", 1080);
    let b = add(&mut e, "B", 1081);
    let run = e.start_ip_tests(vec![a.clone(), b.clone()]).unwrap();
    let first = e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(
        &run.id,
        &first.id,
        Ok(Outcome::Ip {
            ip: "203.0.113.9".into(),
            country: Some("JP".into()),
        }),
    );
    let second = e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(&run.id, &second.id, Err("probe_timeout".into()));
    let view = e.measurement_journal();
    let entries = view["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (
            entries[1]["profileId"].as_str(),
            entries[1]["status"].as_str(),
            entries[1]["ip"].as_str(),
            entries[1]["source"].as_str(),
            entries[1]["kind"].as_str()
        ),
        (
            Some(a.as_str()),
            Some("ok"),
            Some("203.0.113.9"),
            Some("batch"),
            Some("ip")
        )
    );
    assert_eq!(
        (
            entries[0]["profileId"].as_str(),
            entries[0]["status"].as_str(),
            entries[0]["error"].as_str()
        ),
        (Some(b.as_str()), Some("error"), Some("probe_timeout"))
    );
    assert!(entries.iter().all(|e| e.get("memberId").is_none()));
    drop(e);
    let mut reopened = Engine::open(_dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(
        reopened.measurement_journal()["total"],
        2,
        "the journal is persisted"
    );
    reopened.clear_measurement_journal().unwrap();
    assert_eq!(reopened.measurement_journal()["total"], 0);
    drop(reopened);
    assert_eq!(
        Engine::open(_dir.path(), Path::new("missing-core"))
            .unwrap()
            .measurement_journal()["total"],
        0
    );
}

#[test]
fn journal_entries_never_carry_free_text_errors() {
    let (_dir, mut e) = setup();
    let a = add(&mut e, "A", 1080);
    let run = e.start_ip_tests(vec![a.clone()]).unwrap();
    let probe = e.next_url_test(&run.id).unwrap();
    e.finish_url_test_detailed(
        &run.id,
        &probe.id,
        Err("unexpected core text with secret=abc".into()),
    );
    let view = e.measurement_journal();
    let error = view["entries"][0]["error"].as_str().unwrap();
    assert!(
        error
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'-'),
        "{error}"
    );
    assert!(!serde_json::to_string(&view).unwrap().contains("secret=abc"));
    let mut single = entry("speed", "error");
    single.error = Some("core said: token=xyz".into());
    e.record_measurement(single);
    let view = e.measurement_journal();
    assert_eq!(view["entries"][0]["error"], "probe_failed");
    assert_eq!(view["entries"][0]["status"], "error");
    assert!(!serde_json::to_string(&view).unwrap().contains("token=xyz"));
}
#[test]
fn member_origin_round_trips_and_stays_absent_for_plain_profiles() {
    let mut e = entry("ip", "ok");
    e.member_id = Some("m".into());
    e.member_name = Some("Member".into());
    e.member_origin = Some(crate::auto_selector::MemberOrigin::Running);
    let text = serde_json::to_string(&e).unwrap();
    assert!(text.contains("\"memberOrigin\":\"running\""));
    assert_eq!(serde_json::from_str::<Entry>(&text).unwrap(), e);
    let plain = serde_json::to_string(&entry("ip", "ok")).unwrap();
    assert!(!plain.contains("memberOrigin"));
}

/// Codes the batch itself assigns keep their meaning in the journal instead of
/// becoming a generic failure; unknown text still does.
#[test]
fn batch_assigned_codes_survive_the_journal_and_unknown_text_does_not() {
    let (_dir, mut e) = setup();
    for code in [
        "probe_stale",
        "probe_auto_failed",
        "probe_auto_unsupported",
        "geodata_category_missing",
        "raw failure text",
    ] {
        let mut failed = entry("latency", "error");
        failed.error = Some(code.into());
        e.record_measurement(failed);
    }
    let errors: Vec<_> = e.measurement_journal()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["error"].as_str().unwrap().to_owned())
        .collect();
    for code in [
        "probe_stale",
        "probe_auto_failed",
        "probe_auto_unsupported",
        "geodata_category_missing",
        "probe_failed",
    ] {
        assert!(errors.iter().any(|e| e == code), "{code} in {errors:?}");
    }
    assert!(!errors.iter().any(|e| e == "raw failure text"));
}
