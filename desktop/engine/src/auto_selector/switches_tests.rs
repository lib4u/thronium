use super::switches::{Entry, Journal};
use super::*;
use crate::ProfileDraft;
use std::path::Path;

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    (dir, e)
}
fn add(e: &mut Engine, id: &str, name: &str) -> String {
    e.save_profile(ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: name.into(),
        group_id: "personal".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"socks","server":"127.0.0.1","server_port":1080,"tag":id}),
    })
    .unwrap()
}
fn entry(to: &str) -> Entry {
    Entry {
        id: 0,
        at: 0,
        pool_id: "pool".into(),
        pool_name: "Pool".into(),
        from_name: String::new(),
        to_name: to.into(),
    }
}

#[test]
fn history_keeps_bounded_recent_switches_and_reloads_them() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::default();
    for i in 0..620 {
        let id = journal.record(entry(&format!("Member {}", i % 3)));
        assert_eq!(id, i + 1);
    }
    assert_eq!(journal.len(), 500);
    journal.save(dir.path()).unwrap();
    let reloaded = Journal::load(dir.path());
    assert_eq!(reloaded.view(), journal.view());
    assert_eq!(reloaded.len(), journal.len());
    let view = reloaded.view();
    assert_eq!(view["total"], 500);
    assert_eq!(view["limit"], 500);
    assert_eq!(view["retentionDays"], 7);
    assert_eq!(view["entries"][0]["id"], 620, "newest first");
}

#[test]
fn history_rejects_foreign_or_unsafe_files_and_drops_aged_entries() {
    let dir = tempfile::tempdir().unwrap();
    for text in [
        "not json",
        r#"{"version":2,"next_id":1,"entries":[]}"#,
        r#"{"version":1,"next_id":2,"entries":[{"id":1,"at":1,"poolId":"p","poolName":"n","toName":""}]}"#,
        r#"{"version":1,"next_id":1,"entries":[{"id":5,"at":1,"poolId":"p","poolName":"n","toName":"A"}]}"#,
        r#"{"version":1,"next_id":2,"entries":[{"id":1,"at":1,"poolId":"p","poolName":"n","toName":"A","secret":"x"}]}"#,
    ] {
        std::fs::write(dir.path().join("switch-history-v1.json"), text).unwrap();
        assert_eq!(Journal::load(dir.path()).len(), 0, "{text}");
    }
    let aged = format!(
        r#"{{"version":1,"next_id":3,"entries":[{{"id":1,"at":1,"poolId":"p","poolName":"n","toName":"Old"}},{{"id":2,"at":{},"poolId":"p","poolName":"n","toName":"New"}}]}}"#,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    std::fs::write(dir.path().join("switch-history-v1.json"), aged).unwrap();
    let journal = Journal::load(dir.path());
    assert_eq!(
        journal.len(),
        1,
        "entries older than the window are dropped"
    );
    assert_eq!(journal.view()["entries"][0]["toName"], "New");
}

#[test]
fn recording_a_switch_resolves_member_and_pool_names_and_persists() {
    let (_dir, mut e) = setup();
    let first = add(&mut e, "first", "First member");
    let second = add(&mut e, "second", "Second member");
    let pool = e
        .save_profile(ProfileDraft {
            vpn_policy: Default::default(),
            id: None,
            name: "Pool".into(),
            group_id: "personal".into(),
            kind: ProfileKind::AutoSelector,
            config: json!({"type":"auto-selector","members":[first.clone(), second.clone()]}),
        })
        .unwrap();
    e.running = Some(pool.clone());
    let from_tag = member_tag("proxy", &first);
    let to_tag = member_tag("proxy", &second);
    e.record_member_switch("proxy", "", &from_tag);
    e.record_member_switch("proxy", &from_tag, &to_tag);
    let view = e.switch_history();
    let entries = view["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (
            entries[0]["poolId"].as_str(),
            entries[0]["poolName"].as_str(),
            entries[0]["fromName"].as_str(),
            entries[0]["toName"].as_str()
        ),
        (
            Some(pool.as_str()),
            Some("Pool"),
            Some("First member"),
            Some("Second member")
        )
    );
    assert_eq!(
        entries[1]["fromName"], "",
        "the first selection has no origin"
    );
    assert_eq!(entries[1]["toName"], "First member");
    drop(e);
    let mut reopened = Engine::open(_dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(reopened.switch_history()["total"], 2, "history persists");
    reopened.clear_switch_history().unwrap();
    assert_eq!(reopened.switch_history()["total"], 0);
}
