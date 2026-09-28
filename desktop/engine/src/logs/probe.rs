use super::{clean_text, Entry, Logs};
use crate::store::Profile;
use serde::Serialize;

/// Only display identity belongs in the shared log; never a profile config or URL.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeContext {
    pub run_id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub kind: String,
}
impl ProbeContext {
    pub(super) fn matches(&self, search: &str) -> bool {
        [
            &self.run_id,
            &self.profile_id,
            &self.profile_name,
            &self.kind,
        ]
        .into_iter()
        .any(|v| v.to_lowercase().contains(search))
    }
    fn size(&self) -> usize {
        self.run_id.len() + self.profile_id.len() + self.profile_name.len() + self.kind.len()
    }
}
impl Entry {
    pub(super) fn size(&self) -> usize {
        self.text.len()
            + self.probe.as_ref().map_or(0, ProbeContext::size)
            + self.code.as_ref().map_or(0, String::len)
            + self.detail.as_ref().map_or(0, String::len)
    }
}
impl Logs {
    /// `configs` are the disposable core's request configurations.
    pub(crate) fn begin_probe<'a>(&self, configs: impl IntoIterator<Item = &'a str>) -> Run {
        let owner = format!(
            "probe:{}",
            self.1
                .as_ref()
                .map_or_else(|| uuid::Uuid::new_v4().to_string(), |c| c.run_id.clone())
        );
        self.protect(&owner, configs);
        self.event("info", "test_started", None);
        Run {
            logs: self.clone(),
            finished: false,
        }
    }
    pub(crate) fn for_probe(&self, profile: &Profile, kind: &str) -> Self {
        // Bound metadata as well as lines, including names from imported profiles.
        let bounded = |s: &str| clean_text(&s.chars().take(128).collect::<String>());
        Self(
            self.0.clone(),
            Some(ProbeContext {
                run_id: uuid::Uuid::new_v4().to_string(),
                profile_id: bounded(&profile.id),
                profile_name: bounded(&profile.name),
                kind: bounded(kind),
            }),
        )
    }
}

pub(crate) struct Run {
    logs: Logs,
    finished: bool,
}
impl Run {
    pub(crate) fn finish(mut self, error: Option<&str>) {
        match error {
            None => self.logs.event("info", "test_completed", None),
            Some("probe_cancelled") => self.logs.event("info", "test_cancelled", None),
            Some(code) => self.logs.event("warn", "test_failed", Some(code)),
        }
        self.finished = true;
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        if !self.finished {
            self.logs.event("info", "test_cancelled", None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{Filter, MAX_BYTES, MAX_ENTRIES};
    fn profile(name: &str) -> Profile {
        serde_json::from_value(serde_json::json!({"id":"profile-a","groupId":"personal",
            "name":name,"favorite":false,"kind":"sing-box-outbound","config":{"type":"direct","password":"do-not-log"}})).unwrap()
    }
    #[test]
    fn concurrent_runs_have_separate_identity_but_one_filterable_bounded_buffer() {
        let logs = Logs::default();
        let p = profile("東京\n\u{1b}[31m node");
        let a = logs.for_probe(&p, "http");
        let b = logs.for_probe(&p, "speed");
        logs.push("app", None, "session", false);
        a.push("stderr", None, "ERROR peer refused", false);
        b.push("stdout", None, "transferred", false);
        let view = logs
            .view(Filter {
                scope: "tests".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(view.entries.len(), 2);
        assert_ne!(
            view.entries[0].probe.as_ref().unwrap().run_id,
            view.entries[1].probe.as_ref().unwrap().run_id
        );
        assert_eq!(
            view.entries[0].probe.as_ref().unwrap().profile_name,
            "東京 node"
        );
        assert!(!serde_json::to_string(&view).unwrap().contains("do-not-log"));
        assert_eq!(
            logs.view(Filter {
                scope: "session".into(),
                ..Default::default()
            })
            .unwrap()
            .entries
            .len(),
            1
        );
        assert_eq!(
            logs.view(Filter {
                scope: "tests".into(),
                search: "東京".into(),
                source: "stderr".into(),
                ..Default::default()
            })
            .unwrap()
            .entries
            .len(),
            1
        );
        assert!(logs
            .view(Filter {
                scope: "unknown".into(),
                ..Default::default()
            })
            .is_err());
        let large = logs.for_probe(&profile(&"🦊".repeat(4000)), "http");
        for _ in 0..MAX_ENTRIES {
            large.push("stdout", None, &"x".repeat(512), false);
        }
        let buffer = logs.0.lock().unwrap();
        assert!(buffer.bytes <= MAX_BYTES);
        assert_eq!(
            buffer.bytes,
            buffer.entries.iter().map(Entry::size).sum::<usize>()
        );
        drop(buffer);
        logs.clear();
        a.push("stdout", None, "after clear", false);
        assert_eq!(logs.view(Filter::default()).unwrap().total, 1);
    }
    #[tokio::test]
    async fn draining_preserves_final_partial_line_and_aborts_a_never_closing_pipe() {
        use tokio::io::AsyncWriteExt;
        let logs = Logs::default();
        let (mut writer, reader) = tokio::io::duplex(256);
        let sink = logs.for_probe(&profile("Final error"), "http");
        let task = tokio::spawn(crate::logs::capture(reader, sink, "stderr"));
        writer.write_all(b"ERROR final partial line").await.unwrap();
        crate::logs::drain(vec![task]);
        drop(writer);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while logs.view(Filter::default()).unwrap().total == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            logs.view(Filter::default()).unwrap().entries[0].text,
            "ERROR final partial line"
        );
        let (_writer, reader) = tokio::io::duplex(256);
        let task = tokio::spawn(crate::logs::capture(reader, logs, "stdout"));
        let abort = task.abort_handle();
        crate::logs::drain(vec![task]);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !abort.is_finished() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn dropped_and_completed_runs_record_one_terminal_event() {
        let logs = Logs::default();
        let sink = logs.for_probe(&profile("Cancelled"), "tcp");
        drop(sink.begin_probe([]));
        sink.begin_probe([]).finish(None);
        let view = logs.view(Filter::default()).unwrap();
        assert_eq!(
            view.entries
                .iter()
                .map(|e| e.text.as_str())
                .collect::<Vec<_>>(),
            [
                "Test started",
                "Test cancelled",
                "Test started",
                "Test completed"
            ]
        );
    }
}
