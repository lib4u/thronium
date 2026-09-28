//! Bounded, in-memory diagnostics. Read explicitly; never part of profile snapshots.
mod events;
pub(crate) mod filters;
mod probe;
pub(crate) mod redact;
pub use events::EVENTS;
pub use probe::ProbeContext;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_ENTRIES: usize = 2000;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_LINE: usize = 16 * 1024;
const MAX_PROTECTED: usize = 64;
/// Most matching messages one log view returns.
pub const MAX_VISIBLE: usize = 500;
pub const MAX_SEARCH_BYTES: usize = 1024;

fn bounded(mut text: String) -> String {
    if text.len() > MAX_LINE {
        let mut end = MAX_LINE;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: u64,
    pub at: u64,
    pub source: String,
    pub level: String,
    pub text: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeContext>,
    /// Application event code; the window shows it in the user's language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
#[derive(Default)]
struct Buffer {
    entries: VecDeque<Entry>,
    bytes: usize,
    dropped: u64,
    revision: u64,
    settings: Option<LogSettings>,
    /// Credential values of the most recent core requests, by owner.
    protected: VecDeque<(String, Vec<String>)>,
}
struct LogSettings {
    source: serde_json::Value,
    file: Option<std::path::PathBuf>,
    file_level: String,
    max_lines: usize,
    include: Option<Vec<regex::Regex>>,
    exclude: Option<Vec<regex::Regex>>,
}
impl LogSettings {
    fn from_library(l: &crate::store::Library, root: &std::path::Path) -> Self {
        Self {
            file: crate::settings::boolean(l, "log_file_enabled")
                .then(|| root.join("diagnostic.log")),
            file_level: crate::settings::string(l, "log_file_level"),
            source: crate::settings::section(l, "logging"),
            max_lines: crate::settings::integer(l, "max_log_line") as usize,
            include: filters::patterns(l, "include"),
            exclude: filters::patterns(l, "exclude"),
        }
    }
    fn accepts(&self, text: &str) -> bool {
        self.include
            .as_ref()
            .is_none_or(|patterns| patterns.iter().any(|p| p.is_match(text)))
            && !self
                .exclude
                .as_ref()
                .is_some_and(|patterns| patterns.iter().any(|p| p.is_match(text)))
    }
}
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Buffer>>, Option<ProbeContext>);
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Filter {
    pub search: String,
    pub level: String,
    pub source: String,
    pub scope: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub entries: Vec<Entry>,
    pub total: usize,
    pub matching: usize,
    pub dropped: u64,
    pub revision: u64,
}

impl Logs {
    pub fn configure(&self, library: &crate::store::Library, root: &std::path::Path) {
        let mut b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if b.settings
            .as_ref()
            .is_some_and(|s| s.source == crate::settings::section(library, "logging"))
        {
            return;
        }
        b.settings = Some(LogSettings::from_library(library, root));
        b.revision = b.revision.saturating_add(1);
    }
    /// Core output can echo request values ("invalid UUID: ..."). While a core
    /// runs `configs`, its credential values never reach the buffer or the file.
    /// A core's last lines can arrive after its run ended, so values stay
    /// protected until a newer request of the same owner or the bound replaces them.
    pub(crate) fn protect<'a>(&self, owner: &str, configs: impl IntoIterator<Item = &'a str>) {
        let secrets = redact::secrets(configs);
        let mut b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        b.protected.retain(|(o, _)| o != owner);
        b.protected.push_back((owner.to_owned(), secrets));
        while b.protected.len() > MAX_PROTECTED {
            b.protected.pop_front();
        }
    }
    pub fn push(&self, source: &str, level: Option<&str>, text: &str, truncated: bool) {
        self.record(source, level, text, truncated, None);
    }
    fn record(
        &self,
        source: &str,
        level: Option<&str>,
        text: &str,
        truncated: bool,
        event: Option<(&str, Option<&str>)>,
    ) {
        let clean = clean_text(text);
        let too_long = clean.len() > MAX_LINE;
        let clean = bounded(clean);
        if clean.trim().is_empty() {
            return;
        }
        let level = level
            .map(str::to_owned)
            .unwrap_or_else(|| classify(&clean).into());
        let mut b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let clean = if event.is_none() && b.protected.iter().any(|(_, s)| !s.is_empty()) {
            let mut secrets: Vec<String> =
                b.protected.iter().flat_map(|(_, s)| s).cloned().collect();
            secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
            redact::replace(&clean, &secrets)
        } else {
            clean
        };
        b.revision = b.revision.saturating_add(1);
        let entry = Entry {
            id: b.revision,
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            source: source.into(),
            level,
            text: clean,
            truncated: truncated || too_long,
            probe: self.1.clone(),
            code: event.map(|(code, _)| code.to_owned()),
            detail: event
                .and_then(|(_, detail)| detail)
                .map(|detail| bounded(clean_text(detail))),
        };
        if let Some(settings) = &b.settings {
            if let Some(path) = &settings.file {
                let levels = ["trace", "debug", "info", "warn", "error"];
                if levels.iter().position(|l| *l == entry.level).unwrap_or(2)
                    >= levels
                        .iter()
                        .position(|l| *l == settings.file_level)
                        .unwrap_or(1)
                    && settings.accepts(&entry.text)
                {
                    use std::io::Write;
                    if std::fs::metadata(path).is_ok_and(|m| m.len() > 5 * 1024 * 1024) {
                        let _ = std::fs::rename(path, path.with_extension("log.1"));
                    }
                    let mut options = std::fs::OpenOptions::new();
                    options.create(true).append(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    // Logging never fails the caller; the list is still set.
                    #[cfg(windows)]
                    let _ = crate::ownership::restrict_file(path);
                    if let Ok(mut file) = options.open(path) {
                        let _ = writeln!(
                            file,
                            "{} [{}] [{}] {}{}",
                            entry.at,
                            entry.level,
                            entry.source,
                            entry
                                .probe
                                .as_ref()
                                .map(|p| format!(
                                    "[test {} {} {}] ",
                                    p.run_id, p.kind, p.profile_name
                                ))
                                .unwrap_or_default(),
                            entry.text
                        );
                    }
                }
            }
        }
        b.bytes += entry.size();
        b.entries.push_back(entry);
        while b.entries.len() > b.settings.as_ref().map_or(MAX_ENTRIES, |s| s.max_lines)
            || b.bytes > MAX_BYTES
        {
            if let Some(old) = b.entries.pop_front() {
                b.bytes -= old.size();
                b.dropped += 1;
            }
        }
    }
    pub fn clear(&self) {
        let mut b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        b.entries.clear();
        b.bytes = 0;
        b.dropped = 0;
        b.revision = b.revision.saturating_add(1);
    }
    pub fn view(&self, filter: Filter) -> Result<View, String> {
        if filter.search.len() > MAX_SEARCH_BYTES
            || !["", "all", "trace", "debug", "info", "warn", "error"]
                .contains(&filter.level.as_str())
            || !["", "all", "app", "stdout", "stderr"].contains(&filter.source.as_str())
            || !["", "all", "session", "tests"].contains(&filter.scope.as_str())
        {
            return Err("invalid_log_filter".into());
        }
        let search = filter.search.to_lowercase();
        let b = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let matches: Vec<_> = b
            .entries
            .iter()
            .filter(|e| {
                b.settings
                    .as_ref()
                    .is_none_or(|settings| settings.accepts(&e.text))
                    && (filter.level.is_empty() || filter.level == "all" || filter.level == e.level)
                    && (filter.source.is_empty()
                        || filter.source == "all"
                        || filter.source == e.source)
                    && match filter.scope.as_str() {
                        "session" => e.probe.is_none(),
                        "tests" => e.probe.is_some(),
                        _ => true,
                    }
                    && (search.is_empty()
                        || e.text.to_lowercase().contains(&search)
                        || e.probe.as_ref().is_some_and(|p| p.matches(&search)))
            })
            .collect();
        let entries = matches
            .iter()
            .skip(matches.len().saturating_sub(MAX_VISIBLE))
            .map(|e| (*e).clone())
            .collect();
        Ok(View {
            entries,
            total: b.entries.len(),
            matching: matches.len(),
            dropped: b.dropped,
            revision: b.revision,
        })
    }
}

fn classify(text: &str) -> &'static str {
    // Match severity tokens, not arbitrary substrings such as a hostname containing "error".
    let tokens: Vec<_> = text
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .take(12)
        .collect();
    for token in tokens {
        match token.to_ascii_uppercase().as_str() {
            "ERROR" | "FATAL" | "PANIC" => return "error",
            "WARN" | "WARNING" => return "warn",
            "INFO" => return "info",
            "DEBUG" => return "debug",
            "TRACE" => return "trace",
            _ => {}
        }
    }
    "info"
}
fn clean_text(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.next() {
                Some('[') => {
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut escape = false;
                    for next in chars.by_ref() {
                        if next == '\x07' || (escape && next == '\\') {
                            break;
                        }
                        escape = next == '\x1b';
                    }
                }
                _ => {}
            }
        } else if !c.is_control() || c == '\t' {
            out.push(c);
        }
    }
    out
}

pub async fn capture(mut reader: impl AsyncRead + Unpin, logs: Logs, source: &str) {
    let mut chunk = [0u8; 8192];
    let mut line = Vec::new();
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(count) => {
                for &byte in &chunk[..count] {
                    if byte == b'\n' {
                        logs.push(source, None, &String::from_utf8_lossy(&line), truncated);
                        line.clear();
                        truncated = false;
                    } else if line.len() < MAX_LINE {
                        line.push(byte);
                    } else {
                        truncated = true;
                    }
                }
            }
            Err(_) => {
                logs.event("warn", "core_log_stream_failed", None);
                break;
            }
        }
    }
    if !line.is_empty() {
        logs.push(source, None, &String::from_utf8_lossy(&line), truncated);
    }
}

/// A dropped RPC kills its child, closing the pipes. Give capture a bounded
/// chance to consume the final error/partial line before aborting its readers.
pub(crate) fn drain(mut tasks: Vec<tokio::task::JoinHandle<()>>) {
    if tasks.is_empty() {
        return;
    }
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                for task in &mut tasks {
                    let _ = task.await;
                }
            })
            .await;
            for task in tasks {
                task.abort();
            }
        });
    } else {
        for task in tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn capture_handles_fragmented_unicode_ansi_long_lines_and_unterminated_eof() {
        use tokio::io::AsyncWriteExt;
        let (mut write, read) = tokio::io::duplex(32);
        let logs = Logs::default();
        let copy = logs.clone();
        let task = tokio::spawn(async move { capture(read, copy, "stderr").await });
        for chunk in "\x1b[31mERROR\x1b[0m: ошибка 🦊\r\n".as_bytes().chunks(3) {
            write.write_all(chunk).await.unwrap();
        }
        write.write_all(&vec![b'x'; MAX_LINE * 3]).await.unwrap();
        write.write_all(b"\nlast line").await.unwrap();
        drop(write);
        task.await.unwrap();
        let view = logs.view(Filter::default()).unwrap();
        assert_eq!(view.entries.len(), 3);
        assert_eq!(view.entries[0].text, "ERROR: ошибка 🦊");
        assert_eq!(view.entries[0].level, "error");
        assert!(view.entries[1].truncated);
        assert!(view.entries[1].text.len() <= MAX_LINE);
        assert_eq!(view.entries[2].text, "last line");
    }
    #[test]
    fn buffers_and_filtered_views_are_bounded_and_clear_keeps_monotonic_ids() {
        let logs = Logs::default();
        for i in 0..MAX_ENTRIES + 12 {
            logs.push("stdout", Some("info"), &format!("row {i}"), false);
        }
        let view = logs.view(Filter::default()).unwrap();
        assert_eq!(view.total, MAX_ENTRIES);
        assert_eq!(view.entries.len(), MAX_VISIBLE);
        assert_eq!(view.dropped, 12);
        let last = view.revision;
        logs.clear();
        logs.push("stderr", None, "WARN: find ОШИБКА", false);
        let view = logs
            .view(Filter {
                search: "ошибка".into(),
                level: "warn".into(),
                source: "stderr".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(view.entries.len(), 1);
        assert!(view.entries[0].id > last);
        assert_eq!(view.dropped, 0);
        assert!(logs
            .view(Filter {
                level: "invalid".into(),
                ..Default::default()
            })
            .is_err());
        for _ in 0..100 {
            logs.push("stdout", None, &"x".repeat(MAX_LINE), false);
        }
        let b = logs.0.lock().unwrap();
        assert!(b.bytes <= MAX_BYTES);
        assert!(b.dropped > 0);
    }
    #[test]
    fn strips_terminal_commands_and_bounds_unicode_after_lossy_decoding() {
        assert_eq!(classify("INFO[0012] message mentions an error"), "info");
        assert_eq!(
            classify("2026/09/10 12:00:01 [Warning] connection closed"),
            "warn"
        );
        let logs = Logs::default();
        logs.push(
            "stdout",
            None,
            "\x1b]8;;https://example.test\x07visible\x1b]8;;\x1b\\\0",
            false,
        );
        logs.push("stdout", None, &"🦊".repeat(MAX_LINE), false);
        let view = logs.view(Filter::default()).unwrap();
        assert_eq!(view.entries[0].text, "visible");
        assert!(view.entries[1].truncated);
        assert!(view.entries[1].text.len() <= MAX_LINE);
    }
}
