//! System notifications for what happens while the window is hidden in the
//! tray or minimized: the in-window messages would go unseen then. The
//! connection dropping, reconnecting and coming back, and subscription
//! updates that changed profiles (when their results are to be shown).
use crate::localization::{text, Language, TextKey};
use crate::{Ordering, Shared};
use std::collections::HashSet;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

/// What of a snapshot the notifications look at.
#[derive(Clone, Default, PartialEq, Debug)]
pub(crate) struct Seen {
    phase: String,
    name: String,
    failed: bool,
    changed_jobs: HashSet<String>,
}

#[derive(PartialEq, Debug)]
pub(crate) enum Event {
    Lost(String),
    Reconnecting(String),
    Restored(String),
    SubscriptionsChanged,
}

/// The events between two observations. The first observation after start
/// only sets the baseline.
pub(crate) fn events(previous: &Seen, next: &Seen, updates_shown: bool) -> Vec<Event> {
    let mut events = Vec::new();
    let was_up = matches!(previous.phase.as_str(), "connected" | "reconnecting");
    match next.phase.as_str() {
        "reconnecting" if previous.phase == "connected" => {
            events.push(Event::Reconnecting(next.name.clone()))
        }
        "connected" if previous.phase == "reconnecting" => {
            events.push(Event::Restored(next.name.clone()))
        }
        "error" | "disconnected" if was_up && next.failed => {
            events.push(Event::Lost(previous.name.clone()))
        }
        _ => {}
    }
    if updates_shown
        && next
            .changed_jobs
            .iter()
            .any(|job| !previous.changed_jobs.contains(job))
    {
        events.push(Event::SubscriptionsChanged);
    }
    events
}

fn message(language: Language, event: &Event) -> (String, String) {
    let named = |key, name: &str| text(language, key).replace("{name}", name);
    match event {
        Event::Lost(name) => (
            text(language, TextKey::NotificationConnectionLost).to_owned(),
            named(TextKey::NotificationConnectionLostBody, name),
        ),
        Event::Reconnecting(name) => (
            text(language, TextKey::NotificationReconnecting).to_owned(),
            named(TextKey::NotificationReconnectingBody, name),
        ),
        Event::Restored(name) => (
            text(language, TextKey::NotificationRestored).to_owned(),
            named(TextKey::NotificationRestoredBody, name),
        ),
        Event::SubscriptionsChanged => (
            text(language, TextKey::NotificationSubscriptionsChanged).to_owned(),
            text(language, TextKey::NotificationSubscriptionsChangedBody).to_owned(),
        ),
    }
}

/// Whether the person cannot see the window now.
fn window_out_of_sight(app: &AppHandle) -> bool {
    app.get_webview_window("main").is_none_or(|window| {
        !window.is_visible().unwrap_or(false) || window.is_minimized().unwrap_or(false)
    })
}

pub(crate) fn install(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut previous: Option<Seen> = None;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let observed = {
                let shared = app.state::<Shared>();
                if shared.quitting.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut guard) = shared.engine.try_lock() else {
                    continue;
                };
                let Ok(engine) = guard.as_mut() else { continue };
                let snapshot = engine.snapshot();
                let library = &engine.store.library;
                let current = snapshot.running.as_ref().or(snapshot.selected.as_ref());
                let name = current
                    .and_then(|id| library.profiles.iter().find(|p| &p.id == id))
                    .map(|p| {
                        p.name
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(64)
                            .collect()
                    })
                    .unwrap_or_default();
                let changed_jobs = snapshot
                    .subscription_jobs
                    .iter()
                    .filter(|job| {
                        serde_json::to_value(job.status)
                            .is_ok_and(|s| s == "updated" || s == "needs-review")
                    })
                    .map(|job| job.id.clone())
                    .collect();
                (
                    Seen {
                        phase: snapshot.phase.clone(),
                        name,
                        failed: snapshot.error.is_some(),
                        changed_jobs,
                    },
                    Language::from_code(&snapshot.preferences.language),
                    thronium_engine::settings::boolean(library, "system_notifications"),
                    thronium_engine::settings::boolean(library, "sub_show_change_popup"),
                )
            };
            let (seen, language, enabled, updates_shown) = observed;
            let Some(before) = previous.replace(seen.clone()) else {
                continue;
            };
            if !enabled || !window_out_of_sight(&app) {
                continue;
            }
            for event in events(&before, &seen, updates_shown) {
                let (title, body) = message(language, &event);
                let _ = app.notification().builder().title(title).body(body).show();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(phase: &str, failed: bool, jobs: &[&str]) -> Seen {
        Seen {
            phase: phase.into(),
            name: "Home".into(),
            failed,
            changed_jobs: jobs.iter().map(|j| j.to_string()).collect(),
        }
    }

    #[test]
    fn a_dropped_connection_and_its_recovery_are_told_once_each() {
        let up = seen("connected", false, &[]);
        let retry = seen("reconnecting", false, &[]);
        assert_eq!(
            events(&up, &retry, true),
            [Event::Reconnecting("Home".into())]
        );
        assert_eq!(events(&retry, &retry, true), []);
        assert_eq!(events(&retry, &up, true), [Event::Restored("Home".into())]);
        assert_eq!(
            events(&up, &seen("error", true, &[]), true),
            [Event::Lost("Home".into())]
        );
        // Disconnecting on purpose leaves no error behind and says nothing.
        assert_eq!(events(&up, &seen("disconnected", false, &[]), true), []);
        assert_eq!(events(&seen("disconnected", false, &[]), &up, true), []);
    }

    #[test]
    fn only_new_changed_subscription_updates_are_told_and_only_when_shown() {
        let before = seen("disconnected", false, &["a"]);
        assert_eq!(
            events(&before, &seen("disconnected", false, &["a", "b"]), true),
            [Event::SubscriptionsChanged]
        );
        assert_eq!(
            events(&before, &seen("disconnected", false, &["a"]), true),
            []
        );
        assert_eq!(
            events(&before, &seen("disconnected", false, &["a", "b"]), false),
            []
        );
    }
}
