//! Metadata for an independently refreshable routing preset.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub imported_at: u64,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_settings: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub dns_customized: bool,
    /// Codes of what the last update left out or changed (omitted rules and
    /// endpoint gates), shown beside the source; never provider text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub update_notes: Vec<String>,
}
impl Source {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let source: Self = serde_json::from_value(value.clone()).map_err(|_| "invalid_routing")?;
        crate::geodata::catalog::valid_url(&source.url)?;
        if source.update_notes.len() > 32
            || source
                .update_notes
                .iter()
                .any(|code| !crate::ipc::error_codes::codes().contains(&code.as_str()))
        {
            return Err("invalid_routing".into());
        }
        if source.legacy_settings.as_ref().is_some_and(|settings| {
            settings.len() > 64
                || settings
                    .iter()
                    .any(|(key, value)| key.len() > 128 || value.len() > 1024 * 1024)
        }) {
            return Err("invalid_routing".into());
        }
        Ok(source)
    }
}

/// A manual DNS edit becomes authoritative for future remote rule updates.
/// The fetched provider cannot replace it with an old generated-DNS snapshot.
pub(crate) fn retain_dns_edit(
    previous: &super::Routing,
    next: &mut super::Routing,
) -> Result<(), String> {
    for profile in &mut next.profiles {
        if profile.source.is_none()
            || !previous
                .profiles
                .iter()
                .any(|old| old.id == profile.id && old.dns != profile.dns)
        {
            continue;
        }
        let mut source = Source::parse(profile.source.as_ref().unwrap())?;
        source.dns_customized = true;
        if let Some(constraints) = &mut profile.legacy_constraints {
            if constraints.adapt_remote_dns() {
                constraints.version = 5;
                constraints.adaptive_dns = false;
            }
        }
        profile.source = Some(serde_json::to_value(source).map_err(|_| "invalid_routing")?);
    }
    Ok(())
}

/// Runtime retry state, deliberately absent from persisted routing revisions.
#[derive(Default)]
pub struct Schedule(BTreeMap<String, Attempt>);
struct Attempt {
    url: String,
    at: u64,
    failures: u32,
}
/// First retry after a failed scheduled update; later retries double, never
/// waiting longer than the update interval itself.
const RETRY_AFTER: u64 = 60;
impl Schedule {
    fn next(&mut self, routing: &super::Routing, interval: u64, now: u64) -> Option<String> {
        self.0
            .retain(|id, _| routing.profiles.iter().any(|profile| &profile.id == id));
        if interval == 0 {
            return None;
        }
        for profile in &routing.profiles {
            let Some(source) = profile.source.as_ref().and_then(|v| Source::parse(v).ok()) else {
                continue;
            };
            if !source.auto_update {
                continue;
            }
            let previous = self
                .0
                .get(&profile.id)
                .filter(|attempt| attempt.url == source.url);
            // A newer import than the last attempt means that attempt succeeded.
            let failures = previous
                .filter(|attempt| attempt.at > source.imported_at)
                .map_or(0, |attempt| attempt.failures);
            let wait = match failures {
                0 => interval,
                n => RETRY_AFTER
                    .saturating_mul(1 << (n - 1).min(16))
                    .min(interval),
            };
            let last = previous.map_or(0, |a| a.at).max(source.imported_at);
            if last > 0 && now.saturating_sub(last) < wait {
                continue;
            }
            self.0.insert(
                profile.id.clone(),
                Attempt {
                    url: source.url,
                    at: now,
                    failures,
                },
            );
            return Some(profile.id.clone());
        }
        None
    }
    /// The update started by `next` failed; it is retried before the interval.
    pub fn failed(&mut self, id: &str) {
        if let Some(attempt) = self.0.get_mut(id) {
            attempt.failures = attempt.failures.saturating_add(1);
        }
    }
}
impl crate::Engine {
    pub fn next_routing_update(&self, schedule: &mut Schedule, now: u64) -> Option<String> {
        let interval =
            crate::settings::integer(&self.store.library, "route_auto_update").max(0) as u64;
        schedule.next(
            &self.store.library.routing,
            interval.saturating_mul(60),
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn schedule_respects_interval_opt_in_failures_changes_and_clock_reversal() {
        let mut routing = super::super::Routing::default();
        routing.profiles[0].source = Some(
            json!({"url":"https://example.invalid/routes","importedAt":100,"autoUpdate":true}),
        );
        let mut schedule = Schedule::default();
        assert!(schedule.next(&routing, 0, 1000).is_none());
        assert!(schedule.next(&routing, 60, 159).is_none());
        assert_eq!(schedule.next(&routing, 60, 160), Some("default".into()));
        assert!(schedule.next(&routing, 60, 161).is_none());
        assert!(schedule.next(&routing, 60, 90).is_none());
        assert_eq!(schedule.next(&routing, 60, 220), Some("default".into()));
        routing.profiles[0].source.as_mut().unwrap()["autoUpdate"] = json!(false);
        assert!(schedule.next(&routing, 60, 1000).is_none());
        routing.profiles[0].source = Some(
            json!({"url":"https://example.invalid/replaced","importedAt":0,"autoUpdate":true}),
        );
        assert_eq!(schedule.next(&routing, 60, 221), Some("default".into()));
        routing.profiles.clear();
        assert!(schedule.next(&routing, 60, 222).is_none());
        assert!(schedule.0.is_empty());
    }
    #[test]
    fn failed_updates_retry_sooner_and_success_restores_the_interval() {
        let mut routing = super::super::Routing::default();
        routing.profiles[0].source = Some(
            json!({"url":"https://example.invalid/routes","importedAt":100,"autoUpdate":true}),
        );
        let mut schedule = Schedule::default();
        let day = 24 * 3600;
        let start = 100 + day;
        assert_eq!(schedule.next(&routing, day, start), Some("default".into()));
        schedule.failed("default");
        assert!(schedule.next(&routing, day, start + 59).is_none());
        assert_eq!(
            schedule.next(&routing, day, start + 60),
            Some("default".into())
        );
        schedule.failed("default");
        assert!(schedule.next(&routing, day, start + 60 + 119).is_none());
        assert_eq!(
            schedule.next(&routing, day, start + 180),
            Some("default".into())
        );
        // The update succeeded: a newer import waits a whole interval again.
        routing.profiles[0].source.as_mut().unwrap()["importedAt"] = json!(start + 181);
        assert!(schedule.next(&routing, day, start + 3600).is_none());
        assert_eq!(
            schedule.next(&routing, day, start + 181 + day),
            Some("default".into())
        );
    }
}
