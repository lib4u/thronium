//! Saved group filters are resolved at the boundary of a new configuration.
use super::*;
use crate::store::Library;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
mod measurements;
mod preflight;
mod preview;
mod saved_order;
pub use preflight::{ConnectionMeasurementPool, ConnectionMeasurements};
use saved_order::SavedRanking;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Startup,
    Rerank,
    Candidates,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    group_id: String,
    #[serde(default)]
    build_limit: Option<usize>,
    #[serde(default)]
    pool_cap: Option<usize>,
    #[serde(default)]
    saved_ranking: Option<SavedRanking>,
    #[serde(default)]
    name_regex: String,
    #[serde(default)]
    exclude_regex: String,
    #[serde(default)]
    country_filter: String,
    #[serde(default)]
    order: MemberOrder,
    #[serde(default)]
    exclude_unavailable: bool,
    #[serde(default)]
    warm_start: bool,
    #[serde(default)]
    persist_health: bool,
    #[serde(default)]
    measure_before_connect: bool,
    #[serde(default)]
    rebuild_on_exhaustion: bool,
    #[serde(default)]
    rebuild_on_subscription: bool,
    #[serde(default = "default_validity")]
    result_validity_mins: u32,
}
#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum MemberOrder {
    #[default]
    Library,
    HttpLatency,
    SavedHttpLatency,
}
fn default_validity() -> u32 {
    60
}
#[derive(Default)]
struct Summary {
    before_pool_cap: usize,
    omitted_by_pool_cap: usize,
    saved_order_kept: usize,
    before_limit: usize,
    omitted_by_limit: usize,
    unknown_country: usize,
    ranked: usize,
    unknown_http: usize,
    kept_unavailable: usize,
}
impl Source {
    fn uses_http(&self) -> bool {
        matches!(
            self.order,
            MemberOrder::HttpLatency | MemberOrder::SavedHttpLatency
        ) || self.exclude_unavailable
            || self.warm_start
            || self.persist_health
    }
}

pub(crate) fn source_group(profile: &Profile) -> Option<&str> {
    (profile.kind == ProfileKind::AutoSelector)
        .then(|| profile.config["member_source"]["group_id"].as_str())
        .flatten()
}

use crate::subscriptions::name_rules::MAX_PATTERN_BYTES;
fn pattern(value: &str) -> Result<Option<Regex>, String> {
    if value.len() > MAX_PATTERN_BYTES {
        return Err("selector_invalid_regex".into());
    }
    if value.is_empty() {
        return Ok(None);
    }
    RegexBuilder::new(value)
        .case_insensitive(true)
        .size_limit(2 * 1024 * 1024)
        .dfa_size_limit(2 * 1024 * 1024)
        .build()
        .map(Some)
        .map_err(|_| "selector_invalid_regex".into())
}

fn countries(value: &str) -> Result<std::collections::BTreeSet<String>, String> {
    if value.len() > MAX_PATTERN_BYTES {
        return Err("selector_invalid_country_filter".into());
    }
    let mut result = std::collections::BTreeSet::new();
    for code in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err("selector_invalid_country_filter".into());
        }
        result.insert(code.to_ascii_uppercase());
    }
    Ok(result)
}

fn source(
    profile: &Profile,
    library: &Library,
) -> Result<(Source, Option<Regex>, Option<Regex>), String> {
    let value = profile
        .config
        .get("member_source")
        .ok_or("invalid_selector_source")?;
    if profile.kind != ProfileKind::AutoSelector || profile.config.get("members").is_some() {
        return Err("invalid_selector_source".into());
    }
    if value.get("build_limit").is_some_and(|v| {
        v.as_u64()
            .is_none_or(|limit| !(1..=MAX_MEMBERS as u64).contains(&limit))
    }) {
        return Err("selector_invalid_build_limit".into());
    }
    if value.get("pool_cap").is_some_and(|v| {
        v.as_u64()
            .is_none_or(|cap| !(1..=MAX_CANDIDATES as u64).contains(&cap))
    }) {
        return Err("selector_invalid_pool_cap".into());
    }
    if value.get("pool_cap").is_some() && value.get("build_limit").is_none() {
        return Err("selector_pool_cap_requires_limit".into());
    }
    if let Some(ranking) = value.get("saved_ranking") {
        saved_order::validate(ranking)?;
    }
    let source: Source =
        serde_json::from_value(value.clone()).map_err(|_| "invalid_selector_source")?;
    if source.group_id.is_empty() || source.group_id.len() > 512 {
        return Err("invalid_selector_source".into());
    }
    if !library.groups.iter().any(|g| g.id == source.group_id) {
        return Err("selector_source_missing".into());
    }
    if source.result_validity_mins > MAX_RESULT_VALIDITY_MINUTES {
        return Err("selector_invalid_ranking".into());
    }
    if (source.rebuild_on_exhaustion || source.rebuild_on_subscription)
        && !source.measure_before_connect
    {
        return Err("selector_rebuild_requires_measurements".into());
    }
    if source.measure_before_connect && source.order != MemberOrder::SavedHttpLatency {
        return Err("selector_saved_order_required".into());
    }
    if source.measure_before_connect && source.result_validity_mins == 0 {
        return Err("selector_measurement_lifetime_required".into());
    }
    countries(&source.country_filter)?;
    let include = pattern(&source.name_regex)?;
    let exclude = pattern(&source.exclude_regex)?;
    Ok((source, include, exclude))
}

pub(crate) fn resolve(profile: &Profile, library: &Library) -> Result<Vec<String>, String> {
    resolve_with_summary(profile, library).map(|(members, _)| members)
}
// Diagnostics measure an individual root. A pool wraps all members with its
// own group's hops, so an observation only applies when those policies agree.
fn measured_in_pool<'a>(
    library: &'a Library,
    pool: &Profile,
    candidate: &Profile,
) -> Option<&'a crate::country_measurements::Observation> {
    if crate::group_chains::policy(library, pool) != crate::group_chains::policy(library, candidate)
    {
        return None;
    }
    library.country_measurements.current(library, &candidate.id)
}
fn resolve_with_summary(
    profile: &Profile,
    library: &Library,
) -> Result<(Vec<String>, Summary), String> {
    resolve_plan(profile, library, Resolution::Startup)
}
// Re-ranking uses the whole capped candidate pool, before the startup limit.
fn resolve_plan(
    profile: &Profile,
    library: &Library,
    resolution: Resolution,
) -> Result<(Vec<String>, Summary), String> {
    if profile.config.get("member_source").is_none() {
        return Ok((
            references::members(profile)?
                .into_iter()
                .map(str::to_owned)
                .collect(),
            Summary::default(),
        ));
    }
    let (source, include, exclude) = source(profile, library)?;
    let mut members = Vec::new();
    let codes = countries(&source.country_filter)?;
    let mut unknown_country = 0;
    for candidate in &library.profiles {
        if candidate.id == profile.id
            || candidate.group_id != source.group_id
            || !super::member_kind(candidate.kind)
            || !super::member_route_eligible(library, profile, candidate)
            || include
                .as_ref()
                .is_some_and(|r| !r.is_match(&candidate.name))
            || exclude
                .as_ref()
                .is_some_and(|r| r.is_match(&candidate.name))
        {
            continue;
        }
        if !codes.is_empty() {
            match measured_in_pool(library, profile, candidate) {
                Some(measured) if codes.contains(&measured.country_code) => {}
                Some(_) => continue,
                None => {
                    unknown_country += 1;
                    continue;
                }
            }
        }
        members.push(candidate.id.clone());
        let maximum = if source.build_limit.is_some() {
            MAX_CANDIDATES
        } else {
            MAX_MEMBERS
        };
        if members.len() > maximum {
            return Err(if source.build_limit.is_some() {
                "selector_too_many_candidates"
            } else {
                "selector_too_many_members"
            }
            .into());
        }
    }
    let mut summary = Summary {
        unknown_country,
        ..Default::default()
    };
    if source.uses_http() && resolution != Resolution::Candidates {
        let mut scored: Vec<_> = members
            .into_iter()
            .map(|id| {
                let entry = http_in_pool(library, profile, &id, &source);
                let rank = match entry.map(|e| e.latency_ms) {
                    Some(Some(ms)) => {
                        summary.ranked += 1;
                        (0, ms)
                    }
                    None => {
                        summary.unknown_http += 1;
                        (1, 0)
                    }
                    Some(None) => (2, 0),
                };
                (id, rank)
            })
            .collect();
        if source.exclude_unavailable {
            if scored.iter().any(|(_, rank)| rank.0 != 2) {
                scored.retain(|(_, rank)| rank.0 != 2);
            } else {
                summary.kept_unavailable = scored.len();
            }
        }
        if matches!(
            source.order,
            MemberOrder::HttpLatency | MemberOrder::SavedHttpLatency
        ) {
            scored.sort_by_key(|(_, rank)| *rank);
        }
        if source.order == MemberOrder::SavedHttpLatency && resolution == Resolution::Startup {
            if let Some(saved) = &source.saved_ranking {
                let positions: std::collections::HashMap<_, _> = saved
                    .members
                    .iter()
                    .enumerate()
                    .map(|(index, id)| (id.as_str(), index))
                    .collect();
                // Stable sorting preserves the HTTP order of all newcomers.
                scored.sort_by_key(|(id, _)| {
                    positions.get(id.as_str()).copied().unwrap_or(usize::MAX)
                });
            }
        }
        members = scored.into_iter().map(|(id, _)| id).collect();
    }
    summary.before_pool_cap = members.len();
    if resolution != Resolution::Candidates {
        if let Some(cap) = source.pool_cap {
            members.truncate(cap);
            summary.omitted_by_pool_cap = summary.before_pool_cap - members.len();
        }
    }
    summary.before_limit = members.len();
    if source.order == MemberOrder::SavedHttpLatency {
        if let Some(saved) = &source.saved_ranking {
            let prior: HashSet<_> = saved.members.iter().collect();
            summary.saved_order_kept = members.iter().filter(|id| prior.contains(id)).count();
        }
    }
    if resolution == Resolution::Startup {
        if let Some(limit) = source.build_limit {
            members.truncate(limit);
            summary.omitted_by_limit = summary.before_limit - members.len();
        }
    }
    if summary.kept_unavailable > 0 {
        summary.kept_unavailable = members.len();
    }
    Ok((members, summary))
}
fn http_in_pool<'a>(
    library: &'a Library,
    profile: &Profile,
    id: &str,
    source: &Source,
) -> Option<&'a crate::latency_measurements::Observation> {
    let candidate = library.profiles.iter().find(|p| p.id == id)?;
    if crate::group_chains::policy(library, profile)
        != crate::group_chains::policy(library, candidate)
    {
        return None;
    }
    let url = profile
        .config
        .get("url")
        .map_or(Some(crate::probes::DEFAULT_TEST_URL), Value::as_str)?;
    let url = if url.is_empty() {
        crate::probes::DEFAULT_TEST_URL
    } else {
        url
    };
    library
        .latency_measurements
        .fresh(library, id, url, source.result_validity_mins)
}

pub(crate) fn warm_candidates(
    profile: &Profile,
    library: &Library,
    ids: &[String],
) -> Result<serde_json::Map<String, Value>, String> {
    let mut entries = serde_json::Map::new();
    if profile.config.get("member_source").is_none() {
        return Ok(entries);
    }
    let (source, _, _) = source(profile, library)?;
    if !source.warm_start {
        return Ok(entries);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for id in ids {
        let Some(observation) = http_in_pool(library, profile, id, &source) else {
            continue;
        };
        let Some(age) = now.checked_sub(observation.tested_at) else {
            continue;
        };
        // Core uses uint16 milliseconds and reserves zero for known failures.
        let rtt = match observation.latency_ms {
            None => 0,
            Some(0) => 1,
            Some(ms @ 1..=65535) => ms,
            _ => continue,
        };
        entries.insert(id.clone(), json!({"rtt": rtt, "age": age}));
    }
    Ok(entries)
}

pub(crate) fn validate_saved(profile: &Profile, library: &Library) -> Result<(), String> {
    if profile.config.get("member_source").is_none() {
        return validate(profile, &library.profiles);
    }
    source(profile, library)?;
    if profile
        .config
        .get("pinned_profile")
        .is_some_and(|v| v.as_str() != Some(""))
    {
        return Err("invalid_selector_pin".into());
    }
    generated_fields(profile)?;
    // Subscription updates may temporarily leave zero or more than MAX_MEMBERS
    // matches. Keep the saved filter; a build or preview rejects an invalid pool.
    Ok(())
}

pub(crate) fn materialize(profile: &Profile, library: &Library) -> Result<Profile, String> {
    if profile.kind != ProfileKind::AutoSelector || profile.config.get("member_source").is_none() {
        return Ok(profile.clone());
    }
    validate_saved(profile, library)?;
    let members = resolve(profile, library)?;
    if members.is_empty() {
        return Err("selector_empty_pool".into());
    }
    let mut resolved = profile.clone();
    resolved
        .config
        .as_object_mut()
        .unwrap()
        .remove("member_source");
    resolved.config["members"] = json!(members);
    Ok(resolved)
}
