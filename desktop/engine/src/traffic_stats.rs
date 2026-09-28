//! Qt's traffic statistics dialog as data: one window of counted bytes, its
//! buckets for the chart and the breakdowns by profile and by application.
use crate::{
    settings::history::{Entry, Names, DIRECT_PROFILE},
    store::Library,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// Qt's `kMaxBreakdownRows`: named rows per table; everything past them is one
/// folded row, so the cut stays by total however the window re-sorts it.
const MAX_ROWS: usize = 9;
/// Qt's period buttons: a day of hours, or up to a quarter of days.
pub const PERIODS: [u32; 4] = [1, 7, 30, 90];

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Point {
    pub bucket: u64,
    pub upload: i64,
    pub download: i64,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUsage {
    pub id: String,
    /// What the profile is called now, or was called when it was counted; empty
    /// when neither is known, which the window shows as a removed profile.
    pub name: String,
    pub group: String,
    pub upload: i64,
    pub download: i64,
    /// Qt's Direct row: bytes that never went through a server.
    pub direct: bool,
    /// The folded remainder of the breakdown, not a profile of its own.
    pub other: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUsage {
    pub process: String,
    pub upload: i64,
    pub download: i64,
    pub other: bool,
}
/// Qt keeps the two breakdowns in tables of their own, each with its own chart
/// and totals, because an imported copy counts servers and applications
/// independently. Thronium's own recording fills both from the same bytes.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileBreakdown {
    pub upload: i64,
    pub download: i64,
    pub series: Vec<Point>,
    pub rows: Vec<ProfileUsage>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppBreakdown {
    pub upload: i64,
    pub download: i64,
    pub series: Vec<Point>,
    pub rows: Vec<AppUsage>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub from: u64,
    pub to: u64,
    pub bucket_seconds: u64,
    pub profiles: ProfileBreakdown,
    pub applications: AppBreakdown,
}

/// The window the caller asked for. `offset_seconds` is the viewer's own
/// distance east of UTC, so a day boundary is theirs and not the file's.
#[derive(Clone, Copy)]
pub struct Window {
    pub from: u64,
    pub to: u64,
    pub bucket_seconds: u64,
    pub offset_seconds: i64,
}

impl Window {
    /// Qt's period: a single day is read hour by hour, longer ones day by day.
    pub fn of(days: u32, now: u64, offset_seconds: i64) -> Self {
        let span = days as u64 * 86400;
        Self {
            from: now.saturating_sub(span),
            to: now,
            bucket_seconds: if days <= 1 { 3600 } else { 86400 },
            offset_seconds,
        }
    }
    fn align(&self, hour: u64) -> u64 {
        let shifted = hour as i64 + self.offset_seconds;
        let size = self.bucket_seconds as i64;
        (shifted.div_euclid(size) * size - self.offset_seconds).max(0) as u64
    }
}

fn fold<T, K: Ord + Clone>(
    totals: BTreeMap<K, (i64, i64)>,
    mut row: impl FnMut(K, i64, i64) -> T,
    mut rest: impl FnMut(i64, i64) -> T,
) -> Vec<T> {
    let mut sorted: Vec<_> = totals.into_iter().collect();
    // Largest first, the key breaking ties so equal totals keep one order.
    sorted.sort_by(|a, b| {
        (b.1 .0 + b.1 .1)
            .cmp(&(a.1 .0 + a.1 .1))
            .then_with(|| a.0.cmp(&b.0))
    });
    let folded = sorted.split_off(sorted.len().min(MAX_ROWS));
    let mut rows: Vec<_> = sorted
        .into_iter()
        .map(|(key, (upload, download))| row(key, upload, download))
        .collect();
    if !folded.is_empty() {
        let (upload, download) = folded.iter().fold((0i64, 0i64), |sum, (_, (up, down))| {
            (sum.0.saturating_add(*up), sum.1.saturating_add(*down))
        });
        rows.push(rest(upload, download));
    }
    rows
}

fn points(series: &BTreeMap<u64, (i64, i64)>, window: Window) -> Vec<Point> {
    // Every bucket of the window is present, so an empty hour is a gap in the
    // chart rather than a missing column.
    let mut points = Vec::new();
    let mut bucket = window.align(window.from);
    while bucket < window.to {
        let (upload, download) = series.get(&bucket).copied().unwrap_or_default();
        points.push(Point {
            bucket,
            upload,
            download,
        });
        bucket = bucket.saturating_add(window.bucket_seconds);
    }
    points
}

pub fn aggregate<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    names: &BTreeMap<String, Names>,
    library: &Library,
    window: Window,
) -> Stats {
    let mut profile_series: BTreeMap<u64, (i64, i64)> = BTreeMap::new();
    let mut application_series: BTreeMap<u64, (i64, i64)> = BTreeMap::new();
    let mut profiles: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut applications: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut profile_total = (0i64, 0i64);
    let mut application_total = (0i64, 0i64);
    for entry in entries.filter(|e| e.hour >= window.from && e.hour < window.to) {
        let add = |target: &mut (i64, i64)| {
            target.0 = target.0.saturating_add(entry.upload);
            target.1 = target.1.saturating_add(entry.download);
        };
        let bucket = window.align(entry.hour);
        if entry.scope.counts_profiles() {
            add(profile_series.entry(bucket).or_default());
            add(profiles.entry(entry.profile.clone()).or_default());
            add(&mut profile_total);
        }
        if entry.scope.counts_applications() {
            add(application_series.entry(bucket).or_default());
            add(applications.entry(entry.process.clone()).or_default());
            add(&mut application_total);
        }
    }
    Stats {
        from: window.from,
        to: window.to,
        bucket_seconds: window.bucket_seconds,
        profiles: ProfileBreakdown {
            upload: profile_total.0,
            download: profile_total.1,
            series: points(&profile_series, window),
            rows: fold(
                profiles,
                |id, upload, download| {
                    let live = library.profiles.iter().find(|p| p.id == id);
                    let remembered = names.get(&id);
                    ProfileUsage {
                        name: live
                            .map(|p| p.name.clone())
                            .or_else(|| remembered.map(|n| n.profile.clone()))
                            .unwrap_or_default(),
                        group: live
                            .and_then(|p| library.groups.iter().find(|g| g.id == p.group_id))
                            .map(|g| g.name.clone())
                            .or_else(|| remembered.map(|n| n.group.clone()))
                            .unwrap_or_default(),
                        direct: id == DIRECT_PROFILE,
                        id,
                        upload,
                        download,
                        other: false,
                    }
                },
                |upload, download| ProfileUsage {
                    upload,
                    download,
                    other: true,
                    ..Default::default()
                },
            ),
        },
        applications: AppBreakdown {
            upload: application_total.0,
            download: application_total.1,
            series: points(&application_series, window),
            rows: fold(
                applications,
                |process, upload, download| AppUsage {
                    process,
                    upload,
                    download,
                    other: false,
                },
                |upload, download| AppUsage {
                    upload,
                    download,
                    other: true,
                    ..Default::default()
                },
            ),
        },
    }
}

#[cfg(test)]
mod tests;
