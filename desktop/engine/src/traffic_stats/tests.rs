use super::*;
use crate::store::{Group, Library, Profile, ProfileKind};
use serde_json::json;

fn entry(hour: u64, profile: &str, process: &str, upload: i64, download: i64) -> Entry {
    Entry {
        hour,
        profile: profile.into(),
        group: String::new(),
        process: process.into(),
        upload,
        download,
        scope: Default::default(),
    }
}
fn library() -> Library {
    let mut library = Library::default();
    library.groups.push(Group {
        proxy_chain: Default::default(),
        collapsed: false,
        auto_clear_unavailable: false,
        id: "g1".into(),
        name: "Team".into(),
        subscription: None,
    });
    library.profiles.push(Profile {
        id: "p1".into(),
        name: "Kept".into(),
        group_id: "g1".into(),
        kind: ProfileKind::SingBoxOutbound,
        config: json!({"type":"direct"}),
        favorite: false,
        vpn_policy: None,
    });
    library
}

#[test]
fn a_window_reads_its_own_hours_and_keeps_every_bucket_of_the_chart() {
    let day = 86400;
    let entries = [
        entry(day + 3600, "p1", "curl", 10, 20),
        entry(day + 3600, "p1", "wget", 1, 2),
        entry(day + 7200, "p1", "curl", 100, 200),
        // Outside the window on both sides.
        entry(day - 3600, "p1", "curl", 5000, 5000),
        entry(day + 10 * 3600, "p1", "curl", 7000, 7000),
    ];
    let names = BTreeMap::new();
    let window = Window {
        from: day,
        to: day + 4 * 3600,
        bucket_seconds: 3600,
        offset_seconds: 0,
    };
    let stats = aggregate(entries.iter(), &names, &library(), window);
    assert_eq!((stats.profiles.upload, stats.profiles.download), (111, 222));
    assert_eq!(stats.profiles.series.len(), 4);
    assert_eq!(stats.profiles.series[0], Point::default_at(day));
    assert_eq!(stats.profiles.series[1].upload, 11);
    assert_eq!(stats.profiles.series[2].download, 200);
    assert_eq!(stats.profiles.series[3], Point::default_at(day + 3 * 3600));
    // The breakdowns hold the same bytes as the window total.
    assert_eq!(stats.profiles.rows.len(), 1);
    assert_eq!(stats.profiles.rows[0].name, "Kept");
    assert_eq!(stats.profiles.rows[0].group, "Team");
    assert_eq!(
        stats
            .applications
            .rows
            .iter()
            .map(|a| a.upload)
            .sum::<i64>(),
        stats.applications.upload
    );
    assert_eq!(stats.applications.rows[0].process, "curl");
}

impl Point {
    fn default_at(bucket: u64) -> Self {
        Self {
            bucket,
            ..Default::default()
        }
    }
}

#[test]
fn days_are_the_viewers_own_and_not_the_files() {
    // A UTC day boundary, one hour into the day.
    let day = 1_700_000_000u64 / 86400 * 86400;
    let entries = [entry(day + 3600, "p1", "curl", 1, 1)];
    let names = BTreeMap::new();
    // Three hours west of UTC that hour is still the evening before.
    let west = Window {
        from: day - 2 * 86400,
        to: day + 86400,
        bucket_seconds: 86400,
        offset_seconds: -3 * 3600,
    };
    let stats = aggregate(entries.iter(), &names, &library(), west);
    let filled: Vec<_> = stats
        .profiles
        .series
        .iter()
        .filter(|p| p.upload > 0)
        .collect();
    assert_eq!(filled.len(), 1);
    assert_eq!(filled[0].bucket, day - 75600);
    // Three hours east it already belongs to the new day.
    let east = Window {
        offset_seconds: 3 * 3600,
        ..west
    };
    let stats = aggregate(entries.iter(), &names, &library(), east);
    let filled: Vec<_> = stats
        .profiles
        .series
        .iter()
        .filter(|p| p.upload > 0)
        .collect();
    assert_eq!(filled.len(), 1);
    assert_eq!(filled[0].bucket, day - 10800);
}

#[test]
fn direct_removed_and_folded_rows_are_named_apart_without_losing_bytes() {
    let mut entries = vec![
        entry(0, DIRECT_PROFILE, "curl", 5, 5),
        entry(0, "p1", "curl", 4, 4),
        entry(0, "gone", "curl", 3, 3),
    ];
    // Twelve profiles in all, so three of them fold into one row.
    for index in 0..9 {
        entries.push(entry(0, &format!("x{index}"), &format!("app{index}"), 1, 1));
    }
    let mut names = BTreeMap::new();
    names.insert(
        "gone".to_string(),
        Names {
            profile: "Removed".into(),
            group: "Old team".into(),
            last_seen: 10,
        },
    );
    let window = Window {
        from: 0,
        to: 3600,
        bucket_seconds: 3600,
        offset_seconds: 0,
    };
    let stats = aggregate(entries.iter(), &names, &library(), window);
    assert_eq!(stats.profiles.rows.len(), 10);
    let direct = stats.profiles.rows.iter().find(|p| p.direct).unwrap();
    assert_eq!((direct.upload, direct.name.as_str()), (5, ""));
    let removed = stats.profiles.rows.iter().find(|p| p.id == "gone").unwrap();
    assert_eq!(
        (removed.name.as_str(), removed.group.as_str()),
        ("Removed", "Old team")
    );
    let other = stats.profiles.rows.iter().find(|p| p.other).unwrap();
    assert_eq!((other.upload, other.id.as_str()), (3, ""));
    assert_eq!(
        stats.profiles.rows.iter().map(|p| p.upload).sum::<i64>(),
        stats.profiles.upload
    );
    // Applications fold the same way and keep every byte.
    assert_eq!(stats.applications.rows.len(), 10);
    assert_eq!(
        stats
            .applications
            .rows
            .iter()
            .map(|a| a.download)
            .sum::<i64>(),
        stats.applications.download
    );
}

#[test]
fn rows_imported_from_a_copy_answer_only_for_their_own_table() {
    let mut profile_only = entry(0, "p1", "", 10, 20);
    profile_only.scope = crate::settings::history::Scope::Profiles;
    let mut application_only = entry(0, "", "curl", 3, 4);
    application_only.scope = crate::settings::history::Scope::Applications;
    let entries = [profile_only, application_only, entry(0, "p1", "wget", 1, 2)];
    let names = BTreeMap::new();
    let window = Window {
        from: 0,
        to: 3600,
        bucket_seconds: 3600,
        offset_seconds: 0,
    };
    let stats = aggregate(entries.iter(), &names, &library(), window);
    // The server table sees its own rows plus what Thronium counted itself.
    assert_eq!((stats.profiles.upload, stats.profiles.download), (11, 22));
    assert_eq!(stats.profiles.rows.len(), 1);
    assert_eq!(stats.profiles.series[0].upload, 11);
    // The application table sees its own rows and the same shared record.
    assert_eq!(
        (stats.applications.upload, stats.applications.download),
        (4, 6)
    );
    assert_eq!(stats.applications.rows.len(), 2);
    assert_eq!(stats.applications.series[0].download, 6);
}

#[test]
fn qt_periods_choose_the_hour_or_the_day() {
    let now = 200 * 86400;
    assert_eq!(Window::of(1, now, 0).bucket_seconds, 3600);
    assert_eq!(Window::of(1, now, 0).from, now - 86400);
    for days in [7, 30, 90] {
        let window = Window::of(days, now, 0);
        assert_eq!(window.bucket_seconds, 86400);
        assert_eq!(window.to - window.from, days as u64 * 86400);
    }
    assert_eq!(PERIODS, [1, 7, 30, 90]);
}
