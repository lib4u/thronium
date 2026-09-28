//! A partial, foreign, starting or suspended Core reply cannot exhaust a pool.
use super::monitor::Observation;
use crate::proto;
use std::collections::BTreeSet;
pub(super) fn classify(
    expected: &BTreeSet<String>,
    group: Option<&proto::AutoSelectorStatus>,
) -> Observation {
    let Some(group) = group else {
        return Observation::Unknown;
    };
    if expected.is_empty()
        || group.suspended != Some(false)
        || !matches!(group.phase.as_deref(), Some("ready" | "probing"))
        || group.rounds_completed.unwrap_or(0) <= 0
        || group.members_total != i32::try_from(expected.len()).ok()
        || group.members.len() != expected.len()
    {
        return Observation::Unknown;
    }
    let tags: BTreeSet<_> = group
        .members
        .iter()
        .filter_map(|m| m.tag.as_ref())
        .cloned()
        .collect();
    if &tags != expected {
        return Observation::Unknown;
    }
    if group
        .members
        .iter()
        .any(|m| matches!(m.state.as_deref(), Some("ok" | "degraded")))
    {
        return Observation::Healthy;
    }
    if group.members_probed != i32::try_from(expected.len()).ok()
        || group.members.iter().any(|m| {
            !matches!(m.state.as_deref(), Some("dead" | "cooldown"))
                || m.probes.unwrap_or(0) <= 0
                || m.last_probe_ms.unwrap_or(0) <= 0
        })
    {
        return Observation::Unknown;
    }
    Observation::Exhausted
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (BTreeSet<String>, proto::AutoSelectorStatus) {
        let tags = BTreeSet::from(["member-a".into(), "member-b".into()]);
        let group = proto::AutoSelectorStatus {
            phase: Some("ready".into()),
            suspended: Some(false),
            rounds_completed: Some(1),
            members_total: Some(2),
            members_probed: Some(2),
            members: tags
                .iter()
                .map(|tag: &String| proto::AutoSelectorMember {
                    tag: Some(tag.clone()),
                    state: Some("dead".into()),
                    probes: Some(2),
                    last_probe_ms: Some(1234),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        (tags, group)
    }
    #[test]
    fn only_exact_fully_probed_dead_or_cooldown_members_are_exhausted() {
        let (tags, mut group) = fixture();
        assert_eq!(classify(&tags, Some(&group)), Observation::Exhausted);
        group.members[1].state = Some("cooldown".into());
        assert_eq!(classify(&tags, Some(&group)), Observation::Exhausted);
        group.members.reverse();
        assert_eq!(classify(&tags, Some(&group)), Observation::Exhausted);
    }
    #[test]
    fn one_usable_member_recovers_but_untested_and_unknown_states_only_break_grace() {
        let (tags, mut group) = fixture();
        for state in ["ok", "degraded"] {
            group.members[0].state = Some(state.into());
            assert_eq!(classify(&tags, Some(&group)), Observation::Healthy);
        }
        for state in ["untested", "unknown", ""] {
            group.members[0].state = Some(state.into());
            assert_eq!(classify(&tags, Some(&group)), Observation::Unknown);
        }
    }
    #[test]
    fn suspension_startup_and_missing_counters_are_never_attributed_to_members() {
        let (tags, original) = fixture();
        for suspended in [None, Some(true)] {
            let mut g = original.clone();
            g.suspended = suspended;
            assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        }
        for phase in ["starting", "suspended", ""] {
            let mut g = original.clone();
            g.phase = Some(phase.into());
            assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        }
        let mut g = original.clone();
        g.rounds_completed = Some(0);
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original.clone();
        g.members_probed = Some(1);
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original.clone();
        g.members[0].probes = Some(0);
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original;
        g.members[0].last_probe_ms = None;
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
    }
    #[test]
    fn partial_empty_duplicate_and_foreign_replies_are_unknown() {
        let (tags, original) = fixture();
        assert_eq!(classify(&tags, None), Observation::Unknown);
        let mut g = original.clone();
        g.members.pop();
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original.clone();
        g.members[0].tag = Some("foreign".into());
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original.clone();
        g.members[0].tag = g.members[1].tag.clone();
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        g = original.clone();
        g.members_total = Some(0);
        assert_eq!(classify(&tags, Some(&g)), Observation::Unknown);
        assert_eq!(
            classify(&BTreeSet::new(), Some(&original)),
            Observation::Unknown
        );
    }
}
