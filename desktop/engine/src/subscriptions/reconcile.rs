//! Pure preview plan; the existing Engine transaction owns validation and commit.
use super::{
    identity::{content, identity},
    Change, Plan, MAX_BYTES, MAX_PROFILES,
};
use crate::{
    routing,
    store::{Group, Profile, ProfileKind},
    Engine, ProfileDraft,
};
use std::collections::{HashMap, HashSet, VecDeque};

pub(super) fn reconcile(
    engine: &Engine,
    group: &Group,
    drafts: Vec<ProfileDraft>,
) -> Result<Plan, String> {
    if drafts.is_empty() || drafts.len() > MAX_PROFILES {
        return Err("subscription_invalid_profiles".into());
    }
    if drafts
        .iter()
        .any(|draft| draft.kind == ProfileKind::ExternalCore)
    {
        return Err("external_remote_import_unsupported".into());
    }
    // A remote payload cannot replace or clear locally configured policy. Its
    // ordinary omitted field preserves metadata when reconciliation keeps UUID.
    if drafts
        .iter()
        .any(|draft| draft.vpn_policy != crate::vpn_policy::Edit::Keep)
    {
        return Err("vpn_policy_context_unsupported".into());
    }
    let subscription = group.subscription.as_ref().ok_or("subscription_missing")?;
    let members: Vec<_> = engine
        .store
        .library
        .profiles
        .iter()
        .filter(|p| p.group_id == group.id)
        .collect();
    let old: Vec<_> = members
        .iter()
        .copied()
        .filter(|p| subscription.managed_ids.contains(&p.id) && p.kind != ProfileKind::AutoSelector)
        .collect();
    let mut size = 0;
    let incoming: Vec<_> = drafts
        .into_iter()
        .map(|d| {
            size += crate::store::config_size(&d.config).ok_or("subscription_invalid_profiles")?;
            if d.id.is_some()
                || d.group_id != group.id
                || !crate::store::valid_name(&d.name)
                || size > MAX_BYTES
            {
                return Err("subscription_invalid_profiles");
            }
            Ok(Profile {
                vpn_policy: None,
                id: uuid::Uuid::new_v4().to_string(),
                name: d.name.trim().into(),
                group_id: group.id.clone(),
                kind: d.kind,
                config: d.config,
                favorite: false,
            })
        })
        .collect::<Result<_, _>>()?;
    let source_names: HashMap<_, _> = incoming
        .iter()
        .map(|p| (p.id.clone(), p.name.clone()))
        .collect();
    let incoming = subscription.settings.name_rules.apply(incoming)?;
    let recreate = crate::settings::string(&engine.store.library, "sub_update_mode") == "recreate";
    // Recreate removes eligible remote rows before matching, like Qt. Protected
    // survivors still enter reconciliation so their references keep the same ID.
    let removable: HashSet<_> = old
        .iter()
        .enumerate()
        .filter(|(_, p)| recreate && protection(engine, p).is_none())
        .map(|(i, _)| i)
        .collect();
    let old_keys: Vec<_> = old.iter().map(|p| content(p)).collect();
    let new_keys: Vec<_> = incoming.iter().map(content).collect();
    let known: HashSet<_> = old_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| !removable.contains(i))
        .map(|(_, key)| key)
        .collect();
    let arrived: HashSet<_> = new_keys.iter().collect();
    let mut by_content: HashMap<&String, VecDeque<usize>> = HashMap::new();
    for (i, key) in old_keys.iter().enumerate() {
        if removable.contains(&i) {
            continue;
        }
        by_content.entry(key).or_default().push_back(i);
    }
    let take_named = |q: &mut VecDeque<usize>, profile: &Profile| {
        // Prefer the named occurrence when filtering duplicates or rotating credentials.
        let position = q
            .iter()
            .position(|i| old[*i].name == profile.name)
            .or_else(|| {
                q.iter()
                    .position(|i| old[*i].name == source_names[&profile.id])
            });
        q.remove(position.unwrap_or(0))
    };
    let mut claimed = HashSet::new();
    let mut matches: Vec<_> = new_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            by_content
                .get_mut(key)
                .and_then(|q| take_named(q, &incoming[index]))
                .inspect(|i| {
                    claimed.insert(*i);
                })
        })
        .collect();
    let mut by_identity: HashMap<String, VecDeque<usize>> = HashMap::new();
    for (i, p) in old.iter().enumerate() {
        if !removable.contains(&i) && !claimed.contains(&i) && !arrived.contains(&old_keys[i]) {
            by_identity.entry(identity(p)).or_default().push_back(i);
        }
    }
    for (i, p) in incoming.iter().enumerate() {
        if matches[i].is_none() && !known.contains(&new_keys[i]) {
            matches[i] = by_identity
                .get_mut(&identity(p))
                .and_then(|q| take_named(q, p));
            if let Some(index) = matches[i] {
                claimed.insert(index);
            }
        }
    }
    let mut profiles = Vec::new();
    let mut changes = Vec::new();
    let mut managed_ids = Vec::new();
    for (i, mut p) in incoming.into_iter().enumerate() {
        let mut action = "added";
        let mut reason = None;
        if let Some(index) = matches[i] {
            let previous = old[index];
            p.id = previous.id.clone();
            p.favorite = previous.favorite;
            p.vpn_policy = previous.vpn_policy;
            crate::vpn_policy::validate_profile(&p)?;
            action = if p.config == previous.config && p.name == previous.name {
                "unchanged"
            } else {
                "updated"
            };
            if action == "updated" && engine.subscription_update_keeps_running(&p.id) {
                p = previous.clone();
                action = "kept";
                reason = Some("running".into());
            }
        }
        changes.push(Change {
            id: p.id.clone(),
            name: p.name.clone(),
            action: action.into(),
            reason,
        });
        managed_ids.push(p.id.clone());
        profiles.push(p);
    }
    for (i, p) in old.iter().enumerate() {
        if claimed.contains(&i) {
            continue;
        }
        let reason = if !recreate && !crate::settings::boolean(&engine.store.library, "sub_clear") {
            Some("retained")
        } else {
            protection(engine, p)
        };
        changes.push(Change {
            id: p.id.clone(),
            name: p.name.clone(),
            action: if reason.is_some() { "kept" } else { "removed" }.into(),
            reason: reason.map(str::to_owned),
        });
        if reason.is_some() {
            profiles.push((*p).clone());
            managed_ids.push(p.id.clone());
        }
    }
    profiles.extend(
        members
            .into_iter()
            .filter(|p| {
                !subscription.managed_ids.contains(&p.id) || p.kind == ProfileKind::AutoSelector
            })
            .cloned(),
    );
    Ok(Plan {
        profiles,
        managed_ids,
        changes,
    })
}

// Shared by recreation eligibility and stale-row retention; never delete a
// dependency just because it was temporarily excluded from the matching index.
fn protection(engine: &Engine, profile: &Profile) -> Option<&'static str> {
    let library = &engine.store.library;
    let id = &profile.id;
    if engine.subscription_update_keeps_running(id) {
        return Some("running");
    }
    if routing::uses_profile(&library.routing, id) {
        return Some("routing");
    }
    let ids = HashSet::from([id.clone()]);
    if crate::group_chains::referenced(library, &ids, None)
        || crate::references::referenced_outside(&library.profiles, &ids)
    {
        return Some("chain");
    }
    None
}
