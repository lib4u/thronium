//! Device-local references shared by chains and automatic selector pools.
use crate::store::{Profile, ProfileKind};
use std::collections::HashSet;
pub fn key(kind: ProfileKind) -> Option<&'static str> {
    match kind {
        ProfileKind::Chain => Some("hops"),
        ProfileKind::AutoSelector => Some("members"),
        _ => None,
    }
}
pub fn members(profile: &Profile) -> Result<Vec<&str>, String> {
    // Dynamic matches are not fixed deletion references. Runtime dependencies
    // resolve them separately against the library and freeze the resulting set.
    if profile.kind == ProfileKind::AutoSelector && profile.config.get("member_source").is_some() {
        return Ok(vec![]);
    }
    let Some(key) = key(profile.kind) else {
        return Ok(vec![]);
    };
    let selector = profile.kind == ProfileKind::AutoSelector;
    let error = if selector {
        "invalid_selector_members"
    } else {
        "invalid_chain"
    };
    let list = profile.config[key].as_array().ok_or(error)?;
    let limit = if selector {
        crate::auto_selector::MAX_MEMBERS
    } else {
        crate::chains::MAX_HOPS
    };
    if list.is_empty() || list.len() > limit {
        return Err(error.into());
    }
    list.iter()
        .map(|v| {
            v.as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| error.to_string())
        })
        .collect()
}
pub fn validate_all(library: &crate::store::Library) -> Result<(), String> {
    let profiles = &library.profiles;
    for p in profiles.iter().filter(|p| key(p.kind).is_some()) {
        match p.kind {
            ProfileKind::Chain => {
                crate::chains::flatten(p, profiles)?;
            }
            ProfileKind::AutoSelector => crate::auto_selector::validate_saved(p, library)?,
            _ => {}
        }
    }
    Ok(())
}
/// Direct edges are sufficient to protect deletion; transitive ancestors retain those edges.
pub fn referenced_outside(profiles: &[Profile], selected: &HashSet<String>) -> bool {
    profiles
        .iter()
        .filter(|p| key(p.kind).is_some() && !selected.contains(&p.id))
        .any(|p| members(p).is_ok_and(|m| m.iter().any(|id| selected.contains(*id))))
}
pub fn depends_on(profiles: &[Profile], chain_id: &str, id: &str) -> bool {
    fn visit(all: &[Profile], current: &str, target: &str, seen: &mut HashSet<String>) -> bool {
        if current == target {
            return true;
        }
        if !seen.insert(current.into()) {
            return false;
        }
        all.iter().find(|p| p.id == current).is_some_and(|p| {
            members(p).is_ok_and(|m| m.iter().any(|next| visit(all, next, target, seen)))
        })
    }
    visit(profiles, chain_id, id, &mut HashSet::new())
}
