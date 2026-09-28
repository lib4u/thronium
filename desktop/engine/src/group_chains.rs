//! Group hops apply only to the selected root, never recursively to a hop's group.
use crate::{
    chains, references,
    store::{Library, Profile, ProfileKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupChain {
    #[serde(default)]
    pub front: Option<String>,
    #[serde(default)]
    pub landing: Option<String>,
}
impl GroupChain {
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.front
            .iter()
            .chain(self.landing.iter())
            .map(String::as_str)
    }
    pub fn enabled(&self) -> bool {
        self.ids().next().is_some()
    }
}
pub(crate) const MEMBER_HOPS: &str = "_thronium_member_hops";
pub(crate) fn policy(library: &Library, p: &Profile) -> GroupChain {
    library
        .groups
        .iter()
        .find(|g| g.id == p.group_id)
        .map(|g| g.proxy_chain.clone())
        .unwrap_or_default()
}
pub(crate) fn validate(library: &Library) -> Result<(), String> {
    for group in &library.groups {
        for id in group.proxy_chain.ids() {
            let p = library
                .profiles
                .iter()
                .find(|p| p.id == id)
                .ok_or("group_chain_profile_missing")?;
            let hops =
                chains::flatten(p, &library.profiles).map_err(|_| "group_chain_hop_unsupported")?;
            // A chain may start at an external core, but a group's front or
            // landing proxy never runs one: the connection refuses it as an
            // auxiliary core, so the group must not be saved with it either.
            if hops.iter().any(|hop| hop.kind == ProfileKind::ExternalCore) {
                return Err("group_chain_hop_unsupported".into());
            }
            if group.proxy_chain.landing.as_deref() == Some(id)
                && hops.iter().any(|hop| hop.kind == ProfileKind::XrayConfig)
            {
                return Err("group_chain_hop_unsupported".into());
            }
        }
    }
    Ok(())
}
pub(crate) fn referenced(
    library: &Library,
    ids: &HashSet<String>,
    except_group: Option<&str>,
) -> bool {
    library
        .groups
        .iter()
        .filter(|g| Some(g.id.as_str()) != except_group)
        .any(|g| {
            g.proxy_chain.ids().any(|root| {
                ids.iter()
                    .any(|id| references::depends_on(&library.profiles, root, id))
            })
        })
}
pub(crate) fn dependencies(library: &Library, roots: &HashSet<String>) -> HashSet<String> {
    let mut pending: Vec<String> = roots.iter().cloned().collect();
    let policies = policy_roots(library, roots);
    for p in library.profiles.iter().filter(|p| policies.contains(&p.id)) {
        pending.extend(policy(library, p).ids().map(str::to_owned));
    }
    let mut needed = HashSet::new();
    while let Some(id) = pending.pop() {
        if !needed.insert(id.clone()) {
            continue;
        }
        if let Some(p) = library.profiles.iter().find(|p| p.id == id) {
            if p.kind == ProfileKind::AutoSelector {
                if let Ok(members) = crate::auto_selector::resolve(p, library) {
                    pending.extend(members);
                }
            } else if let Ok(members) = references::members(p) {
                pending.extend(members.into_iter().map(str::to_owned));
            }
        }
    }
    needed
}

/// Roots whose group policy contributes to the actual connection.
pub(crate) fn policy_roots(library: &Library, roots: &HashSet<String>) -> HashSet<String> {
    let mut result = roots.clone();
    if roots.contains(crate::auto_selector::AUTO_SELECT_ID) {
        if let Some(pool) = library
            .profiles
            .iter()
            .find(|p| p.id == crate::auto_selector::AUTO_SELECT_ID)
        {
            if let Ok(members) = references::members(pool) {
                result.extend(members.into_iter().map(str::to_owned));
            }
        }
    }
    result
}

/// The same physical route is used by a member probe and by the quick pool.
/// Explicit saved pools keep their own root's group policy.
pub(crate) fn sequence<'a>(
    library: &'a Library,
    member: &'a Profile,
    policy: &GroupChain,
) -> Result<Vec<&'a Profile>, String> {
    let mut hops = Vec::new();
    for id in policy
        .front
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(member.id.as_str()))
        .chain(policy.landing.iter().map(String::as_str))
    {
        let p = if id == member.id {
            member
        } else {
            library
                .profiles
                .iter()
                .find(|p| p.id == id)
                .ok_or("group_chain_profile_missing")?
        };
        hops.extend(chains::flatten(p, &library.profiles).map_err(|code| {
            if policy.enabled()
                && matches!(
                    code.as_str(),
                    "chain_hop_unsupported" | "chain_full_config_unsupported"
                )
            {
                "group_chain_hop_unsupported".into()
            } else {
                code
            }
        })?);
    }
    chains::validate_sequence(&hops)?;
    Ok(hops)
}
pub(crate) fn stamp(library: &Library, p: &Profile) -> Value {
    let ids = dependencies(library, &HashSet::from([p.id.clone()]));
    json!([
        policy(library, p),
        library.preferences.vless_core,
        library
            .profiles
            .iter()
            .filter(|p| ids.contains(&p.id))
            .map(|p| json!([
                p.id,
                p.kind,
                p.config,
                library.preferences.vless_overrides.get(&p.id),
                p.vpn_policy,
                library.vpn_otp_bindings.get(&p.id)
            ]))
            .collect::<Vec<_>>()
    ])
}

/// Freeze raw leaf references before replacing roots. Routing targets can also be
/// chain members; their own group policy must not leak into another root's hops.
/// Returns the renamed copies (alias -> original id) so per-profile state such
/// as OTP bindings can follow a hop into its wrapper.
pub(crate) fn prepare(
    library: &mut Library,
    selected: &mut Profile,
    roots: &HashSet<String>,
) -> Result<HashMap<String, String>, String> {
    if let Some(root) = library.profiles.iter_mut().find(|p| p.id == selected.id) {
        *root = selected.clone();
    } else {
        library.profiles.push(selected.clone());
    }
    let source = library.clone();
    let mut aliases = HashMap::<String, String>::new();
    let mut additions = Vec::new();
    let mut ids: HashSet<_> = source.profiles.iter().map(|p| p.id.clone()).collect();
    let mut alias = |p: &Profile| -> String {
        aliases
            .entry(p.id.clone())
            .or_insert_with(|| {
                let mut id = format!("thronium-group-raw-{}", p.id);
                while !ids.insert(id.clone()) {
                    id.push('_');
                }
                additions.push(Profile {
                    id: id.clone(),
                    ..p.clone()
                });
                id
            })
            .clone()
    };
    for root in &mut library.profiles {
        if !roots.contains(&root.id) {
            continue;
        }
        let original = source.profiles.iter().find(|p| p.id == root.id).unwrap();
        let policy = policy(&source, original);
        if !policy.enabled() && references::key(original.kind).is_none() {
            continue;
        }
        let sequence = |member: &Profile| -> Result<Vec<String>, String> {
            let member_policy = if original.id == crate::auto_selector::AUTO_SELECT_ID {
                self::policy(&source, member)
            } else {
                policy.clone()
            };
            Ok(self::sequence(&source, member, &member_policy)?
                .into_iter()
                .map(&mut alias)
                .collect())
        };
        let mut sequence = sequence;
        if original.kind == ProfileKind::AutoSelector {
            crate::auto_selector::validate(original, &source.profiles)?;
            crate::auto_selector::validate_routes(&source, original)?;
            let mut members = serde_json::Map::new();
            for id in references::members(original)? {
                let member = source
                    .profiles
                    .iter()
                    .find(|p| p.id == id)
                    .ok_or("selector_profile_missing")?;
                members.insert(id.into(), json!(sequence(member)?));
            }
            root.config[MEMBER_HOPS] = Value::Object(members);
        } else {
            root.config = json!({"type":"chain", "hops":sequence(original)?});
            root.kind = ProfileKind::Chain;
        }
    }
    library.profiles.extend(additions);
    if let Some(root) = library.profiles.iter().find(|p| p.id == selected.id) {
        *selected = root.clone();
    }
    Ok(aliases
        .into_iter()
        .map(|(origin, alias)| (alias, origin))
        .collect())
}

#[cfg(test)]
mod tests;
