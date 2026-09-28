use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedRanking {
    pub members: Vec<String>,
    pub ranked_at: u64,
}

pub(super) fn validate(value: &Value) -> Result<(), String> {
    let saved: SavedRanking =
        serde_json::from_value(value.clone()).map_err(|_| "selector_invalid_saved_order")?;
    let mut seen = HashSet::new();
    if saved.members.len() > crate::auto_selector::MAX_CANDIDATES
        || saved.ranked_at > 253_402_300_799
        || saved
            .members
            .iter()
            .any(|id| id.is_empty() || id.len() > 512 || !seen.insert(id))
    {
        return Err("selector_invalid_saved_order".into());
    }
    Ok(())
}

impl Engine {
    /// Produce a draft ranking from existing measurements without IO or mutation.
    pub fn rank_selector(&self, draft: crate::ProfileDraft) -> Result<Value, String> {
        let profile = self.selector_draft(draft)?;
        rank_profile(self, &profile)
    }
}

pub(super) fn rank_profile(engine: &Engine, profile: &Profile) -> Result<Value, String> {
    let (source, _, _) = source(profile, &engine.store.library)?;
    if source.order != MemberOrder::SavedHttpLatency {
        return Err("selector_saved_order_required".into());
    }
    let (members, _) = resolve_plan(profile, &engine.store.library, Resolution::Rerank)?;
    let ranked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(json!({"members": members, "ranked_at": ranked_at}))
}
