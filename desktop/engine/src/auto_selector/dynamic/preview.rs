//! Selector drafts and previews of the members a dynamic pool would resolve.
use super::*;

impl Engine {
    pub(crate) fn selector_draft(&self, draft: crate::ProfileDraft) -> Result<Profile, String> {
        if draft.kind != ProfileKind::AutoSelector
            || crate::store::config_size(&draft.config).is_none()
        {
            return Err("invalid_selector_source".into());
        }
        if !self
            .store
            .library
            .groups
            .iter()
            .any(|g| g.id == draft.group_id)
        {
            return Err("group_not_found".into());
        }
        let profile = Profile {
            vpn_policy: draft.vpn_policy.resolve(None),
            id: draft.id.unwrap_or_default(),
            name: draft.name,
            group_id: draft.group_id,
            kind: draft.kind,
            config: draft.config,
            favorite: false,
        };
        crate::vpn_policy::validate_profile(&profile)?;
        validate_saved(&profile, &self.store.library)?;
        Ok(profile)
    }
    /// Preview uses the exact Rust membership rules, without exposing configurations.
    pub fn preview_selector(&self, draft: crate::ProfileDraft) -> Result<Value, String> {
        let profile = self.selector_draft(draft)?;
        let (ids, summary) = resolve_with_summary(&profile, &self.store.library)?;
        let ranking_source = profile
            .config
            .get("member_source")
            .map(|_| source(&profile, &self.store.library).map(|(s, _, _)| s))
            .transpose()?;
        let members: Vec<_> = ids
            .iter()
            .filter_map(|id| self.store.library.profiles.iter().find(|p| &p.id == id))
            .map(|p| {
                let mut view = json!({"id":p.id,"name":p.name});
                if let Some(measured) = measured_in_pool(&self.store.library, &profile, p) {
                    view["countryCode"] = json!(measured.country_code);
                }
                if let Some(source) = ranking_source.as_ref().filter(|s| s.uses_http()) {
                    if let Some(entry) = http_in_pool(&self.store.library, &profile, &p.id, source)
                    {
                        if entry.origin == crate::latency_measurements::Origin::CoreAverage {
                            view["httpSource"] = json!("core-average");
                        }
                        if let Some(ms) = entry.latency_ms {
                            view["latencyMs"] = json!(ms);
                        } else {
                            view["httpTestFailed"] = json!(true);
                        }
                    }
                }
                view
            })
            .collect();
        let mut result = json!({"total":members.len(),"members":members});
        if let Some(source) = ranking_source
            .as_ref()
            .filter(|source| source.order == MemberOrder::SavedHttpLatency)
        {
            result["savedRankingCount"] = json!(source
                .saved_ranking
                .as_ref()
                .map_or(0, |saved| saved.members.len()));
            result["savedRankedAt"] =
                json!(source.saved_ranking.as_ref().map(|saved| saved.ranked_at));
            result["savedOrderKept"] = json!(summary.saved_order_kept);
            result["newCandidatesCount"] = json!(summary.before_limit - summary.saved_order_kept);
        }
        if ranking_source
            .as_ref()
            .is_some_and(|source| source.pool_cap.is_some())
        {
            result["matchingBeforePoolCap"] = json!(summary.before_pool_cap);
            result["candidatePoolSize"] = json!(summary.before_limit);
            result["omittedByPoolCap"] = json!(summary.omitted_by_pool_cap);
        }
        if ranking_source
            .as_ref()
            .is_some_and(|source| source.build_limit.is_some())
        {
            result["matchingBeforeLimit"] = json!(summary.before_limit);
            result["omittedByLimit"] = json!(summary.omitted_by_limit);
        }
        if !countries(
            profile.config["member_source"]["country_filter"]
                .as_str()
                .unwrap_or(""),
        )?
        .is_empty()
        {
            result["unknownCountryCount"] = json!(summary.unknown_country);
        }
        if ranking_source
            .as_ref()
            .is_some_and(|source| source.warm_start)
        {
            result["warmCandidatesCount"] =
                json!(warm_candidates(&profile, &self.store.library, &ids)?.len());
        }
        if ranking_source.as_ref().is_some_and(Source::uses_http) {
            result["rankedByHttp"] = json!(summary.ranked);
            result["unknownHttpCount"] = json!(summary.unknown_http);
            result["keptUnavailable"] = json!(summary.kept_unavailable);
        }
        Ok(result)
    }
}
