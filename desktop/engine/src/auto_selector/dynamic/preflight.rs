//! Opaque connection plans: network work belongs outside the Engine lock.
use super::*;

pub struct ConnectionMeasurementPool {
    pub profile_id: String,
    pub ids: Vec<String>,
    pub fresh_count: usize,
    pub url: String,
    pub timeout_ms: u32,
    /// Parallel probes for the sweep; the shared setting when `None`.
    pub concurrency: Option<usize>,
    /// Which batch source the sweep runs as: the quick pool's own mechanism
    /// stays out of library rows and caches.
    pub source: crate::probes::Source,
    context: String,
}
pub struct ConnectionMeasurements {
    pub id: String,
    pub pools: Vec<ConnectionMeasurementPool>,
    context: Value,
    quick: Option<QuickPlan>,
}
struct QuickPlan {
    /// Freeze the shortlist before measuring. Never re-expand it after ranking.
    members: Vec<String>,
    reuse: bool,
    /// The sweep's results, taken when it completed: the probe queue keeps
    /// one batch, and a later batch must not erase what this plan measured.
    results: Option<Vec<Option<i32>>>,
}
impl ConnectionMeasurements {
    pub fn reuses_selection(&self) -> bool {
        self.quick.as_ref().is_some_and(|p| p.reuse)
    }
}

fn context(engine: &Engine, id: &str) -> Value {
    let library = &engine.store.library;
    if id == crate::auto_selector::AUTO_SELECT_ID {
        return json!([
            id,
            crate::auto_selector::quick::context(library),
            engine.running,
            engine.since,
            library.selected,
            engine.quick_select.epoch
        ]);
    }
    let profile = library.profiles.iter().find(|p| p.id == id);
    let primary = profile.map(|p| {
        if p.kind == ProfileKind::AutoSelector {
            json!([p.id, p.kind, p.group_id, p.config, p.vpn_policy])
        } else {
            crate::group_chains::stamp(library, p)
        }
    });
    let mut providers = profile
        .and_then(|p| crate::vless::roots(library, p).ok())
        .unwrap_or_default()
        .into_iter()
        .collect::<Vec<_>>();
    providers.sort();
    let providers = providers
        .into_iter()
        .filter_map(|id| library.profiles.iter().find(|p| p.id == id))
        .map(|p| {
            json!([
                p.id,
                crate::geodata::enabled(p, library),
                crate::geodata::provider(p, library)
            ])
        })
        .collect::<Vec<_>>();
    json!([
        primary,
        providers,
        engine.running,
        engine.since,
        library.selected,
        library.routing,
        library.settings,
        library.preferences.connection_mode,
        library.preferences.inbound_port,
        library.preferences.tun,
        library.preferences.vless_core,
        library.preferences.vless_overrides
    ])
}
impl Engine {
    /// Includes opted-in primary and auxiliary routing pools. No IO or mutation.
    pub fn connection_measurements(
        &self,
        id: &str,
    ) -> Result<Option<ConnectionMeasurements>, String> {
        let profile = self.profile(id)?;
        if id == crate::auto_selector::AUTO_SELECT_ID {
            let members: Vec<String> =
                serde_json::from_value(profile.config["members"].clone()).unwrap_or_default();
            if members.is_empty() {
                return Err("auto_select_unavailable".into());
            }
            use crate::auto_selector::quick::{self, config};
            let options = config::normalize(&self.store.library.preferences.auto_select.config)?;
            let timeout_ms = options["timeout"]
                .as_str()
                .and_then(config::duration_ms)
                .ok_or("invalid_auto_select_settings")?;
            let ttl = options["reuse_ttl"]
                .as_str()
                .and_then(config::duration_ms)
                .ok_or("invalid_auto_select_settings")?;
            let remembered =
                self.quick_select
                    .candidate(&quick::context(&self.store.library), ttl, &members);
            let ids = remembered
                .as_ref()
                .map_or_else(|| members.clone(), |id| vec![id.clone()]);
            let context = context(self, id);
            return Ok(Some(ConnectionMeasurements {
                id: id.into(),
                pools: vec![ConnectionMeasurementPool {
                    profile_id: id.into(),
                    fresh_count: 0,
                    ids,
                    url: options["url"]
                        .as_str()
                        .ok_or("invalid_auto_select_settings")?
                        .trim()
                        .into(),
                    timeout_ms,
                    concurrency: options["concurrency"].as_u64().map(|n| n as usize),
                    source: crate::probes::Source::AutoSelect,
                    context: context.to_string(),
                }],
                context,
                quick: Some(QuickPlan {
                    members,
                    reuse: remembered.is_some(),
                    results: None,
                }),
            }));
        }
        let roots = crate::vless::roots(&self.store.library, &profile)?;
        let mut pools = Vec::new();
        for profile in &self.store.library.profiles {
            if !roots.contains(&profile.id)
                || profile.kind != ProfileKind::AutoSelector
                || profile.config["member_source"]["measure_before_connect"] != true
            {
                continue;
            }
            let (source, _, _) = source(profile, &self.store.library)?;
            debug_assert!(source.measure_before_connect);
            let plan = measurements::plan(self, profile)?;
            if plan.candidate_count == 0 {
                return Err("selector_empty_pool".into());
            }
            pools.push(ConnectionMeasurementPool {
                profile_id: profile.id.clone(),
                fresh_count: plan.candidate_count - plan.ids.len(),
                ids: plan.ids,
                url: plan.url,
                timeout_ms: plan.timeout_ms,
                concurrency: None,
                source: crate::probes::Source::Manual,
                context: plan.context,
            });
        }
        if pools.is_empty() {
            return Ok(None);
        }
        Ok(Some(ConnectionMeasurements {
            id: id.into(),
            pools,
            context: context(self, id),
            quick: None,
        }))
    }

    pub fn connection_measurements_current(&self, plan: &ConnectionMeasurements) -> bool {
        if context(self, &plan.id) != plan.context {
            return false;
        }
        if plan.quick.is_some() {
            return true;
        }
        let Ok(Some(current)) = self.connection_measurements(&plan.id) else {
            return false;
        };
        current.pools.len() == plan.pools.len()
            && current
                .pools
                .iter()
                .zip(&plan.pools)
                .all(|(a, b)| a.profile_id == b.profile_id && a.context == b.context)
    }

    /// Seal the actual worker batch, then decide whether a failed memo recheck
    /// needs a full sweep. The host runs that sweep outside the Engine lock.
    pub fn complete_connection_measurements(
        &mut self,
        plan: &mut ConnectionMeasurements,
        batch_id: Option<&str>,
    ) -> Result<bool, String> {
        if !self.connection_measurements_current(plan) {
            return Err("selector_measurements_stale".into());
        }
        let Some(quick) = &mut plan.quick else {
            return Ok(false);
        };
        let pool = &plan.pools[0];
        let id = batch_id.ok_or("selector_measurements_incomplete")?;
        let results = self.quick_batch_results(id, &pool.ids, &pool.url, pool.timeout_ms)?;
        if quick.reuse && !results.iter().any(Option::is_some) {
            self.clear_quick_memory();
            *plan = self
                .connection_measurements(crate::auto_selector::AUTO_SELECT_ID)?
                .ok_or("auto_select_unavailable")?;
            return Ok(true);
        }
        quick.results = Some(results);
        Ok(false)
    }

    fn ranked_quick_members(&self, plan: &ConnectionMeasurements) -> Result<Vec<String>, String> {
        let quick = plan
            .quick
            .as_ref()
            .ok_or("selector_measurements_incomplete")?;
        let pool = &plan.pools[0];
        let results = quick
            .results
            .as_ref()
            .ok_or("selector_measurements_incomplete")?;
        if !results.iter().any(Option::is_some) {
            return Err("auto_select_no_reachable".into());
        }
        let mut members = quick.members.clone();
        members.sort_by_key(|id| {
            pool.ids
                .iter()
                .position(|p| p == id)
                .and_then(|i| results[i])
                .unwrap_or(i32::MAX)
        });
        Ok(members)
    }

    /// Force only members still eligible in this plan. Country/name changes may
    /// remove an old built member; it must not enlarge the bounded candidate sweep.
    pub(crate) fn force_selector_measurements(
        &self,
        plan: &mut ConnectionMeasurements,
        pool_id: &str,
        ids: &[String],
    ) -> Result<(), String> {
        let profile = self.profile(pool_id)?;
        let (eligible, _) = resolve_plan(&profile, &self.store.library, Resolution::Candidates)?;
        let pool = plan
            .pools
            .iter_mut()
            .find(|p| p.profile_id == pool_id)
            .ok_or("selector_measurements_stale")?;
        for id in eligible {
            if ids.contains(&id) && !pool.ids.contains(&id) {
                pool.ids.push(id);
                pool.fresh_count = pool
                    .fresh_count
                    .checked_sub(1)
                    .ok_or("selector_measurements_stale")?;
            }
        }
        Ok(())
    }

    pub(crate) fn force_failed_selector_measurements(
        &self,
        plan: &mut ConnectionMeasurements,
        pool_id: &str,
    ) -> Result<(), String> {
        let profile = self.profile(pool_id)?;
        let (source, _, _) = source(&profile, &self.store.library)?;
        let (eligible, _) = resolve_plan(&profile, &self.store.library, Resolution::Candidates)?;
        let failed = eligible
            .into_iter()
            .filter(|id| {
                http_in_pool(&self.store.library, &profile, id, &source)
                    .is_some_and(|m| m.latency_ms.is_none())
            })
            .collect::<Vec<_>>();
        self.force_selector_measurements(plan, pool_id, &failed)
    }

    pub(crate) fn selector_candidate_ids(
        library: &Library,
        profile: &Profile,
    ) -> Result<Vec<String>, String> {
        resolve_plan(profile, library, Resolution::Candidates).map(|(ids, _)| ids)
    }

    pub(crate) fn selector_library_has_http_success(
        library: &Library,
        id: &str,
    ) -> Result<bool, String> {
        let profile = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("profile_not_found")?;
        let (source, _, _) = source(profile, library)?;
        let (members, _) = resolve_plan(profile, library, Resolution::Startup)?;
        Ok(members.iter().any(|id| {
            http_in_pool(library, profile, id, &source).is_some_and(|m| m.latency_ms.is_some())
        }))
    }

    pub(crate) fn ranked_connection_library(
        &self,
        plan: &ConnectionMeasurements,
    ) -> Result<Library, String> {
        if !self.connection_measurements_current(plan) {
            return Err("selector_measurements_stale".into());
        }
        let mut library = self.store.library.clone();
        for pool in &plan.pools {
            if pool.profile_id == crate::auto_selector::AUTO_SELECT_ID {
                let mut ranked = self
                    .auto_select_profile_from(self.ranked_quick_members(plan)?)
                    .ok_or("auto_select_unavailable")?;
                // Without failover the Core receives only the best measured
                // member, so it has nothing to switch to during the session.
                if !library.preferences.auto_select.failover {
                    if let Some(members) = ranked.config["members"].as_array_mut() {
                        members.truncate(1);
                    }
                }
                library.profiles.retain(|p| p.id != pool.profile_id);
                library.profiles.push(ranked);
                continue;
            }
            let profile = self.profile(&pool.profile_id)?;
            let current = measurements::plan(self, &profile)?;
            if !current.ids.is_empty() {
                return Err("selector_measurements_incomplete".into());
            }
            let ranking = saved_order::rank_profile(self, &profile)?;
            library
                .profiles
                .iter_mut()
                .find(|p| p.id == pool.profile_id)
                .ok_or("selector_measurements_stale")?
                .config["member_source"]["saved_ranking"] = ranking;
        }
        crate::store::validate_library(&library)?;
        Ok(library)
    }

    /// The plan is produced only by this Engine API, never deserialized from IPC.
    /// Ranking and selection are committed together after Start succeeds.
    pub async fn connect_measured(&mut self, plan: &ConnectionMeasurements) -> Result<(), String> {
        let library = self.ranked_connection_library(plan)?;
        let selected = if plan.quick.is_some() {
            self.ranked_quick_members(plan)?.into_iter().next()
        } else {
            None
        };
        self.connect_using_library(
            &plan.id,
            Some(library),
            crate::vpn_auth::otp::Intent::Background,
        )
        .await?;
        if let Some(member) = selected {
            self.remember_quick_connection(member, plan.quick.as_ref().is_some_and(|p| p.reuse));
        }
        Ok(())
    }
}
