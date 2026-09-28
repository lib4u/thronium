use super::*;
use crate::subscriptions::GroupDraft;
use crate::subscriptions::{Download, Settings};
use crate::ProfileDraft;
fn draft(group: &str, name: &str, password: &str) -> ProfileDraft {
    serde_json::from_value(json!({"name":name,"groupId":group,"kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":39998,"username":"user","password":password}})).unwrap()
}
fn preview(
    e: &mut Engine,
    group: &str,
    drafts: Vec<ProfileDraft>,
) -> (String, Vec<crate::subscriptions::Change>) {
    let request = e.subscription_request(group).unwrap();
    let token = e
        .subscription_downloaded(
            request,
            Download {
                body: "fixture".into(),
                usage: None,
                metadata: Default::default(),
            },
        )
        .unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let changes = e.preview_subscription(&token, drafts).unwrap();
    (token, changes)
}
fn recapture(e: &mut Engine, id: &str) {
    let request = e.build(&e.profile(id).unwrap()).unwrap();
    let roots = crate::vless::roots(&e.store.library, &e.profile(id).unwrap()).unwrap();
    e.running = Some(id.into());
    e.store.library.selected = Some(id.into());
    e.routing_revision = Some(e.store.library.routing.revision);
    e.active_connection = Some(ActiveConnection {
        id: id.into(),
        profiles: crate::group_chains::dependencies(&e.store.library, &roots),
        groups: HashSet::from(["personal".into()]),
        request: request.clone(),
        routing_revision: e.store.library.routing.revision,
        system_port: None,
        tun: false,
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
    });
    e.selector_rebuild = State::capture(&e.store.library, id, &request);
}
fn setup_subscription() -> (tempfile::TempDir, Engine, String, Vec<String>, String) {
    let (dir, mut e, _, _) = setup();
    e.running = None;
    e.active_connection = None;
    e.store.library.profiles.clear();
    e.store.library.selected = None;
    let settings: Settings =
        serde_json::from_value(json!({"url":"http://127.0.0.1:39999/sub","inheritDefaults":false}))
            .unwrap();
    let group = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Provider".into(),
            subscription: Some(settings),
            proxy_chain: None,
        })
        .unwrap();
    let (token, _) = preview(
        &mut e,
        &group,
        vec![
            draft(&group, "A", "a"),
            draft(&group, "B", "b"),
            draft(&group, "C", "c"),
        ],
    );
    let ids = e
        .apply_subscription(&token)
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect::<Vec<_>>();
    let pool=e.save_profile(serde_json::from_value(json!({"name":"Subscription pool","groupId":"personal","kind":"auto-selector","config":{"type":"auto-selector","member_source":{"group_id":group,"order":"saved-http-latency","measure_before_connect":true,"rebuild_on_subscription":true,"build_limit":1},"url":URL}})).unwrap()).unwrap();
    recapture(&mut e, &pool);
    (dir, e, group, ids, pool)
}
#[test]
fn subscription_option_is_independent_and_requires_preflight() {
    let (_d, e, _, _, pool) = setup_subscription();
    assert!(!e.selector_rebuild.pools["proxy"].on_exhaustion);
    assert!(e.selector_rebuild.pools["proxy"].on_subscription);
    let mut p = e.profile(&pool).unwrap();
    p.config["member_source"]["measure_before_connect"] = json!(false);
    assert_eq!(
        crate::auto_selector::validate_saved(&p, &e.store.library).unwrap_err(),
        "selector_rebuild_requires_measurements"
    );
}
#[test]
fn committed_rotation_preserves_request_and_identity_and_queues_only_after_apply() {
    let (_d, mut e, g, ids, _) = setup_subscription();
    assert!(e.selector_member_subscription_allowed(&ids[0]));
    assert!(!e.selector_member_subscription_allowed(&ids[1]));
    let request = request_hash(&e.active_connection.as_ref().unwrap().request);
    let (token, changes) = preview(
        &mut e,
        &g,
        vec![
            draft(&g, "A", "rotated"),
            draft(&g, "B", "b"),
            draft(&g, "C", "c"),
        ],
    );
    assert_eq!(changes[0].id, ids[0]);
    assert_eq!(changes[0].action, "updated");
    assert!(e.selector_subscription_update().is_null());
    e.apply_subscription(&token).unwrap();
    assert_eq!(e.profile(&ids[0]).unwrap().config["password"], "rotated");
    assert_eq!(
        request_hash(&e.active_connection.as_ref().unwrap().request),
        request
    );
    assert!(e.selector_subscription_update().is_object());
    assert!(e.selector_rebuild_scope_current());
    assert!(e.subscription_rebuild_ticket().is_some());
}
#[test]
fn nonbuilt_changes_and_rename_do_not_restart_but_removal_retains_old_name() {
    let (_d, mut e, g, ids, _) = setup_subscription();
    let (token, _) = preview(
        &mut e,
        &g,
        vec![
            draft(&g, "A renamed", "a"),
            draft(&g, "B", "changed"),
            draft(&g, "C", "c"),
        ],
    );
    e.apply_subscription(&token).unwrap();
    assert!(e.selector_subscription_update().is_null());
    let (token, changes) = preview(
        &mut e,
        &g,
        vec![draft(&g, "B", "changed"), draft(&g, "C", "c")],
    );
    assert!(changes
        .iter()
        .any(|c| c.id == ids[0] && c.action == "removed"));
    e.apply_subscription(&token).unwrap();
    assert!(e.profile(&ids[0]).is_err());
    assert!(e.selector_rebuild_scope_current());
    assert!(e.subscription_rebuild_ticket().is_some());
    assert_eq!(
        e.selector_rebuild
            .former_member_name("proxy", &crate::auto_selector::member_tag("proxy", &ids[0])),
        Some("A")
    );
}
#[test]
fn failed_store_write_cannot_create_a_pending_replacement() {
    let (dir, mut e, g, _, _) = setup_subscription();
    let (token, _) = preview(&mut e, &g, vec![draft(&g, "A", "changed")]);
    let before = json!(e.store.library);
    let path = dir.path().join("library.json");
    let saved = dir.path().join("library-before.json");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(e.apply_subscription(&token).is_err());
    assert_eq!(json!(e.store.library), before);
    assert!(e.selector_subscription_update().is_null());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(saved, path).unwrap();
}
#[tokio::test]
async fn global_stop_permission_does_not_disconnect_a_scoped_opted_in_pool() {
    let (_d, mut e, g, ids, pool) = setup_subscription();
    e.store
        .library
        .settings
        .insert("allow_stopping_active_profile".into(), json!(true));
    recapture(&mut e, &pool);
    let (token, _) = preview(&mut e, &g, vec![draft(&g, "A", "changed")]);
    assert!(e.stop_for_subscription(&token).await.unwrap().is_none());
    e.apply_subscription(&token).unwrap();
    assert!(e.running.is_some());
    assert_eq!(e.profile(&ids[0]).unwrap().config["password"], "changed");
}
#[test]
fn every_running_pool_must_opt_in_and_explicit_chains_remain_protected() {
    let (_d, mut e, _, ids, pool) = setup_subscription();
    let original = e.store.library.clone();
    let mut other = e.profile(&pool).unwrap();
    other.id = uuid::Uuid::new_v4().to_string();
    other.name = "Other pool".into();
    other.config["member_source"]["rebuild_on_subscription"] = json!(false);
    let other_id = other.id.clone();
    e.store.library.profiles.push(other);
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{other_id}"));
    recapture(&mut e, &pool);
    assert_eq!(e.selector_rebuild.pools.len(), 2);
    assert!(!e.selector_member_subscription_allowed(&ids[0]));
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == other_id)
        .unwrap()
        .config["member_source"]["rebuild_on_subscription"] = json!(true);
    recapture(&mut e, &pool);
    assert!(e.selector_member_subscription_allowed(&ids[0]));
    e.store.library = original;
    recapture(&mut e, &pool);
    let chain=serde_json::from_value(json!({"id":"chain","favorite":false,"name":"Protected chain","groupId":"personal","kind":"chain","config":{"hops":[ids[0]]}})).unwrap();
    e.store.library.profiles.push(chain);
    assert!(!e.selector_member_subscription_allowed(&ids[0]));
}
#[test]
fn ordinary_routing_target_using_the_member_blocks_replacement() {
    let (_d, mut e, _, ids, pool) = setup_subscription();
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{}", ids[0]));
    recapture(&mut e, &pool);
    assert!(!e.selector_member_subscription_allowed(&ids[0]));
}
#[test]
fn opted_in_auxiliary_pool_keeps_routing_revision_applied() {
    let (_d, mut e, g, ids, pool) = setup_subscription();
    let primary=e.save_profile(serde_json::from_value(json!({"name":"Primary","groupId":"personal","kind":"sing-box-outbound","config":{"type":"socks","server":"127.0.0.1","server_port":39996}})).unwrap()).unwrap();
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{pool}"));
    recapture(&mut e, &primary);
    assert!(e.selector_member_subscription_allowed(&ids[0]));
    let (token, _) = preview(
        &mut e,
        &g,
        vec![
            draft(&g, "A", "changed"),
            draft(&g, "B", "b"),
            draft(&g, "C", "c"),
        ],
    );
    e.apply_subscription(&token).unwrap();
    assert!(e.selector_rebuild_scope_current());
    assert!(e.subscription_rebuild_ticket().is_some());
}
#[test]
fn pending_retries_are_bounded_and_explicit_cancel_survives_new_versions() {
    use super::super::subscription::Pending;
    let mut p = Pending::default();
    p.update("v1".into(), true);
    assert!(p.ready(0));
    p.attempted(0);
    assert!(!p.ready(59999));
    assert!(p.ready(60000));
    p.update("v1".into(), true);
    assert_eq!(p.attempts, 1);
    p.attempted(60000);
    assert!(!p.ready(179999));
    assert!(p.ready(180000));
    p.attempted(180000);
    assert!(!p.ready(u64::MAX));
    p.update("v2".into(), true);
    assert_eq!(p.attempts, 0);
    assert!(p.ready(180000));
    p.cancelled = true;
    p.update("v3".into(), true);
    assert!(!p.ready(u64::MAX));
    p.update("v1".into(), false);
    assert!(p.cancelled);
}
#[test]
fn newer_subscription_invalidates_old_plan_and_late_cancel_does_not_pause_it() {
    let (_d, mut e, g, _, _) = setup_subscription();
    let (token, _) = preview(&mut e, &g, vec![draft(&g, "A", "v1")]);
    e.apply_subscription(&token).unwrap();
    let old = e.subscription_rebuild_ticket().unwrap();
    let plan = e.prepare_selector_rebuild(&old).unwrap();
    let (token, _) = preview(&mut e, &g, vec![draft(&g, "A", "v2")]);
    e.apply_subscription(&token).unwrap();
    assert!(!e.selector_rebuild_current(&old));
    assert!(!e.connection_measurements_current(&plan));
    e.finish_selector_rebuild(&old, true);
    assert!(e.selector_rebuild.claimed.is_none());
    assert!(!e.selector_rebuild.pools["proxy"].subscription.cancelled);
    assert!(e.subscription_rebuild_ticket().is_some());
}
#[tokio::test]
async fn all_failed_replacements_leave_old_core_and_ranking_untouched() {
    let (_d, mut e, g, ids, _) = setup_subscription();
    let (token, _) = preview(
        &mut e,
        &g,
        vec![
            draft(&g, "A", "v1"),
            draft(&g, "B", "b"),
            draft(&g, "C", "c"),
        ],
    );
    e.apply_subscription(&token).unwrap();
    for id in &ids {
        measured(&mut e, id, None);
    }
    let ticket = e.subscription_rebuild_ticket().unwrap();
    let plan = e.prepare_selector_rebuild(&ticket).unwrap();
    let before = json!(e.store.library);
    let request = request_hash(&e.active_connection.as_ref().unwrap().request);
    assert_eq!(
        e.connect_rebuilt(&ticket, &plan).await.unwrap_err(),
        "selector_subscription_unavailable"
    );
    assert_eq!(json!(e.store.library), before);
    assert_eq!(
        request_hash(&e.active_connection.as_ref().unwrap().request),
        request
    );
    assert!(e.rpc.is_none());
    e.finish_selector_rebuild(&ticket, false);
    assert_eq!(e.selector_rebuild.pools["proxy"].subscription.attempts, 1);
    e.selector_rebuild.origin = Instant::now() - std::time::Duration::from_secs(61);
    let next = e.subscription_rebuild_ticket().unwrap();
    let plan = e.prepare_selector_rebuild(&next).unwrap();
    assert_eq!(plan.pools[0].ids.len(),3,"Retry checks fresh failures again instead of consuming attempts on the same negative cache");
}
#[test]
fn empty_replacement_plan_consumes_a_bounded_attempt_and_releases_claim() {
    let (_d, mut e, g, _, pool) = setup_subscription();
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]["name_regex"] = json!("^A$");
    recapture(&mut e, &pool);
    let (token, _) = preview(&mut e, &g, vec![draft(&g, "B", "b")]);
    e.apply_subscription(&token).unwrap();
    let ticket = e.subscription_rebuild_ticket().unwrap();
    assert!(e.prepare_selector_rebuild(&ticket).is_err());
    assert!(e.selector_rebuild.claimed.is_none());
    assert_eq!(e.selector_rebuild.pools["proxy"].subscription.attempts, 1);
    assert!(e.subscription_rebuild_ticket().is_none());
}
#[test]
fn provider_routing_edit_invalidates_prepared_connection_but_quota_does_not() {
    let (_d, mut e, g, _, pool) = setup_subscription();
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .group_id = g.clone();
    recapture(&mut e, &pool);
    let plan = e.connection_measurements(&pool).unwrap().unwrap();
    e.store
        .library
        .groups
        .iter_mut()
        .find(|g2| g2.id == g)
        .unwrap()
        .subscription
        .as_mut()
        .unwrap()
        .usage = Some(crate::subscriptions::Usage {
        upload: Some(10),
        download: Some(20),
        total: Some(100),
        expire: None,
    });
    assert!(e.connection_measurements_current(&plan));
    e.store
        .library
        .groups
        .iter_mut()
        .find(|g2| g2.id == g)
        .unwrap()
        .subscription
        .as_mut()
        .unwrap()
        .metadata
        .routing = Some(serde_json::from_value(json!({"action":"on","config":{}})).unwrap());
    assert!(!e.connection_measurements_current(&plan));
}

#[test]
fn renamed_built_member_outside_name_filter_queues_only_eligible_replacements() {
    let (_d, mut e, g, ids, pool) = setup_subscription();
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == pool)
        .unwrap()
        .config["member_source"]["name_regex"] = json!("^[ABC]$");
    recapture(&mut e, &pool);
    let (token, changes) = preview(
        &mut e,
        &g,
        vec![
            draft(&g, "Excluded", "a"),
            draft(&g, "B", "b"),
            draft(&g, "C", "c"),
        ],
    );
    assert_eq!(changes[0].id, ids[0]);
    e.apply_subscription(&token).unwrap();
    assert!(e.selector_rebuild_scope_current());
    let ticket = e.subscription_rebuild_ticket().unwrap();
    let plan = e.prepare_selector_rebuild(&ticket).unwrap();
    assert_eq!(plan.pools[0].ids, vec![ids[1].clone(), ids[2].clone()]);
    measured(&mut e, &ids[1], Some(5));
    measured(&mut e, &ids[2], Some(10));
    let proposed = e.ranked_connection_library(&plan).unwrap();
    let pool = proposed.profiles.iter().find(|p| p.id == pool).unwrap();
    assert_eq!(
        crate::auto_selector::resolve(pool, &proposed).unwrap(),
        vec![ids[1].clone()]
    );
}

#[test]
fn changing_subscription_mode_keeps_live_recreation_eligible_and_queues_fresh_ids() {
    let (_dir, mut e, g, old, pool) = setup_subscription();
    // Saving the form also writes its unchanged effective defaults.
    for (id, value) in crate::settings::section(&e.store.library, "subscriptions")
        .as_object()
        .unwrap()
    {
        e.store.library.settings.insert(id.clone(), value.clone());
    }
    e.store
        .library
        .settings
        .insert("sub_update_mode".into(), json!("recreate"));
    assert!(e.selector_member_subscription_allowed(&old[0]));
    let request = request_hash(&e.active_connection.as_ref().unwrap().request);
    let (token, changes) = preview(&mut e, &g, vec![draft(&g, "A", "a"), draft(&g, "B", "b")]);
    assert_eq!(changes.iter().filter(|c| c.action == "added").count(), 2);
    assert_eq!(
        changes.iter().filter(|c| c.action == "removed").count(),
        old.len()
    );
    assert!(e.selector_subscription_update().is_null());
    e.apply_subscription(&token).unwrap();
    assert_eq!(
        request_hash(&e.active_connection.as_ref().unwrap().request),
        request
    );
    assert_eq!(e.running.as_deref(), Some(pool.as_str()));
    assert!(old.iter().all(|id| e.profile(id).is_err()));
    let ticket = e.subscription_rebuild_ticket().unwrap();
    assert!(e.selector_rebuild_current(&ticket));
    e.store
        .library
        .settings
        .insert("inbound_address".into(), json!("0.0.0.0"));
    assert!(!e.selector_rebuild_current(&ticket));
}
