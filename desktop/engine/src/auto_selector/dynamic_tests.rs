use super::*;
use crate::{
    exports,
    store::Group,
    subscriptions::{Download, GroupDraft},
    ProfileDraft,
};
use std::{collections::HashSet, path::Path};

fn setup() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    engine.store.library.groups.push(Group {
        id: "source".into(),
        name: "Provider".into(),
        collapsed: false,
        auto_clear_unavailable: false,
        proxy_chain: Default::default(),
        subscription: None,
    });
    (dir, engine)
}
fn leaf(id: &str, name: &str) -> Profile {
    Profile {
        vpn_policy: None,
        id: id.into(),
        name: name.into(),
        group_id: "source".into(),
        kind: ProfileKind::SingBoxOutbound,
        favorite: false,
        config: json!({"type":"socks","server":"localhost","server_port":1080,"password":"selector-private-secret"}),
    }
}
fn draft(group: &str, include: &str, exclude: &str) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: None,
        name: "Dynamic pool".into(),
        group_id: "personal".into(),
        kind: ProfileKind::AutoSelector,
        config: json!({"type":"auto-selector","member_source":{"group_id":group,"name_regex":include,"exclude_regex":exclude},"interval":"1m"}),
    }
}
fn as_draft(p: &Profile) -> ProfileDraft {
    ProfileDraft {
        vpn_policy: Default::default(),
        id: Some(p.id.clone()),
        name: p.name.clone(),
        group_id: p.group_id.clone(),
        kind: p.kind,
        config: p.config.clone(),
    }
}
fn pool(e: &Engine, id: &str) -> Vec<String> {
    resolve(&e.profile(id).unwrap(), &e.store.library).unwrap()
}
fn pool_outbound(request: &proto::LoadConfigReq, tag: &str) -> Value {
    let core: Value = serde_json::from_str(request.core_config.as_deref().unwrap()).unwrap();
    core["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == tag)
        .unwrap()
        .clone()
}

#[test]
fn dynamic_filters_use_unicode_saved_order_and_only_supported_ordinary_profiles() {
    let (_dir, mut e) = setup();
    let mut xray = leaf("x", "Сервер JP fast");
    xray.kind = ProfileKind::XrayOutbound;
    xray.config = json!({"protocol":"socks","settings":{"address":"localhost","port":1081}});
    let mut endpoint = leaf("endpoint", "Сервер JP VPN");
    endpoint.config = json!({"type":"wireguard"});
    let mut system = leaf("system", "Сервер JP system VPN");
    system.config = json!({"type":"wireguard","system":true});
    let mut full = leaf("full", "Сервер JP full");
    full.kind = ProfileKind::SingBoxConfig;
    let mut other = leaf("other", "Сервер JP other");
    other.group_id = "personal".into();
    let mut chain = leaf("chain", "Сервер JP chain");
    chain.kind = ProfileKind::Chain;
    chain.config = json!({"type":"chain","hops":["x"]});
    e.store.library.profiles = vec![
        leaf("z", "Сервер JP fast"),
        leaf("skip", "Сервер JP slow"),
        xray,
        endpoint,
        system,
        full,
        other,
        chain,
        leaf("de", "Сервер DE"),
    ];
    let before = json!(e.store.library);
    let preview = e
        .preview_selector(draft("source", r"^сЕРВЕР\s+jp", "SLOW"))
        .unwrap();
    assert_eq!(
        preview,
        json!({"total":3,"members":[{"id":"z","name":"Сервер JP fast"},{"id":"x","name":"Сервер JP fast"},{"id":"endpoint","name":"Сервер JP VPN"}]}),
        "a userspace endpoint qualifies; a system interface, a full configuration and a chain do not"
    );
    assert!(!preview.to_string().contains("selector-private-secret"));
    assert_eq!(json!(e.store.library), before);
    let id = e
        .save_profile(draft("source", r"^Сервер\s+JP", "slow"))
        .unwrap();
    assert_eq!(pool(&e, &id), ["z", "x", "endpoint"]);
    assert!(e.profile(&id).unwrap().config.get("members").is_none());
}

#[test]
fn invalid_source_regex_generated_fields_and_dynamic_pin_are_atomic() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("one", "One"));
    let mut cases = Vec::new();
    for value in [
        json!(null),
        json!({"group_id":"source","unknown":true}),
        json!({"group_id":1}),
        json!({"group_id":""}),
        json!({"group_id":"source","name_regex":null}),
    ] {
        let mut d = draft("source", "", "");
        d.config["member_source"] = value;
        cases.push((d, "invalid_selector_source"));
    }
    cases.push((draft("missing", "", ""), "selector_source_missing"));
    for regex in [
        "[".into(),
        "(?=JP)".into(),
        "(x)\\1".into(),
        "x".repeat(2049),
        "x{999999999}".into(),
    ] {
        cases.push((draft("source", &regex, ""), "selector_invalid_regex"));
    }
    let mut both = draft("source", "", "");
    both.config["members"] = json!(["one"]);
    cases.push((both, "invalid_selector_source"));
    let mut pin = draft("source", "", "");
    pin.config["pinned_profile"] = json!("one");
    cases.push((pin, "invalid_selector_pin"));
    for key in [
        "outbounds",
        "pinned",
        "warm",
        crate::group_chains::MEMBER_HOPS,
    ] {
        let mut d = draft("source", "", "");
        d.config[key] = json!([]);
        cases.push((d, "selector_generated_fields"));
    }
    let before = json!(e.store.library);
    for (d, error) in cases {
        assert_eq!(
            e.preview_selector(ProfileDraft {
                config: d.config.clone(),
                ..draft("source", "", "")
            })
            .unwrap_err(),
            error
        );
        assert_eq!(e.save_profile(d).unwrap_err(), error);
        assert_eq!(json!(e.store.library), before);
    }
}

#[tokio::test]
async fn empty_dynamic_source_is_saved_but_check_start_and_export_preserve_active_session() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("active", "Active"));
    let id = e.save_profile(draft("source", "^absent$", "")).unwrap();
    assert_eq!(
        e.preview_selector(as_draft(&e.profile(&id).unwrap()))
            .unwrap()["total"],
        0
    );
    e.running = Some("active".into());
    let before = json!(e.store.library);
    let p = e.profile(&id).unwrap();
    assert_eq!(e.check(&p).await.unwrap_err(), "selector_empty_pool");
    assert_eq!(e.connect(&id).await.unwrap_err(), "selector_empty_pool");
    assert_eq!(
        e.export_profiles(vec![id], exports::Format::Profiles)
            .unwrap_err(),
        "selector_empty_pool"
    );
    assert_eq!(e.running.as_deref(), Some("active"));
    assert!(e.rpc.is_none());
    assert_eq!(json!(e.store.library), before);
}

#[test]
fn dynamic_limit_accepts_500_and_library_growth_but_rejects_501_runtime_without_truncation() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..500)
        .map(|i| leaf(&format!("m{i}"), &format!("Member {i}")))
        .collect();
    let id = e.save_profile(draft("source", "", "")).unwrap();
    assert_eq!(pool(&e, &id).len(), 500);
    let mut extra = as_draft(&leaf("extra", "Member 501"));
    extra.id = None;
    let extra = e.save_profile(extra).unwrap();
    assert!(e.profile(&extra).is_ok());
    assert_eq!(
        e.preview_selector(draft("source", "", "")).unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(
        e.build(&e.profile(&id).unwrap()).unwrap_err(),
        "selector_too_many_members"
    );
}

#[test]
fn source_group_cannot_disappear_but_inactive_dynamic_members_can_move_or_be_deleted() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("one", "One"));
    let id = e.save_profile(draft("source", "", "")).unwrap();
    let before = json!(e.store.library);
    for remove in [false, true] {
        assert_eq!(
            e.delete_group("source", remove).unwrap_err(),
            "selector_source_in_use"
        );
    }
    assert_eq!(json!(e.store.library), before);
    e.move_profiles(vec!["one".into()], "personal").unwrap();
    assert!(pool(&e, &id).is_empty());
    e.move_profiles(vec!["one".into()], "source").unwrap();
    e.delete("one").unwrap();
    assert!(pool(&e, &id).is_empty());
    e.delete(&id).unwrap();
    e.delete_group("source", false).unwrap();
}

#[test]
fn fresh_build_resolves_core_choices_auxiliary_routes_and_wrappers_without_mutating_source() {
    let (_dir, mut e) = setup();
    let mut member = leaf("member", "JP");
    member.config = json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"});
    e.store.library.profiles = vec![
        member,
        leaf("other", "DE"),
        leaf("front", "Front"),
        leaf("landing", "Landing"),
    ];
    e.store.library.profiles[2].config["server"] = json!("front.test");
    e.store.library.profiles[3].config["server"] = json!("landing.test");
    let id = e.save_profile(draft("source", "^JP$", "")).unwrap();
    e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
        front: Some("front".into()),
        landing: Some("landing".into()),
    };
    let p = e.profile(&id).unwrap();
    let before = json!(e.store.library);
    let request = e.build(&p).unwrap();
    assert_eq!(request.need_xray, Some(true));
    assert_eq!(
        pool_outbound(&request, "proxy")["outbounds"],
        json!([member_tag("proxy", "member")])
    );
    assert!(request.core_config.as_ref().unwrap().contains("front"));
    assert!(!request
        .core_config
        .as_ref()
        .unwrap()
        .contains("member_source"));
    assert_eq!(json!(e.store.library), before);
    assert_eq!(
        crate::vless::relevant(&e.store.library, &p).unwrap(),
        HashSet::from([
            id.clone(),
            "member".into(),
            "front".into(),
            "landing".into()
        ])
    );
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{id}"));
    let request = e.build(&e.profile("other").unwrap()).unwrap();
    let tag = format!("thronium-route-{id}");
    assert_eq!(
        pool_outbound(&request, &tag)["outbounds"],
        json!([member_tag(&tag, "member")])
    );
    assert!(e.routing_uses("member"));
}

#[test]
fn captured_active_members_remain_guarded_after_filtering_rename_and_new_members_wait_for_build() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("old", "JP old"), leaf("other", "DE")];
    let id = e.save_profile(draft("source", "^JP", "")).unwrap();
    let p = e.profile(&id).unwrap();
    let request = e.build(&p).unwrap();
    e.active_connection = Some(crate::connection::ActiveConnection {
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
        id: id.clone(),
        profiles: crate::vless::relevant(&e.store.library, &p).unwrap(),
        groups: HashSet::from(["personal".into()]),
        request: request.clone(),
        routing_revision: 0,
        system_port: None,
        tun: false,
    });
    e.running = Some(id.clone());
    // A pending rename can change future matching, but cannot release a live dependency.
    e.store
        .library
        .profiles
        .iter_mut()
        .find(|p| p.id == "old")
        .unwrap()
        .name = "DE renamed".into();
    let mut new = as_draft(&leaf("new", "JP new"));
    new.id = None;
    let new = e.save_profile(new).unwrap();
    assert!(e.running_uses("old"));
    assert!(!e.running_uses(&new));
    assert_eq!(e.delete("old").unwrap_err(), "stop_before_editing");
    assert_eq!(
        e.move_profiles(vec!["old".into()], "personal").unwrap_err(),
        "stop_before_editing"
    );
    assert_eq!(
        e.save_profile(as_draft(&e.profile("old").unwrap()))
            .unwrap_err(),
        "stop_before_editing"
    );
    assert_eq!(
        e.active_connection.as_ref().unwrap().request.core_config,
        request.core_config
    );
    assert_eq!(
        pool_outbound(&e.build(&p).unwrap(), "proxy")["outbounds"],
        json!([member_tag("proxy", &new)])
    );
}

#[test]
fn portable_export_snapshots_dynamic_members_wrappers_overrides_and_native_backup_keeps_source() {
    let (_dir, mut e) = setup();
    let mut vless = leaf("member", "JP");
    vless.config = json!({"type":"vless","server":"example.test","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"});
    e.store.library.profiles = vec![vless, leaf("front", "Front"), leaf("landing", "Landing")];
    e.store
        .library
        .preferences
        .vless_overrides
        .insert("member".into(), crate::vless::Core::SingBox);
    let id = e.save_profile(draft("source", "^JP$", "")).unwrap();
    e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
        front: Some("front".into()),
        landing: Some("landing".into()),
    };
    let before = json!(e.store.library);
    let text = e
        .export_profiles(vec![id.clone()], exports::Format::Profiles)
        .unwrap();
    let mut bundle: Value = serde_json::from_str(&text).unwrap();
    assert!(!text.contains("member_source"));
    assert!(!text.contains("group_id"));
    assert!(!text.contains(&id));
    let entries = bundle["profiles"].as_array_mut().unwrap();
    assert_eq!(entries.len(), 5);
    let member = entries
        .iter()
        .find(|p| p["kind"] == "sing-box-outbound" && p["name"] == "JP")
        .unwrap();
    assert_eq!(member["vlessCore"], "sing-box");
    let references = entries
        .iter()
        .map(|p| p["reference"].as_str().unwrap().to_string())
        .collect::<HashSet<_>>();
    for entry in entries.iter() {
        for key in ["members", "hops"] {
            if let Some(ids) = entry["config"][key].as_array() {
                assert!(ids.iter().all(|v| references.contains(v.as_str().unwrap())));
            }
        }
    }
    for entry in entries {
        entry["groupId"] = json!("personal");
    }
    let (_dir2, mut imported) = setup();
    let imported_ids = imported
        .import_referenced_profiles(serde_json::from_value(bundle["profiles"].clone()).unwrap())
        .unwrap();
    let selector = imported_ids
        .iter()
        .map(|id| imported.profile(id).unwrap())
        .find(|p| p.kind == ProfileKind::AutoSelector)
        .unwrap();
    let member = imported
        .profile(selector.config["members"][0].as_str().unwrap())
        .unwrap();
    assert_eq!(member.kind, ProfileKind::Chain);
    let names = chains::flatten(&member, &imported.store.library.profiles)
        .unwrap()
        .into_iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["Front", "JP", "Landing"]);
    assert!(imported.build(&selector).is_ok());
    assert_eq!(json!(e.store.library), before);
    let backup = e.export_backup().unwrap();
    let preview = imported.preview_backup(&backup).unwrap();
    imported.restore_backup(&preview.token).unwrap();
    assert_eq!(
        imported.profile(&id).unwrap().config["member_source"]["group_id"],
        "source"
    );
    assert_eq!(pool(&imported, &id), ["member"]);
}

#[test]
fn nested_fixed_chain_members_are_supported_but_selector_recursion_is_rejected() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("two", "Two")];
    let mut chain = leaf("chain", "Chain");
    chain.kind = ProfileKind::Chain;
    chain.config = json!({"hops":["one","two"]});
    e.store.library.profiles.push(chain);
    let mut d = draft("source", "", "");
    d.config = json!({"type":"auto-selector","members":["chain"]});
    let id = e.save_profile(d).unwrap();
    assert!(e.build(&e.profile(&id).unwrap()).is_ok());
    assert!(build(&e.profile(&id).unwrap(), &e.store.library.profiles, 2080).is_ok());
    let mut d = draft("source", "", "");
    d.config = json!({"type":"auto-selector","members":[id]});
    assert_eq!(
        e.save_profile(d).unwrap_err(),
        "selector_member_unsupported"
    );
    let mut next = e.store.library.clone();
    next.profiles
        .iter_mut()
        .find(|p| p.id == "chain")
        .unwrap()
        .config["hops"] = json!([id]);
    assert!(crate::store::validate_library(&next).is_err());
}

#[test]
fn subscription_removals_follow_dynamic_pool_without_acquiring_fixed_references() {
    let (_dir, mut e) = setup();
    let group = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Subscription".into(),
            proxy_chain: None,
            subscription: Some(
                serde_json::from_value(
                    json!({"url":"https://example.test/sub","inheritDefaults":false}),
                )
                .unwrap(),
            ),
        })
        .unwrap();
    fn update(e: &mut Engine, group: &str, names: &[&str]) -> Vec<crate::subscriptions::Change> {
        let request = e.subscription_request(group).unwrap();
        let ticket = e
            .subscription_downloaded(
                request,
                Download {
                    metadata: Default::default(),
                    body: "fixture".into(),
                    usage: None,
                },
            )
            .unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_owned();
        let drafts = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let mut d = as_draft(&leaf("", name));
                d.id = None;
                d.group_id = group.into();
                d.config["server_port"] = json!(1100 + i);
                d
            })
            .collect();
        e.preview_subscription(&ticket, drafts).unwrap();
        e.apply_subscription(&ticket).unwrap()
    }
    update(&mut e, &group, &["JP one", "DE two"]);
    let id = e.save_profile(draft(&group, "^JP", "")).unwrap();
    let old = pool(&e, &id)[0].clone();
    let changes = update(&mut e, &group, &["DE renamed"]);
    assert!(pool(&e, &id).is_empty());
    assert!(changes.iter().any(|c| c.action == "removed"));
    // Name-only identity reconciliation retains IDs without pinning membership.
    assert_eq!(e.profile(&old).unwrap().name, "DE renamed");
    update(&mut e, &group, &["JP returned", "JP new"]);
    assert_eq!(pool(&e, &id).len(), 2);
}

#[test]
fn edited_draft_replaces_old_filter_in_runtime_library_and_preview_without_saving() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("one", "JP one"));
    let id = e.save_profile(draft("source", "^absent$", "")).unwrap();
    let before = json!(e.store.library);
    let mut edited = e.profile(&id).unwrap();
    edited.config["member_source"]["name_regex"] = json!("^jp");
    assert_eq!(e.preview_selector(as_draft(&edited)).unwrap()["total"], 1);
    let (library, selected) = crate::vless::library(&e.store.library, &edited).unwrap();
    assert_eq!(selected.config["members"], json!(["one"]));
    assert_eq!(
        library.profiles.iter().find(|p| p.id == id).unwrap().config,
        selected.config
    );
    assert_eq!(
        pool_outbound(&e.build(&edited).unwrap(), "proxy")["outbounds"],
        json!([member_tag("proxy", "one")])
    );
    let mut unsaved = draft("source", "jp", "");
    unsaved.name.clear();
    assert_eq!(e.preview_selector(unsaved).unwrap()["total"], 1);
    assert_eq!(json!(e.store.library), before);
}

#[test]
fn group_removal_can_remove_its_own_selector_but_never_orphan_an_external_source() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("one", "One"));
    let mut d = draft("source", "", "");
    d.group_id = "source".into();
    e.save_profile(d).unwrap();
    assert_eq!(
        e.delete_group("source", false).unwrap_err(),
        "selector_source_in_use"
    );
    e.delete_group("source", true).unwrap();
    assert!(e.store.library.profiles.is_empty());
    assert!(e.group("source").is_err());
}

#[tokio::test]
async fn subscription_and_import_may_grow_past_500_without_mutating_the_frozen_active_pool() {
    let (_dir, mut e) = setup();
    let group = e
        .save_group(GroupDraft {
            auto_clear_unavailable: None,
            id: None,
            name: "Provider".into(),
            proxy_chain: None,
            subscription: Some(
                serde_json::from_value(
                    json!({"url":"https://example.test/sub","inheritDefaults":false}),
                )
                .unwrap(),
            ),
        })
        .unwrap();
    let update = |e: &mut Engine, count: usize| {
        let request = e.subscription_request(&group).unwrap();
        let token = e
            .subscription_downloaded(
                request,
                Download {
                    metadata: Default::default(),
                    body: "fixture".into(),
                    usage: None,
                },
            )
            .unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_owned();
        let drafts = (0..count)
            .map(|i| ProfileDraft {
                vpn_policy: Default::default(),
                id: None,
                name: format!("JP {i}"),
                group_id: group.clone(),
                kind: ProfileKind::SingBoxOutbound,
                config: json!({"type":"socks","server":"localhost","server_port":1200+i}),
            })
            .collect();
        e.preview_subscription(&token, drafts).unwrap();
        e.apply_subscription(&token).unwrap();
    };
    update(&mut e, 500);
    let id = e.save_profile(draft(&group, "jp", "")).unwrap();
    let profile = e.profile(&id).unwrap();
    let request = e.build(&profile).unwrap();
    let frozen = crate::vless::relevant(&e.store.library, &profile).unwrap();
    e.active_connection = Some(crate::connection::ActiveConnection {
        external_instance: None,
        vpn_primary: false,
        vpn_otp: Default::default(),
        vpn_otp_start: Default::default(),
        id: id.clone(),
        profiles: frozen.clone(),
        groups: HashSet::from(["personal".into()]),
        request: request.clone(),
        routing_revision: 0,
        system_port: None,
        tun: false,
    });
    e.running = Some(id.clone());
    update(&mut e, 501);
    let mut extra = as_draft(&leaf("extra", "JP imported"));
    extra.id = None;
    extra.group_id = group;
    let imported = e.import_profiles(vec![extra]).unwrap();
    assert!(e.profile(&imported[0]).is_ok());
    assert_eq!(
        e.preview_selector(as_draft(&profile)).unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(
        e.check(&profile).await.unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(
        e.connect(&id).await.unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(
        e.export_profiles(vec![id.clone()], exports::Format::Profiles)
            .unwrap_err(),
        "selector_too_many_members"
    );
    assert_eq!(e.running.as_deref(), Some(id.as_str()));
    assert_eq!(e.active_connection.as_ref().unwrap().profiles, frozen);
    assert_eq!(
        e.active_connection.as_ref().unwrap().request.core_config,
        request.core_config
    );
    assert!(!e.running_uses(&imported[0]));
    assert!(e.rpc.is_none());
}

#[test]
fn portable_wrappers_respect_total_reference_bundle_limit_without_truncation() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..500)
        .map(|i| leaf(&format!("member{i}"), &format!("JP {i}")))
        .collect();
    e.store
        .library
        .profiles
        .extend([leaf("front", "Front"), leaf("landing", "Landing")]);
    let id = e.save_profile(draft("source", "^JP", "")).unwrap();
    e.store.library.groups[0].proxy_chain = crate::group_chains::GroupChain {
        front: Some("front".into()),
        landing: Some("landing".into()),
    };
    let before = json!(e.store.library);
    assert_eq!(
        e.export_profiles(vec![id.clone()], exports::Format::Profiles)
            .unwrap_err(),
        "export_reference_limit"
    );
    assert_eq!(json!(e.store.library), before);
    // 498 leaf members +498 chain snapshots +2 wrapper leaves +1 pool fit.
    e.delete_profiles(vec!["member498".into(), "member499".into()])
        .unwrap();
    let text = e
        .export_profiles(vec![id], exports::Format::Profiles)
        .unwrap();
    let bundle: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(bundle["profiles"].as_array().unwrap().len(), 999);
}

fn country_draft(codes: &str) -> ProfileDraft {
    let mut profile = draft("source", "", "");
    profile.config["member_source"]["country_filter"] = json!(codes);
    profile
}
fn measured(e: &mut Engine, id: &str, country: Option<&str>) {
    let request = e.ip_test(id).unwrap();
    e.remember_ip_country(
        &request,
        &json!({"ip":"203.0.113.45","countryCode":country}),
    )
    .unwrap();
}

#[test]
fn country_filter_uses_measurement_instead_of_names_and_preserves_saved_order() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("one", "🇩🇪 Germany"),
        leaf("two", "🇯🇵 Japan"),
        leaf("unknown", "JP unknown"),
    ];
    measured(&mut e, "one", Some("JP"));
    measured(&mut e, "two", Some("DE"));
    let preview = e.preview_selector(country_draft(" jp, JP ")).unwrap();
    assert_eq!(
        preview,
        json!({"total":1,"members":[{"id":"one","name":"🇩🇪 Germany","countryCode":"JP"}],"unknownCountryCount":1})
    );
    let pool_id = e.save_profile(country_draft("de, jp")).unwrap();
    assert_eq!(pool(&e, &pool_id), ["one", "two"]);
    let saved = e.profile(&pool_id).unwrap();
    let compiled = materialize(&saved, &e.store.library).unwrap();
    assert_eq!(compiled.config["members"], json!(["one", "two"]));
    assert!(compiled.config.get("member_source").is_none());
    assert_eq!(e.profile(&pool_id).unwrap().config, saved.config);
}

#[test]
fn country_filter_composes_with_name_filters_and_empty_country_keeps_unmeasured() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("one", "Fast One"),
        leaf("two", "Slow Two"),
        leaf("unknown", "Fast Unmeasured"),
    ];
    measured(&mut e, "one", Some("JP"));
    measured(&mut e, "two", Some("JP"));
    let mut d = country_draft("JP");
    d.config["member_source"]["name_regex"] = json!("Fast");
    let preview = e.preview_selector(d).unwrap();
    assert_eq!(preview["total"], 1);
    assert_eq!(preview["unknownCountryCount"], 1);
    let id = e.save_profile(country_draft("")).unwrap();
    assert_eq!(pool(&e, &id), ["one", "two", "unknown"]);
}

#[test]
fn invalid_country_filters_are_atomic_and_do_not_replace_saved_pool() {
    let (_dir, mut e) = setup();
    e.store.library.profiles.push(leaf("one", "One"));
    let id = e.save_profile(country_draft("")).unwrap();
    let before = json!(e.store.library);
    for codes in [
        "D".into(),
        "Germany".into(),
        "DE;NL".into(),
        "日本".into(),
        "12".into(),
        "DE,".repeat(684),
    ] {
        let mut d = country_draft(&codes);
        d.id = Some(id.clone());
        assert_eq!(
            e.preview_selector(ProfileDraft {
                config: d.config.clone(),
                ..country_draft("")
            })
            .unwrap_err(),
            "selector_invalid_country_filter"
        );
        assert_eq!(
            e.save_profile(d).unwrap_err(),
            "selector_invalid_country_filter"
        );
        assert_eq!(json!(e.store.library), before);
    }
}

#[test]
fn measured_country_changes_rebuild_only_the_next_materialized_pool() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("two", "Two")];
    measured(&mut e, "one", Some("JP"));
    measured(&mut e, "two", Some("DE"));
    let id = e.save_profile(country_draft("JP")).unwrap();
    let first = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    measured(&mut e, "one", Some("DE"));
    measured(&mut e, "two", Some("JP"));
    let second = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    assert_eq!(first.config["members"], json!(["one"]));
    assert_eq!(second.config["members"], json!(["two"]));
    assert!(e.profile(&id).unwrap().config.get("members").is_none());
}

#[test]
fn saved_country_filter_and_local_observations_survive_reopen() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("two", "Two")];
    let id = e.save_profile(country_draft("JP")).unwrap();
    assert_eq!(pool(&e, &id), Vec::<String>::new());
    assert_eq!(
        materialize(&e.profile(&id).unwrap(), &e.store.library)
            .err()
            .as_deref(),
        Some("selector_empty_pool")
    );
    measured(&mut e, "one", Some("JP"));
    measured(&mut e, "two", Some("DE"));
    drop(e);
    let mut e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(pool(&e, &id), ["one"]);
    let mut next = e.store.library.clone();
    next.profiles
        .iter_mut()
        .find(|p| p.id == "one")
        .unwrap()
        .config["server_port"] = json!(1081);
    e.store.commit(next).unwrap();
    assert_eq!(pool(&e, &id), Vec::<String>::new());
    let preview = e
        .preview_selector(as_draft(&e.profile(&id).unwrap()))
        .unwrap();
    assert_eq!(preview["unknownCountryCount"], 1);
}

#[test]
fn country_filter_requires_the_same_group_proxy_policy_as_the_pool() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("landing", "Landing")];
    measured(&mut e, "one", Some("JP"));
    e.store.library.groups[0].proxy_chain.landing = Some("landing".into());
    let preview = e.preview_selector(country_draft("JP")).unwrap();
    assert_eq!(preview["total"], 0);
    assert_eq!(preview["unknownCountryCount"], 2);
    e.store.library.groups[1].proxy_chain.landing = Some("landing".into());
    measured(&mut e, "one", Some("DE"));
    let preview = e.preview_selector(country_draft("DE")).unwrap();
    assert_eq!(preview["total"], 1);
    assert_eq!(preview["members"][0]["id"], "one");
    e.store.library.groups[1].proxy_chain.landing = None;
    assert_eq!(e.preview_selector(country_draft("DE")).unwrap()["total"], 0);
}

fn ranked_draft(order: &str, exclude: bool, minutes: u32) -> ProfileDraft {
    let mut draft = country_draft("");
    draft.config["member_source"]["order"] = json!(order);
    draft.config["member_source"]["exclude_unavailable"] = json!(exclude);
    draft.config["member_source"]["result_validity_mins"] = json!(minutes);
    draft.config["url"] = json!("https://example.test/ranking");
    draft
}
fn http_measured(e: &mut Engine, id: &str, latency: Option<i32>) {
    let next = e
        .store
        .library
        .latency_measurements
        .updated(
            &e.store.library,
            id,
            "https://example.test/ranking",
            3000,
            latency,
        )
        .unwrap();
    e.store.save_latency_measurements(next).unwrap();
}
fn preview_ids(e: &Engine, draft: ProfileDraft) -> Vec<String> {
    e.preview_selector(draft).unwrap()["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().into())
        .collect()
}
#[test]
fn fresh_http_order_is_stable_and_optional_with_zero_latency_allowed() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("unknown", "Unknown"),
        leaf("slow", "Slow"),
        leaf("equal1", "Equal One"),
        leaf("zero", "Zero"),
        leaf("equal2", "Equal Two"),
        leaf("failed", "Failed"),
    ];
    for (id, ms) in [
        ("slow", Some(90)),
        ("equal1", Some(20)),
        ("zero", Some(0)),
        ("equal2", Some(20)),
        ("failed", None),
    ] {
        http_measured(&mut e, id, ms);
    }
    assert_eq!(
        preview_ids(&e, ranked_draft("http-latency", false, 60)),
        ["zero", "equal1", "equal2", "slow", "unknown", "failed"]
    );
    assert_eq!(
        preview_ids(&e, ranked_draft("library", false, 60)),
        ["unknown", "slow", "equal1", "zero", "equal2", "failed"]
    );
    assert_eq!(
        preview_ids(&e, ranked_draft("http-latency", false, 0)),
        ["unknown", "slow", "equal1", "zero", "equal2", "failed"]
    );
    let preview = e
        .preview_selector(ranked_draft("http-latency", false, 60))
        .unwrap();
    assert_eq!(preview["rankedByHttp"], 4);
    assert_eq!(preview["unknownHttpCount"], 1);
    assert_eq!(preview["members"][0]["latencyMs"], 0);
    assert_eq!(preview["members"][5]["httpTestFailed"], true);
}
#[test]
fn excluding_failed_http_keeps_unknown_and_restores_all_failed_candidates() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    http_measured(&mut e, "a", None);
    http_measured(&mut e, "b", None);
    assert_eq!(preview_ids(&e, ranked_draft("library", true, 60)), ["c"]);
    http_measured(&mut e, "c", None);
    let preview = e
        .preview_selector(ranked_draft("http-latency", true, 60))
        .unwrap();
    assert_eq!(preview["keptUnavailable"], 3);
    assert_eq!(preview["total"], 3);
    assert_eq!(
        preview_ids(&e, ranked_draft("http-latency", true, 60)),
        ["a", "b", "c"]
    );
    http_measured(&mut e, "b", Some(10));
    assert_eq!(
        preview_ids(&e, ranked_draft("http-latency", true, 60)),
        ["b"]
    );
}
#[test]
fn http_ranking_composes_with_country_name_and_matching_pool_proxy_policy() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("a", "Fast A"),
        leaf("b", "Fast B"),
        leaf("c", "Slow C"),
        leaf("hop", "Hop"),
    ];
    measured(&mut e, "a", Some("JP"));
    measured(&mut e, "b", Some("DE"));
    measured(&mut e, "c", Some("JP"));
    http_measured(&mut e, "a", Some(30));
    http_measured(&mut e, "b", Some(10));
    http_measured(&mut e, "c", Some(1));
    let mut d = ranked_draft("http-latency", false, 60);
    d.config["member_source"]["country_filter"] = json!("JP");
    d.config["member_source"]["name_regex"] = json!("^Fast");
    assert_eq!(preview_ids(&e, d), ["a"]);
    e.store.library.groups[0].proxy_chain.front = Some("hop".into());
    let preview = e
        .preview_selector(ranked_draft("http-latency", true, 60))
        .unwrap();
    assert_eq!(preview["rankedByHttp"], 0);
    assert_eq!(preview["unknownHttpCount"], 4);
    assert_eq!(preview["total"], 4);
}
#[test]
fn http_rank_requires_same_url_and_saved_filter_does_not_change_materialized_session() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    http_measured(&mut e, "a", Some(40));
    http_measured(&mut e, "b", Some(10));
    let id = e
        .save_profile(ranked_draft("http-latency", false, 60))
        .unwrap();
    let first = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    assert_eq!(first.config["members"], json!(["b", "a"]));
    http_measured(&mut e, "a", Some(1));
    assert_eq!(pool(&e, &id), ["a", "b"]);
    assert_eq!(first.config["members"], json!(["b", "a"]));
    let mut d = ranked_draft("http-latency", true, 60);
    d.config["url"] = json!("https://example.test/other");
    let preview = e.preview_selector(d).unwrap();
    assert_eq!(preview["unknownHttpCount"], 2);
    assert_eq!(preview["rankedByHttp"], 0);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(pool(&e, &id), ["a", "b"]);
    assert_eq!(
        e.profile(&id).unwrap().config["member_source"]["order"],
        "http-latency"
    );
    let exported = e
        .export_profiles(vec![id], exports::Format::Profiles)
        .unwrap();
    assert!(
        !exported.contains("member_source")
            && !exported.contains("urlHash")
            && !exported.contains("fingerprint")
    );
}
#[test]
fn invalid_http_ranking_options_do_not_overwrite_saved_source() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A")];
    let id = e.save_profile(ranked_draft("library", false, 60)).unwrap();
    let before = json!(e.store.library);
    for (field, value) in [
        ("order", json!("random")),
        ("exclude_unavailable", json!("true")),
        ("result_validity_mins", json!(-1)),
        ("result_validity_mins", json!(10081)),
    ] {
        let mut d = ranked_draft("library", false, 60);
        d.id = Some(id.clone());
        d.config["member_source"][field] = value;
        assert!(e.save_profile(d).is_err());
        assert_eq!(json!(e.store.library), before);
    }
}

fn warm_draft() -> ProfileDraft {
    let mut draft = ranked_draft("library", false, 60);
    draft.config["member_source"]["warm_start"] = json!(true);
    draft
}
#[test]
fn warm_hints_encode_zero_success_failure_and_uint16_boundaries_only_in_core_json() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("zero", "Zero"),
        leaf("bad", "Bad"),
        leaf("max", "Max"),
        leaf("large", "Large"),
        leaf("unknown", "Unknown"),
    ];
    for (id, ms) in [
        ("zero", Some(0)),
        ("bad", None),
        ("max", Some(65535)),
        ("large", Some(65536)),
    ] {
        http_measured(&mut e, id, ms);
    }
    let id = e.save_profile(warm_draft()).unwrap();
    let before = json!(e.store.library);
    let generation = e.store.generation();
    let request = e.build(&e.profile(&id).unwrap()).unwrap();
    let group = pool_outbound(&request, "proxy");
    let warm = group["warm"].as_array().unwrap();
    assert_eq!(warm.len(), 3);
    assert_eq!(warm[0]["tag"], member_tag("proxy", "zero"));
    assert_eq!(warm[0]["rtt"], 1);
    assert_eq!(warm[1]["rtt"], 0);
    assert_eq!(warm[2]["rtt"], 65535);
    assert!(warm.iter().all(|s| s["age"].as_u64().unwrap() <= 2));
    assert_eq!(json!(e.store.library), before);
    assert_eq!(e.store.generation(), generation);
    assert!(!request.core_config.unwrap().contains("member_source"));
    let preview = e.preview_selector(warm_draft()).unwrap();
    assert_eq!(preview["warmCandidatesCount"], 3);
    assert_eq!(preview["members"][0]["latencyMs"], 0);
}
#[test]
fn warm_hints_require_opt_in_and_matching_url_validity_and_pool_context() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("hop", "Hop")];
    http_measured(&mut e, "one", Some(20));
    let id = e.save_profile(ranked_draft("library", false, 60)).unwrap();
    let p = e.profile(&id).unwrap();
    assert!(pool_outbound(&e.build(&p).unwrap(), "proxy")
        .get("warm")
        .is_none());
    for (field, value) in [
        ("warm_start", json!(false)),
        ("result_validity_mins", json!(0)),
    ] {
        let mut d = warm_draft();
        d.id = Some(id.clone());
        d.config["member_source"][field] = value;
        e.save_profile(d).unwrap();
        assert!(
            pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy")
                .get("warm")
                .is_none()
        );
    }
    let mut d = warm_draft();
    d.id = Some(id.clone());
    d.config["url"] = json!("https://example.test/other");
    e.save_profile(d).unwrap();
    assert!(
        pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy")
            .get("warm")
            .is_none()
    );
    let mut d = warm_draft();
    d.id = Some(id.clone());
    e.save_profile(d).unwrap();
    e.store.library.groups[0].proxy_chain.front = Some("hop".into());
    assert!(
        pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy")
            .get("warm")
            .is_none()
    );
}
#[test]
fn warm_hints_preserve_original_measurement_age_across_reopen() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One")];
    let id = e.save_profile(warm_draft()).unwrap();
    http_measured(&mut e, "one", Some(40));
    drop(e);
    let path = dir.path().join("http-latencies-v1.json");
    let mut cache: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    cache["entries"]["one"]["testedAt"] = json!(now - 90);
    if cache["entries"]["one"].get("observedAtMs").is_some() {
        cache["entries"]["one"]["observedAtMs"] = json!((now - 90) * 1000);
    }
    std::fs::write(path, cache.to_string()).unwrap();
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    let request = e.build(&e.profile(&id).unwrap()).unwrap();
    let group = pool_outbound(&request, "proxy");
    assert_eq!(group["warm"][0]["rtt"], 40);
    let age = group["warm"][0]["age"].as_u64().unwrap();
    assert!((90..=92).contains(&age));
}
#[test]
fn warm_hints_use_routing_pool_tags_and_skip_unmeasured_members() {
    let (_dir, mut e) = setup();
    let mut main = leaf("main", "Main");
    main.group_id = "personal".into();
    e.store.library.profiles = vec![leaf("one", "One"), leaf("unknown", "Unknown"), main];
    http_measured(&mut e, "one", Some(33));
    let id = e.save_profile(warm_draft()).unwrap();
    e.store.library.routing.profiles[0].route["final"] = json!(format!("profile:{id}"));
    let request = e.build(&e.profile("main").unwrap()).unwrap();
    let tag = format!("thronium-route-{id}");
    let group = pool_outbound(&request, &tag);
    assert_eq!(group["warm"].as_array().unwrap().len(), 1);
    assert_eq!(group["warm"][0]["tag"], member_tag(&tag, "one"));
    assert_eq!(group["warm"][0]["rtt"], 33);
}
#[test]
fn portable_snapshot_omits_warm_values_and_raw_generated_values_remain_rejected() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("one", "One")];
    http_measured(&mut e, "one", Some(30));
    let id = e.save_profile(warm_draft()).unwrap();
    let before = json!(e.store.library);
    for value in [Value::Null, json!([]), json!([{"tag":"injected","rtt":1}])] {
        let mut d = warm_draft();
        d.id = Some(id.clone());
        d.config["warm"] = value;
        assert_eq!(e.save_profile(d).unwrap_err(), "selector_generated_fields");
        assert_eq!(json!(e.store.library), before);
    }
    let text = e
        .export_profiles(vec![id], exports::Format::Profiles)
        .unwrap();
    assert!(
        !text.contains("warm") && !text.contains("member_source") && !text.contains("fingerprint")
    );
}
#[test]
fn complete_user_configuration_keeps_its_own_warm_fields_verbatim() {
    let (_dir, e) = setup();
    let selected = Profile {
        kind: ProfileKind::SingBoxConfig,
        config: json!({"outbounds":[]}),
        ..leaf("full", "Full")
    };
    let original="{\"outbounds\":[{\"type\":\"auto-selector\",\"tag\":\"proxy\",\"warm\":[{\"tag\":\"owned\",\"rtt\":5}]}]}";
    let mut request = proto::LoadConfigReq {
        core_config: Some(original.into()),
        ..Default::default()
    };
    apply_warm(&mut request, &selected, &e.store.library).unwrap();
    assert_eq!(request.core_config.as_deref(), Some(original));
}

fn limited_draft(limit: Value) -> ProfileDraft {
    let mut d = draft("source", "", "");
    d.config["member_source"]["build_limit"] = limit;
    d
}
#[test]
fn explicit_startup_limit_accepts_3000_candidates_and_refuses_3001_without_silent_candidate_truncation(
) {
    let (_dir, mut e) = setup();
    e.store.library.profiles = (0..3000)
        .map(|i| leaf(&format!("m{i:04}"), &format!("Member {i:04}")))
        .collect();
    let preview = e.preview_selector(limited_draft(json!(2))).unwrap();
    assert_eq!(preview["total"], 2);
    assert_eq!(preview["matchingBeforeLimit"], 3000);
    assert_eq!(preview["omittedByLimit"], 2998);
    assert_eq!(preview_ids(&e, limited_draft(json!(2))), ["m0000", "m0001"]);
    assert_eq!(
        e.preview_selector(limited_draft(json!(500))).unwrap()["total"],
        500
    );
    assert_eq!(
        e.preview_selector(draft("source", "", "")).unwrap_err(),
        "selector_too_many_members"
    );
    e.store.library.profiles.push(leaf("extra", "Member 3001"));
    assert_eq!(
        e.preview_selector(limited_draft(json!(1))).unwrap_err(),
        "selector_too_many_candidates"
    );
    let mut filtered = limited_draft(json!(2));
    filtered.config["member_source"]["name_regex"] = json!("^Member 000[01]$");
    assert_eq!(
        e.preview_selector(filtered).unwrap()["matchingBeforeLimit"],
        2
    );
}
#[test]
fn startup_limit_input_is_optional_and_invalid_values_leave_the_saved_library_unchanged() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B")];
    let id = e.save_profile(limited_draft(json!(1))).unwrap();
    let before = json!(e.store.library);
    for value in [
        json!(0),
        json!(501),
        json!(-1),
        json!(null),
        json!(1.5),
        json!("2"),
        json!(true),
    ] {
        let mut d = limited_draft(value);
        d.id = Some(id.clone());
        assert_eq!(
            e.save_profile(limit_copy(&d)).unwrap_err(),
            "selector_invalid_build_limit"
        );
        assert_eq!(
            e.preview_selector(d).unwrap_err(),
            "selector_invalid_build_limit"
        );
        assert_eq!(json!(e.store.library), before);
    }
    let preview = e.preview_selector(draft("source", "", "")).unwrap();
    assert_eq!(preview["total"], 2);
    assert!(preview.get("matchingBeforeLimit").is_none());
    assert!(preview.get("omittedByLimit").is_none());
}
#[test]
fn filters_and_http_order_and_exclusion_run_before_the_explicit_startup_limit() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![
        leaf("a", "A"),
        leaf("b", "B"),
        leaf("c", "C"),
        leaf("d", "D"),
    ];
    http_measured(&mut e, "a", Some(50));
    http_measured(&mut e, "b", Some(10));
    http_measured(&mut e, "c", None);
    let mut d = ranked_draft("http-latency", true, 60);
    d.config["member_source"]["build_limit"] = json!(2);
    assert_eq!(preview_ids(&e, limit_copy(&d)), ["b", "a"]);
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["matchingBeforeLimit"], 3);
    assert_eq!(p["omittedByLimit"], 1);
    measured(&mut e, "a", Some("DE"));
    measured(&mut e, "b", Some("JP"));
    d.config["member_source"]["country_filter"] = json!("DE");
    d.config["member_source"]["build_limit"] = json!(1);
    assert_eq!(preview_ids(&e, d), ["a"]);
}
#[test]
fn all_failed_fallback_remains_eligible_but_only_limited_members_receive_warm_hints() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    for id in ["a", "b", "c"] {
        http_measured(&mut e, id, None);
    }
    let mut d = ranked_draft("http-latency", true, 60);
    d.config["member_source"]["warm_start"] = json!(true);
    d.config["member_source"]["build_limit"] = json!(2);
    let p = e.preview_selector(limit_copy(&d)).unwrap();
    assert_eq!(p["keptUnavailable"], 2);
    assert_eq!(p["matchingBeforeLimit"], 3);
    assert_eq!(p["omittedByLimit"], 1);
    assert_eq!(p["warmCandidatesCount"], 2);
    let id = e.save_profile(d).unwrap();
    let core = pool_outbound(&e.build(&e.profile(&id).unwrap()).unwrap(), "proxy");
    assert_eq!(core["outbounds"].as_array().unwrap().len(), 2);
    let warm = core["warm"].as_array().unwrap();
    assert_eq!(warm.len(), 2);
    assert!(warm
        .iter()
        .all(|v| v["rtt"] == 0 && v["tag"] != "thronium-selector-proxy-c"));
}
#[test]
fn auxiliary_pool_uses_limited_final_tags_for_successful_warm_samples() {
    let (_dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    http_measured(&mut e, "a", Some(30));
    http_measured(&mut e, "b", Some(10));
    http_measured(&mut e, "c", Some(50));
    let mut d = ranked_draft("http-latency", false, 60);
    d.config["member_source"]["warm_start"] = json!(true);
    d.config["member_source"]["build_limit"] = json!(1);
    let id = e.save_profile(d).unwrap();
    let route = e
        .store
        .library
        .routing
        .profiles
        .iter_mut()
        .find(|p| p.id == e.store.library.routing.active)
        .unwrap();
    route.rules=vec![serde_json::from_value(json!({"id":"limited-route","name":"Limited","enabled":true,"config":{"domain":["example.test"],"outbound":format!("profile:{id}")}})).unwrap()];
    let before = json!(e.store.library);
    let tag = format!("thronium-route-{id}");
    let core = pool_outbound(&e.build(&e.profile("a").unwrap()).unwrap(), &tag);
    assert_eq!(core["outbounds"], json!([member_tag(&tag, "b")]));
    assert_eq!(core["warm"][0]["tag"], member_tag(&tag, "b"));
    assert_eq!(core["warm"][0]["rtt"], 10);
    assert_eq!(json!(e.store.library), before);
}
#[test]
fn saved_limit_reopens_exports_only_built_members_and_never_changes_an_old_materialization() {
    let (dir, mut e) = setup();
    e.store.library.profiles = vec![leaf("a", "A"), leaf("b", "B"), leaf("c", "C")];
    let id = e.save_profile(limited_draft(json!(2))).unwrap();
    let frozen = materialize(&e.profile(&id).unwrap(), &e.store.library).unwrap();
    let exported = e
        .export_profiles(vec![id.clone()], exports::Format::Profiles)
        .unwrap();
    assert!(!exported.contains("build_limit") && !exported.contains("member_source"));
    let mut d = limited_draft(json!(1));
    d.id = Some(id.clone());
    e.save_profile(d).unwrap();
    assert_eq!(frozen.config["members"], json!(["a", "b"]));
    assert_eq!(pool(&e, &id), ["a"]);
    drop(e);
    let e = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    assert_eq!(pool(&e, &id), ["a"]);
}

fn limit_copy(d: &ProfileDraft) -> ProfileDraft {
    ProfileDraft {
        id: d.id.clone(),
        name: d.name.clone(),
        group_id: d.group_id.clone(),
        kind: d.kind,
        config: d.config.clone(),
        vpn_policy: Default::default(),
    }
}

mod pool_cap;

mod saved_order;

mod measurements;

mod preflight;
