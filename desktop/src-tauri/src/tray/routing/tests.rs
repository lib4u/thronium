use super::*;
use serde_json::json;
use thronium_engine::routing::RoutingProfile;
fn view(routing: &Routing) -> View {
    View::new(routing, &json!({}), None, Some("server"))
}
#[test]
fn quick_settings_targets_reject_changed_flags_and_changed_warp_credentials() {
    let routing = Routing::default();
    let settings =
        json!({"adblock_enable":false,"enable_warp":false,"warp_private_key":"fixture-one"});
    let before = view(&routing).with_intercept(&settings);
    let target = before.target(Choice::Setting("adblock_enable", true));
    assert!(target.valid(&view(&routing).with_intercept(&settings)));
    for (key, value) in [
        ("adblock_enable", json!(true)),
        ("warp_private_key", json!("fixture-two")),
    ] {
        let mut changed = settings.clone();
        changed[key] = value;
        assert!(!target.valid(&view(&routing).with_intercept(&changed)));
    }
    assert!(!before.adblock && !before.warp);
    assert!(
        view(&routing)
            .with_intercept(&json!({"enable_warp":true}))
            .warp
    );
}
#[test]
fn quick_settings_change_one_flag_and_preserve_credentials_and_other_settings() {
    let settings = json!({"adblock_enable":false,"enable_warp":false,"warp_private_key":"fixture key", "warp_reserved":["0","1","2"],"adblock_ruleset_url":"http://127.0.0.1/fixture"});
    let view = view(&Routing::default()).with_intercept(&settings);
    for key in ["adblock_enable", "enable_warp"] {
        let target = view.target(Choice::Setting(key, true));
        let mut expected = settings.clone();
        expected[key] = json!(true);
        assert_eq!(target.settings_candidate(&settings).unwrap(), expected);
        assert!(target.settings_candidate(&expected).is_none());
        assert!(target.candidate(&Routing::default()).is_none());
    }
    assert!(view
        .target(Choice::Setting("warp_private_key", true))
        .settings_candidate(&settings)
        .is_none());
    assert_eq!(settings["adblock_enable"], false);
}
#[test]
fn old_menu_targets_reject_new_revision_connection_and_policy_ownership() {
    let routing = Routing::default();
    let target = view(&routing).target(Choice::Mode("direct"));
    assert!(target.valid(&view(&routing)));
    let mut changed = routing.clone();
    changed.revision += 1;
    assert!(!target.valid(&view(&changed)));
    for (status, running, selected) in [
        (json!({}), Some("server"), Some("server")),
        (json!({}), None, Some("other")),
        (json!({"profileOwned":true}), None, Some("server")),
        (json!({"providerOwned":true}), None, Some("server")),
    ] {
        assert!(!target.valid(&View::new(&routing, &status, running, selected)));
    }
}
#[test]
fn choices_preserve_other_profiles_and_do_not_save_noops_or_deleted_targets() {
    let mut routing = Routing::default();
    routing.profiles.push(RoutingProfile {
        id: "custom".into(),
        name: "Custom".into(),
        mode: "direct".into(),
        ..Default::default()
    });
    let original = serde_json::to_value(&routing).unwrap();
    let changed = view(&routing)
        .target(Choice::Mode("all"))
        .candidate(&routing)
        .unwrap();
    assert_eq!(changed.active().unwrap().mode, "all");
    assert_eq!(
        serde_json::to_value(&changed.profiles[1]).unwrap(),
        original["profiles"][1]
    );
    assert_eq!(changed.revision, routing.revision);
    let selected = view(&routing)
        .target(Choice::Profile("custom".into()))
        .candidate(&routing)
        .unwrap();
    assert_eq!(selected.active, "custom");
    assert_eq!(
        serde_json::to_value(&selected.profiles).unwrap(),
        original["profiles"]
    );
    for choice in [
        Choice::Profile("default".into()),
        Choice::Profile("deleted".into()),
        Choice::Mode("rules"),
        Choice::Apply,
    ] {
        assert!(view(&routing).target(choice).candidate(&routing).is_none());
    }
}
#[test]
fn display_uses_saved_policy_and_filters_controls_and_menu_accelerators() {
    let mut routing = Routing::default();
    routing.profiles[0].name = "Route & one\n\t".into();
    let saved = View::new(
        &routing,
        &json!({"pending":true}),
        Some("live"),
        Some("other"),
    );
    assert_eq!(saved.name, "Route && one");
    assert!(saved.pending);
    assert_eq!(saved.context.connection.as_deref(), Some("live"));
    assert_eq!(label(&"x".repeat(80)), format!("{}…", "x".repeat(64)));
    assert!(!View::new(&routing, &json!({"profileOwned":true}), None, None).editable());
    assert!(!View::new(&routing, &json!({"providerOwned":true}), None, None).editable());
}
