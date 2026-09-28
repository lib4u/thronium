use super::*;
use crate::{Engine, ProfileDraft};
use serde_json::json;
use std::path::Path;

fn response(name: &str, value: Value) {
    let registry = registry();
    if let Err(field) = registry.commands[name]
        .response
        .validate(&value, &registry.definitions)
    {
        panic!("response {name} failed at {field}");
    }
}

#[test]
fn actual_engine_dtos_match_wire_contracts() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(dir.path(), Path::new("missing-core")).unwrap();
    response("snapshot", serde_json::to_value(engine.snapshot()).unwrap());
    response("settings", engine.settings());
    response("otpList", engine.otp_list());
    response("routing", serde_json::to_value(engine.routing()).unwrap());
    response("backupStatus", engine.backup_status());
    let backup = engine.export_backup().unwrap();
    response(
        "previewPreviousBackup",
        serde_json::to_value(engine.preview_backup(&backup).unwrap()).unwrap(),
    );
    let group = engine.store.library.groups[0].id.clone();
    let id = engine
        .save_profile(
            serde_json::from_value::<ProfileDraft>(json!({
                "name":"Contract fixture", "groupId":group, "kind":"sing-box-outbound",
                "config":{"type":"socks","server":"127.0.0.1","server_port":1080}
            }))
            .unwrap(),
        )
        .unwrap();
    response(
        "profile",
        serde_json::to_value(engine.editable_profile(&id).unwrap()).unwrap(),
    );
    let exported = engine
        .export_profiles(vec![id], crate::exports::Format::Profiles)
        .unwrap();
    let bundle: Value = serde_json::from_str(&exported).unwrap();
    for profile in bundle["profiles"].as_array().unwrap() {
        registry().definitions["ProfileExport"]
            .validate(profile, &registry().definitions)
            .unwrap();
    }
    response("exportProfiles", json!({"text": exported}));
    let row = engine.otp_save("", "", serde_json::from_value(json!({"name":"Contract OTP", "issuer":"Fixture", "type":"totp", "algorithm":"SHA1", "secret":"JBSWY3DPEHPK3PXP", "digits":6,"period":30,"counter":"0"})).unwrap()).unwrap();
    response("otpSave", row);
    response("otpList", engine.otp_list());
    response("snapshot", serde_json::to_value(engine.snapshot()).unwrap());
}

#[test]
fn contracts_have_no_dangling_references() {
    fn check(schema: &Schema, registry: &Registry) {
        match schema {
            Schema::Ref { name } => {
                assert!(registry.definitions.contains_key(name), "missing {name}")
            }
            Schema::Array { items } => check(items, registry),
            Schema::Map { values } => check(values, registry),
            Schema::Object { fields } => fields
                .values()
                .for_each(|field| check(&field.schema, registry)),
            Schema::Union { members } => members.iter().for_each(|schema| check(schema, registry)),
            _ => {}
        }
    }
    let registry = registry();
    for schema in registry.definitions.values() {
        check(schema, registry);
    }
    for command in registry.commands.values() {
        check(&command.request, registry);
        check(&command.response, registry);
    }
}

#[test]
fn boundary_rejects_missing_arguments_without_echoing_secrets() {
    let error = registry()
        .request("profile", &json!({"id":{"synthetic-secret":true}}))
        .err()
        .unwrap();
    assert_eq!(error.code, "invalid_command_payload");
    assert_eq!(error.field.as_deref(), Some("$.id"));
    assert!(!serde_json::to_string(&error)
        .unwrap()
        .contains("synthetic-secret"));
    let error = BoundaryError::legacy("profile_configuration_changed: synthetic-secret");
    assert_eq!(error.code, "profile_configuration_changed");
    assert!(!serde_json::to_string(&error)
        .unwrap()
        .contains("synthetic-secret"));
    assert_eq!(
        BoundaryError::legacy("https://synthetic-secret.invalid").code,
        "operation_failed"
    );
    assert!(registry()
        .request("saveProfileConfiguration", &json!({"id":"p","config":{}}))
        .is_err());
}

#[test]
fn settings_error_parameters_only_contain_catalog_ids() {
    let error = BoundaryError::legacy(
        "settings_conflict:test_concurrent,https://synthetic-secret,ping_method",
    );
    assert_eq!(error.code, "settings_conflict");
    assert_eq!(
        error.safe_params.unwrap()["fields"],
        "test_concurrent,ping_method"
    );
    assert_eq!(
        BoundaryError::legacy("settings_invalid:test_concurrent")
            .field
            .as_deref(),
        Some("$.test_concurrent")
    );
    assert!(BoundaryError::legacy("settings_invalid:synthetic-secret")
        .field
        .is_none());
}

#[test]
fn selection_and_import_failures_cross_the_boundary_as_specific_safe_codes() {
    for code in [
        "auto_select_no_reachable",
        "auto_select_settings_changed",
        "invalid_auto_select_settings",
        "legacy_import_requires_warp",
        "legacy_routing_warp_required",
    ] {
        let error = BoundaryError::legacy(&format!("{code}: synthetic-secret"));
        assert_eq!(error.code, code);
        assert!(!serde_json::to_string(&error)
            .unwrap()
            .contains("synthetic-secret"));
    }
}

#[test]
fn commands_reference_shared_shapes_instead_of_copying_them() {
    use super::schema::Schema;
    let definitions: Vec<(String, serde_json::Value)> = super::models::definitions()
        .into_iter()
        .filter(|(_, schema)| matches!(schema, Schema::Object { .. }))
        .map(|(name, schema)| (name, serde_json::to_value(schema).unwrap()))
        .collect();
    fn walk(
        schema: &Schema,
        path: String,
        definitions: &[(String, serde_json::Value)],
        found: &mut Vec<String>,
    ) {
        if matches!(schema, Schema::Object { .. }) {
            let value = serde_json::to_value(schema).unwrap();
            if let Some((name, _)) = definitions.iter().find(|(_, d)| *d == value) {
                found.push(format!("{path} = {name}"));
                return;
            }
        }
        match schema {
            Schema::Array { items } => walk(items, format!("{path}[]"), definitions, found),
            Schema::Map { values } => walk(values, format!("{path}.*"), definitions, found),
            Schema::Object { fields } => {
                for (name, field) in fields {
                    walk(&field.schema, format!("{path}.{name}"), definitions, found);
                }
            }
            Schema::Union { members } => {
                for member in members {
                    walk(member, path.clone(), definitions, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    for (name, command) in super::catalog::commands() {
        walk(
            &command.request,
            format!("{name}.request"),
            &definitions,
            &mut found,
        );
        walk(
            &command.response,
            format!("{name}.response"),
            &definitions,
            &mut found,
        );
    }
    assert!(
        found.is_empty(),
        "inline copies of named shapes:\n{}",
        found.join("\n")
    );
}

#[test]
fn repeated_choices_are_named_once() {
    use super::schema::Schema;
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    fn walk(schema: &Schema, path: String, seen: &mut BTreeMap<String, Vec<String>>) {
        match schema {
            Schema::Union { members }
                if members.iter().all(|m| matches!(m, Schema::Literal { .. }))
                    && members.len() > 1 =>
            {
                seen.entry(serde_json::to_string(schema).unwrap())
                    .or_default()
                    .push(path);
            }
            Schema::Union { members } => members.iter().for_each(|m| walk(m, path.clone(), seen)),
            Schema::Array { items } => walk(items, format!("{path}[]"), seen),
            Schema::Map { values } => walk(values, format!("{path}.*"), seen),
            Schema::Object { fields } => fields
                .iter()
                .for_each(|(n, f)| walk(&f.schema, format!("{path}.{n}"), seen)),
            _ => {}
        }
    }
    for (name, schema) in super::models::definitions() {
        if !matches!(schema, Schema::Union { .. }) {
            walk(&schema, name, &mut seen);
        }
    }
    for (name, command) in super::catalog::commands() {
        walk(&command.request, format!("{name}.request"), &mut seen);
        walk(&command.response, format!("{name}.response"), &mut seen);
    }
    let repeated: Vec<String> = seen
        .iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(union, paths)| format!("{union}: {}", paths.join(", ")))
        .collect();
    assert!(
        repeated.is_empty(),
        "name these choices in models.rs:\n{}",
        repeated.join("\n")
    );
}

#[test]
fn the_registry_holds_error_codes_not_setting_ids() {
    let ids: std::collections::HashSet<_> = crate::settings::fields()
        .iter()
        .map(|field| field.id.as_str())
        .collect();
    let words: Vec<_> = error_codes::codes()
        .iter()
        .filter(|code| ids.contains(**code))
        .collect();
    assert!(
        words.is_empty(),
        "setting ids are not error codes: {words:?}"
    );
    let mut sorted = error_codes::codes().to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), error_codes::codes().len(), "duplicate codes");
}
