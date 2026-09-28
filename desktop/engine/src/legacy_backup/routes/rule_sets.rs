//! Resolve Qt rule-set references without fetching resources or trusting local paths.
use super::*;

fn url(value: &str) -> Result<reqwest::Url> {
    crate::geodata::catalog::valid_url(value).map_err(|_| "legacy_route_ruleset_unsupported")
}

pub(super) fn source(db: &SourceDatabase, tag: &str) -> Result<String> {
    if let Some(source) = crate::routing::rule_sets::source(tag) {
        let mirror = super::super::settings::core::mirror(setting(db, "ruleset_mirror", "1")?)
            .map_err(|_| "legacy_route_settings_invalid")?;
        return Ok(crate::settings::network::mirror(source, mirror));
    }
    let parsed = url(tag)?;
    if !parsed
        .path()
        .rsplit('/')
        .next()
        .is_some_and(|s| s.contains(".srs"))
    {
        return Err("legacy_route_ruleset_unsupported");
    }
    Ok(tag.into())
}

fn definition(value: &mut Value, context: rules::Context<'_>) -> Result<()> {
    let rules::Context { profiles, .. } = context;
    nonempty(&value["tag"])?;
    match value["type"].as_str() {
        Some("remote") => {
            object_keys(
                value,
                &[
                    "type",
                    "tag",
                    "format",
                    "url",
                    "download_detour",
                    "update_interval",
                ],
            )?;
            if !matches!(value["format"].as_str(), Some("binary" | "source")) {
                return Err("legacy_route_ruleset_unsupported");
            }
            url(nonempty(&value["url"])?)?;
            if let Some(detour) = value.get("download_detour") {
                value["download_detour"] = json!(target(detour, profiles)?);
            }
            if let Some(interval) = value.get("update_interval") {
                duration(interval)?;
            }
        }
        Some("inline") => {
            object_keys(value, &["type", "tag", "rules"])?;
            let rules = value["rules"]
                .as_array_mut()
                .ok_or("legacy_route_structure")?;
            if rules.len() > 1000 {
                return Err("legacy_route_limit");
            }
            for rule in rules {
                // Inline rule-set rules are headless, with no routing actions or
                // references to other rule sets. Core validates its RE2 syntax.
                if !references(rule)?.is_empty() {
                    return Err("legacy_route_ruleset_unsupported");
                }
                rules::validate(
                    rule,
                    rules::Context {
                        profiles: None,
                        ..context
                    },
                    true,
                    0,
                )?;
            }
        }
        Some("local") => {
            object_keys(value, &["type", "tag", "format", "path"])?;
            if !matches!(value["format"].as_str(), Some("binary" | "source"))
                || !value["path"]
                    .as_str()
                    .is_some_and(crate::routing::resources::reference)
            {
                return Err("legacy_route_ruleset_unsupported");
            }
        }
        // Original paths remain blocked until explicitly selected and copied.
        _ => return Err("legacy_route_ruleset_unsupported"),
    }
    Ok(())
}

fn collect(value: &Value, tags: &mut BTreeSet<String>, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err("legacy_route_limit");
    }
    if let Some(rule) = value.as_object() {
        if let Some(value) = rule.get("rule_set") {
            for tag in strings(value)? {
                tags.insert(tag.into());
            }
        }
        if let Some(children) = rule.get("rules") {
            collect(children, tags, depth + 1)?;
        }
    } else if let Some(rules) = value.as_array() {
        for rule in rules {
            collect(rule, tags, depth + 1)?;
        }
    }
    if tags.len() > 1000 {
        return Err("legacy_route_limit");
    }
    Ok(())
}
fn references(value: &Value) -> Result<BTreeSet<String>> {
    let mut tags = BTreeSet::new();
    collect(value, &mut tags, 0)?;
    Ok(tags)
}

pub(super) fn materialize(
    route: &mut Value,
    rules: &[Rule],
    context: rules::Context<'_>,
    db: &SourceDatabase,
    raw: bool,
) -> Result<()> {
    let dns = context.dns;
    let mut needed = BTreeSet::new();
    for rule in rules {
        collect(&rule.config, &mut needed, 0)?;
    }
    if let Some(rules) = dns.get("rules") {
        collect(rules, &mut needed, 0)?;
    }
    let mut sets = vec![];
    let mut names = BTreeSet::new();
    if let Some(existing) = route.get("rule_set") {
        let existing = existing.as_array().ok_or("legacy_route_structure")?;
        if existing.len() > 1000 {
            return Err("legacy_route_limit");
        }
        for value in existing {
            let mut value = value.clone();
            let tag = nonempty(&value["tag"])?.to_owned();
            if !names.insert(tag.clone()) {
                return Err("legacy_route_ruleset_unsupported");
            }
            if raw || needed.contains(&tag) {
                definition(&mut value, context)?;
                sets.push(value);
            }
        }
    }
    for tag in needed {
        if sets.iter().any(|s| s["tag"] == tag) {
            continue;
        }
        if raw {
            return Err("legacy_route_ruleset_unsupported");
        }
        let source = source(db, &tag)?;
        // Use the source identity as tag instead of Qt's process-dependent qHash.
        // Conditions and declarations share it, so the policy is unchanged.
        sets.push(json!({"type":"remote","tag":tag,"format":"binary","url":source}));
    }
    if !sets.is_empty() || route.get("rule_set").is_some() {
        route["rule_set"] = json!(sets);
    }
    Ok(())
}
