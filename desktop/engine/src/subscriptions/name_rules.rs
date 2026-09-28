//! Name rules are applied once to provider names, before reconciliation.
use crate::store::Profile;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NameRules {
    #[serde(default)]
    pub include: String,
    #[serde(default)]
    pub exclude: String,
    #[serde(default)]
    pub rename: Vec<Rename>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    pub pattern: String,
    pub replacement: String,
}
struct Compiled {
    include: Option<Regex>,
    exclude: Option<Regex>,
    rename: Vec<(Regex, String)>,
}
/// Longest name filter or rename pattern.
pub const MAX_PATTERN_BYTES: usize = 2048;
fn pattern(value: &str) -> Result<Option<Regex>, String> {
    if value.len() > MAX_PATTERN_BYTES {
        return Err("subscription_invalid_name_rules".into());
    }
    if value.is_empty() {
        return Ok(None);
    }
    RegexBuilder::new(value)
        .size_limit(2 * 1024 * 1024)
        .build()
        .map(Some)
        .map_err(|_| "subscription_invalid_name_rules".into())
}
/// Most rename rules one subscription applies.
pub const MAX_RENAME_RULES: usize = 16;
impl NameRules {
    fn compile(&self) -> Result<Compiled, String> {
        if self.rename.len() > MAX_RENAME_RULES {
            return Err("subscription_invalid_name_rules".into());
        }
        let rename = self
            .rename
            .iter()
            .map(|r| {
                if r.replacement.len() > crate::store::MAX_NAME_BYTES {
                    return Err("subscription_invalid_name_rules".into());
                }
                Ok((
                    pattern(&r.pattern)?.ok_or("subscription_invalid_name_rules")?,
                    r.replacement.clone(),
                ))
            })
            .collect::<Result<_, String>>()?;
        Ok(Compiled {
            include: pattern(&self.include)?,
            exclude: pattern(&self.exclude)?,
            rename,
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        self.compile().map(|_| ())
    }
    pub fn apply(&self, profiles: Vec<Profile>) -> Result<Vec<Profile>, String> {
        let rules = self.compile()?;
        let mut result = Vec::new();
        for mut profile in profiles {
            if rules
                .include
                .as_ref()
                .is_some_and(|r| !r.is_match(&profile.name))
                || rules
                    .exclude
                    .as_ref()
                    .is_some_and(|r| r.is_match(&profile.name))
            {
                continue;
            }
            for (pattern, replacement) in &rules.rename {
                profile.name = pattern
                    .replace_all(&profile.name, replacement.as_str())
                    .into_owned();
                if profile.name.len() > crate::store::MAX_NAME_BYTES {
                    return Err("subscription_invalid_renamed_name".into());
                }
            }
            profile.name = profile.name.trim().to_owned();
            if profile.name.is_empty() {
                return Err("subscription_invalid_renamed_name".into());
            }
            result.push(profile);
        }
        // An accidental typo must not turn an update into deletion of the collection.
        if result.is_empty() {
            return Err("subscription_filtered_empty".into());
        }
        Ok(result)
    }
}
