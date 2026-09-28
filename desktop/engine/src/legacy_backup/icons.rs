//! Only the six Qt status PNGs have a runtime meaning. No archive path is extracted.
use super::{profiles::Issue, SourceArchive};
use crate::tray_icons::{Icon, Pack, Status};

#[derive(Clone)]
pub struct Plan {
    pub icons: Pack,
    pub report: Vec<Issue>,
}
fn issue(code: &str) -> Issue {
    Issue {
        code: code.into(),
        entity: Some("icons".into()),
        source_id: None,
        name: None,
    }
}
pub fn convert(source: &SourceArchive) -> Result<Plan, Vec<Issue>> {
    if !source.parts.icons {
        return Err(vec![issue("legacy_icons_part_missing")]);
    }
    let mut plan = Plan {
        icons: Pack::default(),
        report: vec![],
    };
    let mut errors = vec![];
    for (path, bytes) in source
        .files
        .iter()
        .filter(|(path, _)| path.starts_with("icons/"))
    {
        let Some(status) = Status::from_archive_path(path) else {
            // Preserve an explicit notice about non-status assets, without
            // exposing arbitrary filenames from an untrusted archive.
            if !plan.report.iter().any(|i| i.code == "legacy_icons_unused") {
                plan.report.push(issue("legacy_icons_unused"));
            }
            continue;
        };
        match bytes
            .as_deref()
            .ok_or("invalid_tray_icon")
            .and_then(Icon::from_png)
        {
            Ok(icon) => plan.icons.insert(status, icon),
            Err(_) => errors.push(issue("legacy_icons_invalid")),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    if plan.icons.is_empty() {
        return Err(vec![issue("legacy_icons_empty")]);
    }
    Ok(plan)
}
