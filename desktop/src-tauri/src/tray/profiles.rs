//! Menus contain only display names and opaque action IDs, never configurations.
use super::Tray;
use crate::localization::{text as localized, TextKey};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use tauri::{
    menu::{CheckMenuItem, MenuItem, Submenu},
    AppHandle,
};
use thronium_engine::store::Library;

const PAGE: usize = 50;

#[derive(Default, PartialEq, Eq)]
pub(super) struct View {
    groups: Vec<Group>,
    active: Option<String>,
}
#[derive(PartialEq, Eq)]
struct Group {
    name: String,
    personal: bool,
    profiles: Vec<Profile>,
}
#[derive(PartialEq, Eq)]
struct Profile {
    id: String,
    name: String,
    favorite: bool,
}

fn label(name: &str) -> String {
    let mut chars = name.chars().filter(|c| !c.is_control());
    let mut text: String = chars.by_ref().take(64).collect();
    if chars.next().is_some() {
        text.push('…');
    }
    text.replace('&', "&&")
}

impl View {
    pub(super) fn new(library: &Library, running: Option<&str>) -> Self {
        let mut members: HashMap<&str, Vec<Profile>> = HashMap::new();
        for p in &library.profiles {
            members.entry(&p.group_id).or_default().push(Profile {
                id: p.id.clone(),
                name: label(&p.name),
                favorite: p.favorite,
            });
        }
        Self {
            groups: library
                .groups
                .iter()
                .map(|g| Group {
                    name: label(g.display_name()),
                    personal: g.id == thronium_engine::store::PERSONAL_GROUP,
                    profiles: members.remove(g.id.as_str()).unwrap_or_default(),
                })
                .collect(),
            active: running.or(library.selected.as_deref()).map(str::to_owned),
        }
    }
}

struct Builder<'a> {
    app: &'a AppHandle,
    view: &'a View,
    language: crate::localization::Language,
    enabled: bool,
    generation: u64,
    index: usize,
    targets: HashMap<String, String>,
}
impl Builder<'_> {
    fn id(&mut self, prefix: &str) -> String {
        self.index += 1;
        format!("tray-{prefix}-{}-{}", self.generation, self.index)
    }
    fn profiles(&mut self, menu: &Submenu<tauri::Wry>, profiles: &[&Profile]) -> tauri::Result<()> {
        if profiles.is_empty() {
            menu.append(&MenuItem::with_id(
                self.app,
                self.id("empty"),
                localized(self.language, TextKey::NoServersDa4c36b),
                false,
                None::<&str>,
            )?)?;
        }
        for (page, rows) in profiles.chunks(PAGE).enumerate() {
            let target = if profiles.len() > PAGE {
                let sub = Submenu::with_id(
                    self.app,
                    self.id("page"),
                    format!("{}–{}", page * PAGE + 1, page * PAGE + rows.len()),
                    true,
                )?;
                menu.append(&sub)?;
                sub
            } else {
                menu.clone()
            };
            for profile in rows {
                let id = self.id("profile");
                self.targets.insert(id.clone(), profile.id.clone());
                target.append(&CheckMenuItem::with_id(
                    self.app,
                    id,
                    &profile.name,
                    self.enabled,
                    self.view.active.as_deref() == Some(&profile.id),
                    None::<&str>,
                )?)?;
            }
        }
        Ok(())
    }
}

pub(super) fn update(
    app: &AppHandle,
    tray: &Tray,
    view: &View,
    language: crate::localization::Language,
    enabled: bool,
) -> tauri::Result<()> {
    let generation = tray.generation.fetch_add(1, Ordering::SeqCst);
    // Build the replacement before changing the live menu. Only successful
    // replacements publish their action map, so stale native events are ignored.
    let mut build = Builder {
        app,
        view,
        language,
        enabled,
        generation,
        index: 0,
        targets: HashMap::new(),
    };
    let mut menus = Vec::new();
    let favorites: Vec<_> = view
        .groups
        .iter()
        .flat_map(|g| &g.profiles)
        .filter(|p| p.favorite)
        .collect();
    if !favorites.is_empty() {
        let menu = Submenu::with_id(
            app,
            build.id("favorites"),
            localized(language, TextKey::Favorites3fcf8bf),
            true,
        )?;
        build.profiles(&menu, &favorites)?;
        menus.push(menu);
    }
    for (page, groups) in view.groups.chunks(PAGE).enumerate() {
        let page_menu = if view.groups.len() > PAGE {
            Some(Submenu::with_id(
                app,
                build.id("groups"),
                format!(
                    "{} {}–{}",
                    localized(language, TextKey::Groups6af1c99),
                    page * PAGE + 1,
                    page * PAGE + groups.len()
                ),
                true,
            )?)
        } else {
            None
        };
        for group in groups {
            let name = if group.personal {
                localized(language, TextKey::Personal09c5ff5)
            } else {
                &group.name
            };
            let menu = Submenu::with_id(
                app,
                build.id("group"),
                format!("{name} ({})", group.profiles.len()),
                true,
            )?;
            build.profiles(&menu, &group.profiles.iter().collect::<Vec<_>>())?;
            if let Some(page_menu) = &page_menu {
                page_menu.append(&menu)?;
            } else {
                menus.push(menu);
            }
        }
        if let Some(page_menu) = page_menu {
            menus.push(page_menu);
        }
    }
    tray.targets.lock().unwrap().clear();
    while tray.servers.remove_at(0)?.is_some() {}
    for menu in menus {
        tray.servers.append(&menu)?;
    }
    tray.servers
        .set_text(localized(language, TextKey::ConnectToServer87401c4))?;
    tray.servers
        .set_enabled(enabled && view.groups.iter().any(|g| !g.profiles.is_empty()))?;
    *tray.targets.lock().unwrap() = build.targets;
    Ok(())
}
