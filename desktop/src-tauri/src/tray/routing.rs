//! Routing choices use the same saved revision and validated reconnect as the editor.
use super::{show, Tray};
use crate::localization::{text as localized, TextKey};
use crate::{Ordering, Shared};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tauri::{
    menu::{CheckMenuItem, MenuItem, PredefinedMenuItem, Submenu},
    AppHandle, Emitter, Manager,
};
use tauri_plugin_dialog::DialogExt;
use thronium_engine::routing::Routing;

#[derive(Clone, Default, PartialEq, Eq)]
struct Context {
    revision: u64,
    active: String,
    connection: Option<String>,
    running: bool,
    owned: bool,
    provider_owned: bool,
    intercept_hash: [u8; 32],
}
#[derive(Default, PartialEq, Eq)]
pub(super) struct View {
    context: Context,
    profiles: Vec<(String, String)>,
    name: String,
    mode: String,
    pending: bool,
    adblock: bool,
    warp: bool,
}
fn label(name: &str) -> String {
    let mut chars = name.chars().filter(|c| !c.is_control());
    let mut result: String = chars.by_ref().take(64).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result.replace('&', "&&")
}
impl View {
    pub(super) fn new(
        routing: &Routing,
        status: &Value,
        running: Option<&str>,
        selected: Option<&str>,
    ) -> Self {
        let active = routing.active().ok();
        Self {
            context: Context {
                revision: routing.revision,
                active: routing.active.clone(),
                connection: running.or(selected).map(str::to_owned),
                running: running.is_some(),
                owned: status["profileOwned"].as_bool().unwrap_or(false),
                provider_owned: status["providerOwned"].as_bool().unwrap_or(false),
                intercept_hash: [0; 32],
            },
            profiles: routing
                .profiles
                .iter()
                .map(|p| (p.id.clone(), label(&p.name)))
                .collect(),
            name: active.map(|p| label(&p.name)).unwrap_or_default(),
            mode: active.map(|p| p.mode.clone()).unwrap_or_default(),
            pending: status["pending"].as_bool().unwrap_or(false),
            adblock: false,
            warp: false,
        }
    }
    pub(super) fn with_intercept(mut self, settings: &Value) -> Self {
        // Only a digest belongs in menu targets. The section also contains WARP
        // keys, which must never appear in native menu properties or labels.
        self.context.intercept_hash = Sha256::digest(settings.to_string().as_bytes()).into();
        self.adblock = settings["adblock_enable"].as_bool().unwrap_or(false);
        self.warp = settings["enable_warp"].as_bool().unwrap_or(false);
        self
    }
    fn editable(&self) -> bool {
        !self.context.owned && !self.context.provider_owned && !self.profiles.is_empty()
    }
    fn target(&self, choice: Choice) -> Target {
        Target {
            context: self.context.clone(),
            choice,
        }
    }
}
#[derive(Clone)]
enum Choice {
    Profile(String),
    Mode(&'static str),
    Apply,
    Setting(&'static str, bool),
}
#[derive(Clone)]
pub(super) struct Target {
    context: Context,
    choice: Choice,
}
impl Target {
    fn valid(&self, view: &View) -> bool {
        view.editable() && self.context == view.context
    }
    fn candidate(&self, routing: &Routing) -> Option<Routing> {
        let mut next = routing.clone();
        match &self.choice {
            Choice::Profile(id) => {
                if id == &routing.active || !routing.profiles.iter().any(|p| &p.id == id) {
                    return None;
                }
                next.active = id.clone();
            }
            Choice::Mode(mode) => {
                let active = next.profiles.iter_mut().find(|p| p.id == next.active)?;
                if active.mode == *mode {
                    return None;
                }
                active.mode = (*mode).into();
            }
            Choice::Apply | Choice::Setting(..) => return None,
        }
        Some(next)
    }
    fn settings_candidate(&self, settings: &Value) -> Option<Value> {
        let Choice::Setting(key @ ("adblock_enable" | "enable_warp"), desired) = self.choice else {
            return None;
        };
        if settings[key].as_bool() == Some(desired) {
            return None;
        }
        let mut next = settings.clone();
        next[key] = Value::Bool(desired);
        Some(next)
    }
}
fn mode_name(mode: &str, language: crate::localization::Language) -> &'static str {
    match mode {
        "all" => localized(language, TextKey::AllTrafficThroughProxy0c33426),
        "direct" => localized(language, TextKey::DirectConnection17b0c96),
        _ => localized(language, TextKey::Rules3ec0bc7),
    }
}
pub(super) fn update(
    app: &AppHandle,
    tray: &Tray,
    view: &View,
    language: crate::localization::Language,
    idle: bool,
    available: bool,
) -> tauri::Result<()> {
    let text = |key| localized(language, key);
    let generation = tray.generation.fetch_add(1, Ordering::SeqCst);
    let mut index = 0;
    let mut id = |action: bool| {
        index += 1;
        format!(
            "tray-route-{}-{generation}-{index}",
            if action { "action" } else { "label" }
        )
    };
    let enabled = idle && view.editable() && (!view.context.running || available);
    let mut targets = HashMap::new();
    let profile_menu =
        Submenu::with_id(app, id(false), text(TextKey::SavedProfile59172eb), enabled)?;
    for (page, profiles) in view.profiles.chunks(50).enumerate() {
        let menu = if view.profiles.len() > 50 {
            let menu = Submenu::with_id(
                app,
                id(false),
                format!("{}–{}", page * 50 + 1, page * 50 + profiles.len()),
                enabled,
            )?;
            profile_menu.append(&menu)?;
            menu
        } else {
            profile_menu.clone()
        };
        for (profile, name) in profiles {
            let action = id(true);
            if enabled {
                targets.insert(
                    action.clone(),
                    view.target(Choice::Profile(profile.clone())),
                );
            }
            menu.append(&CheckMenuItem::with_id(
                app,
                action,
                name,
                enabled,
                profile == &view.context.active,
                None::<&str>,
            )?)?;
        }
    }
    let mode_menu = Submenu::with_id(app, id(false), text(TextKey::SavedMode6858c31), enabled)?;
    for mode in ["rules", "all", "direct"] {
        let action = id(true);
        if enabled {
            targets.insert(action.clone(), view.target(Choice::Mode(mode)));
        }
        mode_menu.append(&CheckMenuItem::with_id(
            app,
            action,
            mode_name(mode, language),
            enabled,
            view.mode == mode,
            None::<&str>,
        )?)?;
    }
    let status = if view.context.owned {
        text(TextKey::FullConfigurationControlsRoutingF940dbc)
    } else if view.context.provider_owned {
        text(TextKey::SubscriptionControlsRoutingD0cc60c)
    } else if !view.context.running {
        text(TextKey::SavedForNextConnection24dc1bb)
    } else if view.pending {
        text(TextKey::SavedChangesAreNotAppliedCd58464)
    } else {
        text(TextKey::SavedRoutingIsAppliedB34e688)
    };
    let status = MenuItem::with_id(app, id(false), status, false, None::<&str>)?;
    let summary = MenuItem::with_id(
        app,
        id(false),
        format!(
            "{}: {} · {}",
            text(TextKey::SavedC2b7708),
            view.name,
            mode_name(&view.mode, language)
        ),
        false,
        None::<&str>,
    )?;
    let hint = if !view.editable() {
        Some(MenuItem::with_id(
            app,
            id(false),
            text(TextKey::ChangePolicyInRoutingSettings84336e9),
            false,
            None::<&str>,
        )?)
    } else {
        None
    };
    let apply_id = id(true);
    let can_apply = enabled && view.context.running && view.pending;
    if can_apply {
        targets.insert(apply_id.clone(), view.target(Choice::Apply));
    }
    let apply = MenuItem::with_id(
        app,
        apply_id,
        text(TextKey::ApplySavedChanges68db303),
        can_apply,
        None::<&str>,
    )?;
    // Publish new opaque IDs only after the complete native menu is installed.
    tray.route_targets.lock().unwrap().clear();
    while tray.routing.remove_at(0)?.is_some() {}
    tray.routing.append(&status)?;
    tray.routing.append(&summary)?;
    if let Some(hint) = hint {
        tray.routing.append(&hint)?;
    }
    tray.routing.append(&PredefinedMenuItem::separator(app)?)?;
    tray.routing.append(&profile_menu)?;
    tray.routing.append(&mode_menu)?;
    for (key, checked, title) in [
        (
            "adblock_enable",
            view.adblock,
            TextKey::BlockAdvertisements7303abe,
        ),
        (
            "enable_warp",
            view.warp,
            TextKey::WarpThroughTheSelectedServerB4d86c9,
        ),
    ] {
        let action = id(true);
        if enabled {
            targets.insert(action.clone(), view.target(Choice::Setting(key, !checked)));
        }
        tray.routing.append(&CheckMenuItem::with_id(
            app,
            action,
            text(title),
            enabled,
            checked,
            None::<&str>,
        )?)?;
    }
    tray.routing.append(&apply)?;
    let catalog = Submenu::with_id(
        app,
        "tray-route-catalog",
        text(TextKey::LoadProfile6dd7d64),
        idle,
    )?;
    for (country, title) in [
        ("Russia", TextKey::RussiaEd6c98e),
        ("China", TextKey::ChinaB2aa98d),
        ("Iran", TextKey::Iran0aec67d),
    ] {
        catalog.append(&MenuItem::with_id(
            app,
            format!("tray-route-catalog-{country}"),
            text(title),
            idle,
            None::<&str>,
        )?)?;
    }
    tray.routing.append(&PredefinedMenuItem::separator(app)?)?;
    tray.routing.append(&catalog)?;
    tray.routing.set_text(text(TextKey::Routing3247b97))?;
    tray.routing.set_enabled(!view.profiles.is_empty())?;
    *tray.route_targets.lock().unwrap() = targets;
    Ok(())
}

pub(super) fn open_catalog(app: &AppHandle, id: &str) {
    let Some(country @ ("Russia" | "China" | "Iran")) = id.strip_prefix("tray-route-catalog-")
    else {
        return;
    };
    if app.state::<Tray>().busy.load(Ordering::SeqCst) {
        return;
    }
    // Navigation only: the existing importer owns download, preview, validation
    // and saving. Opening the catalog must not replace the active connection.
    show(app);
    let _ = app.emit_to("main", "routing-import-open", country);
}

pub(super) fn action(app: &AppHandle, id: &str) {
    let target = app
        .state::<Tray>()
        .route_targets
        .lock()
        .unwrap()
        .get(id)
        .cloned();
    let Some(target) = target else {
        return;
    };
    if app.state::<Tray>().busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let setting_action = matches!(target.choice, Choice::Setting(..));
        let result = async {
            let shared = app.state::<Shared>();
            let mut deferred = crate::geodata_deferral::Deferred::new(&shared);
            let apply = loop {
                let Ok(mut guard) = deferred.lock().await else {
                    return Ok(());
                };
                let engine = guard.as_mut().map_err(|_| false)?;
                let snapshot = engine.snapshot();
                let current = engine.routing();
                let intercept =
                    thronium_engine::settings::section(&engine.store.library, "intercept");
                let view = View::new(
                    &current,
                    &snapshot.routing,
                    snapshot.running.as_deref(),
                    snapshot.selected.as_deref(),
                )
                .with_intercept(&intercept);
                // Menu freshness alone is insufficient: a save, delete, server switch,
                // or policy-ownership change can occur before the one-second refresh.
                if !target.valid(&view) {
                    return Ok(());
                }
                let saved = if let Some(next) = target.settings_candidate(&intercept) {
                    engine
                        .save_settings("intercept", intercept, next)
                        .await
                        .map(|_| snapshot.running.is_some())
                } else if let Some(next) = target.candidate(&current) {
                    engine
                        .save_routing(next)
                        .map(|_| snapshot.running.is_some())
                } else {
                    Ok(matches!(target.choice, Choice::Apply)
                        && view.pending
                        && snapshot.running.is_some())
                };
                // URL workers need Engine between polls; keep the same coordinator
                // as window Apply and Connect without retaining this menu guard.
                if let Some(saved) = deferred.finish(guard, saved).await {
                    break saved.map_err(|_| false)?;
                }
            };
            if apply {
                crate::connection_preflight::apply_routing(&app)
                    .await
                    .map_err(|_| true)?;
            }
            Ok::<(), bool>(())
        }
        .await;
        app.state::<Tray>().busy.store(false, Ordering::SeqCst);
        // Native check items toggle even when a stale/no-op event is discarded.
        app.state::<Tray>().refresh.store(true, Ordering::SeqCst);
        if let Err(saved) = result {
            let shared = app.state::<Shared>();
            if shared.quitting.load(Ordering::SeqCst) {
                return;
            }
            shared.logs.event(
                "error",
                if saved {
                    "tray_routing_apply_failed"
                } else {
                    "tray_routing_save_failed"
                },
                None,
            );
            let language = crate::localization::Language::of(&*shared.engine.lock().await);
            show(&app);
            app.dialog()
                .message(if setting_action {
                    match saved {
                        true => localized(
                            language,
                            TextKey::TheSettingWasSavedButCouldNotBeAppliedC499e90e,
                        ),
                        false => localized(
                            language,
                            TextKey::CouldNotSaveThisSettingCheckTheAdblockWa9daf1aa,
                        ),
                    }
                } else {
                    match saved {
                        true => localized(
                            language,
                            TextKey::RoutingWasSavedButCouldNotBeAppliedCheck1d63565,
                        ),
                        false => localized(
                            language,
                            TextKey::CouldNotSaveRoutingTryAgainInRoutingSettAc73861,
                        ),
                    }
                })
                .title("Thronium")
                .show(|_| {});
        }
    });
}

#[cfg(test)]
mod tests;
