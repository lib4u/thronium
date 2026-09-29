mod backups;
mod connection;
mod diagnostics;
mod library;
mod otp;
mod routing;
mod settings;
mod subscriptions;
use crate::Shared;
use serde_json::Value;
use std::sync::atomic::Ordering;
use tauri::State;
#[tauri::command]
pub(crate) async fn app_command(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: tauri::AppHandle,
) -> Result<Value, thronium_engine::ipc::BoundaryError> {
    let registry = thronium_engine::ipc::registry();
    let command = registry.request(&name, &payload)?;
    let value = dispatch_command(name, payload, state, app)
        .await
        .map_err(|error| thronium_engine::ipc::BoundaryError::legacy(&error))?;
    command
        .response
        .validate(&value, &registry.definitions)
        .map_err(|field| thronium_engine::ipc::BoundaryError {
            field: Some(field),
            ..thronium_engine::ipc::BoundaryError::code("invalid_command_response")
        })?;
    Ok(value)
}

async fn dispatch_command(
    name: String,
    payload: Value,
    state: State<'_, Shared>,
    app: tauri::AppHandle,
) -> Result<Value, String> {
    if state.quitting.load(Ordering::SeqCst) {
        return Err("app_quitting".into());
    }
    match name.as_str() {
        "loadGeodata" | "fetchRoutingSource" | "refreshRoutingSource" | "cancelRoutingDownload" => {
            return crate::routing_downloads::run(&app, &name, payload).await
        }
        "storageLocation"
        | "dashboardStatus"
        | "installDashboard"
        | "cancelDashboardInstallation"
        | "openDashboard"
        | "windowBehavior"
        | "takeSettingsLink"
        | "quitApp"
        | "windowSnapLayouts"
        | "windowSystemMenu"
        | "chooseExternalCorePath"
        | "registerWarp"
        | "cancelWarpRegistration"
        | "openWarpTerms"
        | "checkUpstreamRelease" => return settings::unlocked(name, payload, state, app).await,
        "xrayGeodataStatus"
        | "xrayGeodataSources"
        | "downloadXrayGeodata"
        | "cancelXrayGeodataDownload" => return routing::unlocked(name, payload, state, app).await,
        "processMetrics" | "getLogs" | "clearLogs" | "exportLogs" | "startUrlTests"
        | "startPing" | "startIpTests" | "startSpeedTests" | "testSpeed" | "testIp"
        | "testInternet" | "cancelSettingsTest" => {
            return diagnostics::unlocked(name, payload, state, app).await
        }
        "resolveProfileAddresses"
        | "readClipboard"
        | "decodeQrImage"
        | "readQrClipboard"
        | "scanScreenQr"
        | "writeClipboard"
        | "exportQr"
        | "exportArchive"
        | "exportSharedText"
        | "exportConfiguration"
        | "exportProfiles" => return library::unlocked(name, payload, state, app).await,
        "exportBackup" | "readBackup" | "chooseLegacyResource" => {
            return backups::unlocked(name, payload, state, app).await
        }
        "cancelSubscription"
        | "cancelSubscriptionUpdates"
        | "releaseSubscriptionWorker"
        | "checkSubscriptionJob"
        | "fetchSubscription"
        | "fetchSubscriptionJob" => {
            return subscriptions::unlocked(name, payload, state, app).await
        }
        "openVpnChallengeUrl"
        | "cancelConnectionPreparation"
        | "applyRouting"
        | "connect"
        | "disconnect" => return connection::unlocked(name, payload, state, app).await,
        _ => {}
    }
    let mut deferred = crate::geodata_deferral::Deferred::new(&state);
    loop {
        let mut guard = deferred.lock().await?;
        let engine = guard.as_mut().map_err(|e| e.clone())?;
        let result = locked(&name, payload.clone(), engine, &app).await;
        if let Some(result) = deferred.finish(guard, result).await {
            return result;
        }
    }
}

async fn locked(
    name: &str,
    payload: Value,
    engine: &mut thronium_engine::Engine,
    app: &tauri::AppHandle,
) -> Result<Value, String> {
    match name {
        "otpList" | "getVpnOtpBinding" | "saveVpnOtpBinding" | "otpGet" | "otpSave"
        | "otpRemove" | "otpReorder" | "otpCodes" | "otpImport" | "otpExport" => {
            otp::locked(name, payload, engine).await
        }
        "settings"
        | "saveSettings"
        | "preferences"
        | "saveWindowSettings"
        | "saveAutoSelectSettings"
        | "setVlessCore"
        | "connectionSettings"
        | "savePingSettings" => settings::locked(name, payload, engine, app).await,
        "trafficHistory"
        | "trafficStats"
        | "clearTrafficHistory"
        | "getMeasurementJournal"
        | "clearMeasurementJournal"
        | "getSwitchHistory"
        | "clearSwitchHistory"
        | "cancelUrlTests"
        | "clearUrlTests"
        | "cancelUrlTestBatch"
        | "closeConnections" => diagnostics::locked(name, payload, engine).await,
        "backupStatus"
        | "previewPreviousBackup"
        | "refreshBackupPreview"
        | "legacyBackupScopes"
        | "discardBackupPreview"
        | "restoreBackup" => backups::locked(name, payload, engine, app).await,
        "deleteProfiles"
        | "maintenanceCandidates"
        | "resetProfileTraffic"
        | "moveProfiles"
        | "group"
        | "collapseGroup"
        | "saveGroup"
        | "moveGroup"
        | "reorderGroup"
        | "reorderProfile"
        | "deleteGroup"
        | "profile"
        | "saveProfile"
        | "saveProfileConfiguration"
        | "saveProfileCore"
        | "previewDuplicates"
        | "removeDuplicates"
        | "discardDuplicates"
        | "importProfiles"
        | "checkImportProfile"
        | "checkProfile"
        | "select"
        | "favorite"
        | "delete"
        | "generateWgKeys"
        | "addGroup" => library::locked(name, payload, engine).await,
        "startSubscriptionUpdates"
        | "claimSubscriptionJob"
        | "prepareSubscriptionJob"
        | "applySubscriptionJob"
        | "failSubscriptionJob"
        | "clearSubscriptionJobs"
        | "checkSubscriptionProfile"
        | "previewSubscription"
        | "applySubscription"
        | "discardSubscription" => subscriptions::locked(name, payload, engine).await,
        "routing"
        | "geodataSources"
        | "geodataCategory"
        | "exportRoutingProfile"
        | "importThroneRoute"
        | "getAutoSelectors"
        | "getSelectorHistory"
        | "clearSelectorHistory"
        | "previewSelector"
        | "rankSelector"
        | "planSelectorMeasurements"
        | "rankMeasuredSelector"
        | "autoSelectorAction"
        | "saveRouting"
        | "subscriptionRouting"
        | "useSubscriptionRouting"
        | "checkRouting" => routing::locked(name, payload, engine).await,
        "snapshot"
        | "vpnChallenge"
        | "vpnChallengeUrl"
        | "vpnCredentials"
        | "restartVpnCredentials"
        | "cancelVpnCredentials"
        | "submitVpnChallenge"
        | "cancelVpnChallenge"
        | "connectionConfiguration"
        | "disconnect"
        | "restoreSystemProxy" => connection::locked(name, payload, engine, app).await,
        _ => Err("unknown_command".into()),
    }
}
