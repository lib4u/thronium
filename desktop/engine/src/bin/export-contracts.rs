//! Generate the TypeScript contract and its matching runtime schema from Rust.
use std::{path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match generate() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn generate() -> Result<(), Box<dyn std::error::Error>> {
    let check = std::env::args().skip(1).any(|arg| arg == "--check");
    let desktop = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let registry = thronium_engine::ipc::registry();
    let files = [
        (
            desktop.join("src/shared/api/generated/commands.ts"),
            registry.typescript(),
        ),
        (
            desktop.join("contracts/ipc.generated.json"),
            format!("{}\n", serde_json::to_string(registry)?),
        ),
        (desktop.join("src/shared/api/generated/limits.ts"), limits()),
        (
            desktop.join("src/shared/api/generated/defaults.ts"),
            defaults()?,
        ),
    ];
    for (path, contents) in files {
        if check {
            if std::fs::read_to_string(&path)? != contents {
                return Err(format!("Generated contract is stale: {}", path.display()).into());
            }
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, contents)?;
        }
    }
    Ok(())
}

/// Engine limits the window checks before sending, generated so they never drift.
fn limits() -> String {
    use serde_json::json;
    use thronium_engine::{
        auto_selector, chains, exports, external_core, logs, otp, probes, routing, store,
        subscriptions,
    };
    let seconds = |ms: u64| ms / 1000;
    let values: std::collections::BTreeMap<&str, serde_json::Value> = [
        (
            "autoSelectReuseHoursMax",
            json!(auto_selector::QUICK_MAX_REUSE_TTL_MS / 3_600_000),
        ),
        (
            "autoSelectTimeoutMsMin",
            json!(auto_selector::QUICK_TIMEOUT_MS.start()),
        ),
        (
            "autoSelectTimeoutSecondsMax",
            json!(auto_selector::QUICK_TIMEOUT_MS.end() / 1000),
        ),
        (
            "coreRestartWindowSeconds",
            json!(thronium_engine::CORE_RAPID_EXIT_WINDOW.as_secs()),
        ),
        ("externalPortMax", json!(external_core::PORTS.end())),
        ("externalPortMin", json!(external_core::PORTS.start())),
        ("maxArchiveBytes", json!(exports::MAX_ARCHIVE_BYTES)),
        ("maxBackupBytes", json!(thronium_engine::backups::MAX_BYTES)),
        ("maxBatchProfiles", json!(store::MAX_BATCH_PROFILES)),
        (
            "maxCategoryDatabaseBytes",
            json!(routing::MAX_CATEGORY_DATABASE_BYTES),
        ),
        ("maxChainHops", json!(chains::MAX_HOPS)),
        ("maxConfigBytes", json!(store::MAX_CONFIG_BYTES)),
        ("maxExportBytes", json!(exports::MAX_BYTES)),
        ("maxExternalArgsBytes", json!(external_core::MAX_ARGS_BYTES)),
        (
            "maxExternalConfigBytes",
            json!(external_core::MAX_CONFIG_BYTES),
        ),
        ("maxExternalNameBytes", json!(external_core::MAX_NAME_BYTES)),
        (
            "maxGeodataAssetBytes",
            json!(routing::MAX_GEODATA_ASSET_BYTES),
        ),
        ("maxNameBytes", json!(store::MAX_NAME_BYTES)),
        ("maxOtpCodesPerRequest", json!(otp::MAX_CODES_PER_REQUEST)),
        ("maxOtpEntries", json!(otp::MAX_ENTRIES)),
        ("maxOtpCounterDigits", json!(otp::MAX_COUNTER_DIGITS)),
        ("maxOtpLabelBytes", json!(otp::MAX_LABEL_BYTES)),
        ("maxOtpSecretBytes", json!(otp::MAX_KEY_BYTES)),
        ("maxOtpSecretTextBytes", json!(otp::MAX_SECRET_TEXT)),
        ("maxOtpTextBytes", json!(otp::MAX_TEXT)),
        (
            "maxPatternBytes",
            json!(subscriptions::name_rules::MAX_PATTERN_BYTES),
        ),
        ("maxPoolMembers", json!(auto_selector::MAX_MEMBERS)),
        ("maxPoolCandidates", json!(auto_selector::MAX_CANDIDATES)),
        ("maxLogSearchBytes", json!(logs::MAX_SEARCH_BYTES)),
        ("maxQrImageBytes", json!(exports::MAX_QR_IMAGE_BYTES)),
        (
            "maxQrImageMegapixels",
            json!(exports::MAX_QR_IMAGE_PIXELS / (1024 * 1024)),
        ),
        (
            "maxQueuedSubscriptionUpdates",
            json!(subscriptions::jobs::MAX_JOBS),
        ),
        (
            "maxRenameRules",
            json!(subscriptions::name_rules::MAX_RENAME_RULES),
        ),
        (
            "maxResultValidityMinutes",
            json!(auto_selector::MAX_RESULT_VALIDITY_MINUTES),
        ),
        ("maxRoutingProfileBytes", json!(routing::MAX_PROFILE_BYTES)),
        ("maxRoutingProfiles", json!(routing::MAX_PROFILES)),
        (
            "maxRoutingResourceBytes",
            json!(routing::resources::MAX_FILE_BYTES),
        ),
        (
            "maxRoutingResourcePackBytes",
            json!(routing::resources::MAX_PACK_BYTES),
        ),
        ("maxRoutingResources", json!(routing::resources::MAX_FILES)),
        ("maxRoutingRules", json!(routing::MAX_RULES)),
        ("maxSubscriptionBytes", json!(subscriptions::MAX_BYTES)),
        (
            "maxSubscriptionHeaderBytes",
            json!(subscriptions::MAX_HEADER_BYTES),
        ),
        ("maxSubscriptionHeaders", json!(subscriptions::MAX_HEADERS)),
        (
            "maxSubscriptionIntervalMinutes",
            json!(subscriptions::MAX_INTERVAL_MINUTES),
        ),
        (
            "maxSubscriptionProfiles",
            json!(subscriptions::MAX_PROFILES),
        ),
        (
            "maxSubscriptionUrlBytes",
            json!(subscriptions::MAX_URL_BYTES),
        ),
        (
            "maxSubscriptionUserAgentBytes",
            json!(subscriptions::MAX_USER_AGENT_BYTES),
        ),
        (
            "maxTrayIconBytes",
            json!(thronium_engine::tray_icons::MAX_PNG_BYTES),
        ),
        (
            "maxTrayIconPixels",
            json!(thronium_engine::tray_icons::MAX_SIDE_PIXELS),
        ),
        (
            "maxTunExcludeAddresses",
            json!(thronium_engine::tun::MAX_EXCLUDE_ADDRESSES),
        ),
        ("maxVisibleLogs", json!(logs::MAX_VISIBLE)),
        (
            "maxVpnCredentialBytes",
            json!(thronium_engine::vpn_auth::MAX_TEXT_BYTES),
        ),
        (
            "maxWireguardPeers",
            json!(thronium_engine::legacy_backup::wireguard::MAX_PEERS),
        ),
        (
            "minOtpBareSecretBytes",
            json!(otp::formats::MIN_BARE_SECRET_BYTES),
        ),
        ("otpDigitsMax", json!(otp::DIGITS.end())),
        ("otpDigitsMin", json!(otp::DIGITS.start())),
        ("otpPeriodSecondsMax", json!(otp::PERIOD_SECONDS.end())),
        ("otpPeriodSecondsMin", json!(otp::PERIOD_SECONDS.start())),
        (
            "poolRecheckAttempts",
            json!(auto_selector::RECHECK_ATTEMPTS),
        ),
        (
            "poolRecheckFirstRetrySeconds",
            json!(seconds(auto_selector::RECHECK_FIRST_RETRY_MS)),
        ),
        (
            "poolRecheckGraceSeconds",
            json!(seconds(auto_selector::RECHECK_GRACE_MS)),
        ),
        (
            "poolRecheckSecondRetrySeconds",
            json!(seconds(auto_selector::RECHECK_FIRST_RETRY_MS * 2)),
        ),
        ("probeTimeoutMsMax", json!(probes::TIMEOUT_MS.end())),
        ("probeTimeoutMsMin", json!(probes::TIMEOUT_MS.start())),
        (
            "subscriptionUserAgent",
            json!(subscriptions::DEFAULT_USER_AGENT),
        ),
        ("tunMtuMax", json!(thronium_engine::tun::MTU.end())),
        ("tunMtuMin", json!(thronium_engine::tun::MTU.start())),
        (
            "vpnStatusTimeoutSeconds",
            json!(probes::VPN_STATUS_TIMEOUT_MS / 1000),
        ),
    ]
    .into_iter()
    .collect();
    format!(
        "// Generated from engine constants; change them in Rust.\nexport const limits = {} as const;\n",
        serde_json::to_string_pretty(&values).unwrap_or_default()
    )
}

/// Values a new library starts with, shown until the first snapshot arrives.
fn defaults() -> Result<String, serde_json::Error> {
    let library = thronium_engine::store::Library::default();
    let routing = library
        .routing
        .profiles
        .iter()
        .find(|profile| profile.id == library.routing.active);
    let values = serde_json::json!({
        "geodataProviders": thronium_engine::geodata_assets::PROVIDERS,
        "otp": thronium_engine::otp::Draft::default(),
        "personalGroup": thronium_engine::store::PERSONAL_GROUP,
        "dynamicPool": {
            "buildLimit": thronium_engine::auto_selector::SUGGESTED_BUILD_LIMIT,
            "poolCap": thronium_engine::auto_selector::SUGGESTED_POOL_CAP,
        },
        "poolProfile": thronium_engine::auto_selector::default_pool_config(),
        "testUrl": thronium_engine::probes::DEFAULT_TEST_URL,
        "preferences": library.preferences,
        "groups": library.groups.iter().map(|g| serde_json::json!({"id": g.id, "name": g.name})).collect::<Vec<_>>(),
        "routing": routing.map(|profile| serde_json::json!({"active": profile.id, "name": profile.name, "mode": profile.mode})),
        "routingProfile": thronium_engine::routing::RoutingProfile::default(),
    });
    Ok(format!(
        "// Generated from engine defaults; change them in Rust.\nexport const defaults = {} as const;\n",
        serde_json::to_string_pretty(&values)?
    ))
}
