use crate::{geodata_assets, Shared};
use serde_json::Value;
use tauri::AppHandle;
use tauri::State;
use thronium_engine::Engine;
pub(super) async fn unlocked(
    name: String,
    payload: Value,
    _state: State<'_, Shared>,
    app: AppHandle,
) -> Result<Value, String> {
    if matches!(
        name.as_str(),
        "xrayGeodataStatus"
            | "xrayGeodataSources"
            | "downloadXrayGeodata"
            | "cancelXrayGeodataDownload"
    ) {
        return geodata_assets::run(&app, &name, &payload).await;
    }
    Err("unknown_command".into())
}

pub(super) async fn locked(
    name: &str,
    payload: Value,
    engine: &mut Engine,
) -> Result<Value, String> {
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    match name {
        "routing" => serde_json::to_value(engine.routing())
            .map_err(|_| "invalid_command_response".to_owned()),
        "geodataSources" => engine.geodata_sources(),
        "geodataCategory" => engine.geodata_category(payload),
        "exportRoutingProfile" => engine.export_routing_profile(id),
        "importThroneRoute" => serde_json::to_value(engine.import_throne_route(
            payload["text"].as_str().unwrap_or(""),
            payload["name"].as_str().unwrap_or(""),
            payload["url"].as_str(),
        )?)
        .map_err(|_| "invalid_command_response".to_owned()),
        "getAutoSelectors" => engine.auto_selectors().await,
        "getSelectorHistory" => Ok(engine.selector_history()),
        "clearSelectorHistory" => {
            engine.clear_selector_history(id)?;
            Ok(Value::Null)
        }
        "previewSelector" => engine.preview_selector(
            serde_json::from_value(payload["profile"].clone())
                .map_err(|_| "invalid_selector_source")?,
        ),
        "rankSelector" => engine.rank_selector(
            serde_json::from_value(payload["profile"].clone())
                .map_err(|_| "invalid_selector_source")?,
        ),
        "planSelectorMeasurements" => engine.plan_selector_measurements(
            serde_json::from_value(payload["profile"].clone())
                .map_err(|_| "invalid_selector_source")?,
        ),
        "rankMeasuredSelector" => engine.rank_measured_selector(
            serde_json::from_value(payload["profile"].clone())
                .map_err(|_| "invalid_selector_source")?,
            payload["context"].as_str().unwrap_or(""),
        ),
        "autoSelectorAction" => {
            engine
                .auto_selector_action(
                    payload["tag"].as_str().unwrap_or(""),
                    payload["action"].as_str().unwrap_or(""),
                    payload["member"].as_str().unwrap_or(""),
                )
                .await?;
            Ok(Value::Null)
        }
        "saveRouting" => {
            let routing = serde_json::from_value(payload).map_err(|_| "invalid_routing")?;
            serde_json::to_value(engine.save_routing(routing)?)
                .map_err(|_| "invalid_command_response".to_owned())
        }
        "subscriptionRouting" => {
            engine.subscription_routing(payload["groupId"].as_str().unwrap_or(""))
        }
        "useSubscriptionRouting" => serde_json::to_value(engine.use_subscription_routing(
            payload["revision"].as_u64().ok_or("invalid_routing")?,
            payload["keptName"].as_str().unwrap_or(""),
        )?)
        .map_err(|_| "invalid_command_response".to_owned()),
        "checkRouting" => {
            let routing = serde_json::from_value(payload).map_err(|_| "invalid_routing")?;
            engine.check_routing(routing).await?;
            Ok(Value::Null)
        }
        _ => Err("unknown_command".into()),
    }
}
