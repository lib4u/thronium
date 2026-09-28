use serde_json::Value;
use thronium_engine::Engine;
pub(super) async fn locked(
    name: &str,
    payload: Value,
    engine: &mut Engine,
) -> Result<Value, String> {
    let id = payload.get("id").and_then(Value::as_str).unwrap_or("");
    match name {
        "otpList" => Ok(engine.otp_list()),
        "getVpnOtpBinding" => {
            let profile_id = payload["profileId"]
                .as_str()
                .ok_or("vpn_otp_binding_invalid")?;
            serde_json::to_value(engine.get_vpn_otp_binding(profile_id)?)
                .map_err(|_| "vpn_otp_binding_invalid".into())
        }
        "saveVpnOtpBinding" => {
            let request = serde_json::from_value(payload).map_err(|_| "vpn_otp_binding_invalid")?;
            serde_json::to_value(engine.save_vpn_otp_binding(request)?)
                .map_err(|_| "vpn_otp_binding_invalid".into())
        }
        "otpGet" => engine.otp_get(id),
        "otpSave" => engine.otp_save(
            id,
            payload["revision"].as_str().unwrap_or(""),
            serde_json::from_value(payload["value"].clone()).map_err(|_| "otp_invalid_entry")?,
        ),
        "otpRemove" => {
            engine.otp_remove(id, payload["revision"].as_str().unwrap_or(""))?;
            Ok(Value::Null)
        }
        "otpReorder" => {
            engine.otp_reorder(
                &serde_json::from_value::<Vec<String>>(payload["previous"].clone())
                    .map_err(|_| "otp_invalid_order")?,
                &serde_json::from_value::<Vec<String>>(payload["ids"].clone())
                    .map_err(|_| "otp_invalid_order")?,
            )?;
            Ok(Value::Null)
        }
        "otpCodes" => engine.otp_codes(
            &serde_json::from_value::<Vec<String>>(payload["ids"].clone())
                .map_err(|_| "otp_invalid_entry")?,
        ),
        "otpImport" => engine.otp_import(payload["text"].as_str().ok_or("otp_import_invalid")?),
        "otpExport" => engine
            .otp_export(
                &serde_json::from_value::<Vec<String>>(payload["ids"].clone())
                    .map_err(|_| "otp_invalid_entry")?,
                payload["format"].as_str().unwrap_or(""),
            )
            .map(Value::String),
        _ => Err("unknown_command".into()),
    }
}
