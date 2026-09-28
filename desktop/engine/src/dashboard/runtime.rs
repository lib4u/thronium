use super::files::{Assets, Receipt};
use crate::{
    proto, settings,
    store::{Library, Profile, ProfileKind},
    Engine,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{net::IpAddr, path::Path};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub installed: Option<Receipt>,
    pub can_open: bool,
    pub can_install: bool,
    pub reason: Option<String>,
    pub settings_enabled: bool,
}
struct Listener {
    host: String,
    port: u16,
    secret: String,
}

pub fn configure(
    request: &mut proto::LoadConfigReq,
    profile: &Profile,
    library: &Library,
    directory: &Path,
) -> Result<(), String> {
    if profile.kind == ProfileKind::SingBoxConfig
        || !settings::boolean(library, "core_box_api_enabled")
        || !settings::boolean(library, "core_box_api_dashboard")
    {
        return Ok(());
    }
    let mut core: Value = serde_json::from_str(
        request
            .core_config
            .as_deref()
            .ok_or("invalid_configuration")?,
    )
    .map_err(|_| "invalid_configuration")?;
    let Some(api) = core["services"]
        .as_array_mut()
        .and_then(|services| services.iter_mut().find(|service| service["type"] == "api"))
    else {
        return Err("invalid_configuration".into());
    };
    let assets = Assets::new(directory);
    assets.ensure()?;
    let path = assets.serving_path();
    let path = path
        .to_str()
        .filter(|path| !path.contains('$'))
        .ok_or("dashboard_files_unavailable")?;
    api["dashboard"] = json!({"enabled":true,"path":path});
    request.core_config = Some(core.to_string());
    Ok(())
}

fn listener(request: &proto::LoadConfigReq, assets: &Assets) -> Result<Listener, String> {
    let core: Value =
        serde_json::from_str(request.core_config.as_deref().ok_or("dashboard_disabled")?)
            .map_err(|_| "dashboard_custom_configuration")?;
    let apis: Vec<_> = core["services"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|service| service["type"] == "api")
        .collect();
    if apis.is_empty() {
        return Err("dashboard_disabled".into());
    }
    if apis.len() != 1 {
        return Err("dashboard_custom_configuration".into());
    }
    let api = apis[0];
    let dashboard = &api["dashboard"];
    if dashboard.is_null()
        || dashboard == false
        || (dashboard.is_object() && dashboard["enabled"] != true)
    {
        return Err("dashboard_disabled".into());
    }
    let path = dashboard
        .as_str()
        .or_else(|| dashboard["path"].as_str())
        .ok_or("dashboard_custom_configuration")?;
    if !assets.serves(Path::new(path)) {
        return Err("dashboard_custom_configuration".into());
    }
    if api["tls"]["enabled"] == true {
        return Err("dashboard_listener_unsupported".into());
    }
    let port = api["listen_port"]
        .as_u64()
        .filter(|port| *port > 0 && *port <= u16::MAX as u64)
        .ok_or("dashboard_listener_unsupported")? as u16;
    let ip = api["listen"]
        .as_str()
        .ok_or("dashboard_listener_unsupported")?
        .parse::<IpAddr>()
        .map_err(|_| "dashboard_listener_unsupported")?;
    let host = match ip {
        IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".into(),
        IpAddr::V6(ip) if ip.is_unspecified() => "[::1]".into(),
        IpAddr::V4(ip) if ip.is_loopback() => ip.to_string(),
        IpAddr::V6(ip) if ip.is_loopback() => format!("[{ip}]"),
        _ => return Err("dashboard_listener_unsupported".into()),
    };
    let secret = match api.get("secret") {
        None => String::new(),
        Some(value) => value
            .as_str()
            .filter(|s| s.len() <= 4096)
            .ok_or("dashboard_listener_unsupported")?
            .to_owned(),
    };
    Ok(Listener { host, port, secret })
}

fn url(listener: Listener, language: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&format!(
        "http://{}:{}/thronium-dashboard.html",
        listener.host, listener.port
    ))
    .map_err(|_| "dashboard_open_failed")?;
    url.query_pairs_mut()
        .append_pair("secret", &listener.secret)
        .append_pair("language", language);
    let fragment = url.query().unwrap_or_default().to_owned();
    url.set_query(None);
    url.set_fragment(Some(&fragment));
    Ok(url.into())
}

impl Engine {
    pub fn dashboard_status(&mut self) -> Result<Status, String> {
        let assets = Assets::new(&self.data_dir);
        let (installed, files_error) = match assets.inspect() {
            Ok(value) => (value, None),
            Err(error) => (None, Some(error)),
        };
        let active =
            self.rpc.as_mut().is_some_and(|rpc| rpc.is_alive()) && self.active_connection.is_some();
        let reason = if !cfg!(any(unix, windows)) {
            Some("dashboard_platform_unsupported".into())
        } else if files_error.is_some() {
            files_error
        } else if !active {
            Some("dashboard_disconnected".into())
        } else {
            listener(&self.active_connection.as_ref().unwrap().request, &assets)
                .err()
                .or_else(|| {
                    installed
                        .is_none()
                        .then(|| "dashboard_not_installed".into())
                })
        };
        Ok(Status {
            can_open: reason.is_none(),
            can_install: cfg!(any(unix, windows)),
            installed,
            reason,
            settings_enabled: settings::boolean(&self.store.library, "core_box_api_enabled")
                && settings::boolean(&self.store.library, "core_box_api_dashboard"),
        })
    }
    pub fn dashboard_open_url(&mut self) -> Result<String, String> {
        let status = self.dashboard_status()?;
        if let Some(reason) = status.reason {
            return Err(reason);
        }
        url(
            listener(
                &self
                    .active_connection
                    .as_ref()
                    .ok_or("dashboard_disconnected")?
                    .request,
                &Assets::new(&self.data_dir),
            )?,
            &self.store.library.preferences.language,
        )
    }
}

#[cfg(test)]
mod tests;
