//! Categorized settings, validated and committed as a single section transaction.
use crate::{
    store::{Library, ProfileKind},
    Engine,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;
pub mod history;
mod intercept;
pub mod network;
mod runtime;
pub(crate) use runtime::prepare_profile;
mod singbox;
mod xray;
pub(crate) use singbox::configure_cache;
pub mod tests_runtime;
pub mod updates;
pub mod warp;

#[derive(Deserialize)]
pub struct Field {
    pub id: String,
    pub section: String,
    pub kind: String,
    pub default: Value,
    pub preference: Option<String>,
    pub options: Option<Vec<String>>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    /// Systems the setting has an effect on; absent means every system. The
    /// stored value is kept elsewhere so a library moves between systems whole.
    pub platforms: Option<Vec<String>>,
}
/// Fields of otherwise network sections that never reach a Core request:
/// log view and file options, traffic history presentation and deletion
/// confirmation. Editing them neither checks the configuration nor resets
/// measurements.
const LOCAL_FIELDS: [&str; 16] = [
    "max_log_line",
    "log_auto_scroll",
    "log_enable_include",
    "log_include_keyword",
    "log_include_regex",
    "log_enable_exclude",
    "log_exclude_keyword",
    "log_exclude_regex",
    "log_file_enabled",
    "log_file_level",
    "disable_traffic_aggregation",
    "traffic_stats_retention_days",
    "connection_sort",
    "connection_sort_asc",
    "show_system_dns",
    "skip_delete_confirmation",
];
pub fn fields() -> &'static [Field] {
    static FIELDS: OnceLock<Vec<Field>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        serde_json::from_str(include_str!("../../../contracts/settings.catalog.json"))
            .expect("settings catalog")
    })
}
pub fn value(library: &Library, key: &str) -> Value {
    let Some(field) = fields().iter().find(|f| f.id == key) else {
        return Value::Null;
    };
    if let Some(path) = &field.preference {
        serde_json::to_value(&library.preferences)
            .ok()
            .and_then(|p| p.pointer(path).cloned())
            .unwrap_or_else(|| field.default.clone())
    } else {
        library
            .settings
            .get(key)
            .cloned()
            .unwrap_or_else(|| field.default.clone())
    }
}
pub fn section(library: &Library, id: &str) -> Value {
    Value::Object(
        fields()
            .iter()
            .filter(|f| f.section == id)
            .map(|f| (f.id.clone(), value(library, &f.id)))
            .collect(),
    )
}
pub fn all(library: &Library) -> Value {
    Value::Object(
        fields()
            .iter()
            .map(|f| (f.section.clone(), section(library, &f.section)))
            .collect(),
    )
}
pub fn boolean(library: &Library, key: &str) -> bool {
    value(library, key).as_bool().unwrap_or(false)
}
pub fn string(library: &Library, key: &str) -> String {
    value(library, key).as_str().unwrap_or("").to_owned()
}
pub fn integer(library: &Library, key: &str) -> i64 {
    value(library, key).as_i64().unwrap_or(0)
}
fn invalid(field: &str) -> String {
    format!("settings_invalid:{field}")
}
pub(crate) fn validate_field(field: &Field, v: &Value) -> Result<(), String> {
    let good = match field.kind.as_str() {
        "bool" => v.is_boolean(),
        "number" => v.as_i64().is_some_and(|n| {
            field.min.is_none_or(|min| n >= min) && field.max.is_none_or(|max| n <= max)
        }),
        "list" => v.as_array().is_some_and(|a| {
            a.len() <= 1000
                && a.iter().all(|v| {
                    v.as_str()
                        .is_some_and(|s| s.len() <= 8192 && !s.contains('\0'))
                })
        }),
        "json" => v.is_array() && v.to_string().len() <= 262144,
        "ip" => v
            .as_str()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok()),
        "optional-url" if v == "" => true,
        "url" | "optional-url" => v.as_str().is_some_and(|s| {
            s.len() <= 8192
                && reqwest::Url::parse(s).is_ok_and(|u| {
                    matches!(u.scheme(), "http" | "https")
                        && u.host_str().is_some()
                        && u.username().is_empty()
                        && u.password().is_none()
                })
        }),
        _ => v.as_str().is_some_and(|s| {
            s.len() <= 8192
                && !s.contains('\0')
                && field
                    .options
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|v| v == s))
        }),
    };
    if !good {
        return Err(invalid(&field.id));
    }
    if matches!(field.id.as_str(), "xray_geoip_url" | "xray_geosite_url")
        && !v.as_str().is_some_and(|s| s.starts_with("https://"))
    {
        return Err(invalid(&field.id));
    }
    if field.id.ends_with("_regex") {
        crate::logs::filters::expression(v).map_err(|_| invalid(&field.id))?;
    }
    Ok(())
}
/// sing-box duration text such as `30m` or `1h30m`.
pub(crate) fn valid_duration(value: &str) -> bool {
    regex::Regex::new(r"^(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+$")
        .unwrap()
        .is_match(value)
}
/// The local proxy scheme must place the listener port somewhere.
pub(crate) fn valid_proxy_scheme(value: &str) -> bool {
    !value.is_empty() && value.contains("{port}")
}
pub fn validate(library: &Library) -> Result<(), String> {
    for field in fields() {
        validate_field(field, &value(library, &field.id))?;
    }
    xray::validate(library)?;
    for (key, v6) in [("vpn_tun_ipv4_cidr", false), ("vpn_tun_ipv6_cidr", true)] {
        if !crate::tun::valid_interface_cidr(&string(library, key), v6) {
            return Err(invalid(key));
        }
    }

    let custom = value(library, "custom_inbound");
    let mut tags = std::collections::HashSet::new();
    for inbound in custom.as_array().into_iter().flatten() {
        if !inbound.is_object()
            || inbound["type"].as_str().is_none_or(str::is_empty)
            || inbound["tag"]
                .as_str()
                .is_some_and(|tag| ["mixed-in", "thronium-tun"].contains(&tag) || !tags.insert(tag))
        {
            return Err(invalid("custom_inbound"));
        }
    }
    if !string(library, "core_box_underlying_dns").is_empty() {
        intercept::dns_server(&string(library, "core_box_underlying_dns"))?;
    }
    if !valid_proxy_scheme(&string(library, "proxy_scheme")) {
        return Err(invalid("proxy_scheme"));
    }
    for key in ["ntp_interval", "h2_idle_timeout", "h2_keep_alive_period"] {
        let value = string(library, key);
        if !value.is_empty() && !valid_duration(&value) {
            return Err(invalid(key));
        }
    }
    if boolean(library, "inbound_auth")
        && (string(library, "inbound_user").is_empty()
            || string(library, "inbound_pass").is_empty())
    {
        return Err(invalid("inbound_user"));
    }
    if library.preferences.connection_mode == crate::system_proxy::ConnectionMode::SystemProxy
        && (boolean(library, "disable_mixed_inbound")
            || boolean(library, "inbound_auth")
            || string(library, "inbound_address") != "127.0.0.1")
    {
        return Err("settings_system_proxy_incompatible".into());
    }
    if boolean(library, "disable_tray")
        && library.preferences.close_behavior == crate::store::CloseBehavior::Background
    {
        return Err("settings_invalid:close_behavior".into());
    }
    if boolean(library, "core_box_clash_enabled")
        && !["127.0.0.1", "::1"].contains(&string(library, "core_box_clash_listen_addr").as_str())
        && string(library, "core_box_clash_api_secret").is_empty()
    {
        return Err(invalid("core_box_clash_api_secret"));
    }
    if boolean(library, "enable_warp") {
        warp::validate(library)?;
    }
    if boolean(library, "tls_spoof_default_on") && string(library, "tls_spoof").trim().is_empty() {
        return Err(invalid("tls_spoof"));
    }
    for (key, value) in s_params(library)? {
        let _ = (key, value);
    }
    for key in ["fragment_size", "fragment_sleep"] {
        let range = string(library, key);
        let numbers = range
            .split('-')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid(key))?;
        if numbers.is_empty()
            || numbers.len() > 2
            || (key == "fragment_size" && numbers[0] == 0)
            || numbers[0] > *numbers.last().unwrap()
            || *numbers.last().unwrap() > 65535
        {
            return Err(invalid(key));
        }
    }
    Ok(())
}
fn s_params(library: &Library) -> Result<Vec<(String, String)>, String> {
    let input = string(library, "sub_custom_hwid_params");
    let mut out = Vec::new();
    for entry in input.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| invalid("sub_custom_hwid_params"))?;
        if !["hwid", "os", "osversion", "model"].contains(&key.trim().to_ascii_lowercase().as_str())
            || value.len() > 1000
            || value.contains(['\r', '\n'])
        {
            return Err(invalid("sub_custom_hwid_params"));
        }
        out.push((key.trim().into(), value.trim().into()));
    }
    Ok(out)
}
pub use runtime::{apply, prepare_profiles};
impl Engine {
    pub fn reload_settings(&self) {
        self.logs.configure(&self.store.library, &self.data_dir);
    }
    pub fn settings(&self) -> Value {
        all(&self.store.library)
    }
    pub async fn save_settings(
        &mut self,
        section_id: &str,
        previous: Value,
        values: Value,
    ) -> Result<Value, String> {
        let fields: Vec<_> = fields()
            .iter()
            .filter(|f| f.section == section_id)
            .collect();
        if fields.is_empty() {
            return Err("settings_section_unknown".into());
        }
        let current = section(&self.store.library, section_id);
        let previous = previous.as_object().ok_or("invalid_preferences")?;
        let values = values.as_object().ok_or("invalid_preferences")?;
        if values.len() != fields.len()
            || values.keys().any(|k| !fields.iter().any(|f| f.id == *k))
            || previous.len() != fields.len()
            || previous.keys().any(|k| !fields.iter().any(|f| f.id == *k))
        {
            return Err("invalid_preferences".into());
        }
        // Merge only the fields edited in this form. Toolbar actions and other
        // editors may have changed unrelated fields since the form was opened.
        let mut merged = current.clone();
        let mut conflicts = Vec::new();
        for field in &fields {
            let desired = &values[&field.id];
            validate_field(field, desired)?;
            if desired != &previous[&field.id] {
                if current[&field.id] != previous[&field.id] && &current[&field.id] != desired {
                    conflicts.push(field.id.as_str());
                } else {
                    merged[&field.id] = desired.clone();
                }
            }
        }
        if !conflicts.is_empty() {
            return Err(format!("settings_conflict:{}", conflicts.join(",")));
        }
        let mut next = self.store.library.clone();
        let mut prefs =
            serde_json::to_value(&next.preferences).map_err(|_| "invalid_preferences")?;
        for field in &fields {
            let v = &merged[&field.id];
            validate_field(field, v)?;
            if let Some(path) = &field.preference {
                *prefs.pointer_mut(path).ok_or("invalid_preferences")? = v.clone();
            } else {
                next.settings.insert(field.id.clone(), v.clone());
            }
        }
        next.preferences = serde_json::from_value(prefs).map_err(|_| "invalid_preferences")?;
        validate(&next)?;
        crate::store::validate_library(&next)?;
        let edited = section(&next, section_id);
        if edited == current {
            return Ok(edited);
        }
        if self.running.is_some() && matches!(section_id, "inbound" | "tun") {
            return Err("stop_before_editing".into());
        }
        self.check_connection_mode(next.preferences.connection_mode)?;
        let network = matches!(
            section_id,
            "inbound" | "tun" | "dns" | "core" | "presets" | "security" | "intercept" | "logging"
        ) && fields
            .iter()
            .any(|f| edited[&f.id] != current[&f.id] && !LOCAL_FIELDS.contains(&f.id.as_str()));
        if network {
            self.url_tests_resettable()?;
            if let Some(profile) = self
                .running
                .as_ref()
                .or(next.selected.as_ref())
                .and_then(|id| next.profiles.iter().find(|p| p.id == *id))
            {
                if !matches!(
                    profile.kind,
                    ProfileKind::SingBoxConfig | ProfileKind::XrayConfig
                ) {
                    let profile = profile.clone();
                    self.check_with_library(&profile, &next).await?;
                }
            }
        }
        let defaults = next.clone();
        for group in &mut next.groups {
            if let Some(sub) = &mut group.subscription {
                network::subscription_defaults(&mut sub.settings, &defaults);
            }
        }
        let periodic_changed =
            crate::probes::periodic::settings_changed(&self.store.library, &next);
        let committed = self.store.commit(next);
        if let Err(error) = &committed {
            if !crate::store::Store::written(&committed) {
                return Err(error.clone());
            }
        }
        if periodic_changed {
            self.reset_periodic_probes();
        }
        self.logs.configure(&self.store.library, &self.data_dir);
        if network {
            self.reset_url_tests_after_commit();
            if self.running.is_some() {
                self.routing_revision = None;
            }
        }
        committed?;
        Ok(section(&self.store.library, section_id))
    }
}

mod system_proxy;
#[cfg(test)]
mod tests;
mod traffic;

/// Descriptive transport metadata only. Authentication fields never enter a snapshot.
pub fn profile_security(profile: &crate::store::Profile) -> String {
    crate::profile_descriptor::describe(profile).security
}
