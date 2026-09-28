//! Validate desktop quick-pool options before storing or starting a probe.
use serde_json::{json, Value};
use std::sync::LazyLock;

const INVALID: &str = "invalid_auto_select_settings";
/// Allowed probe timeout, in milliseconds.
pub const TIMEOUT_MS: std::ops::RangeInclusive<u32> = 100..=10_000;
/// Longest time a selected server is remembered, in milliseconds (24 h).
pub const MAX_REUSE_TTL_MS: u32 = 86_400_000;
static DURATION: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"(\d+(?:\.\d+)?)(ms|s|m|h)").ok());

pub(crate) fn duration_ms(text: &str) -> Option<u32> {
    let mut end = 0;
    let mut total = 0.0_f64;
    for cap in DURATION.as_ref()?.captures_iter(text) {
        let whole = cap.get(0)?;
        if whole.start() != end {
            return None;
        }
        end = whole.end();
        let number: f64 = cap[1].parse().ok()?;
        total += number
            * match &cap[2] {
                "ms" => 1.0,
                "s" => 1000.0,
                "m" => 60_000.0,
                _ => 3_600_000.0,
            };
    }
    (end > 0
        && end == text.len()
        && total.is_finite()
        && total <= f64::from(u32::MAX)
        && total.fract() == 0.0)
        .then_some(total as u32)
}

pub(crate) fn normalize(saved: &Value) -> Result<Value, String> {
    let object = saved.as_object().ok_or(INVALID)?;
    let mut config = super::super::default_quick_config();
    for (key, value) in object {
        if value.is_null() || value == "" {
            continue;
        }
        match key.as_str() {
            "url" | "connectivity_url" => {
                let url = value.as_str().ok_or(INVALID)?;
                let url = crate::probes::PingSettings {
                    method: crate::probes::Method::Http,
                    url: url.into(),
                    timeout_ms: 1000,
                }
                .validate()?;
                config[key] = json!(url.as_str());
                continue;
            }
            "interval" | "bench_interval" | "watch_interval" | "timeout" | "max_rtt"
            | "balance_interval" | "reuse_ttl" => {
                let duration = value.as_str().and_then(duration_ms).ok_or(INVALID)?;
                let range = match key.as_str() {
                    "timeout" => TIMEOUT_MS,
                    "reuse_ttl" => 0..=MAX_REUSE_TTL_MS,
                    _ => 1..=MAX_REUSE_TTL_MS,
                };
                if !range.contains(&duration) {
                    return Err(INVALID.into());
                }
            }
            "concurrency" | "active_size" | "sampling" | "expected" | "tolerance"
            | "dial_retries" => {
                let number = value.as_u64().ok_or(INVALID)?;
                let range = match key.as_str() {
                    "concurrency" => 1..=64,
                    "sampling" => 2..=60,
                    "tolerance" => 0..=65535,
                    "dial_retries" => 0..=5,
                    _ => 1..=500,
                };
                if !range.contains(&number) {
                    return Err(INVALID.into());
                }
                // Core treats zero as the default, never as "no retries/tolerance".
                if number == 0 {
                    config[key] = if key == "tolerance" {
                        json!(100)
                    } else {
                        json!(2)
                    };
                    continue;
                }
            }
            "balance" | "interrupt_exist_connections" => {
                value.as_bool().ok_or(INVALID)?;
            }
            "balance_mode" if matches!(value.as_str(), Some("rotate" | "connection")) => {}
            _ => return Err(INVALID.into()),
        }
        config[key] = value.clone();
    }
    Ok(config)
}

/// Missing defaults and legacy zero aliases are the same effective settings.
/// Invalid inputs only match verbatim, so malformed values cannot bypass the guard.
pub(crate) fn equivalent(a: &Value, b: &Value) -> bool {
    a == b || matches!((normalize(a), normalize(b)), (Ok(a), Ok(b)) if a == b)
}
