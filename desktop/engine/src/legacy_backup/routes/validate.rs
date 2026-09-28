use super::Result;
use serde_json::Value;
use std::net::IpAddr;
pub(super) fn object_keys(v: &Value, allowed: &[&str]) -> Result<()> {
    if v.as_object()
        .ok_or("legacy_route_structure")?
        .keys()
        .any(|k| !allowed.contains(&k.as_str()))
    {
        Err("legacy_route_field_unsupported")
    } else {
        Ok(())
    }
}
pub(super) fn bool_value(v: &Value) -> Result<bool> {
    v.as_bool().ok_or("legacy_route_structure")
}
pub(super) fn string(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or("legacy_route_structure")?;
    if s.len() > 8192 || s.chars().any(char::is_control) {
        return Err("legacy_route_structure");
    }
    Ok(s)
}
pub(super) fn nonempty(v: &Value) -> Result<&str> {
    let s = string(v)?;
    if s.trim().is_empty() {
        Err("legacy_route_structure")
    } else {
        Ok(s)
    }
}
pub(super) fn strategy(s: &str) -> Result<()> {
    if matches!(
        s,
        "" | "as_is" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
    ) {
        Ok(())
    } else {
        Err("legacy_route_structure")
    }
}
pub(super) fn port(v: &Value) -> Result<()> {
    if v.as_u64().is_some_and(|n| (1..=65535).contains(&n)) {
        Ok(())
    } else {
        Err("legacy_route_structure")
    }
}
pub(super) fn list(v: &Value) -> Result<Vec<&Value>> {
    match v {
        Value::Array(a) if !a.is_empty() && a.len() <= 1000 => Ok(a.iter().collect()),
        Value::Array(_) => Err("legacy_route_structure"),
        _ => Ok(vec![v]),
    }
}
pub(super) fn strings(v: &Value) -> Result<Vec<&str>> {
    list(v)?.into_iter().map(nonempty).collect()
}
pub(super) fn cidr(s: &str) -> Result<()> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, n)) => (
            ip,
            Some(n.parse::<u8>().map_err(|_| "legacy_route_structure")?),
        ),
        None => (s, None),
    };
    let ip = ip.parse::<IpAddr>().map_err(|_| "legacy_route_structure")?;
    if prefix.is_some_and(|n| n > if ip.is_ipv4() { 32 } else { 128 }) {
        return Err("legacy_route_structure");
    }
    Ok(())
}
pub(super) fn duration(v: &Value) -> Result<()> {
    // Bounded positive Go duration subset, with the same signed int64 ns bound.
    let s = nonempty(v)?;
    static ALL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let all = ALL.get_or_init(|| {
        regex::Regex::new(r"^(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+$").unwrap()
    });
    if s.len() > 64 || !all.is_match(s) {
        return Err("legacy_route_structure");
    }
    static PARTS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let parts = PARTS
        .get_or_init(|| regex::Regex::new(r"([0-9]+)(?:\.([0-9]+))?(ns|us|µs|ms|s|m|h)").unwrap());
    let mut total = 0u128;
    for captures in parts.captures_iter(s) {
        let scale: u128 = match &captures[3] {
            "ns" => 1,
            "us" | "µs" => 1000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => unreachable!(),
        };
        let whole = captures[1]
            .parse::<u128>()
            .map_err(|_| "legacy_route_structure")?;
        let mut nanos = whole.checked_mul(scale).ok_or("legacy_route_structure")?;
        if let Some(fraction) = captures.get(2) {
            let digits = &fraction.as_str()[..fraction.len().min(18)];
            nanos = nanos
                .checked_add(
                    digits
                        .parse::<u128>()
                        .map_err(|_| "legacy_route_structure")?
                        * scale
                        / 10u128.pow(digits.len() as u32),
                )
                .ok_or("legacy_route_structure")?;
        }
        total = total.checked_add(nanos).ok_or("legacy_route_structure")?;
        if total > i64::MAX as u128 {
            return Err("legacy_route_structure");
        }
    }
    Ok(())
}
pub(super) fn regexp(s: &str) -> Result<()> {
    // Preserve Go RE2 exactly. Rust regex syntax is not an authority for the
    // pinned core; CheckConfig validates expressions before any active stop.
    if s.len() > 2048 {
        return Err("legacy_route_limit");
    }
    Ok(())
}
pub(super) fn host(s: &str) -> Result<()> {
    if s.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.len() > 253
        || name.is_empty()
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("legacy_route_structure");
    }
    Ok(())
}
