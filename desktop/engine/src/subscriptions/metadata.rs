use super::{Usage, MAX_BYTES};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Default, Serialize, Deserialize, Debug, PartialEq)]
pub struct Metadata {
    pub title: Option<String>,
    pub announcement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<super::provider_routing::ProviderRouting>,
}

fn decode(value: &str) -> Option<Vec<u8>> {
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(value).ok())
}
fn text(value: &str, limit: usize) -> Option<String> {
    if value.len() > 16 * 1024 {
        return None;
    }
    let value = value.trim();
    let decoded = value
        .strip_prefix("base64:")
        .map(|v| String::from_utf8(decode(v)?).ok());
    let value = match &decoded {
        Some(Some(v)) => v.as_str(),
        Some(None) => return None,
        None => value,
    };
    let value: String = value
        .replace("\r\n", "\n")
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(limit)
        .collect();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}
fn field(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.trim().strip_prefix('#')?.split_once(':')?;
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "announce"
            | "profile-title"
            | "subscription-userinfo"
            | "profile-update-interval"
            | "routing"
    )
    .then_some((key.trim(), value.trim()))
}

/// Provider routing is retained as subscription data. It never executes commands.
/// HTTP headers take precedence, including an explicitly empty announcement.
pub fn extract(headers: &HeaderMap, body: &mut String) -> (Metadata, Option<Usage>) {
    let encoded = body.trim();
    if encoded.len() <= MAX_BYTES && !encoded.contains(':') && !encoded.starts_with(['{', '[']) {
        let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(decoded) = decode(&compact).and_then(|b| String::from_utf8(b).ok()) {
            if decoded
                .lines()
                .any(|line| field(line).is_some() || line.trim().starts_with("happ://routing/"))
            {
                *body = decoded;
            }
        }
    }
    let fields: HashMap<String, String> = body
        .lines()
        .filter_map(field)
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    let value = |name: &str| -> Option<&str> {
        if let Some(header) = headers.get(name) {
            std::str::from_utf8(header.as_bytes()).ok()
        } else {
            fields.get(name).map(String::as_str)
        }
    };
    let metadata = Metadata {
        title: value("profile-title")
            .and_then(|v| text(v, 256))
            .map(|v| v.replace(['\n', '\t'], " ")),
        announcement: value("announce").and_then(|v| text(v, 4096)),
        routing: value("routing")
            .or_else(|| {
                body.lines()
                    .find(|l| l.trim().starts_with("happ://routing/"))
            })
            .map(super::provider_routing::ProviderRouting::parse),
    };
    let usage = value("subscription-userinfo").and_then(Usage::parse);
    if !fields.is_empty()
        || body
            .lines()
            .any(|l| l.trim().starts_with("happ://routing/"))
    {
        *body = body
            .lines()
            .filter(|line| field(line).is_none() && !line.trim().starts_with("happ://routing/"))
            .collect::<Vec<_>>()
            .join("\n");
    }
    (metadata, usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routing_headers_override_body_and_encoded_directives_are_not_server_rows() {
        let link = format!(
            "happ://routing/add/{}",
            STANDARD.encode(r#"{"DirectSites":["domain:example.test"]}"#)
        );
        for raw in [
            format!("{link}\nvless://fixture"),
            format!("# Routing: {link}\nvless://fixture"),
        ] {
            let mut body = STANDARD.encode(&raw);
            let (meta, _) = extract(&HeaderMap::new(), &mut body);
            assert_eq!(meta.routing.unwrap().summary()["rules"], 1);
            assert_eq!(body, "vless://fixture");
            let mut headers = HeaderMap::new();
            headers.insert("routing", "happ://routing/off".parse().unwrap());
            let mut body = raw;
            let (meta, _) = extract(&headers, &mut body);
            assert_eq!(meta.routing.unwrap().action, "off");
            assert_eq!(body, "vless://fixture");
        }
        let mut headers = HeaderMap::new();
        headers.insert("routing", "happ://routing/add/invalid".parse().unwrap());
        let (meta, _) = extract(&headers, &mut "vless://fixture".into());
        assert_eq!(
            meta.routing.unwrap().error.as_deref(),
            Some("subscription_routing_invalid")
        );
    }
    #[test]
    fn metadata_supports_headers_comments_unicode_and_encoded_bodies() {
        let mut body = format!("#profile-title: Provider\n#announce: base64:{}\n#subscription-userinfo: upload=10; download=20; total=0\n{{\"type\":\"direct\"}}", STANDARD.encode("Привет\nНовая строка"));
        body = STANDARD.encode(body);
        let (meta, usage) = extract(&HeaderMap::new(), &mut body);
        assert_eq!(meta.title.as_deref(), Some("Provider"));
        assert_eq!(meta.announcement.as_deref(), Some("Привет\nНовая строка"));
        assert_eq!(usage.unwrap().total, Some(0));
        assert_eq!(body, r#"{"type":"direct"}"#);
        let mut headers = HeaderMap::new();
        headers.insert("announce", "".parse().unwrap());
        let (meta, _) = extract(&headers, &mut "#announce: old\nsocks://test".into());
        assert_eq!(meta.announcement, None);
    }
    #[test]
    fn malformed_and_large_metadata_never_breaks_or_executes_profiles() {
        let mut headers = HeaderMap::new();
        headers.insert("announce", "base64:!!!".parse().unwrap());
        let mut body = r#"{"type":"direct"}"#.to_string();
        assert!(extract(&headers, &mut body).0.announcement.is_none());
        assert_eq!(body, r#"{"type":"direct"}"#);
        assert_eq!(
            text("<script>hello</script>", 4096).as_deref(),
            Some("<script>hello</script>")
        );
        assert_eq!(text("a\0b\r\nc", 4096).as_deref(), Some("ab\nc"));
        assert!(text(&"a".repeat(17000), 4096).is_none());
        assert_eq!(text(&"я".repeat(6000), 4096).unwrap().chars().count(), 4096);
    }
}
