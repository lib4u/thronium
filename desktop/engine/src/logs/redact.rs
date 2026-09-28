//! Core diagnostics may echo credential values taken from the request (for
//! example "invalid UUID: <uuid>"). Before such text reaches the log, every
//! credential value of that request is replaced; key paths and the reason stay.
use serde_json::Value;

const MIN_SECRET_LEN: usize = 4;

fn credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "id"
        || [
            "pass", "secret", "token", "private", "psk", "uuid", "auth", "key",
        ]
        .iter()
        .any(|part| key.contains(part))
}

fn collect(value: &Value, secret: bool, found: &mut Vec<String>) {
    match value {
        Value::String(text) if secret && text.len() >= MIN_SECRET_LEN => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect(item, secret, found)),
        Value::Object(map) => {
            for (key, item) in map {
                collect(item, secret || credential_key(key), found);
            }
        }
        _ => {}
    }
}

/// Credential values of JSON configurations sent to a core, longest first so a
/// value containing a shorter one is replaced whole.
pub(crate) fn secrets<'a>(configs: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut secrets = Vec::new();
    for config in configs {
        if let Ok(config) = serde_json::from_str::<Value>(config) {
            collect(&config, false, &mut secrets);
        }
    }
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets.dedup();
    secrets
}

pub(crate) fn replace(text: &str, secrets: &[String]) -> String {
    secrets.iter().fold(text.to_owned(), |text, secret| {
        text.replace(secret.as_str(), "***")
    })
}

/// Every JSON configuration a start or check request hands to the core.
pub(crate) fn request_configs(request: &crate::proto::LoadConfigReq) -> Vec<&str> {
    [
        request.core_config.as_deref(),
        request.xray_config.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(request.xray_full_configs.iter().map(String::as_str))
    .collect()
}

/// `core_config` is the JSON request sent to the core, when there is one.
pub(crate) fn request_values(text: &str, core_config: Option<&str>) -> String {
    replace(text, &secrets(core_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_values_of_the_request_never_reach_the_log_but_paths_do() {
        let config = serde_json::json!({"outbounds":[{"type":"vless","server":"edge.example.test",
            "uuid":"11111111-2222-4333-8444-555555555555","tls":{"reality":{"private_key":"reality-private"}}},
            {"type":"trojan","password":"trojan-secret"}],
            "dns":{"servers":[{"headers":{"Authorization":["Bearer dns-token"]}}]}})
        .to_string();
        let text = "outbounds[0].uuid: invalid UUID: 11111111-2222-4333-8444-555555555555; \
            trojan-secret rejected; Bearer dns-token; reality-private; server edge.example.test";
        let redacted = request_values(text, Some(&config));
        for secret in [
            "11111111-2222-4333-8444-555555555555",
            "trojan-secret",
            "dns-token",
            "reality-private",
        ] {
            assert!(!redacted.contains(secret), "{secret}");
        }
        assert!(redacted.contains("outbounds[0].uuid: invalid UUID: ***"));
        assert!(
            redacted.contains("edge.example.test"),
            "non-credential values stay"
        );
        assert_eq!(request_values("plain", None), "plain");
    }

    #[test]
    fn core_output_never_keeps_values_of_protected_requests_after_the_run() {
        let logs = crate::logs::Logs::default();
        let session = serde_json::json!({"outbounds":[{"type":"vless","uuid":"aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"}]}).to_string();
        let probe = serde_json::json!({"outbounds":[{"type":"trojan","password":"probe-secret"}]})
            .to_string();
        logs.protect("session", [session.as_str()]);
        let profile = crate::store::Profile {
            vpn_policy: None,
            id: "p".into(),
            name: "p".into(),
            group_id: "personal".into(),
            kind: crate::store::ProfileKind::SingBoxOutbound,
            config: serde_json::json!({"type":"direct"}),
            favorite: false,
        };
        let sink = logs.for_probe(&profile, "http");
        sink.begin_probe([probe.as_str()]).finish(None);
        // Late lines of an ended run are still redacted; events keep their text.
        logs.push(
            "stderr",
            None,
            "invalid UUID: aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb",
            false,
        );
        sink.push("stdout", None, "auth probe-secret rejected", false);
        let texts: Vec<String> = logs
            .view(Default::default())
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.text)
            .collect();
        assert!(texts.iter().any(|t| t == "invalid UUID: ***"));
        assert!(texts.iter().any(|t| t == "auth *** rejected"));
        assert!(!texts
            .iter()
            .any(|t| t.contains("probe-secret") || t.contains("bbbbbbbbbbbb")));
        // A newer request of the same owner replaces the old values; the set is bounded.
        logs.protect("session", ["{}"]);
        for i in 0..100 {
            logs.protect(&format!("probe:{i}"), ["{}"]);
        }
        logs.push(
            "stderr",
            None,
            "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb",
            false,
        );
        assert!(logs
            .view(Default::default())
            .unwrap()
            .entries
            .iter()
            .any(|e| e.text == "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"));
    }
}
