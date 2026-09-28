//! Provider routing is data attached to its subscription, never an OS command.
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRouting {
    pub action: String,
    pub config: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProviderRouting {
    pub fn parse(input: &str) -> Self {
        let invalid = || Self {
            action: "invalid".into(),
            config: json!({}),
            error: Some("subscription_routing_invalid".into()),
        };
        if input.len() > 256 * 1024 {
            return invalid();
        }
        let Some(path) = input.trim().strip_prefix("happ://routing/") else {
            return invalid();
        };
        if path == "off" {
            return Self {
                action: "off".into(),
                config: json!({}),
                error: None,
            };
        }
        let Some((action, raw)) = path.split_once('/') else {
            return invalid();
        };
        if !matches!(action, "add" | "onadd") {
            return invalid();
        }
        let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
            .iter()
            .find_map(|e| e.decode(raw).ok());
        let Some(config) = decoded
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(Value::is_object)
        else {
            return invalid();
        };
        Self {
            action: action.into(),
            config,
            error: None,
        }
    }
    /// Keys this build cannot translate. Provider key names are remote input, so
    /// only plain identifiers are named; anything else is counted, never shown.
    pub fn unsupported(&self) -> (Vec<String>, usize) {
        let Some(object) = self.config.as_object() else {
            return (vec![], 0);
        };
        let mut names: Vec<String> = object
            .keys()
            .filter(|key| !super::provider_policy::KNOWN_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        names.sort();
        let total = names.len();
        names.retain(|key| {
            (1..=32).contains(&key.len())
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        names.truncate(8);
        (names, total)
    }
    // No provider URLs, arbitrary strings, or credentials in status snapshots.
    pub fn summary(&self) -> Value {
        let rules = [
            "DirectSites",
            "DirectIp",
            "ProxySites",
            "ProxyIp",
            "BlockSites",
            "BlockIp",
        ]
        .iter()
        .map(|k| self.config[*k].as_array().map_or(0, Vec::len))
        .sum::<usize>();
        let (unsupported, unsupported_count) = self.unsupported();
        json!({"available":true,"action":self.action,"error":self.error,
            "hasDns":self.config.as_object().is_some_and(|c|c.keys().any(|k|k.contains("DNS") || k=="DnsHosts")),
            "fakeDns":matches!(&self.config["FakeDNS"], Value::Bool(true)) || self.config["FakeDNS"] == "true",
            "rules":rules,"unsupported":unsupported,"unsupportedCount":unsupported_count})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_routing_decodes_data_and_never_exposes_urls_in_summary() {
        let data = json!({"DirectSites":["domain:example.test"],"RemoteDNSDomain":"https://private.example/token","RouteOrder":"block-proxy-direct"});
        let parsed = ProviderRouting::parse(&format!(
            "happ://routing/add/{}",
            STANDARD.encode(data.to_string())
        ));
        assert_eq!(parsed.config, data);
        assert_eq!(parsed.summary()["rules"], 1);
        assert!(!parsed.summary().to_string().contains("token"));
        assert_eq!(parsed.summary()["unsupportedCount"], 0);
        let extended = ProviderRouting::parse(&format!(
            "happ://routing/add/{}",
            STANDARD.encode(
                json!({"RouteOrder":"block-proxy-direct","SplitTunnelingV2":true,
                    "Отчёт":"https://private.example/token","a b":1})
                .to_string()
            )
        ));
        // Key names are remote input: only plain identifiers may be named.
        assert_eq!(
            extended.summary()["unsupported"],
            json!(["SplitTunnelingV2"])
        );
        assert_eq!(extended.summary()["unsupportedCount"], 3);
        assert!(!extended.summary().to_string().contains("token"));
        assert_eq!(ProviderRouting::parse("happ://routing/off").action, "off");
        for value in [
            "happ://routing/add/bad",
            "happ://routing/run/xyz",
            "https://example.test",
        ] {
            assert!(ProviderRouting::parse(value).error.is_some());
        }
    }
}
