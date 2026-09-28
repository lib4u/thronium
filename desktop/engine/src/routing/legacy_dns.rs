//! Qt changes generated remote UDP/QUIC DNS when any relevant path uses Xray.
//! Keep the portable source transport in the preset; adapt only the built copy.
use serde_json::{json, Value};

pub(crate) fn adaptive(dns: &Value) -> bool {
    dns["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|server| {
            server["tag"] == "dns-remote" && matches!(server["type"].as_str(), Some("udp" | "quic"))
        })
}

pub(crate) fn apply(dns: &mut Value, uses_xray: bool) {
    if !uses_xray {
        return;
    }
    for server in dns["servers"].as_array_mut().into_iter().flatten() {
        if server["tag"] != "dns-remote" || !matches!(server["type"].as_str(), Some("udp" | "quic"))
        {
            continue;
        }
        // Exact upgradeUdpDnsToDoH mapping from the local Qt source, including
        // its fallback and deliberate removal of the old port/transport fields.
        let host = match server["server"].as_str().unwrap_or("") {
            known @ ("8.8.8.8" | "8.8.4.4" | "1.1.1.1" | "1.0.0.1" | "1.1.1.2" | "1.0.0.2"
            | "1.1.1.3" | "1.0.0.3" | "9.9.9.9" | "149.112.112.112" | "94.140.14.14"
            | "94.140.15.15") => known,
            _ => "8.8.8.8",
        };
        *server = json!({"type":"https","server":host,"path":"/dns-query",
            "tag":"dns-remote","domain_resolver":"dns-local","detour":"proxy"});
    }
}
