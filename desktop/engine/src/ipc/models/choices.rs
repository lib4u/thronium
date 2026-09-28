//! Named choices repeated across commands.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "OtpAlgorithm".into(),
            union(vec![literal("SHA1"), literal("SHA256"), literal("SHA512")]),
        ),
        (
            "VpnBindingMode".into(),
            union(vec![literal("auto-live"), literal("auto-start")]),
        ),
        (
            "ConnectionMode".into(),
            union(vec![
                literal("local"),
                literal("system-proxy"),
                literal("tun"),
            ]),
        ),
        (
            "CloseBehavior".into(),
            union(vec![literal("quit"), literal("background")]),
        ),
        (
            "RoutingMode".into(),
            union(vec![literal("rules"), literal("all"), literal("direct")]),
        ),
        (
            "OtpType".into(),
            union(vec![literal("totp"), literal("hotp")]),
        ),
        (
            "VlessCore".into(),
            union(vec![literal("xray"), literal("sing-box")]),
        ),
        (
            "ProfileKind".into(),
            union(vec![
                literal("sing-box-outbound"),
                literal("sing-box-config"),
                literal("xray-outbound"),
                literal("xray-config"),
                literal("chain"),
                literal("auto-selector"),
                literal("external-core"),
            ]),
        ),
        (
            "MemberOrigin".into(),
            union(vec![
                literal("running"),
                literal("pinned"),
                literal("first"),
            ]),
        ),
        (
            "ProbeKind".into(),
            union(vec![literal("latency"), literal("ip"), literal("speed")]),
        ),
        (
            "PingMethod".into(),
            union(vec![
                literal("auto"),
                literal("http"),
                literal("tcp"),
                literal("icmp"),
            ]),
        ),
        (
            "OtpExportFormat".into(),
            union(vec![literal("uri"), literal("json"), literal("migration")]),
        ),
        (
            "GeoKind".into(),
            union(vec![literal("geoip"), literal("geosite")]),
        ),
        (
            "GeodataAssetKind".into(),
            union(vec![literal("geoip"), literal("geosite")]),
        ),
    ]
}
