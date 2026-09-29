//! The periodic application snapshot and its preferences.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "Connection".into(),
            object([
                ("id", required(Schema::String)),
                ("createdAt", required(Schema::Number)),
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
                ("uploadSpeed", required(Schema::Number)),
                ("downloadSpeed", required(Schema::Number)),
                ("outbound", required(Schema::String)),
                ("network", required(Schema::String)),
                ("destination", required(Schema::String)),
                ("protocol", required(Schema::String)),
                ("domain", required(Schema::String)),
                ("process", required(Schema::String)),
                ("chain", required(array(Schema::String))),
                ("source", required(Schema::String)),
            ]),
        ),
        (
            "LastUpdate".into(),
            object([
                ("at", required(Schema::Number)),
                ("status", required(reference("UpdateStatus"))),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
                ("counts", required(reference("UpdateCounts"))),
            ]),
        ),
        (
            "Measurement".into(),
            object([
                ("kind", required(reference("ProbeKind"))),
                ("effectiveMethod", required(reference("PingMethod"))),
                (
                    "attempts",
                    required(array(object([
                        ("method", required(reference("PingMethod"))),
                        ("status", required(reference("ProbeStatus"))),
                        ("error", required(union(vec![Schema::Null, Schema::String]))),
                    ]))),
                ),
                ("method", required(reference("PingMethod"))),
                ("firstHop", required(Schema::Boolean)),
                ("profileId", required(Schema::String)),
                ("name", required(Schema::String)),
                ("status", required(reference("ProbeStatus"))),
                (
                    "latencyMs",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
                ("at", required(union(vec![Schema::Null, Schema::Number]))),
                ("ip", required(union(vec![Schema::Null, Schema::String]))),
                (
                    "countryCode",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "download",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "upload",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "downloadBytes",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "uploadBytes",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "transport",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "memberId",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "memberName",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "memberOrigin",
                    required(union(vec![Schema::Null, reference("MemberOrigin")])),
                ),
            ]),
        ),
        (
            "PingSettings".into(),
            object([
                ("method", required(reference("PingMethod"))),
                ("url", required(Schema::String)),
                ("timeoutMs", required(Schema::Number)),
            ]),
        ),
        (
            "AutoSelect".into(),
            object([
                ("enabled", required(Schema::Boolean)),
                ("config", required(map(Schema::Json))),
                ("failover", required(Schema::Boolean)),
                ("sourceGroupId", required(nullable(Schema::String))),
            ]),
        ),
        (
            "Preferences".into(),
            object([
                ("vlessCore", required(reference("VlessCore"))),
                ("vlessOverrides", required(map(reference("VlessCore")))),
                ("closeBehavior", required(reference("CloseBehavior"))),
                ("connectionMode", required(reference("ConnectionMode"))),
                ("tun", required(reference("TunSettings"))),
                ("ping", required(reference("PingSettings"))),
                (
                    "language",
                    required(union(crate::languages::codes().map(literal).collect())),
                ),
                (
                    "theme",
                    required(union(vec![
                        literal("light"),
                        literal("dark"),
                        literal("system"),
                    ])),
                ),
                ("inboundPort", required(Schema::Number)),
                (
                    "librarySort",
                    required(union(vec![
                        literal("name"),
                        literal("protocol"),
                        literal("original"),
                        literal("address"),
                        literal("latency"),
                        literal("security"),
                        literal("traffic"),
                    ])),
                ),
                ("librarySortDescending", required(Schema::Boolean)),
                ("autoSelect", required(reference("AutoSelect"))),
            ]),
        ),
        (
            "ProbeBatch".into(),
            object([
                ("kind", required(reference("ProbeKind"))),
                ("method", required(reference("PingMethod"))),
                (
                    "source",
                    required(union(vec![
                        literal("manual"),
                        literal("periodic"),
                        literal("auto-select"),
                    ])),
                ),
                ("id", required(Schema::String)),
                ("url", required(Schema::String)),
                ("timeoutMs", required(Schema::Number)),
                ("entries", required(array(reference("Measurement")))),
            ]),
        ),
        (
            "ProbeStatus".into(),
            union(vec![
                literal("testing"),
                literal("error"),
                literal("ok"),
                literal("queued"),
                literal("cancelled"),
                literal("stale"),
                literal("unsupported"),
                literal("connected-only"),
                literal("auth-required"),
            ]),
        ),
        (
            "ProviderRouting".into(),
            object([
                ("available", required(Schema::Boolean)),
                ("action", required(Schema::String)),
                ("error", optional(union(vec![Schema::Null, Schema::String]))),
                ("hasDns", required(Schema::Boolean)),
                ("fakeDns", optional(Schema::Boolean)),
                ("rules", required(Schema::Number)),
                ("unsupported", required(array(Schema::String))),
                ("unsupportedCount", required(Schema::Number)),
                ("enabled", optional(Schema::Boolean)),
            ]),
        ),
        (
            "RoutingStatus".into(),
            object([
                ("active", required(Schema::String)),
                ("name", required(Schema::String)),
                ("mode", required(reference("RoutingMode"))),
                ("revision", required(Schema::Number)),
                ("pending", required(Schema::Boolean)),
                ("profileOwned", required(Schema::Boolean)),
                ("providerOwned", required(Schema::Boolean)),
                // The subscription whose routing is offered for the running or
                // selected server, even while a client profile takes priority.
                (
                    "providerGroup",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
            ]),
        ),
        (
            "Snapshot".into(),
            object([
                (
                    "selectorSubscriptionUpdate",
                    optional(union(vec![
                        Schema::Null,
                        object([
                            ("profileId", required(Schema::String)),
                            (
                                "pools",
                                required(array(object([
                                    ("profileId", required(Schema::String)),
                                    ("name", required(Schema::String)),
                                    (
                                        "status",
                                        required(object([
                                            ("pending", required(Schema::Boolean)),
                                            ("attempts", required(Schema::Number)),
                                            ("limit", required(Schema::Number)),
                                            ("paused", required(Schema::Boolean)),
                                        ])),
                                    ),
                                ]))),
                            ),
                        ]),
                    ])),
                ),
                (
                    "connectionPreparation",
                    optional(union(vec![
                        Schema::Null,
                        object([
                            ("id", required(Schema::String)),
                            ("profileId", required(Schema::String)),
                            ("name", required(Schema::String)),
                            ("total", required(Schema::Number)),
                            ("done", required(Schema::Number)),
                            ("fresh", required(Schema::Number)),
                            ("reusing", optional(Schema::Boolean)),
                        ]),
                    ])),
                ),
                ("libraryRevision", optional(Schema::Number)),
                ("appearance", optional(map(Schema::Json))),
                ("subscriptionNotifications", optional(Schema::Boolean)),
                ("tunSupported", required(Schema::Boolean)),
                (
                    "systemProxy",
                    required(object([
                        ("available", required(Schema::Boolean)),
                        ("active", required(Schema::Boolean)),
                        ("error", required(union(vec![Schema::Null, Schema::String]))),
                    ])),
                ),
                (
                    "urlTests",
                    required(union(vec![Schema::Null, reference("ProbeBatch")])),
                ),
                ("routing", required(reference("RoutingStatus"))),
                ("autoSelectAvailable", required(Schema::Boolean)),
                ("autoSelectMemberCount", required(Schema::Number)),
                ("profiles", required(array(reference("ProfileSummary")))),
                ("groups", required(array(reference("GroupSummary")))),
                (
                    "subscriptionJobs",
                    required(array(reference("SubscriptionJob"))),
                ),
                ("preferences", required(reference("Preferences"))),
                (
                    "selected",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "running",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("coreAvailable", required(Schema::Boolean)),
                (
                    "phase",
                    required(union(vec![
                        literal("error"),
                        literal("connected"),
                        literal("reconnecting"),
                        literal("disconnected"),
                        literal("connecting"),
                        literal("auth-pending"),
                        literal("unknown"),
                    ])),
                ),
                ("since", required(union(vec![Schema::Null, Schema::Number]))),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
                ("vpn", required(reference("VpnStatus"))),
                ("trafficAvailable", required(Schema::Boolean)),
                ("trafficUp", required(Schema::Number)),
                ("trafficDown", required(Schema::Number)),
                (
                    "localProxy",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("connections", required(array(reference("Connection")))),
                (
                    "sealing",
                    required(union(vec![
                        literal("sealed"),
                        literal("unavailable"),
                        literal("refused"),
                        literal("portable"),
                    ])),
                ),
            ]),
        ),
        (
            "TunSettings".into(),
            object([
                ("autoReconnect", required(Schema::Boolean)),
                ("requestPermission", required(Schema::Boolean)),
                ("mtu", required(Schema::Number)),
                (
                    "stack",
                    required(union(vec![
                        literal("system"),
                        literal("gvisor"),
                        literal("mixed"),
                    ])),
                ),
                ("ipv6", required(Schema::Boolean)),
                ("strictRoute", required(Schema::Boolean)),
                ("dnsHijack", required(Schema::Boolean)),
                (
                    "systemDns",
                    required(union(vec![
                        literal("disabled"),
                        literal("resolved"),
                        literal("resolvconf"),
                    ])),
                ),
                ("excludeAddresses", required(array(Schema::String))),
            ]),
        ),
        (
            "TrafficHistoryEntry".into(),
            object([
                ("hour", required(Schema::Number)),
                ("profile", required(Schema::String)),
                ("group", required(Schema::String)),
                ("process", required(Schema::String)),
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
            ]),
        ),
        (
            "TrafficPoint".into(),
            object([
                ("bucket", required(Schema::Number)),
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
            ]),
        ),
        (
            "TrafficProfileUsage".into(),
            object([
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                ("group", required(Schema::String)),
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
                ("direct", required(Schema::Boolean)),
                ("other", required(Schema::Boolean)),
            ]),
        ),
        (
            "TrafficAppUsage".into(),
            object([
                ("process", required(Schema::String)),
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
                ("other", required(Schema::Boolean)),
            ]),
        ),
        (
            "TrafficProfileBreakdown".into(),
            object([
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
                ("series", required(array(reference("TrafficPoint")))),
                ("rows", required(array(reference("TrafficProfileUsage")))),
            ]),
        ),
        (
            "TrafficAppBreakdown".into(),
            object([
                ("upload", required(Schema::Number)),
                ("download", required(Schema::Number)),
                ("series", required(array(reference("TrafficPoint")))),
                ("rows", required(array(reference("TrafficAppUsage")))),
            ]),
        ),
        (
            "TrafficStats".into(),
            object([
                ("from", required(Schema::Number)),
                ("to", required(Schema::Number)),
                ("bucketSeconds", required(Schema::Number)),
                ("profiles", required(reference("TrafficProfileBreakdown"))),
                ("applications", required(reference("TrafficAppBreakdown"))),
            ]),
        ),
        ("SettingsValues".into(), map(Schema::Json)),
        (
            "StorageLocation".into(),
            object([
                (
                    "mode",
                    required(union(vec![
                        literal("system"),
                        literal("portable"),
                        literal("custom"),
                        literal("error"),
                    ])),
                ),
                (
                    "directory",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
            ]),
        ),
        (
            "ConnectionTestResult".into(),
            object([
                ("online", optional(Schema::Boolean)),
                ("ip", optional(Schema::String)),
                (
                    "countryCode",
                    optional(union(vec![Schema::Null, Schema::String])),
                ),
                ("provider", optional(Schema::String)),
                ("download", optional(Schema::String)),
                ("upload", optional(Schema::String)),
                ("latencyMs", optional(Schema::Number)),
                ("downloadBytes", optional(Schema::Number)),
                ("uploadBytes", optional(Schema::Number)),
                ("profileId", optional(Schema::String)),
                ("profileName", optional(Schema::String)),
                ("testedAt", optional(Schema::Number)),
                ("kind", optional(Schema::String)),
                ("transport", optional(Schema::String)),
                ("memberId", optional(Schema::String)),
                ("memberName", optional(Schema::String)),
                ("memberOrigin", optional(reference("MemberOrigin"))),
            ]),
        ),
    ]
}
