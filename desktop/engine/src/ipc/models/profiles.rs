//! Profiles, their drafts, edits, exports and duplicates.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "DeliveryResult".into(),
            union(vec![
                object([
                    ("status", required(Schema::String)),
                    ("text", optional(Schema::String)),
                    ("image", optional(Schema::String)),
                ]),
                object([
                    ("status", optional(Schema::String)),
                    ("text", required(Schema::String)),
                    ("image", optional(Schema::String)),
                ]),
                object([
                    ("status", optional(Schema::String)),
                    ("text", optional(Schema::String)),
                    ("image", required(Schema::String)),
                ]),
            ]),
        ),
        (
            "EditableProfile".into(),
            object([
                ("expectedRevision", required(Schema::String)),
                (
                    "vpnPolicy",
                    optional(union(vec![Schema::Null, reference("VpnPolicy")])),
                ),
                ("vlessCore", optional(reference("VlessCore"))),
                ("id", required(Schema::String)),
                ("reference", optional(Schema::String)),
                ("name", required(Schema::String)),
                ("groupId", required(Schema::String)),
                ("kind", required(reference("ProfileKind"))),
                ("config", required(map(Schema::Json))),
                ("favorite", required(Schema::Boolean)),
            ]),
        ),
        (
            "ProfileEditRequest".into(),
            object([
                ("expectedRevision", optional(Schema::String)),
                (
                    "vpnPolicy",
                    optional(union(vec![Schema::Null, reference("VpnPolicy")])),
                ),
                (
                    "vlessCore",
                    optional(union(vec![
                        Schema::Null,
                        union(vec![
                            literal("default"),
                            literal("xray"),
                            literal("sing-box"),
                        ]),
                    ])),
                ),
                ("id", optional(nullable(Schema::String))),
                ("reference", optional(Schema::String)),
                ("name", required(Schema::String)),
                ("groupId", required(Schema::String)),
                ("kind", required(reference("ProfileKind"))),
                ("config", required(map(Schema::Json))),
            ]),
        ),
        (
            "ProfileDraft".into(),
            object([
                ("expectedRevision", optional(Schema::String)),
                (
                    "vpnPolicy",
                    optional(union(vec![Schema::Null, reference("VpnPolicy")])),
                ),
                ("vlessCore", optional(reference("VlessCore"))),
                ("id", optional(Schema::String)),
                ("reference", optional(Schema::String)),
                ("name", required(Schema::String)),
                ("groupId", required(Schema::String)),
                ("kind", required(reference("ProfileKind"))),
                ("config", required(map(Schema::Json))),
            ]),
        ),
        (
            "GroupSummary".into(),
            object([
                ("proxyChain", optional(reference("GroupChain"))),
                (
                    "providerRouting",
                    optional(union(vec![Schema::Null, reference("ProviderRouting")])),
                ),
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                ("displayName", optional(Schema::String)),
                ("collapsed", optional(Schema::Boolean)),
                (
                    "announcement",
                    optional(union(vec![Schema::Null, Schema::String])),
                ),
                ("subscribed", optional(Schema::Boolean)),
                ("autoClearUnavailable", optional(Schema::Boolean)),
                (
                    "updatedAt",
                    optional(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "usage",
                    optional(union(vec![Schema::Null, reference("SubscriptionUsage")])),
                ),
                ("intervalMinutes", optional(Schema::Number)),
                (
                    "nextUpdateAt",
                    optional(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "lastUpdate",
                    optional(union(vec![Schema::Null, reference("LastUpdate")])),
                ),
            ]),
        ),
        (
            "GroupChain".into(),
            object([
                ("front", required(union(vec![Schema::Null, Schema::String]))),
                (
                    "landing",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
            ]),
        ),
        (
            "ProfileSummary".into(),
            object([
                ("ipSpeedSupported", optional(Schema::Boolean)),
                ("poolEligible", required(Schema::Boolean)),
                ("vpn", required(Schema::Boolean)),
                ("security", optional(Schema::String)),
                ("securityLevel", optional(Schema::Number)),
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                ("groupId", required(Schema::String)),
                ("kind", required(reference("ProfileKind"))),
                ("protocol", required(Schema::String)),
                ("address", required(Schema::String)),
                ("port", optional(Schema::Number)),
                ("favorite", required(Schema::Boolean)),
                (
                    "measurement",
                    optional(union(vec![Schema::Null, reference("Measurement")])),
                ),
                (
                    "ipMeasurement",
                    optional(union(vec![Schema::Null, reference("Measurement")])),
                ),
                (
                    "speedMeasurement",
                    optional(union(vec![Schema::Null, reference("Measurement")])),
                ),
                (
                    "traffic",
                    optional(object([
                        ("upload", required(Schema::Number)),
                        ("download", required(Schema::Number)),
                    ])),
                ),
            ]),
        ),
        (
            "GroupDraft".into(),
            object([
                ("proxyChain", optional(nullable(reference("GroupChain")))),
                ("autoClearUnavailable", optional(Schema::Boolean)),
                ("id", optional(nullable(Schema::String))),
                ("name", required(Schema::String)),
                (
                    "subscription",
                    optional(union(vec![
                        Schema::Null,
                        reference("SubscriptionSettingsInput"),
                    ])),
                ),
            ]),
        ),
        (
            "DuplicateEntry".into(),
            object([
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                (
                    "reason",
                    required(union(vec![
                        Schema::Null,
                        literal("routing"),
                        literal("chain"),
                        literal("running"),
                        literal("otp"),
                        literal("selected"),
                        literal("favorite"),
                        literal("first"),
                    ])),
                ),
            ]),
        ),
        (
            "DuplicatesPreview".into(),
            object([
                ("token", required(Schema::String)),
                ("count", required(Schema::Number)),
                (
                    "clusters",
                    required(array(object([
                        ("groupId", required(Schema::String)),
                        ("keep", required(array(reference("DuplicateEntry")))),
                        ("remove", required(array(reference("DuplicateEntry")))),
                    ]))),
                ),
            ]),
        ),
        ("Configuration".into(), map(Schema::Json)),
        (
            "WarpConfig".into(),
            object([
                ("privateKey", required(Schema::String)),
                ("clientPublicKey", required(Schema::String)),
                ("peerPublicKey", required(Schema::String)),
                ("endpoint", required(Schema::String)),
                ("host", required(Schema::String)),
                ("port", required(Schema::Number)),
                ("addresses", required(array(Schema::String))),
                ("reserved", required(array(Schema::Number))),
                ("mtu", required(Schema::Number)),
                ("persistentKeepalive", required(Schema::Number)),
            ]),
        ),
        (
            "ProfileExport".into(),
            object([
                ("name", required(Schema::String)),
                ("kind", required(reference("ProfileKind"))),
                ("config", required(map(Schema::Json))),
                ("reference", optional(Schema::String)),
                ("vlessCore", optional(reference("VlessCore"))),
                ("vpnPolicy", optional(nullable(reference("VpnPolicy")))),
            ]),
        ),
    ]
}
