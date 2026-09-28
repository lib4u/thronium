//! Backups and the Throne backup review.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "LegacyBackupScopes".into(),
            object([
                ("profiles", required(Schema::Boolean)),
                ("routes", required(Schema::Boolean)),
                ("otp", optional(Schema::Boolean)),
                ("icons", optional(Schema::Boolean)),
                (
                    "settings",
                    optional(object([
                        ("appearance", optional(Schema::Boolean)),
                        ("testing", optional(Schema::Boolean)),
                        ("logging", optional(Schema::Boolean)),
                        ("geodata", optional(Schema::Boolean)),
                        ("warp", optional(Schema::Boolean)),
                        ("network", optional(Schema::Boolean)),
                        ("subscriptions", optional(Schema::Boolean)),
                        ("inbound", optional(Schema::Boolean)),
                        ("system", optional(Schema::Boolean)),
                        ("presets", optional(Schema::Boolean)),
                        ("intercept", optional(Schema::Boolean)),
                        ("tun", optional(Schema::Boolean)),
                        ("core", optional(Schema::Boolean)),
                        ("hotkeys", optional(Schema::Boolean)),
                    ])),
                ),
                (
                    "autoSelectors",
                    optional(union(vec![
                        literal("require-choice"),
                        literal("last-built"),
                    ])),
                ),
                (
                    "vpnBindings",
                    optional(union(vec![
                        literal("auto-live"),
                        literal("automatic"),
                        literal("require-choice"),
                        literal("manual"),
                    ])),
                ),
            ]),
        ),
        (
            "LegacyBackupPreview".into(),
            object([
                ("format", required(literal("throne-backup"))),
                (
                    "mode",
                    required(union(vec![
                        literal("add-profiles"),
                        literal("add-selected"),
                    ])),
                ),
                (
                    "createdAt",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "resources",
                    optional(array(object([
                        ("id", required(Schema::String)),
                        ("path", required(Schema::String)),
                        (
                            "kind",
                            required(union(vec![
                                literal("hosts"),
                                literal("rule-set-source"),
                                literal("rule-set-binary"),
                                literal("pem"),
                                literal("text"),
                                literal("geodata"),
                            ])),
                        ),
                        (
                            "entity",
                            required(union(vec![literal("route"), literal("profile")])),
                        ),
                        ("name", optional(Schema::String)),
                        ("selected", required(Schema::Boolean)),
                        ("bytes", required(Schema::Number)),
                    ]))),
                ),
                ("canApply", required(Schema::Boolean)),
                (
                    "inventory",
                    required(object([
                        ("containerVersion", required(Schema::Number)),
                        ("profiles", required(Schema::Number)),
                        ("groups", required(Schema::Number)),
                        ("routes", required(Schema::Number)),
                        ("rules", required(Schema::Number)),
                        ("settings", required(Schema::Number)),
                        ("otp", required(Schema::Number)),
                        ("icons", required(Schema::Number)),
                        ("parts", required(map(Schema::Boolean))),
                    ])),
                ),
                ("scopes", required(reference("LegacyBackupScopes"))),
                ("routeCount", required(Schema::Number)),
                ("otpCount", optional(Schema::Number)),
                ("iconCount", optional(Schema::Number)),
                ("trafficBuckets", optional(Schema::Number)),
                ("requirements", required(array(Schema::String))),
                (
                    "settingsGroups",
                    optional(object([
                        (
                            "appearance",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "testing",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "logging",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "geodata",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "warp",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "network",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "subscriptions",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "inbound",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "system",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "presets",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "intercept",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "tun",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "core",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                        (
                            "hotkeys",
                            optional(object([
                                ("count", required(Schema::Number)),
                                ("fields", required(array(Schema::String))),
                            ])),
                        ),
                    ])),
                ),
                ("settingsCount", optional(Schema::Number)),
                ("settingsDeferred", optional(Schema::Number)),
                ("autoSelectorCount", optional(Schema::Number)),
                (
                    "selectorSnapshots",
                    optional(array(object([
                        ("sourceId", required(Schema::Number)),
                        ("name", required(Schema::String)),
                        ("members", required(Schema::Number)),
                        ("pinned", required(Schema::Boolean)),
                    ]))),
                ),
                ("externalCoreCount", optional(Schema::Number)),
                ("vpnBindingCount", optional(Schema::Number)),
                ("vpnBindingsPlanned", optional(Schema::Number)),
                (
                    "vpnBindings",
                    optional(array(object([
                        ("sourceId", required(Schema::Number)),
                        ("name", required(Schema::String)),
                        ("otpSourceId", required(Schema::Number)),
                        ("otpName", optional(Schema::String)),
                        ("manualAllowed", required(Schema::Boolean)),
                        ("mode", optional(reference("VpnBindingMode"))),
                    ]))),
                ),
                (
                    "issues",
                    required(array(object([
                        ("code", required(Schema::String)),
                        (
                            "entity",
                            required(union(vec![Schema::Null, Schema::String])),
                        ),
                        (
                            "sourceId",
                            required(union(vec![Schema::Null, Schema::Number])),
                        ),
                        ("name", required(union(vec![Schema::Null, Schema::String]))),
                    ]))),
                ),
            ]),
        ),
        (
            "BackupPreview".into(),
            object([
                ("token", required(Schema::String)),
                ("createdAt", required(Schema::Number)),
                ("current", required(reference("BackupSummary"))),
                ("incoming", required(reference("BackupSummary"))),
                ("legacy", optional(reference("LegacyBackupPreview"))),
            ]),
        ),
        (
            "BackupSummary".into(),
            object([
                ("icons", optional(Schema::Number)),
                ("profiles", required(Schema::Number)),
                ("groups", required(Schema::Number)),
                ("subscriptions", required(Schema::Number)),
                ("routingProfiles", required(Schema::Number)),
                ("language", required(Schema::String)),
                ("settings", required(Schema::Number)),
                ("otp", required(Schema::Number)),
                ("autostart", required(Schema::Boolean)),
                ("deepLinks", required(Schema::Boolean)),
            ]),
        ),
    ]
}
