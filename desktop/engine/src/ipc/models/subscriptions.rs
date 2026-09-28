//! Subscription settings, updates and their jobs.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "SubscriptionJob".into(),
            object([
                ("id", required(Schema::String)),
                ("batchId", required(Schema::String)),
                ("groupId", required(Schema::String)),
                ("groupName", required(Schema::String)),
                ("scheduled", required(Schema::Boolean)),
                ("status", required(reference("UpdateStatus"))),
                ("checked", required(Schema::Number)),
                ("total", required(Schema::Number)),
                ("createdAt", required(Schema::Number)),
                (
                    "finishedAt",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
                ("counts", required(reference("UpdateCounts"))),
            ]),
        ),
        (
            "SubscriptionNameRules".into(),
            object([
                ("include", required(Schema::String)),
                ("exclude", required(Schema::String)),
                (
                    "rename",
                    required(array(object([
                        ("pattern", required(Schema::String)),
                        ("replacement", required(Schema::String)),
                    ]))),
                ),
            ]),
        ),
        (
            "SubscriptionSettings".into(),
            object([
                ("nameRules", optional(reference("SubscriptionNameRules"))),
                (
                    "inheritDefaults",
                    optional(union(vec![Schema::Null, literal(false), literal(true)])),
                ),
                ("url", required(Schema::String)),
                ("userAgent", required(Schema::String)),
                ("headers", required(map(Schema::String))),
                ("viaProxy", required(Schema::Boolean)),
                ("intervalMinutes", optional(Schema::Number)),
                ("useProviderRouting", optional(Schema::Boolean)),
            ]),
        ),
        (
            "SubscriptionUsage".into(),
            object([
                (
                    "upload",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "download",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                ("total", required(union(vec![Schema::Null, Schema::Number]))),
                (
                    "expire",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
            ]),
        ),
        (
            "UpdateCounts".into(),
            object([
                ("added", required(Schema::Number)),
                ("updated", required(Schema::Number)),
                ("removed", required(Schema::Number)),
                ("kept", required(Schema::Number)),
                ("unchanged", required(Schema::Number)),
                ("skipped", required(Schema::Number)),
                ("warned", required(Schema::Number)),
            ]),
        ),
        (
            "UpdateStatus".into(),
            union(vec![
                literal("error"),
                literal("updated"),
                literal("unchanged"),
                literal("queued"),
                literal("cancelled"),
                literal("downloading"),
                literal("checking"),
                literal("needs-review"),
            ]),
        ),
        (
            "SubscriptionChange".into(),
            object([
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                (
                    "action",
                    required(union(vec![
                        literal("added"),
                        literal("updated"),
                        literal("unchanged"),
                        literal("kept"),
                        literal("removed"),
                    ])),
                ),
                (
                    "reason",
                    required(union(vec![
                        Schema::Null,
                        literal("routing"),
                        literal("chain"),
                        literal("running"),
                        literal("retained"),
                    ])),
                ),
            ]),
        ),
        (
            "SubscriptionDownload".into(),
            object([
                ("ticket", required(Schema::String)),
                ("body", required(Schema::String)),
                (
                    "usage",
                    required(union(vec![Schema::Null, reference("SubscriptionUsage")])),
                ),
                (
                    "providerRouting",
                    required(union(vec![Schema::Null, reference("ProviderRouting")])),
                ),
            ]),
        ),
    ]
}
