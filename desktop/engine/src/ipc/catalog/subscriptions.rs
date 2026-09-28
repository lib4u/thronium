//! Subscription previews, updates and the update worker.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "applySubscription".into(),
            Command {
                request: object([
                    ("ticket", required(Schema::String)),
                    ("useProviderRouting", optional(Schema::Boolean)),
                ]),
                response: array(reference("SubscriptionChange")),
            },
        ),
        (
            "applySubscriptionJob".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("owner", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "cancelSubscription".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "cancelSubscriptionUpdates".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "checkSubscriptionJob".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("owner", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "checkSubscriptionProfile".into(),
            Command {
                request: object([
                    ("ticket", required(Schema::String)),
                    ("profileId", required(Schema::String)),
                    ("useProviderRouting", optional(Schema::Boolean)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "claimSubscriptionJob".into(),
            Command {
                request: object([("owner", required(Schema::String))]),
                response: union(vec![
                    Schema::Null,
                    object([
                        ("id", required(Schema::String)),
                        ("groupId", required(Schema::String)),
                    ]),
                ]),
            },
        ),
        (
            "clearSubscriptionJobs".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "discardSubscription".into(),
            Command {
                request: object([("ticket", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "failSubscriptionJob".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("owner", required(Schema::String)),
                    ("error", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "fetchSubscription".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("requestId", required(Schema::String)),
                ]),
                response: reference("SubscriptionDownload"),
            },
        ),
        (
            "fetchSubscriptionJob".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("owner", required(Schema::String)),
                ]),
                response: object([("body", required(Schema::String))]),
            },
        ),
        (
            "prepareSubscriptionJob".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("owner", required(Schema::String)),
                    ("profiles", required(array(reference("ProfileDraft")))),
                    (
                        "omitted",
                        optional(object([
                            ("skipped", required(Schema::Number)),
                            ("warned", required(Schema::Number)),
                        ])),
                    ),
                ]),
                response: object([("checks", required(Schema::Number))]),
            },
        ),
        (
            "previewSubscription".into(),
            Command {
                request: object([
                    ("ticket", required(Schema::String)),
                    ("profiles", required(array(reference("ProfileDraft")))),
                ]),
                response: array(reference("SubscriptionChange")),
            },
        ),
        (
            "releaseSubscriptionWorker".into(),
            Command {
                request: object([("owner", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "startSubscriptionUpdates".into(),
            Command {
                request: object([("id", optional(Schema::String))]),
                response: object([("queued", required(Schema::Number))]),
            },
        ),
    ]
}
