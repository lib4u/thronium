//! Automatic selection pools.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "autoSelectorAction".into(),
            Command {
                request: object([
                    ("tag", required(Schema::String)),
                    ("action", required(Schema::String)),
                    ("member", optional(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "clearSelectorHistory".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "getAutoSelectors".into(),
            Command {
                request: object([]),
                response: array(reference("SelectorPool")),
            },
        ),
        (
            "getSelectorHistory".into(),
            Command {
                request: object([]),
                response: array(reference("SelectorHistoryPool")),
            },
        ),
        (
            "planSelectorMeasurements".into(),
            Command {
                request: object([("profile", required(reference("ProfileDraft")))]),
                response: object([
                    ("context", required(Schema::String)),
                    ("ids", required(array(Schema::String))),
                    ("candidateCount", required(Schema::Number)),
                    ("freshCount", required(Schema::Number)),
                    ("url", required(Schema::String)),
                    ("timeoutMs", required(Schema::Number)),
                ]),
            },
        ),
        (
            "saveAutoSelectSettings".into(),
            Command {
                request: object([
                    ("previous", required(map(Schema::Json))),
                    ("config", required(map(Schema::Json))),
                    ("failover", optional(Schema::Boolean)),
                    ("sourceGroupId", optional(nullable(Schema::String))),
                    (
                        "previousOptions",
                        optional(object([
                            ("failover", required(Schema::Boolean)),
                            ("sourceGroupId", required(nullable(Schema::String))),
                        ])),
                    ),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "previewSelector".into(),
            Command {
                request: object([("profile", required(reference("ProfileDraft")))]),
                response: reference("SelectorPreview"),
            },
        ),
        (
            "rankMeasuredSelector".into(),
            Command {
                request: object([
                    ("profile", required(reference("ProfileDraft"))),
                    ("context", required(Schema::String)),
                ]),
                response: reference("SelectorRanking"),
            },
        ),
        (
            "rankSelector".into(),
            Command {
                request: object([("profile", required(reference("ProfileDraft")))]),
                response: reference("SelectorRanking"),
            },
        ),
    ]
}
