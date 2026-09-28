//! Profiles and groups of the library.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "addGroup".into(),
            Command {
                request: object([("name", required(Schema::String))]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "checkImportProfile".into(),
            Command {
                request: object([
                    ("profiles", required(array(reference("ProfileDraft")))),
                    ("index", required(Schema::Number)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "checkProfile".into(),
            Command {
                request: reference("ProfileEditRequest"),
                response: Schema::Null,
            },
        ),
        (
            "collapseGroup".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("collapsed", required(Schema::Boolean)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "delete".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "deleteGroup".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("deleteProfiles", optional(Schema::Boolean)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "deleteProfiles".into(),
            Command {
                request: object([
                    ("ids", required(array(Schema::String))),
                    ("groupId", optional(Schema::String)),
                ]),
                response: object([("count", required(Schema::Number))]),
            },
        ),
        (
            "maintenanceCandidates".into(),
            Command {
                request: object([
                    (
                        "kind",
                        required(union(vec![
                            literal("unavailable"),
                            literal("insecure"),
                            literal("named"),
                        ])),
                    ),
                    ("ids", required(array(Schema::String))),
                ]),
                response: object([("ids", required(array(Schema::String)))]),
            },
        ),
        (
            "resetProfileTraffic".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: Schema::Null,
            },
        ),
        (
            "resolveProfileAddresses".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: object([
                    ("resolved", required(Schema::Number)),
                    ("named", required(Schema::Number)),
                ]),
            },
        ),
        (
            "discardDuplicates".into(),
            Command {
                request: object([("token", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "favorite".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "generateWgKeys".into(),
            Command {
                request: object([]),
                response: object([
                    ("privateKey", required(Schema::String)),
                    ("publicKey", required(Schema::String)),
                ]),
            },
        ),
        (
            "group".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: object([
                    ("proxyChain", optional(reference("GroupChain"))),
                    ("autoClearUnavailable", optional(Schema::Boolean)),
                    ("id", optional(Schema::String)),
                    ("name", required(Schema::String)),
                    // A group without a subscription omits the field entirely.
                    (
                        "subscription",
                        optional(union(vec![Schema::Null, reference("SubscriptionSettings")])),
                    ),
                ]),
            },
        ),
        (
            "importProfiles".into(),
            Command {
                request: object([("profiles", required(array(reference("ProfileDraft"))))]),
                response: object([("ids", required(array(Schema::String)))]),
            },
        ),
        (
            "moveGroup".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("offset", required(Schema::Number)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "moveProfiles".into(),
            Command {
                request: object([
                    ("ids", required(array(Schema::String))),
                    ("groupId", required(Schema::String)),
                ]),
                response: object([("count", required(Schema::Number))]),
            },
        ),
        (
            "previewDuplicates".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: reference("DuplicatesPreview"),
            },
        ),
        (
            "profile".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: reference("EditableProfile"),
            },
        ),
        (
            "removeDuplicates".into(),
            Command {
                request: object([("token", required(Schema::String))]),
                response: object([("count", required(Schema::Number))]),
            },
        ),
        (
            "reorderGroup".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("targetId", required(Schema::String)),
                    ("after", required(Schema::Boolean)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "reorderProfile".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("targetId", required(Schema::String)),
                    ("after", required(Schema::Boolean)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "saveGroup".into(),
            Command {
                request: reference("GroupDraft"),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "saveProfile".into(),
            Command {
                request: reference("ProfileEditRequest"),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "saveProfileConfiguration".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("expectedRevision", required(Schema::String)),
                    ("config", required(map(Schema::Json))),
                ]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "saveProfileCore".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("expectedRevision", required(Schema::String)),
                    (
                        "core",
                        required(union(vec![Schema::Null, reference("VlessCore")])),
                    ),
                ]),
                response: reference("EditableProfile"),
            },
        ),
        (
            "select".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "setVlessCore".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    (
                        "core",
                        required(union(vec![Schema::Null, reference("VlessCore")])),
                    ),
                ]),
                response: Schema::Null,
            },
        ),
    ]
}
