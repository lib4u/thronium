//! Exports, the clipboard and QR codes.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "decodeQrImage".into(),
            Command {
                request: object([("data", required(Schema::String))]),
                response: array(Schema::String),
            },
        ),
        (
            "exportArchive".into(),
            Command {
                request: object([
                    ("data", required(Schema::String)),
                    (
                        "format",
                        required(union(vec![
                            literal("wireguard-archive"),
                            literal("qr-archive"),
                        ])),
                    ),
                ]),
                response: object([("status", required(Schema::String))]),
            },
        ),
        (
            "exportConfiguration".into(),
            Command {
                request: object([
                    ("config", required(map(Schema::Json))),
                    (
                        "destination",
                        required(union(vec![literal("file"), literal("clipboard")])),
                    ),
                    ("sourceProfileId", optional(Schema::String)),
                ]),
                response: reference("DeliveryResult"),
            },
        ),
        (
            "exportProfiles".into(),
            Command {
                request: object([
                    ("ids", required(array(Schema::String))),
                    ("format", required(Schema::String)),
                    ("destination", required(Schema::String)),
                ]),
                response: reference("DeliveryResult"),
            },
        ),
        (
            "exportQr".into(),
            Command {
                request: object([
                    ("text", required(Schema::String)),
                    ("destination", required(Schema::String)),
                ]),
                response: reference("DeliveryResult"),
            },
        ),
        (
            "exportSharedText".into(),
            Command {
                request: object([
                    ("text", required(Schema::String)),
                    ("format", required(Schema::String)),
                    ("destination", required(Schema::String)),
                ]),
                response: reference("DeliveryResult"),
            },
        ),
        (
            "readClipboard".into(),
            Command {
                request: object([]),
                response: Schema::String,
            },
        ),
        (
            "readQrClipboard".into(),
            Command {
                request: object([]),
                response: array(Schema::String),
            },
        ),
        (
            "scanScreenQr".into(),
            Command {
                request: object([]),
                response: array(Schema::String),
            },
        ),
        (
            "writeClipboard".into(),
            Command {
                request: object([("text", required(Schema::String))]),
                response: object([("status", required(Schema::String))]),
            },
        ),
    ]
}
