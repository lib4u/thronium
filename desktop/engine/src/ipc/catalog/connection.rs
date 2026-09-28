//! Connecting, the snapshot, preferences and traffic.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "cancelConnectionPreparation".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Boolean,
            },
        ),
        (
            "clearTrafficHistory".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "closeConnections".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: Schema::Null,
            },
        ),
        (
            "connect".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "connectionConfiguration".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("active", optional(Schema::Boolean)),
                ]),
                response: object([(
                    "parts",
                    required(array(object([
                        ("name", required(Schema::String)),
                        ("config", required(map(Schema::Json))),
                    ]))),
                )]),
            },
        ),
        (
            "connectionSettings".into(),
            Command {
                request: object([
                    ("mode", required(reference("ConnectionMode"))),
                    ("vlessCore", optional(reference("VlessCore"))),
                    ("port", required(Schema::Number)),
                    ("tun", optional(reference("TunSettings"))),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "disconnect".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "preferences".into(),
            Command {
                request: reference("Preferences"),
                response: Schema::Null,
            },
        ),
        (
            "restoreSystemProxy".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "snapshot".into(),
            Command {
                request: object([]),
                response: reference("Snapshot"),
            },
        ),
        (
            "trafficHistory".into(),
            Command {
                request: object([]),
                response: array(reference("TrafficHistoryEntry")),
            },
        ),
        (
            "trafficStats".into(),
            Command {
                request: object([
                    ("days", required(Schema::Number)),
                    ("utcOffsetMinutes", required(Schema::Number)),
                ]),
                response: reference("TrafficStats"),
            },
        ),
    ]
}
