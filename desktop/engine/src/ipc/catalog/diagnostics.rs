//! Tests, logs, process usage and measurement histories.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "cancelSettingsTest".into(),
            Command {
                request: object([("requestId", optional(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "cancelUrlTestBatch".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: Schema::Boolean,
            },
        ),
        (
            "cancelUrlTests".into(),
            Command {
                request: union(vec![
                    object([("ids", required(array(Schema::String)))]),
                    object([]),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "clearLogs".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "clearUrlTests".into(),
            Command {
                request: union(vec![
                    object([("ids", required(array(Schema::String)))]),
                    object([]),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "exportLogs".into(),
            Command {
                request: object([("text", required(Schema::String))]),
                response: object([("status", required(Schema::String))]),
            },
        ),
        (
            "getLogs".into(),
            Command {
                request: object([
                    ("search", optional(Schema::String)),
                    ("level", optional(Schema::String)),
                    ("source", optional(Schema::String)),
                    ("scope", optional(Schema::String)),
                ]),
                response: reference("LogView"),
            },
        ),
        (
            "processMetrics".into(),
            Command {
                request: object([("reset", optional(Schema::Boolean))]),
                response: reference("ResourceSnapshot"),
            },
        ),
        (
            "savePingSettings".into(),
            Command {
                request: object([
                    ("method", optional(reference("PingMethod"))),
                    ("url", required(Schema::String)),
                    ("timeoutMs", required(Schema::Number)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "startIpTests".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "startPing".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "startSpeedTests".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "startUrlTests".into(),
            Command {
                request: object([
                    ("ids", required(array(Schema::String))),
                    ("url", required(Schema::String)),
                    ("timeoutMs", required(Schema::Number)),
                    ("method", optional(reference("PingMethod"))),
                    ("concurrency", optional(Schema::Number)),
                ]),
                response: object([("id", required(Schema::String))]),
            },
        ),
        (
            "testInternet".into(),
            Command {
                request: object([
                    ("requestId", optional(Schema::String)),
                    ("id", optional(union(vec![Schema::Null, Schema::String]))),
                ]),
                response: object([("result", required(reference("ConnectionTestResult")))]),
            },
        ),
        (
            "testIp".into(),
            Command {
                request: object([
                    ("requestId", optional(Schema::String)),
                    ("id", required(Schema::String)),
                ]),
                response: object([("result", required(reference("ConnectionTestResult")))]),
            },
        ),
        (
            "testSpeed".into(),
            Command {
                request: object([
                    ("requestId", optional(Schema::String)),
                    ("id", required(Schema::String)),
                ]),
                response: object([("result", required(reference("ConnectionTestResult")))]),
            },
        ),
        (
            "getMeasurementJournal".into(),
            Command {
                request: object([]),
                response: reference("MeasurementJournal"),
            },
        ),
        (
            "clearMeasurementJournal".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "getSwitchHistory".into(),
            Command {
                request: object([]),
                response: reference("SwitchHistory"),
            },
        ),
        (
            "clearSwitchHistory".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
    ]
}
