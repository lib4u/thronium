//! The authenticator collection.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "otpCodes".into(),
            Command {
                request: object([("ids", required(array(Schema::String)))]),
                response: array(reference("OtpCode")),
            },
        ),
        (
            "otpExport".into(),
            Command {
                request: object([
                    ("ids", required(array(Schema::String))),
                    ("format", required(reference("OtpExportFormat"))),
                ]),
                response: Schema::String,
            },
        ),
        (
            "otpGet".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: object([
                    ("name", required(Schema::String)),
                    ("issuer", required(Schema::String)),
                    ("secret", required(Schema::String)),
                    ("algorithm", required(reference("OtpAlgorithm"))),
                    ("type", required(reference("OtpType"))),
                    ("digits", required(Schema::Number)),
                    ("period", required(Schema::Number)),
                    ("counter", required(Schema::String)),
                    ("id", required(Schema::String)),
                    ("revision", required(Schema::String)),
                ]),
            },
        ),
        (
            "otpImport".into(),
            Command {
                request: object([("text", required(Schema::String))]),
                response: object([("added", required(Schema::Number))]),
            },
        ),
        (
            "otpList".into(),
            Command {
                request: object([]),
                response: array(reference("OtpRow")),
            },
        ),
        (
            "otpRemove".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("revision", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "otpReorder".into(),
            Command {
                request: object([
                    ("previous", required(array(Schema::String))),
                    ("ids", required(array(Schema::String))),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "otpSave".into(),
            Command {
                request: object([
                    ("id", optional(Schema::String)),
                    ("revision", optional(Schema::String)),
                    ("value", required(reference("OtpDraftInput"))),
                ]),
                response: reference("OtpRow"),
            },
        ),
    ]
}
