//! The authenticator collection.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "OtpCode".into(),
            object([
                ("id", required(Schema::String)),
                ("code", required(Schema::String)),
                ("secondsRemaining", required(Schema::Number)),
                ("counter", optional(Schema::String)),
            ]),
        ),
        (
            "OtpDraft".into(),
            object([
                ("name", required(Schema::String)),
                ("issuer", required(Schema::String)),
                ("secret", required(Schema::String)),
                ("algorithm", required(reference("OtpAlgorithm"))),
                ("type", required(reference("OtpType"))),
                ("digits", required(Schema::Number)),
                ("period", required(Schema::Number)),
                ("counter", required(Schema::String)),
            ]),
        ),
        (
            "OtpEditRequest".into(),
            object([
                ("id", required(Schema::String)),
                ("revision", required(Schema::String)),
                ("value", required(reference("OtpDraft"))),
            ]),
        ),
        (
            "OtpRow".into(),
            object([
                ("name", required(Schema::String)),
                ("issuer", required(Schema::String)),
                ("algorithm", required(reference("OtpAlgorithm"))),
                ("type", required(reference("OtpType"))),
                ("digits", required(Schema::Number)),
                ("period", required(Schema::Number)),
                ("counter", required(Schema::String)),
                ("id", required(Schema::String)),
                ("revision", required(Schema::String)),
            ]),
        ),
    ]
}
