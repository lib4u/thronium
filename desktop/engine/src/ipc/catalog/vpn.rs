//! VPN authentication, credentials and OTP bindings.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "cancelVpnChallenge".into(),
            Command {
                request: reference("VpnChallengeRequest"),
                response: Schema::Null,
            },
        ),
        (
            "cancelVpnCredentials".into(),
            Command {
                request: object([
                    ("editToken", required(Schema::String)),
                    ("sessionId", required(Schema::String)),
                    ("endpointTag", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "getVpnOtpBinding".into(),
            Command {
                request: object([("profileId", required(Schema::String))]),
                response: reference("VpnOtpBinding"),
            },
        ),
        (
            "openVpnChallengeUrl".into(),
            Command {
                request: reference("VpnChallengeRequest"),
                response: Schema::Null,
            },
        ),
        (
            "restartVpnCredentials".into(),
            Command {
                request: object([
                    ("editToken", required(Schema::String)),
                    ("username", required(Schema::String)),
                    ("password", required(Schema::String)),
                    ("sessionId", required(Schema::String)),
                    ("endpointTag", required(Schema::String)),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "saveVpnOtpBinding".into(),
            Command {
                request: object([
                    ("profileId", required(Schema::String)),
                    ("editToken", required(Schema::String)),
                    ("otpId", required(union(vec![Schema::Null, Schema::String]))),
                    (
                        "otpRevision",
                        required(union(vec![Schema::Null, Schema::String])),
                    ),
                    ("mode", optional(reference("VpnBindingMode"))),
                ]),
                response: reference("VpnOtpBinding"),
            },
        ),
        (
            "submitVpnChallenge".into(),
            Command {
                request: object([
                    ("sessionId", required(Schema::String)),
                    ("endpointTag", required(Schema::String)),
                    ("challengeId", required(Schema::String)),
                    ("username", optional(Schema::String)),
                    ("password", optional(Schema::String)),
                    ("secret", optional(Schema::String)),
                    ("formValues", optional(map(Schema::String))),
                ]),
                response: Schema::Null,
            },
        ),
        (
            "vpnChallenge".into(),
            Command {
                request: reference("VpnChallengeRequest"),
                response: reference("VpnChallenge"),
            },
        ),
        (
            "vpnChallengeUrl".into(),
            Command {
                request: reference("VpnChallengeRequest"),
                response: Schema::String,
            },
        ),
        (
            "vpnCredentials".into(),
            Command {
                request: reference("VpnCredentialRequest"),
                response: reference("VpnCredentials"),
            },
        ),
    ]
}
