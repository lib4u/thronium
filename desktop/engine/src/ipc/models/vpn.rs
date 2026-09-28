//! VPN endpoint status, authentication, credentials and OTP bindings.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "VpnChallenge".into(),
            object([
                ("sessionId", required(Schema::String)),
                ("endpointTag", required(Schema::String)),
                ("challengeId", required(Schema::String)),
                ("kind", required(Schema::String)),
                ("username", required(Schema::String)),
                ("message", required(Schema::String)),
                ("banner", required(Schema::String)),
                ("error", required(Schema::String)),
                ("echo", required(Schema::Boolean)),
                ("deadline", required(Schema::Number)),
                ("fields", required(array(reference("VpnChallengeField")))),
            ]),
        ),
        (
            "VpnChallengeField".into(),
            object([
                ("submissionKey", required(Schema::String)),
                ("name", required(Schema::String)),
                ("label", required(Schema::String)),
                ("kind", required(Schema::String)),
                ("value", required(Schema::String)),
                (
                    "options",
                    required(array(object([
                        ("value", required(Schema::String)),
                        ("label", required(Schema::String)),
                    ]))),
                ),
            ]),
        ),
        (
            "VpnChallengeRequest".into(),
            object([
                ("sessionId", required(Schema::String)),
                ("endpointTag", required(Schema::String)),
                ("challengeId", required(Schema::String)),
            ]),
        ),
        (
            "VpnEndpoint".into(),
            object([
                (
                    "otp",
                    optional(union(vec![Schema::Null, reference("VpnOtpStatus")])),
                ),
                ("tag", required(Schema::String)),
                ("protocol", required(Schema::String)),
                ("state", required(Schema::String)),
                (
                    "challengeId",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                (
                    "challengeKind",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("authFailed", required(Schema::Boolean)),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
                (
                    "tunnel",
                    required(union(vec![Schema::Null, reference("VpnTunnel")])),
                ),
            ]),
        ),
        (
            "VpnTunnel".into(),
            object([
                ("server", required(Schema::String)),
                ("network", required(Schema::String)),
                ("cipher", required(Schema::String)),
                ("mtu", required(Schema::Number)),
                ("connectedSince", required(Schema::Number)),
                ("ipv4", required(array(Schema::String))),
                ("ipv6", required(array(Schema::String))),
                ("dns", required(array(Schema::String))),
                ("routes", required(array(Schema::String))),
                ("excludedRoutes", required(array(Schema::String))),
                ("searchDomains", required(array(Schema::String))),
            ]),
        ),
        (
            "VpnOtpStatus".into(),
            object([
                (
                    "state",
                    required(union(vec![
                        literal("manual"),
                        literal("error"),
                        literal("ready"),
                        literal("disabled"),
                        literal("waiting"),
                        literal("limited"),
                        literal("start"),
                    ])),
                ),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
            ]),
        ),
        (
            "VpnPolicy".into(),
            object([
                ("onlyAdvertisedRoutes", required(Schema::Boolean)),
                ("useTunnelDns", required(Schema::Boolean)),
                ("blockOutsideDns", required(Schema::Boolean)),
            ]),
        ),
        (
            "VpnStatus".into(),
            object([
                (
                    "sessionId",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("endpoints", required(array(reference("VpnEndpoint")))),
                ("error", required(union(vec![Schema::Null, Schema::String]))),
            ]),
        ),
        (
            "VpnOtpBinding".into(),
            object([
                (
                    "binding",
                    required(union(vec![
                        Schema::Null,
                        object([
                            ("revision", required(Schema::String)),
                            ("otpId", required(Schema::String)),
                            ("mode", required(reference("VpnBindingMode"))),
                        ]),
                    ])),
                ),
                ("editToken", required(Schema::String)),
                ("supported", required(Schema::Boolean)),
                ("hotpSupported", optional(Schema::Boolean)),
                (
                    "reason",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("startSupported", required(Schema::Boolean)),
                (
                    "startReason",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
            ]),
        ),
        (
            "VpnBindingOtpRow".into(),
            object([
                ("id", required(Schema::String)),
                ("revision", required(Schema::String)),
                ("name", required(Schema::String)),
                ("issuer", required(Schema::String)),
                ("type", required(reference("OtpType"))),
                ("counter", required(Schema::String)),
            ]),
        ),
        (
            "VpnCredentialRequest".into(),
            object([
                ("sessionId", required(Schema::String)),
                ("endpointTag", required(Schema::String)),
            ]),
        ),
        (
            "VpnCredentials".into(),
            object([
                ("sessionId", required(Schema::String)),
                ("endpointTag", required(Schema::String)),
                ("editToken", required(Schema::String)),
                ("username", required(Schema::String)),
            ]),
        ),
    ]
}
