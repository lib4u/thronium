//! Routing profiles, sources and geodata.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "applyRouting".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "cancelXrayGeodataDownload".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "checkRouting".into(),
            Command {
                request: reference("RouteProfile"),
                response: Schema::Null,
            },
        ),
        (
            "downloadXrayGeodata".into(),
            Command {
                request: object([
                    ("requestId", required(Schema::String)),
                    (
                        "selection",
                        required(object([
                            ("kind", required(reference("GeodataAssetKind"))),
                            ("url", required(Schema::String)),
                        ])),
                    ),
                ]),
                response: reference("GeodataAssetStatus"),
            },
        ),
        (
            "exportRoutingProfile".into(),
            Command {
                request: object([("id", required(Schema::String))]),
                response: object([
                    ("format", required(literal("thronium-routing-profile"))),
                    ("version", required(literal(1))),
                    ("profile", required(reference("RouteProfile"))),
                ]),
            },
        ),
        (
            "cancelRoutingDownload".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "fetchRoutingSource".into(),
            Command {
                request: object([
                    ("url", required(Schema::String)),
                    ("requestId", optional(Schema::String)),
                ]),
                response: object([("text", required(Schema::String))]),
            },
        ),
        (
            "refreshRoutingSource".into(),
            Command {
                request: object([
                    ("id", required(Schema::String)),
                    ("requestId", optional(Schema::String)),
                ]),
                response: reference("Routing"),
            },
        ),
        (
            "geodataCategory".into(),
            Command {
                request: object([
                    ("kind", required(reference("GeoKind"))),
                    ("url", optional(Schema::String)),
                    ("category", required(Schema::String)),
                ]),
                response: object([("rules", required(array(map(Schema::Json))))]),
            },
        ),
        (
            "geodataSources".into(),
            Command {
                request: object([]),
                response: array(reference("GeoSummary")),
            },
        ),
        (
            "importThroneRoute".into(),
            Command {
                request: object([
                    ("text", required(Schema::String)),
                    ("name", required(Schema::String)),
                    ("url", optional(Schema::String)),
                ]),
                response: reference("RouteProfile"),
            },
        ),
        (
            "loadGeodata".into(),
            Command {
                request: object([
                    ("requestId", optional(Schema::String)),
                    ("kind", required(reference("GeoKind"))),
                    ("url", optional(Schema::String)),
                    ("data", optional(Schema::String)),
                    ("force", optional(Schema::Boolean)),
                    ("name", optional(Schema::String)),
                ]),
                response: reference("GeoSource"),
            },
        ),
        (
            "routing".into(),
            Command {
                request: object([]),
                response: reference("Routing"),
            },
        ),
        (
            "saveRouting".into(),
            Command {
                request: reference("Routing"),
                response: reference("Routing"),
            },
        ),
        (
            "subscriptionRouting".into(),
            Command {
                request: object([("groupId", required(Schema::String))]),
                response: object([
                    ("groupId", required(Schema::String)),
                    (
                        "profile",
                        required(union(vec![Schema::Null, reference("RouteProfile")])),
                    ),
                    ("error", required(union(vec![Schema::Null, Schema::String]))),
                    ("pinnedResolvers", required(Schema::Boolean)),
                ]),
            },
        ),
        (
            "useSubscriptionRouting".into(),
            Command {
                request: object([
                    ("revision", required(Schema::Number)),
                    ("keptName", required(Schema::String)),
                ]),
                response: reference("Routing"),
            },
        ),
        (
            "xrayGeodataSources".into(),
            Command {
                request: object([]),
                response: reference("GeodataAssetSources"),
            },
        ),
        (
            "xrayGeodataStatus".into(),
            Command {
                request: object([
                    (
                        "kind",
                        required(union(vec![literal("geoip"), literal("geosite")])),
                    ),
                    ("url", required(Schema::String)),
                ]),
                response: reference("GeodataAssetStatus"),
            },
        ),
    ]
}
