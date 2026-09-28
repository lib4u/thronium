//! Routing profiles, rules and geodata.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "GeoCategory".into(),
            object([
                ("code", required(Schema::String)),
                ("count", required(Schema::Number)),
                ("attributes", required(array(Schema::String))),
            ]),
        ),
        (
            "GeoSource".into(),
            object([
                ("kind", required(reference("GeoKind"))),
                ("url", required(Schema::String)),
                ("name", required(Schema::String)),
                ("hash", required(Schema::String)),
                ("bytes", required(Schema::Number)),
                ("updatedAt", required(Schema::Number)),
                ("categories", required(array(reference("GeoCategory")))),
            ]),
        ),
        (
            "GeoSummary".into(),
            object([
                ("name", required(Schema::String)),
                ("kind", required(reference("GeoKind"))),
                ("url", required(Schema::String)),
                ("hash", required(Schema::String)),
                ("bytes", required(Schema::Number)),
                ("updatedAt", required(Schema::Number)),
                ("count", required(Schema::Number)),
            ]),
        ),
        (
            "RouteProfile".into(),
            object([
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                ("mode", required(reference("RoutingMode"))),
                ("rules", required(array(reference("RouteRule")))),
                ("route", required(reference("Configuration"))),
                ("dns", required(reference("Configuration"))),
                (
                    "source",
                    optional(object([
                        ("url", required(Schema::String)),
                        ("importedAt", required(Schema::Number)),
                        ("autoUpdate", optional(Schema::Boolean)),
                        ("dnsCustomized", optional(Schema::Boolean)),
                        ("legacySettings", optional(reference("Configuration"))),
                        ("updateNotes", optional(array(Schema::String))),
                    ])),
                ),
                (
                    "legacyConstraints",
                    optional(object([
                        ("warpEnabled", optional(Schema::Boolean)),
                        ("rawVerbatim", optional(Schema::Boolean)),
                        ("adaptiveDns", optional(Schema::Boolean)),
                        ("endpoints", optional(array(Schema::String))),
                        ("inboundTags", optional(array(Schema::String))),
                        ("version", required(Schema::Number)),
                        (
                            "xrayDnsStrategy",
                            optional(union(vec![
                                literal("UseIP"),
                                literal("UseIPv4v6"),
                                literal("UseIPv6v4"),
                                literal("UseIPv4"),
                                literal("ForceIPv4"),
                                literal("ForceIPv6"),
                            ])),
                        ),
                    ])),
                ),
            ]),
        ),
        (
            "RouteRule".into(),
            object([
                ("id", required(Schema::String)),
                ("name", required(Schema::String)),
                ("enabled", required(Schema::Boolean)),
                ("config", required(reference("Configuration"))),
                ("simple", optional(Schema::String)),
            ]),
        ),
        (
            "Routing".into(),
            object([
                ("revision", required(Schema::Number)),
                ("active", required(Schema::String)),
                ("profiles", required(array(reference("RouteProfile")))),
            ]),
        ),
        (
            "GeodataAssetStatus".into(),
            object([
                ("kind", required(reference("GeodataAssetKind"))),
                ("url", required(Schema::String)),
                (
                    "state",
                    required(union(vec![
                        literal("missing"),
                        literal("ready"),
                        literal("invalid"),
                    ])),
                ),
                ("hash", required(union(vec![Schema::Null, Schema::String]))),
                ("bytes", required(union(vec![Schema::Null, Schema::Number]))),
                (
                    "categories",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "entries",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "updatedAt",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
            ]),
        ),
        (
            "GeodataAssetSources".into(),
            object([
                (
                    "providers",
                    required(array(object([
                        ("id", required(Schema::String)),
                        ("name", required(Schema::String)),
                        ("geoip", required(Schema::String)),
                        ("geosite", required(Schema::String)),
                    ]))),
                ),
                (
                    "history",
                    required(object([
                        ("geoip", required(array(Schema::String))),
                        ("geosite", required(array(Schema::String))),
                    ])),
                ),
            ]),
        ),
    ]
}
