//! Automatic selection pools, their previews and histories.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "SelectorPreview".into(),
            object([
                ("savedRankingCount", optional(Schema::Number)),
                (
                    "savedRankedAt",
                    optional(union(vec![Schema::Null, Schema::Number])),
                ),
                ("savedOrderKept", optional(Schema::Number)),
                ("newCandidatesCount", optional(Schema::Number)),
                (
                    "members",
                    required(array(object([
                        ("id", required(Schema::String)),
                        ("name", required(Schema::String)),
                        (
                            "countryCode",
                            optional(union(vec![Schema::Null, Schema::String])),
                        ),
                        ("latencyMs", optional(Schema::Number)),
                        ("httpTestFailed", optional(Schema::Boolean)),
                        ("httpSource", optional(literal("core-average"))),
                    ]))),
                ),
                ("total", required(Schema::Number)),
                ("unknownCountryCount", optional(Schema::Number)),
                ("rankedByHttp", optional(Schema::Number)),
                ("unknownHttpCount", optional(Schema::Number)),
                ("keptUnavailable", optional(Schema::Number)),
                ("warmCandidatesCount", optional(Schema::Number)),
                ("matchingBeforeLimit", optional(Schema::Number)),
                ("omittedByLimit", optional(Schema::Number)),
                ("matchingBeforePoolCap", optional(Schema::Number)),
                ("candidatePoolSize", optional(Schema::Number)),
                ("omittedByPoolCap", optional(Schema::Number)),
            ]),
        ),
        (
            "SelectorRanking".into(),
            object([
                ("members", required(array(Schema::String))),
                ("ranked_at", required(Schema::Number)),
            ]),
        ),
        (
            "SelectorHistoryEntry".into(),
            object([
                ("profileId", required(Schema::String)),
                ("name", required(Schema::String)),
                ("missing", required(Schema::Boolean)),
                ("firstUsed", required(Schema::Number)),
                ("lastUsed", required(Schema::Number)),
                ("builds", required(Schema::Number)),
            ]),
        ),
        (
            "SelectorHistoryPool".into(),
            object([
                ("profileId", required(Schema::String)),
                ("name", required(Schema::String)),
                ("lastBuiltAt", required(Schema::Number)),
                ("lastBuilt", required(array(Schema::String))),
                (
                    "entries",
                    required(array(reference("SelectorHistoryEntry"))),
                ),
            ]),
        ),
        (
            "SelectorMember".into(),
            object([
                ("tag", required(Schema::String)),
                (
                    "profileId",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("name", required(Schema::String)),
                ("rank", required(Schema::Number)),
                ("state", required(Schema::String)),
                ("selected", required(Schema::Boolean)),
                ("selectedUdp", required(Schema::Boolean)),
                ("qualified", required(Schema::Boolean)),
                ("active", required(Schema::Boolean)),
                ("averageMs", required(Schema::Number)),
                ("deviationMs", required(Schema::Number)),
                ("minMs", required(Schema::Number)),
                ("maxMs", required(Schema::Number)),
                ("samples", required(Schema::Number)),
                ("failures", required(Schema::Number)),
                ("probes", required(Schema::Number)),
                ("dialTotal", required(Schema::Number)),
                ("dialFailures", required(Schema::Number)),
                ("lastOkMs", required(Schema::Number)),
                ("lastProbeMs", required(Schema::Number)),
                ("cooldownUntilMs", required(Schema::Number)),
                ("lastError", required(Schema::String)),
            ]),
        ),
        (
            "SelectorPool".into(),
            object([
                ("profileId", optional(nullable(Schema::String))),
                ("needsReconnect", optional(Schema::Boolean)),
                (
                    "subscriptionUpdate",
                    optional(union(vec![
                        Schema::Null,
                        object([
                            ("pending", required(Schema::Boolean)),
                            ("attempts", required(Schema::Number)),
                            ("limit", required(Schema::Number)),
                            ("paused", required(Schema::Boolean)),
                        ]),
                    ])),
                ),
                (
                    "rebuild",
                    optional(union(vec![
                        Schema::Null,
                        object([
                            ("attempts", required(Schema::Number)),
                            ("limit", required(Schema::Number)),
                            ("paused", required(Schema::Boolean)),
                        ]),
                    ])),
                ),
                ("tag", required(Schema::String)),
                ("name", required(Schema::String)),
                ("phase", required(Schema::String)),
                ("selected", required(Schema::String)),
                ("selectedUdp", required(Schema::String)),
                ("pinned", required(Schema::String)),
                ("suspended", required(Schema::Boolean)),
                ("balance", required(Schema::Boolean)),
                ("balanceMode", required(Schema::String)),
                ("membersTotal", required(Schema::Number)),
                ("membersAlive", required(Schema::Number)),
                ("membersQualified", required(Schema::Number)),
                ("probesInFlight", required(Schema::Number)),
                ("roundsCompleted", required(Schema::Number)),
                ("lastRoundMs", required(Schema::Number)),
                ("nextRoundMs", required(Schema::Number)),
                ("lastSwitchMs", required(Schema::Number)),
                ("lastSwitchReason", required(Schema::String)),
                ("membersProbed", required(Schema::Number)),
                ("membersCooldown", required(Schema::Number)),
                ("suspendedSinceMs", required(Schema::Number)),
                ("members", required(array(reference("SelectorMember")))),
            ]),
        ),
    ]
}
