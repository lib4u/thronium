//! Logs, dashboards, process usage and measurement histories.
use crate::ipc::schema::*;

pub(super) fn entries() -> Vec<(String, Schema)> {
    vec![
        (
            "DashboardReceipt".into(),
            object([
                ("archiveSha256", required(Schema::String)),
                ("installationId", required(Schema::String)),
                ("installedAt", required(Schema::Number)),
                ("fileCount", required(Schema::Number)),
                ("unpackedBytes", required(Schema::Number)),
            ]),
        ),
        (
            "DashboardStatus".into(),
            object([
                (
                    "installed",
                    required(union(vec![Schema::Null, reference("DashboardReceipt")])),
                ),
                ("canOpen", required(Schema::Boolean)),
                ("canInstall", required(Schema::Boolean)),
                (
                    "reason",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("settingsEnabled", required(Schema::Boolean)),
            ]),
        ),
        (
            "LogEntry".into(),
            object([
                ("id", required(Schema::Number)),
                ("at", required(Schema::Number)),
                ("level", required(Schema::String)),
                ("source", required(Schema::String)),
                ("text", required(Schema::String)),
                ("truncated", required(Schema::Boolean)),
                ("code", optional(Schema::String)),
                ("detail", optional(Schema::String)),
                (
                    "probe",
                    optional(object([
                        ("runId", required(Schema::String)),
                        ("profileId", required(Schema::String)),
                        ("profileName", required(Schema::String)),
                        ("kind", required(Schema::String)),
                    ])),
                ),
            ]),
        ),
        (
            "LogView".into(),
            object([
                ("entries", required(array(reference("LogEntry")))),
                ("total", required(Schema::Number)),
                ("matching", required(Schema::Number)),
                ("dropped", required(Schema::Number)),
                ("revision", required(Schema::Number)),
            ]),
        ),
        (
            "ProcessUsage".into(),
            object([
                (
                    "status",
                    required(union(vec![
                        literal("ok"),
                        literal("partial"),
                        literal("unavailable"),
                        literal("inactive"),
                    ])),
                ),
                (
                    "cpuPercent",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "rssBytes",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                ("processes", required(Schema::Number)),
                (
                    "reason",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
            ]),
        ),
        (
            "ResourceSnapshot".into(),
            object([
                ("supported", required(Schema::Boolean)),
                (
                    "logicalCpus",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "intervalMs",
                    required(union(vec![Schema::Null, Schema::Number])),
                ),
                (
                    "coreInstance",
                    required(union(vec![Schema::Null, Schema::String])),
                ),
                ("app", required(reference("ProcessUsage"))),
                ("core", required(reference("ProcessUsage"))),
            ]),
        ),
        (
            "MeasurementJournalEntry".into(),
            object([
                ("id", required(Schema::Number)),
                ("at", required(Schema::Number)),
                (
                    "kind",
                    required(union(vec![
                        literal("latency"),
                        literal("ip"),
                        literal("speed"),
                        literal("internet"),
                    ])),
                ),
                (
                    "source",
                    required(union(vec![
                        literal("single"),
                        literal("batch"),
                        literal("periodic"),
                        literal("auto-select"),
                    ])),
                ),
                ("profileId", required(Schema::String)),
                ("profileName", required(Schema::String)),
                ("memberId", optional(Schema::String)),
                ("memberName", optional(Schema::String)),
                ("memberOrigin", optional(reference("MemberOrigin"))),
                ("transport", optional(Schema::String)),
                ("status", required(Schema::String)),
                ("latencyMs", optional(Schema::Number)),
                ("ip", optional(Schema::String)),
                ("countryCode", optional(Schema::String)),
                ("download", optional(Schema::String)),
                ("upload", optional(Schema::String)),
                ("error", optional(Schema::String)),
            ]),
        ),
        (
            "MeasurementJournal".into(),
            object([
                (
                    "entries",
                    required(array(reference("MeasurementJournalEntry"))),
                ),
                ("total", required(Schema::Number)),
                ("retentionDays", required(Schema::Number)),
                ("limit", required(Schema::Number)),
            ]),
        ),
        (
            "SwitchHistoryEntry".into(),
            object([
                ("id", required(Schema::Number)),
                ("at", required(Schema::Number)),
                ("poolId", required(Schema::String)),
                ("poolName", required(Schema::String)),
                ("fromName", required(Schema::String)),
                ("toName", required(Schema::String)),
            ]),
        ),
        (
            "SwitchHistory".into(),
            object([
                ("entries", required(array(reference("SwitchHistoryEntry")))),
                ("total", required(Schema::Number)),
                ("retentionDays", required(Schema::Number)),
                ("limit", required(Schema::Number)),
            ]),
        ),
    ]
}
