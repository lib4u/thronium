//! Backups and Throne backup import.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "backupStatus".into(),
            Command {
                request: object([]),
                response: object([("canUndo", required(Schema::Boolean))]),
            },
        ),
        (
            "discardBackupPreview".into(),
            Command {
                request: object([("token", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "exportBackup".into(),
            Command {
                request: object([]),
                response: object([("status", required(Schema::String))]),
            },
        ),
        (
            "chooseLegacyResource".into(),
            Command {
                request: object([
                    ("token", required(Schema::String)),
                    ("id", required(Schema::String)),
                ]),
                response: object([
                    (
                        "status",
                        required(union(vec![literal("ready"), literal("cancelled")])),
                    ),
                    ("preview", optional(reference("BackupPreview"))),
                ]),
            },
        ),
        (
            "legacyBackupScopes".into(),
            Command {
                request: object([
                    ("token", required(Schema::String)),
                    ("scopes", required(reference("LegacyBackupScopes"))),
                ]),
                response: reference("BackupPreview"),
            },
        ),
        (
            "previewPreviousBackup".into(),
            Command {
                request: object([]),
                response: reference("BackupPreview"),
            },
        ),
        (
            "readBackup".into(),
            Command {
                request: object([]),
                response: object([
                    ("status", required(Schema::String)),
                    ("preview", optional(reference("BackupPreview"))),
                ]),
            },
        ),
        (
            "refreshBackupPreview".into(),
            Command {
                request: object([("token", required(Schema::String))]),
                response: reference("BackupPreview"),
            },
        ),
        (
            "restoreBackup".into(),
            Command {
                request: object([("token", required(Schema::String))]),
                response: object([("canUndo", required(Schema::Boolean))]),
            },
        ),
    ]
}
