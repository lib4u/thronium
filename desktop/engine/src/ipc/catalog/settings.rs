//! Settings, the window, the dashboard and WARP.
use crate::ipc::{schema::*, Command};

pub(super) fn entries() -> Vec<(String, Command)> {
    vec![
        (
            "cancelDashboardInstallation".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "cancelWarpRegistration".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: Schema::Null,
            },
        ),
        (
            "checkUpstreamRelease".into(),
            Command {
                request: object([]),
                response: object([
                    ("version", required(Schema::String)),
                    ("publishedAt", required(Schema::String)),
                    ("url", required(Schema::String)),
                    ("prerelease", required(Schema::Boolean)),
                ]),
            },
        ),
        (
            "chooseExternalCorePath".into(),
            Command {
                request: object([]),
                response: union(vec![Schema::Null, Schema::String]),
            },
        ),
        (
            "dashboardStatus".into(),
            Command {
                request: object([]),
                response: reference("DashboardStatus"),
            },
        ),
        (
            "installDashboard".into(),
            Command {
                request: object([("requestId", required(Schema::String))]),
                response: reference("DashboardReceipt"),
            },
        ),
        (
            "openDashboard".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "openWarpTerms".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "quitApp".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        // Windows 11 snap layouts and the system menu of the frameless window;
        // nothing on other systems.
        (
            "windowSnapLayouts".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "windowSystemMenu".into(),
            Command {
                request: object([]),
                response: Schema::Null,
            },
        ),
        (
            "registerWarp".into(),
            Command {
                request: object([
                    ("requestId", required(Schema::String)),
                    ("acceptTerms", required(Schema::Boolean)),
                ]),
                response: reference("WarpConfig"),
            },
        ),
        (
            "saveSettings".into(),
            Command {
                request: object([
                    ("section", required(Schema::String)),
                    ("previous", required(map(Schema::Json))),
                    ("values", required(map(Schema::Json))),
                ]),
                response: map(Schema::Json),
            },
        ),
        (
            "saveWindowSettings".into(),
            Command {
                request: object([("closeBehavior", required(reference("CloseBehavior")))]),
                response: Schema::Null,
            },
        ),
        (
            "settings".into(),
            Command {
                request: object([]),
                response: map(map(Schema::Json)),
            },
        ),
        (
            "storageLocation".into(),
            Command {
                request: object([]),
                response: reference("StorageLocation"),
            },
        ),
        (
            "takeSettingsLink".into(),
            Command {
                request: object([]),
                response: union(vec![Schema::Null, system_request()]),
            },
        ),
        (
            "windowBehavior".into(),
            Command {
                request: object([]),
                response: object([("trayAvailable", required(Schema::Boolean))]),
            },
        ),
    ]
}

/// A link or the files the system asked the running application to open.
fn system_request() -> Schema {
    let problem = union(
        [
            "unreadable",
            "import_too_large",
            "qr_image_too_large",
            "qr_image_invalid",
            "qr_not_found",
        ]
        .into_iter()
        .map(literal)
        .collect(),
    );
    union(vec![
        object([
            ("kind", required(literal("link"))),
            ("text", required(Schema::String)),
        ]),
        object([
            ("kind", required(literal("files"))),
            (
                "documents",
                required(array(object([
                    ("filename", required(Schema::String)),
                    ("text", required(Schema::String)),
                ]))),
            ),
            (
                "problems",
                required(array(object([
                    ("filename", required(Schema::String)),
                    ("code", required(problem)),
                ]))),
            ),
        ]),
    ])
}
