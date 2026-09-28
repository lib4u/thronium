//! The application and its core ship as one pair: the same version and the
//! same `libcore.proto`. The application asks the core file for both once at
//! start (`ThroniumCore --thronium-core-info`) and runs no other core.
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

const PROTOCOL: &[u8] = include_bytes!("../../../../core/server/gen/libcore.proto");

static VERIFIED: OnceLock<Result<(), String>> = OnceLock::new();

/// The digest the core reports for the protocol it was compiled against.
pub(crate) fn protocol_digest() -> String {
    Sha256::digest(PROTOCOL)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether what a core printed makes it this application's pair. A core
/// built without a version stamp (a development build) is judged by its
/// protocol alone.
pub(crate) fn matches(printed: &[u8], version: &str, protocol: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Info {
        version: String,
        protocol: String,
    }
    serde_json::from_slice::<Info>(printed).is_ok_and(|info| {
        info.protocol == protocol && (info.version.is_empty() || info.version == version)
    })
}

fn identify(core: &Path) -> Result<Vec<u8>, String> {
    let mut command = Command::new(core);
    command
        .arg("--thronium-core-info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().map_err(|_| "core_mismatch")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return Err("core_mismatch".into()),
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("core_mismatch".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut printed = Vec::new();
    use std::io::Read;
    child
        .stdout
        .take()
        .ok_or("core_mismatch")?
        .take(4096)
        .read_to_end(&mut printed)
        .map_err(|_| "core_mismatch")?;
    Ok(printed)
}

/// Checks `core` against this application and remembers the answer for the
/// rest of the process. A missing file is left to `core_missing`.
pub fn verify(core: &Path) -> Result<(), String> {
    let result = if core.is_file() {
        identify(core).and_then(|printed| {
            matches(&printed, env!("CARGO_PKG_VERSION"), &protocol_digest())
                .then_some(())
                .ok_or_else(|| "core_mismatch".to_string())
        })
    } else {
        Ok(())
    };
    VERIFIED.get_or_init(|| result).clone()
}

/// The verdict of `verify`; unchecked (tests with their own cores) is allowed.
pub(crate) fn required() -> Result<(), String> {
    VERIFIED.get().cloned().unwrap_or(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pair_is_the_protocol_and_the_stamped_version() {
        let protocol = protocol_digest();
        assert_eq!(protocol.len(), 64);
        let info = |version: &str, protocol: &str| {
            serde_json::to_vec(&serde_json::json!({"version": version, "protocol": protocol}))
                .unwrap()
        };
        assert!(matches(&info("1.2.3", &protocol), "1.2.3", &protocol));
        assert!(matches(&info("", &protocol), "1.2.3", &protocol));
        assert!(!matches(&info("1.2.4", &protocol), "1.2.3", &protocol));
        assert!(!matches(&info("1.2.3", "00"), "1.2.3", &protocol));
        assert!(!matches(b"sing-box: 1.14", "1.2.3", &protocol));
    }

    #[cfg(unix)]
    #[test]
    fn a_core_file_is_asked_and_one_that_cannot_answer_is_not_a_pair() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: String| {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        let good = write(
            "good",
            format!(
                r#"[ "$1" = --thronium-core-info ] && echo '{{"version":"{}","protocol":"{}"}}'"#,
                env!("CARGO_PKG_VERSION"),
                protocol_digest()
            ),
        );
        assert!(identify(&good).is_ok_and(|out| matches(
            &out,
            env!("CARGO_PKG_VERSION"),
            &protocol_digest()
        )));
        let old = write("old", "echo unknown flag; exit 2".into());
        assert_eq!(identify(&old).unwrap_err(), "core_mismatch");
    }
}
