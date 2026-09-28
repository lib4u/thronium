//! Resolve storage before instance matching and retain only genuine launch payloads.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    System,
    Portable,
    Custom,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    Automatic,
    System,
    Portable,
    Custom(PathBuf),
}
#[derive(Clone, Debug)]
pub struct Arguments {
    pub selection: Selection,
    pub payloads: Vec<OsString>,
}
#[derive(Clone, Debug)]
pub struct Location {
    pub mode: Mode,
    pub force_system: bool,
    pub directory: PathBuf,
    pub payloads: Vec<OsString>,
}

const PORTABLE_MARKER: &str = "portable-mode";
const PORTABLE_MAGIC: &[u8] = b"thronium-portable-v1\n";
fn portable_marker(directory: &Path) -> Result<bool, String> {
    use std::io::Read;
    let path = directory.join(PORTABLE_MARKER);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("storage_portable_marker_invalid".into()),
    };
    if !metadata.is_file() || metadata.len() > 64 {
        return Err("storage_portable_marker_invalid".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err("storage_portable_marker_invalid".into());
        }
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    crate::nofollow::open_link_itself(&mut options);
    let file = options
        .open(path)
        .map_err(|_| "storage_portable_marker_invalid")?;
    #[cfg(windows)]
    if !crate::nofollow::single_plain_file(&file) {
        return Err("storage_portable_marker_invalid".into());
    }
    let mut bytes = Vec::new();
    file.take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| "storage_portable_marker_invalid")?;
    if bytes != PORTABLE_MAGIC {
        return Err("storage_portable_marker_invalid".into());
    }
    Ok(true)
}
fn write_portable_marker(directory: &Path) -> Result<(), String> {
    use std::io::Write;
    if portable_marker(directory)? {
        return Ok(());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|_| "storage_unavailable")?;
    file.write_all(PORTABLE_MAGIC)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|_| "storage_unavailable")?;
    if file
        .persist_noclobber(directory.join(PORTABLE_MARKER))
        .is_err()
        && !portable_marker(directory)?
    {
        return Err("storage_unavailable".into());
    }
    #[cfg(unix)]
    std::fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| "storage_unavailable")?;
    Ok(())
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Arguments, String> {
    let mut args = args.into_iter().peekable();
    let mut selection = None;
    let mut payloads = Vec::new();
    while let Some(arg) = args.next() {
        if arg.to_str().is_none() && arg.to_string_lossy().starts_with("--data-dir=") {
            return Err("storage_invalid_arguments".into());
        }
        let selected = match arg.to_str() {
            Some("--") => {
                payloads.extend(args);
                break;
            }
            Some("--portable") => Some(Selection::Portable),
            Some("--data-dir") => {
                let value = args
                    .next()
                    .filter(|v| !v.is_empty() && !v.to_string_lossy().starts_with('-'))
                    .ok_or("storage_invalid_arguments")?;
                Some(Selection::Custom(value.into()))
            }
            Some("-appdata") => {
                if args.peek().is_some_and(|v| {
                    !v.is_empty()
                        && !v.to_string_lossy().starts_with('-')
                        && !v.to_string_lossy().contains("://")
                }) {
                    Some(Selection::Custom(args.next().unwrap().into()))
                } else {
                    Some(Selection::System)
                }
            }
            Some(value) if value.starts_with("--data-dir=") => {
                let value = value.strip_prefix("--data-dir=").unwrap();
                if value.is_empty() {
                    return Err("storage_invalid_arguments".into());
                }
                Some(Selection::Custom(value.into()))
            }
            _ => {
                payloads.push(arg);
                None
            }
        };
        if let Some(value) = selected {
            if selection.replace(value).is_some() {
                return Err("storage_invalid_arguments".into());
            }
        }
    }
    Ok(Arguments {
        selection: selection.unwrap_or(Selection::Automatic),
        payloads,
    })
}
impl Arguments {
    pub fn resolve(
        self,
        executable: &Path,
        appimage: Option<&Path>,
        standard: Option<&Path>,
        cwd: &Path,
    ) -> Result<Location, String> {
        let force_system = self.selection == Selection::System;
        let portable_directory = || -> Result<PathBuf, String> {
            let launcher = appimage.unwrap_or(executable);
            let launcher = if launcher.is_absolute() {
                launcher.to_owned()
            } else {
                cwd.join(launcher)
            };
            Ok(launcher
                .parent()
                .ok_or("storage_unavailable")?
                .join("thronium-data"))
        };
        let (mode, directory) = match self.selection {
            Selection::Automatic => {
                let adjacent = portable_directory()?;
                if portable_marker(&adjacent)? {
                    (Mode::Portable, adjacent)
                } else {
                    (
                        Mode::System,
                        standard.ok_or("storage_unavailable")?.to_owned(),
                    )
                }
            }
            Selection::System => (
                Mode::System,
                standard.ok_or("storage_unavailable")?.to_owned(),
            ),
            Selection::Portable => (Mode::Portable, portable_directory()?),
            Selection::Custom(path) => (
                Mode::Custom,
                if path.is_absolute() {
                    path
                } else {
                    cwd.join(path)
                },
            ),
        };
        if !directory.is_absolute() {
            return Err("storage_unavailable".into());
        }
        Ok(Location {
            mode,
            force_system,
            directory,
            payloads: self.payloads,
        })
    }
}
impl Location {
    /// This matches Store's existing private-directory policy before hashing its identity.
    pub fn prepare(mut self) -> Result<Self, String> {
        // A Throne data directory (for example a reused Qt `-appdata` path) keeps
        // its own files and permissions; nothing here may create or chmod it.
        if self.mode == Mode::Custom
            && std::fs::symlink_metadata(self.directory.join("throne.db")).is_ok()
        {
            return Err("storage_throne_directory".into());
        }
        std::fs::create_dir_all(&self.directory).map_err(|_| "storage_unavailable")?;
        self.directory =
            std::fs::canonicalize(&self.directory).map_err(|_| "storage_unavailable")?;
        let metadata = std::fs::metadata(&self.directory).map_err(|_| "storage_unavailable")?;
        if !metadata.is_dir() {
            return Err("storage_unavailable".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || (self.mode != Mode::System && metadata.mode() & 0o200 == 0)
            {
                return Err("storage_unavailable".into());
            }
        }
        crate::ownership::restrict_directory(&self.directory).map_err(|_| "storage_unavailable")?;
        // Verify writing now. Do not silently choose another directory on failure.
        let probe =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| "storage_unavailable")?;
        probe.close().map_err(|_| "storage_unavailable")?;
        if self.mode == Mode::Portable {
            write_portable_marker(&self.directory)?;
        }
        Ok(self)
    }
    pub fn instance_id(&self, identifier: &str) -> String {
        let digest = Sha256::digest(self.directory.as_os_str().as_encoded_bytes());
        format!("{identifier}.Library_{digest:x}")
    }
    pub fn launch_arguments(&self) -> Vec<OsString> {
        match self.mode {
            Mode::System => {
                if self.force_system {
                    vec!["-appdata".into()]
                } else {
                    vec![]
                }
            }
            Mode::Portable => vec!["--portable".into()],
            Mode::Custom => vec!["--data-dir".into(), self.directory.clone().into_os_string()],
        }
    }
    pub fn webview_directory(&self) -> Option<PathBuf> {
        (self.mode != Mode::System).then(|| self.directory.clone())
    }
}

/// Desktop Entry Exec is parsed by the desktop launcher, not by a shell.
/// Keep each argument separately quoted and escape field-code percent signs.
pub fn desktop_exec(
    executable: &Path,
    args: &[OsString],
    url_field: bool,
) -> Result<String, String> {
    fn quote(arg: &std::ffi::OsStr) -> Result<String, String> {
        let text = arg
            .to_str()
            .filter(|s| !s.contains(['\n', '\r', '\0']))
            .ok_or("storage_launch_arguments_invalid")?;
        let escaped = text
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
            .replace('%', "%%");
        Ok(format!("\"{escaped}\""))
    }
    if executable.as_os_str().to_string_lossy().contains('=') {
        return Err("storage_launch_arguments_invalid".into());
    }
    let mut words = vec![quote(executable.as_os_str())?];
    for arg in args {
        words.push(quote(arg)?);
    }
    if url_field {
        words.push("%U".into());
    }
    Ok(words.join(" "))
}

/// Windows parses a command line with `CommandLineToArgvW`, not a shell: an
/// argument is quoted only when it carries a space, a tab or a quote, and a run
/// of backslashes doubles only in front of a quote. The registry value the Run
/// key and a URL handler hold is read exactly this way, so a library path with
/// spaces survives a restart.
pub fn windows_command_line(
    executable: &Path,
    args: &[OsString],
    url_field: bool,
) -> Result<String, String> {
    fn text(arg: &std::ffi::OsStr) -> Result<&str, String> {
        arg.to_str()
            .filter(|s| !s.contains(['\n', '\r', '\0']))
            .ok_or_else(|| "storage_launch_arguments_invalid".to_owned())
    }
    fn quote(value: &str) -> String {
        if !value.is_empty() && !value.contains([' ', '\t', '"']) {
            return value.to_owned();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0;
        for character in value.chars() {
            match character {
                '\\' => {
                    backslashes += 1;
                    out.push(character);
                }
                '"' => {
                    // 2n+1 backslashes leave one literal quote behind.
                    for _ in 0..=backslashes {
                        out.push('\\');
                    }
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    backslashes = 0;
                    out.push(character);
                }
            }
        }
        // A closing quote doubles the run that reaches it.
        for _ in 0..backslashes {
            out.push('\\');
        }
        out.push('"');
        out
    }
    let mut words = vec![quote(text(executable.as_os_str())?)];
    for arg in args {
        words.push(quote(text(arg)?));
    }
    if url_field {
        // The shell substitutes the opened link for this field.
        words.push("\"%1\"".into());
    }
    Ok(words.join(" "))
}

#[cfg(test)]
mod tests;
