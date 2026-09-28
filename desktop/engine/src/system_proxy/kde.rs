//! KDE's kioslaverc adapter under the common lease and recovery transaction.
//! KConfig decodes effective values; raw local entries preserve inheritance,
//! deletion/expansion markers and spelling when a lease is restored.
use super::{Backend, BackendKind, Value};
use gio::glib::variant::ToVariant;
use std::{
    fs,
    io::{Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

const GROUP: &str = "Proxy Settings";
const KEYS: &[&str] = &[
    "httpProxy",
    "httpsProxy",
    "ftpProxy",
    "socksProxy",
    "ReversedException",
    "ProxyType",
];
const MAX_FILE: u64 = 1024 * 1024;
type Contents = Vec<Option<String>>;
type Cache = Option<(Contents, Vec<Value>)>;

pub(super) struct Kde {
    config: PathBuf,
    defaults: Vec<PathBuf>,
    reader: PathBuf,
    cache: Mutex<Cache>,
}

pub(super) fn platform(config: &Path) -> Option<Kde> {
    if !std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .any(|v| v.eq_ignore_ascii_case("kde"))
    {
        return None;
    }
    let search = std::env::var_os("PATH")?;
    let reader = ["kreadconfig6", "kreadconfig5"].iter().find_map(|name| {
        std::env::split_paths(&search)
            .map(|dir| dir.join(name))
            .find(|path| {
                path.is_absolute()
                    && path
                        .metadata()
                        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    })?;
    let defaults = std::env::var_os("XDG_CONFIG_DIRS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/etc/xdg".into());
    let mut defaults: Vec<_> = std::env::split_paths(&defaults)
        .filter(|path| path.is_absolute())
        .collect();
    if defaults.is_empty() {
        defaults.push("/etc/xdg".into());
    }
    Some(Kde {
        config: config.to_owned(),
        defaults,
        reader,
        cache: Mutex::new(None),
    })
}

fn content(path: &Path) -> Result<Option<String>, String> {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("system_proxy_read_failed".into()),
    };
    let meta = file.metadata().map_err(|_| "system_proxy_read_failed")?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err("system_proxy_read_failed".into());
    }
    let mut text = String::new();
    file.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|_| "system_proxy_read_failed")?;
    if text.len() as u64 > MAX_FILE || text.contains('\0') {
        return Err("system_proxy_read_failed".into());
    }
    Ok(Some(text))
}

fn group(line: &str) -> Option<bool> {
    let line = line.trim();
    line.starts_with('[').then(|| {
        line.strip_prefix("[Proxy Settings]")
            .is_some_and(|tail| tail.trim().is_empty() || tail.trim() == "[$i]")
    })
}

fn entry(line: &str, key: &str) -> bool {
    line.trim_start().strip_prefix(key).is_some_and(|tail| {
        tail.trim_start().starts_with('=') || tail.trim_start().starts_with('[')
    })
}

fn entries(text: &str, key: &str) -> Vec<String> {
    let mut inside = false;
    text.lines()
        .filter_map(|line| {
            if let Some(value) = group(line) {
                inside = value;
                None
            } else if inside && entry(line, key) {
                Some(line.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn immutable(text: &str) -> bool {
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line == "[$i]" {
            return true;
        }
        if let Some(value) = group(line) {
            inside = value;
            if inside && line.contains("[$i]") {
                return true;
            }
        } else if inside
            && line.split('=').next().is_some_and(|key| {
                key.contains("[$i]") && KEYS.iter().any(|name| entry(line, name))
            })
        {
            return true;
        }
    }
    false
}

// Change one owned key, retaining every unrelated line. A missing local key is
// removed, rather than writing KConfig's [$d] marker (which hides system defaults).
fn replace(text: &str, key: &str, values: &[String]) -> String {
    let mut output = String::new();
    let mut inside = false;
    let mut inserted = false;
    for line in text.split_inclusive('\n') {
        if let Some(value) = group(line) {
            if inside && !inserted {
                append(&mut output, values);
                inserted = true;
            }
            inside = value;
        } else if inside && entry(line, key) {
            if !inserted {
                append(&mut output, values);
                inserted = true;
            }
            continue;
        }
        output.push_str(line);
    }
    if !inserted && !values.is_empty() {
        if !inside {
            append(&mut output, &[format!("[{GROUP}]")]);
        }
        append(&mut output, values);
    }
    output
}

fn append(output: &mut String, lines: &[String]) {
    if !output.is_empty() && !output.ends_with('\n') && !lines.is_empty() {
        output.push('\n');
    }
    for line in lines {
        output.push_str(line);
        output.push('\n');
    }
}

impl Kde {
    fn target(&self) -> Result<PathBuf, String> {
        let path = self.config.join("kioslaverc");
        match path.symlink_metadata() {
            Ok(_) => path
                .canonicalize()
                .map_err(|_| "system_proxy_not_writable".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
            Err(_) => Err("system_proxy_not_writable".into()),
        }
    }

    fn contents(&self) -> Result<Contents, String> {
        std::iter::once(&self.config)
            .chain(&self.defaults)
            .map(|dir| content(&dir.join("kioslaverc")))
            .collect()
    }

    fn effective(&self, index: usize) -> Result<String, String> {
        let default = match index {
            4 => "false",
            5 => "0",
            _ => "",
        };
        // Use a file for output so even a malformed, long value cannot fill a
        // pipe and prevent the subprocess deadline from being enforced.
        let mut output = tempfile::tempfile().map_err(|_| "system_proxy_read_failed")?;
        let mut child = Command::new(&self.reader)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                GROUP,
                "--key",
                KEYS[index],
                "--default",
                default,
            ])
            .env("XDG_CONFIG_HOME", &self.config)
            .env(
                "XDG_CONFIG_DIRS",
                std::env::join_paths(&self.defaults).map_err(|_| "system_proxy_read_failed")?,
            )
            .env("LC_ALL", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(output.try_clone().map_err(|_| "system_proxy_read_failed")?)
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "system_proxy_read_failed")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("system_proxy_read_failed".into());
                }
            }
        }
        output.rewind().map_err(|_| "system_proxy_read_failed")?;
        let mut value = String::new();
        output
            .take(65537)
            .read_to_string(&mut value)
            .map_err(|_| "system_proxy_read_failed")?;
        if value.len() > 65536 || !value.ends_with('\n') {
            return Err("system_proxy_read_failed".into());
        }
        value.pop();
        Ok(value)
    }
}

impl Backend for Kde {
    fn kind(&self) -> BackendKind {
        BackendKind::Kde
    }

    fn read(&self) -> Result<Vec<Value>, String> {
        let contents = self.contents()?;
        let mut cache = self.cache.lock().map_err(|_| "system_proxy_read_failed")?;
        if let Some((old, values)) = cache.as_ref() {
            if *old == contents {
                return Ok(values.clone());
            }
        }
        let local = contents[0].as_deref().unwrap_or_default();
        let values = KEYS
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let raw = entries(local, key);
                Ok(Value {
                    effective: self.effective(index)?,
                    user: if raw.is_empty() {
                        None
                    } else {
                        Some(serde_json::to_string(&raw).map_err(|_| "system_proxy_read_failed")?)
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if contents != self.contents()? {
            return Err("system_proxy_read_failed".into());
        }
        *cache = Some((contents, values.clone()));
        Ok(values)
    }

    fn writable(&self) -> Result<(), String> {
        if self
            .contents()?
            .iter()
            .flatten()
            .any(|text| immutable(text))
        {
            return Err("system_proxy_not_writable".into());
        }
        let path = self.target()?;
        if let Ok(meta) = path.metadata() {
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().readonly()
            {
                return Err("system_proxy_not_writable".into());
            }
        }
        let parent = path
            .parent()
            .ok_or("system_proxy_not_writable")?
            .ancestors()
            .find(|dir| dir.exists())
            .ok_or("system_proxy_not_writable")?;
        if parent
            .metadata()
            .map_err(|_| "system_proxy_not_writable")?
            .permissions()
            .readonly()
        {
            return Err("system_proxy_not_writable".into());
        }
        Ok(())
    }

    fn write(&self, index: usize, value: Option<&str>) -> Result<(), String> {
        self.writable()?;
        let key = KEYS.get(index).ok_or("system_proxy_recovery_failed")?;
        let raw: Vec<String> = match value {
            Some(value) if value.starts_with('[') => {
                serde_json::from_str(value).map_err(|_| "system_proxy_recovery_failed")?
            }
            Some(value) if !value.contains(['\n', '\r', '\0']) => vec![format!("{key}={value}")],
            Some(_) => return Err("system_proxy_recovery_failed".into()),
            None => Vec::new(),
        };
        if raw
            .iter()
            .any(|line| line.contains(['\n', '\r', '\0']) || !entry(line, key))
        {
            return Err("system_proxy_recovery_failed".into());
        }
        let path = self.target()?;
        let directory = path.parent().ok_or("system_proxy_not_writable")?;
        let before = content(&path)?;
        let text = replace(before.as_deref().unwrap_or_default(), key, &raw);
        fs::create_dir_all(directory).map_err(|_| "system_proxy_apply_failed")?;
        let mut temp =
            tempfile::NamedTempFile::new_in(directory).map_err(|_| "system_proxy_apply_failed")?;
        if let Ok(meta) = path.metadata() {
            temp.as_file()
                .set_permissions(meta.permissions())
                .map_err(|_| "system_proxy_apply_failed")?;
        }
        temp.write_all(text.as_bytes())
            .and_then(|()| temp.as_file().sync_all())
            .map_err(|_| "system_proxy_apply_failed")?;
        if self.target()? != path || content(&path)? != before {
            return Err("system_proxy_changed".into());
        }
        temp.persist(&path)
            .map_err(|_| "system_proxy_apply_failed")?;
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| "system_proxy_apply_failed")?;
        *self.cache.lock().map_err(|_| "system_proxy_apply_failed")? = None;
        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        let bus = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)
            .map_err(|_| "system_proxy_apply_failed")?;
        bus.emit_signal(
            None,
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler",
            "reparseSlaveConfiguration",
            Some(&("",).to_variant()),
        )
        .and_then(|()| bus.flush_sync(gio::Cancellable::NONE))
        .map_err(|_| "system_proxy_apply_failed".into())
    }
}

#[cfg(test)]
mod tests;
