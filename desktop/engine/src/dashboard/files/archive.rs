//! Dashboard archive extraction into a private version directory.
use super::*;

pub(crate) fn extract(
    bytes: &[u8],
    directory: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(usize, u64), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid())?;
    if archive.is_empty() || archive.len() > MAX_ENTRIES {
        return Err(invalid());
    }
    let mut names = Vec::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|_| invalid())?;
        let name = file.name().trim_end_matches('/');
        if name.is_empty()
            || name.len() > 512
            || name.contains(['\\', ':'])
            || name.bytes().any(|b| b.is_ascii_control())
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid());
        }
        if let Some(mode) = file.unix_mode() {
            if !matches!(mode & 0o170000, 0 | 0o100000 | 0o040000) {
                return Err(invalid());
            }
        }
        if file.size() > MAX_FILE {
            return Err(invalid());
        }
        total = total
            .checked_add(file.size())
            .filter(|v| *v <= MAX_UNPACKED)
            .ok_or_else(invalid)?;
        names.push((name.to_owned(), file.is_dir()));
    }
    let files: Vec<_> = names.iter().filter(|(_, dir)| !dir).collect();
    if files.is_empty() {
        return Err(invalid());
    }
    let prefix = files[0]
        .0
        .split_once('/')
        .map(|(first, _)| first.to_owned());
    let strip = prefix.filter(|p| {
        files
            .iter()
            .all(|(name, _)| name.starts_with(&format!("{p}/")))
    });
    let mut paths = HashSet::new();
    let mut file_count = 0;
    for (index, (name, is_dir)) in names.iter().enumerate() {
        if cancelled() {
            return Err("dashboard_cancelled".into());
        }
        let relative = if let Some(prefix) = &strip {
            if name == prefix && *is_dir {
                continue;
            }
            name.strip_prefix(&format!("{prefix}/"))
                .ok_or_else(invalid)?
        } else {
            name.as_str()
        };
        if relative.is_empty()
            || !paths.insert(relative.to_owned())
            || matches!(
                relative,
                ".etag" | "receipt.json" | "thronium.html" | "thronium-bootstrap.js"
            )
        {
            return Err(invalid());
        }
        let path = directory.join(relative);
        if *is_dir {
            io_error(fs::create_dir_all(&path))?;
            continue;
        }
        io_error(fs::create_dir_all(path.parent().ok_or_else(invalid)?))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut output = io_error(options.open(path))?;
        let file = archive.by_index(index).map_err(|_| invalid())?;
        let expected = file.size();
        let written =
            std::io::copy(&mut file.take(expected + 1), &mut output).map_err(|_| invalid())?;
        if written != expected {
            return Err(invalid());
        }
        io_error(output.sync_all())?;
        file_count += 1;
    }
    if regular(&directory.join("index.html"))?.len() == 0 {
        return Err(invalid());
    }
    Ok((file_count, total))
}
