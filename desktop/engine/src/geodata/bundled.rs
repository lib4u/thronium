//! The default geodata pair shipped with the application. It stands in for the
//! first download of the default sources, so geo categories work offline and
//! before a tunnel is up; a later refresh from the network replaces it.
use super::{default_url, IpList, SiteList};
use prost::Message;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
};

/// File names inside the application's `geodata` resource folder.
pub const SITE_FILE: &str = "geosite.dat";
pub const IP_FILE: &str = "geoip.dat";

static DIRECTORY: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Where the host installed the shipped files; unset in builds without them.
pub fn use_directory(directory: PathBuf) {
    *DIRECTORY.write().unwrap_or_else(|e| e.into_inner()) = Some(directory);
}
pub(crate) fn directory() -> Option<PathBuf> {
    DIRECTORY.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The shipped list for `url`, only when it is the default source of its kind
/// and the file is a readable list of that kind. Any other source is always
/// downloaded as the user named it.
pub(crate) fn bytes(directory: Option<&Path>, sites: bool, url: &str) -> Option<Vec<u8>> {
    let file = if sites { SITE_FILE } else { IP_FILE };
    if url != default_url(sites) {
        return None;
    }
    let bytes = std::fs::read(directory?.join(file)).ok()?;
    if bytes.len() > super::LIMIT {
        return None;
    }
    let valid = if sites {
        SiteList::decode(bytes.as_slice()).is_ok_and(|l| !l.entry.is_empty())
    } else {
        IpList::decode(bytes.as_slice()).is_ok_and(|l| !l.entry.is_empty())
    };
    valid.then_some(bytes)
}
