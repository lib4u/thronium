//! Portable, decoded-once PNG icons. Cloning a library shares immutable image
//! data; backup/restore uses the normal library transaction, never loose files.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeMap, io::Cursor, sync::Arc};

pub const MAX_PNG_BYTES: usize = 2 * 1024 * 1024;
/// Largest icon width and height, in pixels.
pub const MAX_SIDE_PIXELS: u32 = 512;
const MAX_BASE64_BYTES: usize = MAX_PNG_BYTES.div_ceil(3) * 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Status {
    Off,
    Throne,
    Proxy,
    Tun,
    Dns,
    #[serde(rename = "Proxy-Dns")]
    ProxyDns,
}
impl Status {
    pub fn for_connection(running: bool, mode: &crate::system_proxy::ConnectionMode) -> Self {
        use crate::system_proxy::ConnectionMode;
        if !running {
            Self::Off
        } else {
            match mode {
                ConnectionMode::Tun => Self::Tun,
                ConnectionMode::SystemProxy => Self::Proxy,
                ConnectionMode::Local => Self::Throne,
            }
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Throne => "Throne",
            Self::Proxy => "Proxy",
            Self::Tun => "Tun",
            Self::Dns => "Dns",
            Self::ProxyDns => "Proxy-Dns",
        }
    }
    pub(crate) fn from_archive_path(path: &str) -> Option<Self> {
        [
            Self::Off,
            Self::Throne,
            Self::Proxy,
            Self::Tun,
            Self::Dns,
            Self::ProxyDns,
        ]
        .into_iter()
        .find(|status| path == format!("icons/{}.png", status.name()))
    }
}

#[derive(PartialEq, Eq)]
struct Data {
    png: String,
    rgba: Vec<u8>,
    width: u32,
    height: u32,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Icon(Arc<Data>);
impl Icon {
    pub fn from_png(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_PNG_BYTES {
            return Err("invalid_tray_icon");
        }
        let mut reader =
            image::ImageReader::with_format(Cursor::new(bytes), image::ImageFormat::Png);
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(MAX_SIDE_PIXELS);
        limits.max_image_height = Some(MAX_SIDE_PIXELS);
        limits.max_alloc = Some(4 * 1024 * 1024);
        reader.limits(limits);
        let rgba = reader
            .decode()
            .map_err(|_| "invalid_tray_icon")?
            .into_rgba8();
        let (width, height) = rgba.dimensions();
        if width == 0 || height == 0 {
            return Err("invalid_tray_icon");
        }
        Ok(Self(Arc::new(Data {
            png: STANDARD.encode(bytes),
            rgba: rgba.into_raw(),
            width,
            height,
        })))
    }
    pub fn rgba(&self) -> &[u8] {
        &self.0.rgba
    }
    pub fn width(&self) -> u32 {
        self.0.width
    }
    pub fn height(&self) -> u32 {
        self.0.height
    }
}
impl Serialize for Icon {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.png)
    }
}
impl<'de> Deserialize<'de> for Icon {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > MAX_BASE64_BYTES {
            return Err(serde::de::Error::custom("invalid_tray_icon"));
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| serde::de::Error::custom("invalid_tray_icon"))?;
        Self::from_png(&bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pack(BTreeMap<Status, Icon>);
impl Pack {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn get(&self, status: Status) -> Option<&Icon> {
        self.0.get(&status)
    }
    pub(crate) fn insert(&mut self, status: Status, icon: Icon) {
        self.0.insert(status, icon);
    }
    pub(crate) fn merge(&mut self, source: &Self) {
        self.0.extend(source.0.clone());
    }
}

#[cfg(test)]
mod tests;
