use base64::Engine as _;
use image::{DynamicImage, ImageReader, RgbaImage};
use std::io::Cursor;
// Only the portal path reads a capture back from a file.
#[cfg(target_os = "linux")]
use std::io::Read;
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;

use thronium_engine::exports::MAX_QR_IMAGE_BYTES as MAX_BYTES;
use thronium_engine::exports::MAX_QR_IMAGE_PIXELS as MAX_PIXELS;

fn decode(image: DynamicImage) -> Result<Vec<String>, String> {
    if u64::from(image.width()) * u64::from(image.height()) > MAX_PIXELS {
        return Err("qr_image_too_large".into());
    }
    let mut gray = image.to_luma8();
    if image.color().has_alpha() {
        for (luma, rgba) in gray.pixels_mut().zip(image.to_rgba8().pixels()) {
            let alpha = u16::from(rgba[3]);
            luma[0] = ((u16::from(luma[0]) * alpha + 255 * (255 - alpha)) / 255) as u8;
        }
    }
    let mut texts = Vec::new();
    for inverted in [false, true] {
        if inverted {
            image::imageops::invert(&mut gray);
        }
        let mut prepared = rqrr::PreparedImage::prepare(gray.clone());
        for grid in prepared.detect_grids() {
            if let Ok((_, text)) = grid.decode() {
                if !text.trim().is_empty() && !texts.contains(&text) {
                    texts.push(text);
                }
            }
        }
    }
    if texts.is_empty() {
        Err("qr_not_found".into())
    } else {
        Ok(texts)
    }
}

pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() > MAX_BYTES {
        return Err("qr_image_too_large".into());
    }
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| "qr_image_invalid")?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_PIXELS * 4);
    limits.max_image_width = Some(16384);
    limits.max_image_height = Some(16384);
    reader.limits(limits);
    decode(reader.decode().map_err(|_| "qr_image_invalid")?)
}

pub async fn image(encoded: String) -> Result<Vec<String>, String> {
    if encoded.len() > (MAX_BYTES * 4 / 3) + 4 {
        return Err("qr_image_too_large".into());
    }
    tokio::task::spawn_blocking(move || {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "qr_image_invalid")?;
        from_bytes(&bytes)
    })
    .await
    .map_err(|_| "qr_image_invalid")?
}

pub async fn clipboard(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        let image = app
            .clipboard()
            .read_image()
            .map_err(|_| "qr_clipboard_empty")?;
        if u64::from(image.width()) * u64::from(image.height()) > MAX_PIXELS {
            return Err("qr_image_too_large".into());
        }
        let image = RgbaImage::from_raw(image.width(), image.height(), image.rgba().to_vec())
            .ok_or("qr_image_invalid")?;
        decode(DynamicImage::ImageRgba8(image))
    })
    .await
    .map_err(|_| "qr_image_invalid")?
}

pub async fn screen(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let window = app.get_webview_window("main").ok_or("qr_capture_failed")?;
    // Linux asks through the screenshot portal; here nothing else would.
    #[cfg(target_os = "windows")]
    if !consent(&app).await {
        return Err("qr_capture_cancelled".into());
    }
    let visible = window.is_visible().unwrap_or(false);
    if visible {
        window.hide().map_err(|_| "qr_capture_failed")?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    let result = capture().await;
    if visible {
        let _ = window.show();
        let _ = window.set_focus();
    }
    result
}

#[cfg(target_os = "linux")]
async fn capture() -> Result<Vec<String>, String> {
    use ashpd::desktop::screenshot::Screenshot;
    let portal_error = |error: ashpd::Error| match error {
        ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled) => "qr_capture_cancelled",
        _ => "qr_capture_failed",
    };
    let request = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        Screenshot::request().interactive(true).modal(true).send(),
    )
    .await
    .map_err(|_| "qr_capture_failed")?
    .map_err(portal_error)?;
    let response = request.response().map_err(portal_error)?;
    let path = tauri::Url::parse(response.uri().as_str())
        .map_err(|_| "qr_capture_failed")?
        .to_file_path()
        .map_err(|_| "qr_capture_failed")?;
    tokio::task::spawn_blocking(move || {
        let result = (|| {
            let file = std::fs::File::open(&path).map_err(|_| "qr_capture_failed")?;
            let mut bytes = Vec::new();
            file.take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "qr_capture_failed")?;
            from_bytes(&bytes)
        })();
        // The screenshot portal gives this request a temporary file.
        let _ = std::fs::remove_file(path);
        result
    })
    .await
    .map_err(|_| "qr_capture_failed")?
}

/// Windows captures every screen at once, so the person agrees to it first.
#[cfg(target_os = "windows")]
async fn consent(app: &tauri::AppHandle) -> bool {
    use crate::localization::{text, Language, TextKey};
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    let language = Language::of(&*app.state::<crate::Shared>().engine.lock().await);
    let (send, receive) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(text(language, TextKey::WindowsQrConsent))
        .title("Thronium")
        .buttons(MessageDialogButtons::OkCancelCustom(
            text(language, TextKey::WindowsQrConsentCapture).into(),
            text(language, TextKey::WindowsQrConsentCancel).into(),
        ))
        .show(move |agreed| {
            let _ = send.send(agreed);
        });
    receive.await.unwrap_or(false)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
async fn capture() -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(|| {
        let mut texts = Vec::new();
        let mut captured = false;
        for screen in screenshots::Screen::all().map_err(|_| "qr_capture_failed")? {
            if let Ok(shot) = screen.capture() {
                captured = true;
                if let Some(image) =
                    RgbaImage::from_raw(shot.width(), shot.height(), shot.into_raw())
                {
                    if let Ok(values) = decode(DynamicImage::ImageRgba8(image)) {
                        for text in values {
                            if !texts.contains(&text) {
                                texts.push(text);
                            }
                        }
                    }
                }
            }
        }
        if texts.is_empty() {
            Err(if captured {
                "qr_not_found"
            } else {
                "qr_capture_failed"
            }
            .into())
        } else {
            Ok(texts)
        }
    })
    .await
    .map_err(|_| "qr_capture_failed")?
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
async fn capture() -> Result<Vec<String>, String> {
    Err("qr_capture_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    const QR: &[u8] = include_bytes!("../../tests/fixtures/import-qr.png");
    #[test]
    fn reads_profile_qr_rotated_inverted_and_multiple_codes() {
        let image = image::load_from_memory(QR).unwrap();
        let expected = from_bytes(QR).unwrap();
        assert_eq!(expected.len(), 1);
        assert!(expected[0].starts_with("vless://"));
        assert_eq!(decode(image.rotate90()).unwrap(), expected);
        let mut inverse = image.to_rgba8();
        image::imageops::invert(&mut inverse);
        assert_eq!(decode(DynamicImage::ImageRgba8(inverse)).unwrap(), expected);
        let mut pair =
            image::RgbaImage::from_pixel(image.width() * 2, image.height(), image::Rgba([255; 4]));
        image::imageops::overlay(&mut pair, &image, 0, 0);
        image::imageops::overlay(&mut pair, &image, i64::from(image.width()), 0);
        assert_eq!(decode(DynamicImage::ImageRgba8(pair)).unwrap(), expected);
    }
    #[test]
    fn reports_empty_invalid_and_oversized_images_without_contents() {
        assert_eq!(
            decode(DynamicImage::new_luma8(100, 100)),
            Err("qr_not_found".into())
        );
        assert_eq!(
            from_bytes(b"sensitive invalid file"),
            Err("qr_image_invalid".into())
        );
        assert_eq!(
            from_bytes(&vec![0; MAX_BYTES + 1]),
            Err("qr_image_too_large".into())
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Requires the isolated screenshot portal fixture"]
    fn screenshot_portal_fixture() {
        assert!(std::env::var_os("_THRONIUM_TEST_BUS").is_some());
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(capture());
        assert_eq!(result.unwrap(), from_bytes(QR).unwrap());
    }
}
