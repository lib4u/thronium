//! Local QR generation. No export data is sent over the network or logged.
use crate::localization::{text as localized, TextKey};
use base64::Engine as _;
use image::{GrayImage, Luma};
use qrcode::{types::Color, EcLevel, QrCode};
use std::io::Cursor;
use tauri::{AppHandle, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

fn render(text: &str) -> Result<GrayImage, String> {
    if text.is_empty() || text.len() > 4096 {
        return Err("qr_export_too_large".into());
    }
    let qr = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|_| "qr_export_too_large")?;
    let side = (qr.width() as u32 + 8) * 6;
    let mut image = GrayImage::from_pixel(side, side, Luma([255]));
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr[(x, y)] == Color::Dark {
                for dy in 0..6 {
                    for dx in 0..6 {
                        image.put_pixel(
                            (x as u32 + 4) * 6 + dx,
                            (y as u32 + 4) * 6 + dy,
                            Luma([0]),
                        );
                    }
                }
            }
        }
    }
    Ok(image)
}
fn png(image: GrayImage) -> Result<Vec<u8>, String> {
    let mut bytes = Cursor::new(Vec::new());
    image::DynamicImage::ImageLuma8(image)
        .write_to(&mut bytes, image::ImageFormat::Png)
        .map_err(|_| "export_failed")?;
    Ok(bytes.into_inner())
}
pub async fn deliver(
    app: &AppHandle,
    text: &str,
    destination: &str,
    language: crate::localization::Language,
) -> Result<serde_json::Value, String> {
    if !["preview", "clipboard", "file"].contains(&destination) {
        return Err("invalid_export_destination".into());
    }
    let text = text.to_owned();
    let image = tokio::task::spawn_blocking(move || render(&text))
        .await
        .map_err(|_| "export_failed")??;
    if destination == "clipboard" {
        let rgba = image::DynamicImage::ImageLuma8(image).into_rgba8();
        let (width, height) = rgba.dimensions();
        app.clipboard()
            .write_image(&tauri::image::Image::new_owned(
                rgba.into_raw(),
                width,
                height,
            ))
            .map_err(|_| "clipboard_write_failed")?;
        return Ok(serde_json::json!({"status":"copied"}));
    }
    let bytes = png(image)?;
    if destination == "preview" {
        return Ok(
            serde_json::json!({"image":"data:image/png;base64,".to_owned() + &base64::engine::general_purpose::STANDARD.encode(bytes)}),
        );
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut dialog = app
        .dialog()
        .file()
        .set_title(localized(language, TextKey::SaveQrCodeB18e38b))
        .set_file_name("thronium-qr.png")
        .add_filter("PNG", &["png"]);
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    dialog.save_file(move |path| {
        let _ = sender.send(path);
    });
    let Some(file) = receiver.await.map_err(|_| "export_failed")? else {
        return Ok(serde_json::json!({"status":"cancelled"}));
    };
    let path = file.into_path().map_err(|_| "export_write_failed")?;
    tokio::task::spawn_blocking(move || {
        thronium_engine::exports::save_bytes_limited(
            &path,
            &bytes,
            thronium_engine::exports::MAX_BYTES,
        )
    })
    .await
    .map_err(|_| "export_write_failed")??;
    Ok(serde_json::json!({"status":"saved"}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_png_decodes_exact_unicode_content_with_quiet_zone() {
        for text in [
            "vless://fixture@example.test:443?security=tls#Тест 🦊",
            &format!("thronium://profiles/{}", "a".repeat(1500)),
        ] {
            let bytes = png(render(text).unwrap()).unwrap();
            let image = image::load_from_memory(&bytes).unwrap().into_luma8();
            assert!((0..24).all(|x| (0..image.height()).all(|y| image.get_pixel(x, y)[0] == 255)));
            let mut prepared = rqrr::PreparedImage::prepare(image);
            let grids = prepared.detect_grids();
            assert_eq!(grids.len(), 1);
            assert_eq!(grids[0].decode().unwrap().1, text);
        }
    }
    #[test]
    fn rejects_empty_or_over_capacity_instead_of_truncating() {
        assert!(render("").is_err());
        assert!(render(&"a".repeat(4097)).is_err());
        assert!(render(&"a".repeat(3000)).is_err());
    }
}
