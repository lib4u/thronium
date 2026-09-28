use super::*;

#[test]
fn launch_arguments_name_existing_files_only() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("profile one.json");
    std::fs::write(&config, "{}").unwrap();
    let cwd = directory.path();
    assert_eq!(
        file(OsStr::new("profile one.json"), cwd),
        Some(config.clone())
    );
    assert_eq!(
        file(config.as_os_str(), Path::new("/")),
        Some(config.clone())
    );
    let url = tauri::Url::from_file_path(&config).unwrap();
    assert_eq!(file(OsStr::new(url.as_str()), Path::new("/")), Some(config));
    for ignored in [
        "",
        "--portable",
        "missing.json",
        ".",
        "https://example.test/a",
    ] {
        assert_eq!(file(OsStr::new(ignored), cwd), None, "{ignored}");
    }
}

#[test]
fn files_become_import_documents_with_per_file_problems() {
    let directory = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let utf8 = write("bom.yaml", "\u{feff}proxies: []\n".as_bytes());
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend("[Interface]".encode_utf16().flat_map(u16::to_le_bytes));
    let utf16 = write("wg.conf", &utf16);
    let binary = write("binary.json", b"{\x01}");
    let blank = write("blank.txt", b" \n");
    let image = write("broken.png", b"\x89PNG\r\n\x1a\nnot an image");
    let large = write("large.json", &vec![b' '; MAX_CONFIG_BYTES + 1]);
    let result = documents(&[utf8, utf16, binary, blank, image, large]);
    assert_eq!(
        result,
        json!({
            "kind": "files",
            "documents": [
                {"filename": "bom.yaml", "text": "proxies: []\n"},
                {"filename": "wg.conf", "text": "[Interface]"},
            ],
            "problems": [
                {"filename": "binary.json", "code": "unreadable"},
                {"filename": "blank.txt", "code": "unreadable"},
                {"filename": "broken.png", "code": "qr_image_invalid"},
                {"filename": "large.json", "code": "import_too_large"},
            ],
        })
    );
}

#[test]
fn files_together_stay_within_one_import() {
    let directory = tempfile::tempdir().unwrap();
    let half = vec![b'a'; MAX_CONFIG_BYTES / 2 + 1];
    let paths: Vec<_> = ["a.txt", "b.txt"]
        .iter()
        .map(|name| {
            let path = directory.path().join(name);
            std::fs::write(&path, &half).unwrap();
            path
        })
        .collect();
    let result = documents(&paths);
    assert_eq!(result["documents"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["problems"],
        json!([{"filename": "b.txt", "code": "import_too_large"}])
    );
}
