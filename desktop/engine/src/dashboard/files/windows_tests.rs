use super::*;
use zip::{write::SimpleFileOptions, ZipWriter};

fn archive(html: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in [
        ("site/index.html", html),
        ("site/assets/main.js", b"void 0;"),
    ] {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn a_pointer_file_names_the_served_version_and_replaces_it_whole() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assets.ensure().unwrap();
    assert_eq!(assets.serving_path(), assets.versions().join("seed"));
    assert_eq!(
        fs::read_to_string(assets.serving_path().join("index.html")).unwrap(),
        PLACEHOLDER
    );
    let first = assets.install(&archive(b"<p>one</p>"), || false).unwrap();
    let served = assets.serving_path();
    assert_eq!(served, assets.versions().join(&first.installation_id));
    assert_eq!(fs::read(served.join("index.html")).unwrap(), b"<p>one</p>");
    let second = assets.install(&archive(b"<p>two</p>"), || false).unwrap();
    assert_eq!(
        fs::read_to_string(assets.root.join("current")).unwrap(),
        second.installation_id
    );
    // A Core still serving the first version is not mistaken for a stranger.
    assert!(assets.serves(&served));
    assert!(assets.serves(&assets.serving_path()));
    assert!(!assets.serves(&directory.path().join("elsewhere")));
    assert_eq!(
        assets.inspect().unwrap().unwrap().installation_id,
        second.installation_id
    );
}

#[test]
fn a_damaged_pointer_is_refused_rather_than_followed() {
    let directory = tempfile::tempdir().unwrap();
    let assets = Assets::new(directory.path());
    assets.ensure().unwrap();
    fs::write(assets.root.join("current"), b"..\\..\\outside").unwrap();
    assert!(assets.inspect().is_err());
}
