use super::*;
/// An absolute path on this system: Unix names it from the root, Windows
/// from a drive.
fn abs(path: &str) -> PathBuf {
    PathBuf::from(if cfg!(windows) {
        format!("C:{path}")
    } else {
        path.to_owned()
    })
}
fn args(values: &[&str]) -> Result<Arguments, String> {
    parse(values.iter().map(OsString::from))
}
fn resolve(values: &[&str]) -> Location {
    args(values)
        .unwrap()
        .resolve(
            &abs("/apps/Thronium"),
            None,
            Some(&abs("/system/data")),
            &abs("/launch/cwd"),
        )
        .unwrap()
}
#[test]
fn explicit_storage_modes_and_relative_paths_preserve_launch_payloads() {
    let system = resolve(&[]);
    assert_eq!(system.mode, Mode::System);
    assert_eq!(system.directory, abs("/system/data"));
    assert!(system.launch_arguments().is_empty());
    assert!(system.webview_directory().is_none());
    let portable = resolve(&["--portable", "thronium://payload"]);
    assert_eq!(portable.directory, abs("/apps/thronium-data"));
    assert_eq!(
        portable.launch_arguments(),
        vec![OsString::from("--portable")]
    );
    assert_eq!(
        portable.payloads,
        vec![OsString::from("thronium://payload")]
    );
    for input in [
        vec!["--data-dir", "folder space"],
        vec!["--data-dir=folder space"],
        vec!["-appdata", "folder space"],
    ] {
        let custom = resolve(&input);
        assert_eq!(custom.mode, Mode::Custom);
        assert_eq!(custom.directory, abs("/launch/cwd/folder space"));
        assert_eq!(custom.webview_directory(), Some(custom.directory.clone()));
    }
    let old = args(&["-appdata", "throne://payload"]).unwrap();
    assert_eq!(old.selection, Selection::System);
    assert_eq!(old.payloads.len(), 1);
    let data = args(&[
        "--data-dir",
        "thronium://not-a-payload",
        "thronium://actual",
    ])
    .unwrap();
    assert_eq!(data.payloads, vec![OsString::from("thronium://actual")]);
}
#[test]
fn portable_appimage_uses_image_location_and_does_not_change_core_location() {
    let loc = args(&["--portable"])
        .unwrap()
        .resolve(
            &abs("/tmp/mounted/AppRun"),
            Some(&abs("/media/usb/Thronium.AppImage")),
            None,
            &abs("/elsewhere"),
        )
        .unwrap();
    assert_eq!(loc.directory, abs("/media/usb/thronium-data"));
}
#[test]
fn conflicting_or_incomplete_storage_arguments_fail_before_opening_a_library() {
    for input in [
        vec!["--portable", "--data-dir", "folder"],
        vec!["--portable", "--portable"],
        vec!["--data-dir"],
        vec!["--data-dir", ""],
        vec!["--data-dir="],
        vec!["-appdata", "--portable"],
        vec!["--data-dir", "--portable"],
    ] {
        assert_eq!(
            args(&input).unwrap_err(),
            "storage_invalid_arguments",
            "{input:?}"
        );
    }
    assert!(args(&[])
        .unwrap()
        .resolve(Path::new("/app"), None, None, Path::new("/"))
        .is_err());
    let remaining = args(&["--", "--portable", "thronium://link"]).unwrap();
    assert_eq!(remaining.selection, Selection::Automatic);
    assert_eq!(remaining.payloads.len(), 2);
}
#[test]
fn canonical_aliases_share_identity_but_distinct_libraries_do_not() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("first");
    let open = |path: PathBuf| {
        Location {
            mode: Mode::Custom,
            force_system: false,
            directory: path,
            payloads: vec![],
        }
        .prepare()
        .unwrap()
    };
    let first = open(path.clone());
    let other = open(temp.path().join("second"));
    assert_ne!(
        first.instance_id("io.thronium.desktop"),
        other.instance_id("io.thronium.desktop")
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&path, temp.path().join("alias")).unwrap();
        let alias = open(temp.path().join("alias"));
        assert_eq!(
            first.instance_id("io.thronium.desktop"),
            alias.instance_id("io.thronium.desktop")
        );
        assert_eq!(first.directory, alias.directory);
    }
    assert!(!first.directory.join("library.json").exists());
    assert_eq!(std::fs::read_dir(first.directory).unwrap().count(), 0);
}
#[test]
fn file_in_place_of_directory_is_not_replaced_or_redirected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("selected");
    std::fs::write(&path, b"keep").unwrap();
    let loc = Location {
        mode: Mode::Custom,
        force_system: false,
        directory: path.clone(),
        payloads: vec![],
    };
    assert_eq!(loc.prepare().unwrap_err(), "storage_unavailable");
    assert_eq!(std::fs::read(path).unwrap(), b"keep");
}
#[test]
fn desktop_launch_arguments_are_separate_and_field_codes_are_literal_except_url() {
    let line = desktop_exec(
        Path::new("/app space/Thronium"),
        &[
            "--data-dir".into(),
            "/data/quote\" dollar$ back` slash\\ percent%".into(),
        ],
        true,
    )
    .unwrap();
    assert_eq!(line,"\"/app space/Thronium\" \"--data-dir\" \"/data/quote\\\" dollar\\$ back\\` slash\\\\ percent%%\" %U");
    assert!(desktop_exec(Path::new("/app"), &["bad\nargument".into()], false).is_err());
    assert!(desktop_exec(Path::new("/app=path/Thronium"), &[], false).is_err());
}

#[cfg(unix)]
#[test]
fn explicitly_read_only_custom_directory_is_not_made_writable() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("readonly");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let loc = Location {
        mode: Mode::Custom,
        force_system: false,
        directory: path.clone(),
        payloads: vec![],
    };
    assert_eq!(loc.prepare().unwrap_err(), "storage_unavailable");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o500
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn portable_choice_survives_a_plain_launch_and_system_override_remains_explicit() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("Thronium");
    let system = root.path().join("system");
    let resolve = |values: &[&str]| {
        args(values)
            .unwrap()
            .resolve(&executable, None, Some(&system), root.path())
            .unwrap()
    };
    assert_eq!(resolve(&[]).mode, Mode::System);
    let portable = resolve(&["--portable"]).prepare().unwrap();
    assert_eq!(
        std::fs::read(portable.directory.join(PORTABLE_MARKER)).unwrap(),
        PORTABLE_MAGIC
    );
    assert_eq!(resolve(&[]).mode, Mode::Portable);
    let explicit = resolve(&["-appdata"]);
    assert_eq!(explicit.directory, system);
    assert_eq!(
        explicit.launch_arguments(),
        vec![OsString::from("-appdata")]
    );
    let moved = root.path().join("moved");
    std::fs::create_dir(&moved).unwrap();
    std::fs::rename(&portable.directory, moved.join("thronium-data")).unwrap();
    let relocated = args(&[])
        .unwrap()
        .resolve(&moved.join("Thronium"), None, Some(&system), root.path())
        .unwrap();
    assert_eq!(relocated.mode, Mode::Portable);
    assert_eq!(relocated.directory, moved.join("thronium-data"));
}
#[test]
fn invalid_or_symlinked_portable_marker_never_selects_an_unrelated_default_library() {
    let root = tempfile::tempdir().unwrap();
    let adjacent = root.path().join("thronium-data");
    std::fs::create_dir(&adjacent).unwrap();
    let resolve = || {
        args(&[]).unwrap().resolve(
            &root.path().join("Thronium"),
            None,
            Some(&root.path().join("standard")),
            root.path(),
        )
    };
    assert_eq!(resolve().unwrap().mode, Mode::System);
    std::fs::write(adjacent.join(PORTABLE_MARKER), b"foreign").unwrap();
    assert_eq!(resolve().unwrap_err(), "storage_portable_marker_invalid");
    assert_eq!(
        std::fs::read(adjacent.join(PORTABLE_MARKER)).unwrap(),
        b"foreign"
    );
    #[cfg(unix)]
    {
        std::fs::remove_file(adjacent.join(PORTABLE_MARKER)).unwrap();
        let other = root.path().join("other-marker");
        std::fs::write(&other, PORTABLE_MAGIC).unwrap();
        std::os::unix::fs::symlink(other, adjacent.join(PORTABLE_MARKER)).unwrap();
        assert_eq!(resolve().unwrap_err(), "storage_portable_marker_invalid");
    }
}
#[test]
#[cfg(unix)]
fn a_throne_data_directory_is_refused_without_touching_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let throne = dir.path().join("config");
    std::fs::create_dir(&throne).unwrap();
    std::fs::write(throne.join("throne.db"), b"SQLite format 3\0").unwrap();
    std::fs::set_permissions(&throne, std::fs::Permissions::from_mode(0o755)).unwrap();
    let location = args(&["-appdata", throne.to_str().unwrap()])
        .unwrap()
        .resolve(Path::new("/apps/Thronium"), None, None, dir.path())
        .unwrap();
    assert_eq!(location.prepare().unwrap_err(), "storage_throne_directory");
    assert_eq!(
        std::fs::metadata(&throne).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(std::fs::read_dir(&throne).unwrap().count(), 1);
}

/// An independent reader of the rules `CommandLineToArgvW` documents, so the
/// composition is proven by parsing it back rather than by matching a string.
fn parse_windows(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut backslashes = 0usize;
    let flush_backslashes = |current: &mut String, backslashes: &mut usize, halve: bool| {
        let count = if halve {
            *backslashes / 2
        } else {
            *backslashes
        };
        current.push_str(&"\\".repeat(count));
        *backslashes = 0;
    };
    for character in line.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                started = true;
            }
            '"' => {
                let literal = backslashes % 2 == 1;
                flush_backslashes(&mut current, &mut backslashes, true);
                started = true;
                if literal {
                    current.push('"');
                } else {
                    quoted = !quoted;
                }
            }
            ' ' | '\t' if !quoted => {
                flush_backslashes(&mut current, &mut backslashes, false);
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                flush_backslashes(&mut current, &mut backslashes, false);
                started = true;
                current.push(character);
            }
        }
    }
    flush_backslashes(&mut current, &mut backslashes, false);
    if started {
        args.push(current);
    }
    args
}

#[test]
fn a_windows_command_line_reads_back_as_the_very_arguments_it_was_given() {
    let cases: [(&str, Vec<&str>); 6] = [
        (r"C:\Apps\Thronium.exe", vec![]),
        (
            r"C:\Program Files\Thronium\Thronium.exe",
            vec!["--portable"],
        ),
        (
            r"C:\Apps\Thronium.exe",
            vec!["--data-dir", r"D:\My Library\Thronium\"],
        ),
        (
            r"C:\Apps\Thronium.exe",
            vec!["--data-dir", r#"D:\"quoted""#],
        ),
        (r"C:\Apps\Thronium.exe", vec!["--data-dir", ""]),
        (
            r"C:\Apps\Thronium.exe",
            vec!["--data-dir", r"C:\ends\with\\backslashes\\\\"],
        ),
    ];
    for (executable, args) in cases {
        let owned: Vec<OsString> = args.iter().map(OsString::from).collect();
        let line = super::windows_command_line(Path::new(executable), &owned, false).unwrap();
        let mut expected = vec![executable.to_owned()];
        expected.extend(args.iter().map(|a| (*a).to_owned()));
        assert_eq!(parse_windows(&line), expected, "line was {line}");
    }
}

#[test]
fn a_windows_handler_keeps_the_link_field_after_the_library_arguments() {
    let args = [OsString::from("--data-dir"), OsString::from(r"D:\Lib rary")];
    let line =
        super::windows_command_line(Path::new(r"C:\Apps\Thronium.exe"), &args, true).unwrap();
    assert_eq!(
        line,
        r#"C:\Apps\Thronium.exe --data-dir "D:\Lib rary" "%1""#
    );
    assert_eq!(
        parse_windows(&line),
        [r"C:\Apps\Thronium.exe", "--data-dir", r"D:\Lib rary", "%1"]
    );
}

#[test]
fn a_windows_command_line_refuses_arguments_that_would_break_the_registry_value() {
    for bad in ["with\nnewline", "with\rreturn", "with\0nul"] {
        assert_eq!(
            super::windows_command_line(
                Path::new(r"C:\Apps\Thronium.exe"),
                &[OsString::from(bad)],
                false
            )
            .unwrap_err(),
            "storage_launch_arguments_invalid"
        );
    }
}
