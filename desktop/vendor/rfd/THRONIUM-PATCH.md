# Thronium GTK filename fix

This directory contains rfd 0.16.0 from crates.io, with its MIT license.
Upstream archive checksum:
`a15ad77d9e70a92437d8f74c35d99b4e4691128df018833e99f90bcd36152672`.

The GTK backend called `CStr::from_ptr` on a nullable result from
`gtk_file_chooser_get_filename`. An actual Thronium file-picker response
crashed in `strlen`; the saved core dump confirms a null argument. GTK's GIR
marks this return as nullable with full ownership.

`dialog_ffi.rs` now treats a missing local filename as no selection and frees
GTK-owned filename strings after copying them. Multiple selections use the
same conversion and free the list container. Valid UTF-8 paths and the existing
None result for invalid UTF-8 are preserved. Other backends are unchanged.

The application uses this copy through `[patch.crates-io]` in src-tauri.
Tests cover null, copied Unicode paths, invalid UTF-8, and an actual unselected
GTK chooser on a private display. From the repository root:

```sh
python3 desktop/scripts/test_rfd_gtk.py --artifacts /tmp/thronium-rfd-check-new
```

The script requires `broadwayd`, compiles the locked GTK backend and keeps its
settings and display separate from the desktop. Native application regressions
are covered by the native `rfd-dialogs` suite.
