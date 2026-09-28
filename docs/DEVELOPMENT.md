# Developing Thronium

Build requirements and release builds are in the [README](../README.md). This
guide covers the parts of the tree, the checks and the tools behind them. All
commands run in `desktop/` unless stated otherwise.

## Layout

| Path | Contents |
| --- | --- |
| `desktop/src` | The window: React + TypeScript and styles |
| `desktop/src-tauri` | Tauri 2 host: commands, tray, window, OS integration (autostart, links, session end, notifications) |
| `desktop/engine` | The engine library: store, profiles, routing compiler, subscriptions, system proxy, TUN, secrets, backups, import from Throne; `src/bin` holds core smoke programs |
| `desktop/contracts` | Settings catalog and the generated IPC contract |
| `desktop/locales` | Interface texts per language; `languages.json` lists the languages |
| `desktop/tests` | Unit tests (`*.test.mjs`), native suites (`*_ui.py`), fixtures and fixture servers |
| `desktop/tests/harness` | Private display, accessibility bus and the registry of native suites |
| `desktop/scripts` | Core build, Windows builds, test runners, generators |
| `desktop/vendor` | Vendored crates with local patches (see each `THRONIUM-PATCH.md`) |
| `core/server` | ThroniumCore (Go): IPC dispatch, sing-box and Xray, process supervision, the Windows service |

Downloaded toolchains and caches live in `desktop/.tools` (ignored by git):
protobuf generators, the core's module overlay, MinGW, llvm-mingw, NSIS and
the private display's Xvfb and openbox. Results of test runs go to
`desktop/test-results` (ignored).

## Everyday checks

```sh
npm run check:frontend   # version, i18n catalogs, types, lint, format, unit tests
npm run contracts:check  # generated IPC contract matches the engine
npm run rust:fmt:check
npm run rust:clippy
npm run test:engine      # engine unit and integration tests
cargo test --manifest-path src-tauri/Cargo.toml   # host tests
```

The core's own tests run from `core/server`:

```sh
go test -ldflags=-X=ThroneCore/parentcheck.expectedParentName=Thronium ./internal/...
```

## Tests against the real core

`npm run core:build` first. The core accepts only a parent process named
`Thronium` in its own directory, so runners place test binaries accordingly.

- `npm run test:engine-live` — every engine test marked `#[ignore]` because it
  needs the core: loopback servers, synthetic fixtures from `desktop/tests`,
  private namespaces and a private GNOME keyfile. `--list` shows them; an
  ignored test missing from the runner's registry fails the run.
  `--with-keyring` adds the test that touches this desktop's keyring.
- `npm run test:core`, `test:*-core` — standalone checks of the core with the
  engine's smoke programs (routing, chains, selectors, WireGuard, DNS,
  OpenConnect, managed VPN and others). Those that need arguments take them
  after `--`.

## Native window suites

The native suites drive the real window through WebDriver and the
accessibility bus, on an Xvfb display the run owns — the desktop session is
never used. Requirements: `cargo install tauri-driver --version 2.0.6 --locked`,
`WebKitWebDriver`, Python with `gi` (GLib/Gio), `pyatspi`, Pillow and
`python-xlib`, `dbus-run-session`, and a built application
(`npm run core:build && npm run desktop:build`).

```sh
npm run native -- --list
npm run native -- settings library connection recovery-core legacy-backup
```

Each suite runs on a copy of the application and core. Suites that need their
own wrapper (fixture servers, namespaces, pinned hashes) are listed in
`tests/harness/suites.json`; the rest are `scripts/test_native.py
--<suite>-only`. Arguments after `--` go to the wrappers. Results, screenshots
and logs are in `test-results/native/<time>/`. The display tools are
downloaded with `dnf` on first use.

## Windows

- `npm run check:windows` — the engine and host compile for
  `x86_64-pc-windows-gnu` (`-- --arch aarch64` for ARM64).
- `npm run release:windows` — core, application and NSIS installer (see the
  README for cross builds and signing).
- CI (`.github/workflows/thronium-build.yml`) builds and tests on
  `windows-latest` and `windows-11-arm`.
- `scripts/windows_bootstrap.ps1` prepares a Windows machine for native
  builds and checks.

## Imports from Throne

Throne backups (`.thrbackup`) and installed libraries are read by
`engine/src/legacy_backup`. The fixtures under `engine/**/fixtures` and
`tests/fixtures` were produced by Throne's own Qt code; their manifests record
where each came from. `tests/thrbackup_writer.py` writes archives byte for
byte as Throne does (`--verify <archive>...` proves it on existing ones), and
the stands use it to build their archives. Frozen blocks of Throne's source
that the tests read as data are in `engine/qt-source` and `tests/qt-snapshot`;
`scripts/freeze_qt_snapshot.py --throne <checkout>` refreshes them.

## Continuous integration

- `thronium-quality.yml` — frontend checks, IPC contracts, Rust format,
  clippy and the engine library tests on every change.
- `thronium-build.yml` — release builds: Linux packages (deb, rpm, AppImage)
  and the Windows installers (x86_64 and ARM64), uploaded as run artifacts.
  Pushing a `v*` tag also creates a draft GitHub release with them.

## Generated files

- `npm run contracts:generate` — the IPC contract and TypeScript types from
  the engine.
- `npm run i18n:generate` — catalogs, native text keys and the installer
  languages from `locales/`. A language is added as a folder plus a line in
  `languages.json`.
- `npm run version:set -- 1.2.3` — the one version, in `package.json`, the
  crates and the core.
- `core/server/gen/*.pb.go` are generated from `libcore.proto` by
  `npm run core:build`.
