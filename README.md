# Thronium

**English** · [Русский](README.ru.md)

**A modern proxy and VPN client for the desktop: a fast, thoughtful interface
on top of the proven foundation of [Throne](https://github.com/throneproj/Throne).**

Thronium runs [sing-box](https://github.com/SagerNet/sing-box) and
[Xray](https://github.com/XTLS/Xray-core) side by side, with the protocol forks
that Throne users rely on — AmneziaWG, TrustTunnel, Mieru, NaïveProxy and more.
It is written from scratch as a [Tauri 2](https://tauri.app/) application: a
React interface, an engine in Rust and the core in Go. The result is a light,
responsive app where every everyday task — picking a server,
checking it, organizing subscriptions, routing traffic — takes a click instead
of a config file.

Coming from Throne or Nekoray? Thronium imports your backup or installed
library in one step: profiles, groups, subscriptions, routes and settings.

> **Version 0.1.0.** Linux (x86_64) and Windows 10/11 (x86_64 and ARM64).
> macOS is planned.

<p align="center">
  <img src="docs/screenshots/servers.png" alt="Servers: subscriptions with VLESS, AmneziaWG and TrustTunnel" width="49%">
  <img src="docs/screenshots/connected.png" alt="Connected" width="49%">
</p>

## Why Thronium

### Automatic server selection that adapts to you

- **Quick auto-select, always at hand.** One card picks the best server from
  all groups or a single group, switches on failure, and remembers the last
  good choice (up to 24 hours) so it is checked first on the next connect.
- **Pools as flexible as you need.** Build a pool from a group, a filter or an
  explicit list: name and country filters, exclude patterns, order by latency
  or by saved results, pool caps and startup limits, balancing, a pinned
  member.
- **Self-healing.** Health checks and instant failover run inside the core;
  a pool can measure before connecting, start warm from saved health, and
  rebuild itself when every member fails or a subscription updates.
- **Transparent.** A history of every switch shows which server took over and
  why.

### Ping that simply works

- **Automatic method.** Latency is measured over HTTP, falling back to TCP and
  then ICMP when a server cannot answer the previous method. Thronium knows
  which protocols cannot be pinged over TCP (WireGuard, Hysteria, TUIC, QUIC
  transports and others) and picks accordingly. Every method can also be
  forced by hand.
- **VPN endpoints too.** OpenVPN, OpenConnect and other VPN profiles are tested
  in a throwaway core session that never disturbs the active connection.
- **More than latency.** Exit IP and country, speed tests, periodic checks of
  favourites and a journal of every measurement.

### Subscriptions, neatly organized

- Every subscription is its own group with its own update interval,
  User-Agent, headers and "update through proxy" switch.
- **Name rules** keep lists tidy: include or exclude by pattern and rename
  servers as they arrive.
- **Review before apply.** An update shows what is added, changed and removed
  before anything touches your library; updates are queued and scheduled.
- **Provider data.** Title, announcements, traffic quota and expiry, and
  provider-supplied routing (including `happ://routing/`).

### Routing without writing JSON

- A visual editor for nested AND/OR conditions, per-rule outbounds and rule
  actions (route, block, direct, DNS interception, protocol sniffing, domain
  resolution, bypass).
- Routing profiles with their own DNS servers and rules, hosts and FakeIP,
  geodata and rule sets, plus ready-made presets.

### Two engines, full control

- **sing-box and Xray in one client.** VLESS profiles run on the engine of
  your choice — a global default with per-profile overrides that never rewrite
  the saved profile.
- Complete sing-box and Xray configurations as profiles, proxy chains, and
  external cores started as a local proxy.
- Per-core settings: log levels, APIs, multiplexing and the API dashboard.

### Native AmneziaWG

AmneziaWG **2.0 and 3.0/3.1** work natively, alongside 1.0 and 1.5: junk
packets, header protection, padding, timing ranges, trailers and cookies. The
list shows which version each profile uses.

### Import everything

- Share links and QR codes in both directions for every supported protocol.
- **Amnezia `vpn://`** links and subscriptions — AmneziaWG, WireGuard, Xray
  and OpenVPN configurations inside are recognized automatically.
- **TrustTunnel `tt://`** links, including the new deep-link format.
- Clash YAML, WireGuard `.conf`, OpenVPN, OpenConnect and AnyConnect XML,
  SIP008, `thronium://` profile bundles, Throne backups and libraries.

### Corporate VPNs with one-time codes

Interactive OpenVPN and OpenConnect sign-in, and a built-in HOTP/TOTP
authenticator whose codes fill VPN forms automatically.

### Safe by design

- The whole library is sealed with a key from the system keyring (Secret
  Service on Linux, Credential Manager on Windows).
- The system proxy is restored even after a crash; on Linux a crashed
  core is restarted.
- The window never touches the network or the system: every action is a typed
  command to the engine.

### Everyday comfort

Tray with status icons, notifications, portable mode, backups, a duplicate
finder that asks before it removes, settings search, traffic statistics per
profile and per application, `throne://` and `thronium://` links, light, dark
and system themes, English and Russian.

## Protocols

SOCKS, HTTP(S), Shadowsocks, Trojan, VMess, VLESS (sing-box and Xray), TUIC,
Hysteria and Hysteria2, AnyTLS, Mieru, Snell, NaïveProxy, Juicity, TrustTunnel,
ShadowTLS, WireGuard, AmneziaWG, SSH, OpenVPN, OpenConnect and Tailscale.

Connection modes: local proxy, system proxy (GNOME, KDE, Windows) and TUN
(Linux through a privileged helper, Windows through the Thronium service) with
system DNS.

## How it is built

```
desktop/src         React + TypeScript window
      │  typed IPC commands (desktop/contracts)
desktop/src-tauri   Tauri 2 host in Rust: window, tray, OS integration
      │
desktop/engine      Rust engine: library, profiles, routing, subscriptions,
      │             system proxy, TUN, secrets, import from Throne
      │  protobuf over a private socket (Unix) or named pipe (Windows)
core/server         ThroniumCore in Go: sing-box and Xray with the protocol
                    forks Thronium ships; on Windows also the TUN service
```

The engine owns the library and runs the core as a child process it verifies
(and, for TUN, through a helper or service).

## Repository

| Path | Contents |
| --- | --- |
| `desktop/` | The application: `src`, `src-tauri`, `engine`, `locales`, `contracts`, `tests`, `scripts` |
| `core/server/` | The Go core |
| `docs/DEVELOPMENT.md` | Checks, native test suites, scripts |
| `.github/workflows/` | Quality checks and the Linux and Windows builds |

## Building

All commands run in `desktop/`. The core and the application are built by the
repository's scripts; nothing is installed system-wide.

### Linux

Tested on Fedora 44, x86_64. Requirements:

- Node.js 22 with npm, Rust (stable, 1.98 or newer), Go 1.26, Python 3,
  Clang and LLVM LLD (the core links Cronet for NaïveProxy);
- the [Tauri prerequisites for Linux](https://v2.tauri.app/start/prerequisites/#linux):
  GTK 3 and WebKitGTK 4.1 development packages, `glib2`, `pkg-config`.

```sh
cd desktop
npm ci
npm run core:build        # ThroniumCore into src-tauri/binaries
npm run desktop:build     # debug build
./src-tauri/target/debug/Thronium
```

`npm run tauri dev` runs the window with live reload once the core is built.

Release packages (deb, rpm and AppImage, in
`src-tauri/target/release/bundle/`):

```sh
npm run release:linux
```

The AppImage step downloads `linuxdeploy`; its bundled `strip` cannot read
binaries of current toolchains, so the script packs them unstripped
(`NO_STRIP=true`) and runs `linuxdeploy` without FUSE.

### Windows

The installer is NSIS; it installs for all users (with the TUN service) or for
the current user only, and brings the WebView2 runtime when it is missing.

**From Linux** (Fedora or another `dnf` system; the MinGW, llvm-mingw and NSIS
toolchains are downloaded into `desktop/.tools` on first use):

```sh
rustup target add x86_64-pc-windows-gnu aarch64-pc-windows-gnullvm
npm run release:windows                    # x86_64
npm run release:windows -- --arch aarch64  # ARM64
```

**On Windows**: run `desktop/scripts/windows_bootstrap.ps1` in an elevated
PowerShell once (it installs the MSVC toolchain, Go, Node, Python and Git),
then `npm ci` and `npm run release:windows`.

The installer and the binaries end up in
`desktop/test-results/windows/<time>/build/`.

**Signing.** Builds are unsigned unless the environment names a signer:
`THRONIUM_SIGN_COMMAND` (a command with `%1` for the file, for example
`trusted-signing-cli` for Azure Trusted Signing) or `THRONIUM_SIGN_THUMBPRINT`
(a certificate in the user's store). See `desktop/scripts/windows_signing.py`.

## Checks

```sh
npm run check:frontend    # types, lint, format, catalogs, unit tests
npm run contracts:check   # IPC contracts match the engine
npm run test:engine       # engine unit and integration tests
npm run test:engine-live  # engine tests against the real core
npm run native -- --list  # native window suites on a private display
```

Details, including the Windows checks, are in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License

GPL-3.0, as Throne. See [LICENSE](LICENSE). The Manrope font is under the SIL
Open Font License ([desktop/src/assets/OFL-Manrope.txt](desktop/src/assets/OFL-Manrope.txt)).

## Credits

- [Throne](https://github.com/throneproj/Throne) and
  [Nekoray](https://github.com/MatsuriDayo/nekoray), whose protocol forks and
  years of work Thronium builds on
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) and
  [XTLS/Xray-core](https://github.com/xtls/xray-core)
- [Tauri](https://tauri.app/)
