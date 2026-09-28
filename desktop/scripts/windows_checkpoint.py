#!/usr/bin/env python3
"""Build Thronium for Windows: core, application and, with --installer, the
NSIS installer (`npm run release:windows`).

`desktop/test-results/windows/<stage>/build` receives Thronium.exe,
ThroniumCore.exe, libcronet.dll and the installer, and `binaries.json` their
SHA-256. On Linux the build crosses to x86_64-pc-windows-gnu with MinGW, or to
aarch64-pc-windows-gnullvm with llvm-mingw (--arch aarch64), both fetched into
`.tools` by `windows_cross.py`; makensis comes from `.tools/nsis`. On Windows
the build is native (MSVC). Signing is configured by `windows_signing.py`.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time

DESKTOP = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DESKTOP / 'scripts'))
import windows_cross  # noqa: E402
import windows_signing  # noqa: E402


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', nargs='?', default=time.strftime('%Y%m%d-%H%M%S'),
                        help='name of the output folder (default: the time)')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--installer', action='store_true', help='also build the NSIS installer')
    parser.add_argument('--arch', choices=list(windows_cross.TARGETS), default='x86_64')
    parser.add_argument('--release', action='store_true', help='release profile instead of debug')
    args = parser.parse_args()
    if not args.stage.replace('-', '').isalnum():
        parser.error('stage must contain letters, numbers or hyphens')
    out = DESKTOP / 'test-results/windows' / args.stage
    out.mkdir(parents=True, exist_ok=False)
    native = platform.system() == 'Windows'
    env = {**os.environ, 'CARGO_BUILD_JOBS': str(args.jobs)}
    if native:
        host = next(line.removeprefix('host: ') for line in subprocess.check_output(
            ['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
        triple, target = host, []
        if args.arch != host.split('-')[0]:
            triple = f'{args.arch}-pc-windows-msvc'
            target = ['--target', triple]
            env['THRONIUM_CORE_TARGET'] = triple
    else:
        triple, extra = windows_cross.environment(args.arch)
        env.update(extra)
        env['THRONIUM_CORE_TARGET'] = triple
        target = ['--target', triple]
        if triple.endswith('-gnullvm'):
            # llvm-mingw would leave the application needing its libunwind.dll,
            # and Tauri packs WebView2Loader.dll only for the -gnu targets.
            key = triple.replace('-', '_').upper()
            env[f'CARGO_TARGET_{key}_RUSTFLAGS'] = '-C target-feature=+crt-static'
            loader = f"target/{triple}/{'release' if args.release else 'debug'}/WebView2Loader.dll"
            packed = out / 'cross.tauri.json'
            packed.write_text(json.dumps({'bundle': {'resources': {loader: 'WebView2Loader.dll'}}}) + '\n')
            target += ['--config', str(packed)]
    tauri = ['npx', 'tauri', 'build', *([] if args.release else ['--debug']),
             *(['--bundles', 'nsis'] if args.installer else ['--no-bundle']),
             *target, *windows_signing.tauri_arguments(out)]
    if args.installer and not native:
        tauri = windows_cross.nsis(tauri, env)
    try:
        with (out / 'build.log').open('w') as log:
            for command in (
                [sys.executable, str(DESKTOP / 'scripts/build_core.py'), '--jobs', str(args.jobs)],
                tauri,
            ):
                print('+', ' '.join(command), flush=True)
                subprocess.run(command, cwd=DESKTOP, env=env, stdout=log, stderr=subprocess.STDOUT,
                               check=True, shell=native and command[0] == 'npx')
    finally:
        if not native:
            windows_cross.remove_overlay()
    binaries = DESKTOP / 'src-tauri/binaries'
    core = binaries / f'ThroniumCore-{triple}.exe'
    manifest = json.loads(core.with_suffix('.build.json').read_text())
    # Signing rewrites the core and Cronet in place; unsigned, they must be the ones built.
    signed = bool(windows_signing.config())
    assert signed or sha(core) == manifest['sha256'], 'Core differs from its build manifest'
    assert signed or sha(binaries / 'libcronet.dll') == manifest['libcronetSha256'], 'libcronet.dll differs'
    build = out / 'build'
    build.mkdir()
    folder = DESKTOP / 'src-tauri/target' / (triple if target else '') / ('release' if args.release else 'debug')
    shutil.copy2(folder / 'Thronium.exe', build / 'Thronium.exe')
    shutil.copy2(core, build / 'ThroniumCore.exe')
    shutil.copy2(binaries / 'libcronet.dll', build / 'libcronet.dll')
    if args.installer:
        for installer in (folder / 'bundle/nsis').glob('*-setup.exe'):
            shutil.copy2(installer, build / installer.name)
    hashes = {path.name: sha(path) for path in sorted(build.iterdir())}
    (out / 'binaries.json').write_text(json.dumps(
        {'target': triple, 'signed': signed, 'coreManifest': manifest, 'binaries': hashes}, indent=2) + '\n')
    print(json.dumps(hashes), flush=True)


if __name__ == '__main__':
    main()
