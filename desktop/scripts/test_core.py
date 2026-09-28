#!/usr/bin/env python3
"""Run the Rust/Go integration test with the real production parent check."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import sys

desktop = pathlib.Path(__file__).resolve().parents[1]
host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
suffix = '.exe' if 'windows' in host else ''
core = desktop / 'src-tauri/binaries' / f'ThroniumCore-{host}{suffix}'
if not core.is_file():
    raise SystemExit('Build the sidecar first: npm run core:build')
binary = 'singbox-settings-smoke' if '--singbox-settings' in sys.argv else 'xray-settings-smoke' if '--xray-settings' in sys.argv else 'group-chain-smoke' if '--group-chains' in sys.argv else 'settings-smoke' if '--settings' in sys.argv else 'connection-smoke' if '--connection' in sys.argv else 'selector-smoke' if '--selector' in sys.argv else 'chain-smoke' if '--chains' in sys.argv else 'routing-smoke' if '--routing' in sys.argv else 'legacy-protocols-smoke' if '--legacy-protocols' in sys.argv else 'engine-smoke'
if '--warp-routes' in sys.argv or '--warp-import' in sys.argv:
    binary = 'chain-smoke'
subprocess.run(['cargo', 'build', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--bin', binary, '-j', '2'], check=True)
with tempfile.TemporaryDirectory(prefix='thronium-engine-test-') as folder:
    folder = pathlib.Path(folder)
    shutil.copy2(core, folder / ('ThroniumCore' + suffix))
    shutil.copy2(desktop / 'engine/target/debug' / (binary + suffix), folder / ('Thronium' + suffix))
    if '--xray-settings' in sys.argv:
        subprocess.run(['go', 'build', '-o', str(folder / ('check-xray-api' + suffix)), str(desktop / 'tests/xray_api_check.go')], cwd=desktop.parent / 'core/server', check=True)
    if '--routing' in sys.argv:
        fixture = folder / 'routing.json'
        subprocess.run(['node', str(desktop / 'tests/routing-fixtures.mjs'), str(fixture)], check=True)
        subprocess.run([str(folder / ('Thronium' + suffix)), str(fixture)], check=True, timeout=90)
    if '--profiles' in sys.argv or '--imports' in sys.argv or '--share' in sys.argv:
        fixture = folder / 'profiles.json'
        subprocess.run(['node', str(desktop / ('tests/share-fixtures.mjs' if '--share' in sys.argv else 'tests/import-fixtures.mjs' if '--imports' in sys.argv else 'tests/profile-fixtures.mjs')), str(fixture)], check=True)
        subprocess.run([str(folder / ('Thronium' + suffix)), str(fixture)], check=True, timeout=90)
    elif binary == 'chain-smoke':
        # Real WireGuard hops: the independent wireguard-go peer relays tunnel traffic.
        sys.path.insert(0, str(desktop / 'scripts'))
        from wireguard_fixture import build
        peer, _, _ = build(desktop)
        flags = [flag for flag in ['--warp-routes', '--warp-import'] if flag in sys.argv]
        # Real OpenVPN hops: an owned openvpn-server in a second pinned Core whose
        # parent must be named Thronium, hence the copied interpreter.
        ovpn = folder / 'openvpn-fixture'
        ovpn.mkdir(mode=0o700)
        shutil.copy2(core, ovpn / 'ThroniumCore')
        shutil.copy2(sys.executable, ovpn / 'Thronium')
        shutil.copy2(desktop / 'tests/openvpn_chain_fixture.py', ovpn / 'fixture.py')
        env = {**os.environ, '_THRONIUM_WG_FIXTURE': str(peer), '_THRONIUM_OVPN_FIXTURE': str(ovpn),
               'PYTHONPATH': str(desktop / 'tests') + os.pathsep + os.environ.get('PYTHONPATH', '')}
        subprocess.run([str(folder / ('Thronium' + suffix)), *flags], check=True, timeout=240, env=env)
    else:
        subprocess.run([str(folder / ('Thronium' + suffix))], check=True, timeout=90)
