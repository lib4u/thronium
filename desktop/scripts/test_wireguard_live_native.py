#!/usr/bin/env python3
"""Pinned native WireGuard import/traffic tests with an independent userspace peer.

Requires Go and a Qt6 SDK (system pkg-config or --qt-prefix); creates no host TUN.
The server uses standard wireguard-go, independent of the application's fork.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys


def main():
    desktop = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', required=True, type=Path)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--outer-family', choices=['4', '6'], default='4')
    parser.add_argument('--disable-auto-interface', action='store_true', help='Only for reproducing the pre-fix loopback workaround')
    args = parser.parse_args()
    app = args.application.resolve()
    core = app.with_name('ThroniumCore')
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    sources = out / 'test-sources'
    sources.mkdir()
    root = desktop.parent
    fixture = desktop / 'engine/tests/fixtures/wireguard-live'
    files = [*fixture.glob('*.go'),
             root / 'core/server/go.mod', root / 'core/server/go.sum',
             *desktop.joinpath('scripts').glob('*.py'), *desktop.joinpath('tests').glob('*.py')]
    before = {str(p.relative_to(root)): sha(p) for p in files}
    for file in files:
        target = sources / file.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
    (out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app), 'coreSha256': sha(core), 'sources': before}, indent=2) + '\n')
    module = out / 'fixture-build'
    module.mkdir()
    for name in ['go.mod', 'go.sum']:
        shutil.copy2(sources / 'core/server' / name, module / name)
    for name in ['server.go', 'bind.go']:
        shutil.copy2(sources / 'desktop/engine/tests/fixtures/wireguard-live' / name, module / name)
    binary = module / 'wg-fixture'
    go_command = ['go', 'build', '-race', '-p', '2', '-o', str(binary), 'server.go', 'bind.go']
    with (out / 'fixture-build.log').open('w') as log:
        subprocess.run(go_command, cwd=module, env={**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'}, stdout=log, stderr=subprocess.STDOUT, check=True)
    assert all(sha(module / name) == before['core/server/' + name] for name in ['go.mod', 'go.sum']), 'Fixture build modified pinned modules'
    # Archives are written as Qt-Throne writes them, without Qt (thrbackup_writer.py).
    writer = sources / 'desktop/tests/thrbackup_writer.py'
    sys.path.insert(0, str(sources / 'desktop/tests'))
    from wireguard_live_archive import prepare
    native_command = [sys.executable, str(sources / 'desktop/scripts/test_native.py'), '--application', str(app), '--wireguard-live-only', '--private-tray-bus', '--artifacts', str(out)]
    record = {'fixtureBuild': go_command, 'native': native_command,
              'fixtureSha256': sha(binary), 'writerSha256': sha(writer),
              'scope': 'Standard WG + PSK, encrypted loopback UDP, userspace inner IPv4/IPv6 HTTP; no host TUN or route changes; automatic interface binding is enabled unless explicitly disabled for baseline diagnosis.',
              'fixtureRaceDetector': True, 'outerFamily': args.outer_family, 'autoDetectInterface': not args.disable_auto_interface}
    (out / 'command.json').write_text(json.dumps(record, indent=2) + '\n')
    result = None
    with (out / 'fixture-stderr.log').open('w') as log:
        process = subprocess.Popen([str(binary), str(out / 'fixture'), '127.0.0.1' if args.outer_family == '4' else '::1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            assert select.select([process.stdout], [], [], 10)[0], 'WG fixture readiness timeout'
            ready = process.stdout.readline().strip()
            assert ready
            prepare(ready, writer)
            ready_file = Path(ready)
            info = json.loads(ready_file.read_text())
            info['autoDetectInterface'] = not args.disable_auto_interface
            ready_file.write_text(json.dumps(info, indent=2) + '\n')
            with (out / 'native.log').open('w') as native:
                result = subprocess.run(native_command, env={**os.environ, '_THRONIUM_WIREGUARD_LIVE_READY': ready}, stdout=native, stderr=subprocess.STDOUT)
        finally:
            process.stdin.close()
            try:
                fixture_exit = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    fixture_exit = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    fixture_exit = process.wait(timeout=5)
    changes = [str(p.relative_to(root)) for p in files if sha(p) != before[str(p.relative_to(root))]]
    pins_unchanged = sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    count = json.loads((out / 'results.json').read_text())['count'] if (out / 'results.json').exists() else 0
    summary = {'passed': result is not None and result.returncode == 0 and fixture_exit == 0 and not changes and pins_unchanged,
               'checks': count, 'nativeExit': None if result is None else result.returncode, 'fixtureExit': fixture_exit,
               'fixtureReaped': not Path('/proc', str(process.pid)).exists(), 'fixtureRaceDetector': True, 'outerFamily': args.outer_family, 'autoDetectInterface': not args.disable_auto_interface,
               'sourceChanges': changes, 'pinsUnchanged': pins_unchanged, 'applicationSha256': sha(app), 'coreSha256': sha(core)}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    assert summary['passed'] and summary['fixtureReaped']


if __name__ == '__main__':
    main()
