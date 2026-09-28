#!/usr/bin/env python3
"""Pinned native VPN auth acceptance with private userspace servers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile

desktop = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--application', type=Path, required=True)
parser.add_argument('--application-sha256', required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--artifacts', type=Path, required=True)
parser.add_argument('--prepare-only', action='store_true')
parser.add_argument('--managed', action='store_true', help='Require private user/network/mount namespaces and use the managed auth suite')
args = parser.parse_args()
if args.managed:
    assert os.geteuid() == 0 and not args.prepare_only
    for kind in ['net', 'mnt', 'user']:
        assert os.environ.get('THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS') not in (None, os.readlink('/proc/self/ns/' + kind))
    assert os.environ.get('DBUS_SYSTEM_BUS_ADDRESS') == 'unix:path=/run/host-system-bus-unavailable'
    assert not Path('/run/dbus/system_bus_socket').exists()
    assert any(row.split()[1] == '/run' and row.split()[2] == 'tmpfs' for row in Path('/proc/mounts').read_text().splitlines())
app = args.application.resolve()
core = app.with_name('ThroniumCore')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
out = args.artifacts.resolve()
out.mkdir(parents=True, exist_ok=False)
sources = out / 'test-sources'
sources.mkdir()
files = [Path(__file__), desktop / 'tests/vpn_auth_fixture.py']
if not args.prepare_only:
    files += [desktop / name for name in ['tests/vpn_auth_ui.py', 'scripts/test_native.py',
        'tests/native_smoke.py', 'tests/native_transport.py', 'tests/native_screenshot.py',
        'tests/native_processes.py', 'tests/native_menu.py', 'tests/native_dialogs.py', 'tests/rfd_dialog_fixture.py', 'tests/tray_ui.py', 'tests/window_ui.py']]
if args.managed:
    files += [desktop / 'tests/vpn_auth_managed_ui.py', desktop / 'scripts/test_vpn_auth_managed_native.py']
source_hashes = {str(path.relative_to(desktop)): sha(path) for path in files}
for path in files:
    shutil.copy2(path, sources / path.name)
(out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app),
    'coreSha256': sha(core), 'testSources': source_hashes}, indent=2) + '\n')
status = {'passed': False, 'prepareOnly': args.prepare_only}
try:
    with tempfile.TemporaryDirectory(prefix='thronium-vpn-auth-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        shutil.copy2(Path(sys.executable).resolve(), root / 'Thronium')
        shutil.copy2(core, root / 'ThroniumCore')
        fixture_command = [str(root / 'Thronium'), str(sources / 'vpn_auth_fixture.py'), str(root)]
        if args.prepare_only:
            fixture_command.append('--self-check')
        with (out / 'fixture-stderr.log').open('w') as log:
            fixture = subprocess.Popen(fixture_command,
                env={**os.environ, 'PYTHONHOME': sys.prefix},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                assert select.select([fixture.stdout], [], [], 15)[0], 'fixture_ready_timeout'
                line = fixture.stdout.readline()
                assert line, 'fixture_start_failed'
                ready = json.loads(line)
                ready_file = out / 'fixture-ready.json'
                ready_file.write_text(json.dumps(ready, indent=2) + '\n')
                if args.prepare_only:
                    assert select.select([fixture.stdout], [], [], 35)[0], 'fixture_selfcheck_timeout'
                    line = fixture.stdout.readline()
                    assert line, 'fixture_selfcheck_failed'
                    status['fixtureChecks'] = json.loads(line)
                else:
                    native_command = [sys.executable, str(desktop / 'scripts/test_native.py'),
                        '--application', str(app), '--vpn-auth-managed-only' if args.managed else '--vpn-auth-only', '--private-tray-bus', '--artifacts', str(out)]
                    (out / 'command.json').write_text(json.dumps({'native': native_command,
                        'scope': 'Owned userspace OpenVPN/HTTPS servers and private CA/XDG; managed TUN only in guarded private namespaces.' if args.managed else 'Owned userspace OpenVPN/HTTPS servers, private CA and XDG. No host TUN/proxy.'}, indent=2) + '\n')
                    with (out / 'native.log').open('w') as native_log:
                        result = subprocess.run(native_command, stdout=native_log, stderr=subprocess.STDOUT,
                            env={**os.environ, '_THRONIUM_VPN_AUTH_READY': str(ready_file)})
                    status['nativeExitCode'] = result.returncode
                    result.check_returncode()
                    status['checks'] = json.loads((out / 'results.json').read_text())['count']
            finally:
                fixture.stdin.close()
                try:
                    status['fixtureExitCode'] = fixture.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    fixture.terminate()
                    status['fixtureExitCode'] = fixture.wait(timeout=5)
                # Never preserve the generated private key or raw request bodies.
                for name in ['events.jsonl', 'server-core.log', 'client-core.log']:
                    if (root / name).exists():
                        shutil.copy2(root / name, out / ('fixture-' + name))
                assert sha(root / 'ThroniumCore') == args.core_sha256
            assert status['fixtureExitCode'] == 0, 'fixture_cleanup_failed'
            status['passed'] = True
finally:
    status['applicationSha256'] = sha(app)
    status['coreSha256'] = sha(core)
    status['pinnedInputsUnchanged'] = sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    status['testSourcesUnchanged'] = source_hashes == {str(path.relative_to(desktop)): sha(path) for path in files}
    (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
    assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
print('PASS', 'fixture preparation' if args.prepare_only else status['checks'])
