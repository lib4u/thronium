#!/usr/bin/env python3
"""Pinned OTP binding UI with owned userspace VPN/HTTPS verification servers."""
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
parser.add_argument('--managed', action='store_true')
args = parser.parse_args()
if args.managed:
    assert os.geteuid() == 0
    for kind in ['net', 'mnt', 'user']:
        assert os.environ.get('THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS') not in (None, os.readlink('/proc/self/ns/' + kind))
    assert os.environ.get('DBUS_SYSTEM_BUS_ADDRESS') == 'unix:path=/run/host-system-bus-unavailable'
    assert not Path('/run/dbus/system_bus_socket').exists()
    assert any(row.split()[1:3] == ['/run', 'tmpfs'] for row in Path('/proc/mounts').read_text().splitlines())
app = args.application.resolve()
core = app.with_name('ThroniumCore')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
out = args.artifacts.resolve()
out.mkdir(parents=True, exist_ok=False)
sources = out / 'test-sources'
sources.mkdir()
files = [Path(__file__), *[desktop / name for name in [
    'tests/vpn_otp_fixture.py', 'tests/vpn_auth_fixture.py', 'tests/vpn_otp_binding_ui.py',
    'scripts/test_native.py', 'tests/native_smoke.py', 'tests/native_transport.py',
    'tests/native_screenshot.py', 'tests/native_processes.py', 'tests/native_menu.py',
    'tests/tray_ui.py', 'tests/window_ui.py']]]
if args.managed:
    files += [desktop / 'tests/vpn_otp_binding_managed_ui.py', desktop / 'scripts/test_vpn_otp_binding_managed_native.py']
hashes = {str(path.relative_to(desktop)): sha(path) for path in files}
for path in files:
    shutil.copy2(path, sources / path.name)
(out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app),
    'coreSha256': sha(core), 'testSources': hashes}, indent=2) + '\n')
status = {'passed': False, 'managedPrivateNamespace': args.managed, 'hostTun': False, 'hostProxy': False}
try:
    with tempfile.TemporaryDirectory(prefix='vpn-otp-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        shutil.copy2(Path(sys.executable).resolve(), root / 'Thronium')
        shutil.copy2(core, root / 'ThroniumCore')
        with (out / 'fixture-stderr.log').open('w') as log:
            fixture = subprocess.Popen([str(root / 'Thronium'), str(sources / 'vpn_otp_fixture.py'), str(root)],
                env={**os.environ, 'PYTHONHOME': sys.prefix},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                assert select.select([fixture.stdout], [], [], 15)[0], 'fixture_ready_timeout'
                line = fixture.stdout.readline()
                assert line, 'fixture_ready_failed'
                ready = out / 'fixture-ready.json'
                ready.write_text(json.dumps(json.loads(line), indent=2) + '\n')
                native = [sys.executable, str(desktop / 'scripts/test_native.py'),
                    '--application', str(app), '--vpn-otp-binding-managed-only' if args.managed else '--vpn-otp-binding-only',
                    '--private-tray-bus', '--artifacts', str(out)]
                (out / 'command.json').write_text(json.dumps({'native': native,
                    'scope': 'Owned OpenVPN userspace and verified HTTPS; private CA/XDG; no host TUN/proxy/trust changes.'}, indent=2) + '\n')
                with (out / 'native.log').open('w') as native_log:
                    result = subprocess.run(native, stdout=native_log, stderr=subprocess.STDOUT,
                        env={**os.environ, '_THRONIUM_VPN_OTP_READY': str(ready),
                             'TMPDIR': os.environ.get('_THRONIUM_TEST_APP_TMPDIR', tempfile.gettempdir())})
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
                for name in ['events.jsonl', 'server-core.log']:
                    if (root / name).exists():
                        shutil.copy2(root / name, out / ('fixture-' + name))
                assert sha(root / 'ThroniumCore') == args.core_sha256
            assert status['fixtureExitCode'] == 0
            status['passed'] = True
finally:
    status['applicationSha256'] = sha(app)
    status['coreSha256'] = sha(core)
    status['pinnedInputsUnchanged'] = sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    status['testSourcesUnchanged'] = hashes == {str(path.relative_to(desktop)): sha(path) for path in files}
    (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
    assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
print('PASS', status['checks'])
