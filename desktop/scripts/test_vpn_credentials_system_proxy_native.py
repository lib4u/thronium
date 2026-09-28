#!/usr/bin/env python3
"""Pinned SystemProxy credentials UI with private GNOME keyfile and real owned servers."""
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
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--application', type=Path, required=True)
p.add_argument('--application-sha256', required=True)
p.add_argument('--core-sha256', required=True)
p.add_argument('--artifacts', type=Path, required=True)
a = p.parse_args()
# Prevent inherited proxy variables from bypassing the private Gio resolver or
# directing the fixture/Core toward any host proxy.
for key in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'):
    os.environ.pop(key, None)
app = a.application.resolve()
core = app.with_name('ThroniumCore')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app) == a.application_sha256 and sha(core) == a.core_sha256
out = a.artifacts.resolve()
out.mkdir(parents=True, exist_ok=False)
sources = out / 'test-sources'
sources.mkdir()
files = [Path(__file__), *[desktop / f for f in [
    'tests/vpn_credentials_fixture.py', 'tests/vpn_otp_fixture.py', 'tests/vpn_auth_fixture.py',
    'tests/vpn_credentials_system_proxy_ui.py', 'scripts/test_native.py', 'tests/native_smoke.py',
    'tests/native_transport.py', 'tests/native_screenshot.py', 'tests/native_processes.py',
    'tests/native_menu.py', 'tests/tray_ui.py', 'tests/window_ui.py']]]
hashes = {str(f.relative_to(desktop)): sha(f) for f in files}
for f in files:
    shutil.copy2(f, sources / f.name)
(out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app),
    'coreSha256': sha(core), 'testSources': hashes}, indent=2) + '\n')
status = {'passed': False, 'hostTun': False, 'hostProxy': False,
          'privateGnomeKeyfile': True, 'hostPolkitTested': False,
          'openconnectCstpConnectedClaimed': False, 'openvpnPayloadTested': False}
try:
    with tempfile.TemporaryDirectory(prefix='vpn-credentials-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        shutil.copy2(Path(sys.executable).resolve(), root / 'Thronium')
        shutil.copy2(core, root / 'ThroniumCore')
        with (out / 'fixture-stderr.log').open('w') as log:
            fixture = subprocess.Popen([str(root / 'Thronium'), str(sources / 'vpn_credentials_fixture.py'), str(root)],
                env={**os.environ, 'PYTHONHOME': sys.prefix}, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                assert select.select([fixture.stdout], [], [], 15)[0], 'credentials_fixture_ready_timeout'
                line = fixture.stdout.readline()
                assert line, 'credentials_fixture_start_failed'
                ready = json.loads(line)
                # Config and stored synthetic credentials stay in the temporary
                # private directory; only safe event observations are archived.
                ready_file = root / 'ready.json'
                ready_file.write_text(json.dumps(ready))
                ready_file.chmod(0o600)
                cmd = [sys.executable, str(desktop / 'scripts/test_native.py'),
                    '--application', str(app), '--vpn-credentials-system-proxy-only', '--private-tray-bus', '--artifacts', str(out)]
                (out / 'command.json').write_text(json.dumps({'native': cmd,
                    'scope': 'Owned userspace OpenVPN/HTTPS and private GNOME keyfile/XDG/DBus; no host proxy, TUN or polkit.'}, indent=2) + '\n')
                with (out / 'native.log').open('w') as native_log:
                    result = subprocess.run(cmd, stdout=native_log, stderr=subprocess.STDOUT,
                        env={**os.environ, '_THRONIUM_VPN_CREDENTIALS_READY': str(ready_file)})
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
                if (root / 'events.jsonl').exists():
                    shutil.copy2(root / 'events.jsonl', out / 'fixture-events.jsonl')
                # Raw server logs contain usernames and are never copied.
                assert sha(root / 'ThroniumCore') == a.core_sha256
            assert status['fixtureExitCode'] == 0
            status['passed'] = True
finally:
    status.update(applicationSha256=sha(app), coreSha256=sha(core),
        pinnedInputsUnchanged=sha(app) == a.application_sha256 and sha(core) == a.core_sha256,
        testSourcesUnchanged=hashes == {str(f.relative_to(desktop)): sha(f) for f in files})
    (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
    assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
print('PASS', status['checks'])
