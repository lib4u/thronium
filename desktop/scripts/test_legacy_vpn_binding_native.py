#!/usr/bin/env python3
"""Pinned native legacy VPN/OTP binding import with immutable static Qt fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

DESKTOP = Path(__file__).resolve().parents[1]

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--application-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    app = args.application.resolve(); core = app.with_name('ThroniumCore')
    assert sha(app) == args.application_sha256 and sha(core) == args.core_sha256
    out = args.artifacts.resolve(); out.mkdir(parents=True, exist_ok=False)
    files = [Path(__file__).resolve(), *[DESKTOP / file for file in [
        'tests/legacy_vpn_binding_ui.py', 'scripts/test_native.py', 'tests/native_smoke.py',
        'tests/native_transport.py', 'tests/native_screenshot.py', 'tests/native_processes.py',
        'tests/native_menu.py', 'tests/native_dialogs.py', 'tests/rfd_dialog_fixture.py', 'tests/tray_ui.py', 'tests/window_ui.py']]]
    fixtures = DESKTOP / 'tests/fixtures/legacy-vpn-bindings'
    files += sorted(path for path in fixtures.rglob('*') if path.is_file())
    before = {str(path.relative_to(DESKTOP)): sha(path) for path in files}
    for path in files:
        target = out / 'test-sources' / path.relative_to(DESKTOP)
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
    copied = out / 'test-sources/tests/fixtures/legacy-vpn-bindings'
    manifest = json.loads((copied / 'manifest.json').read_text())
    for name, entry in manifest['archives'].items(): assert sha(copied / name) == entry['sha256']
    (out / 'before-run.json').write_text(json.dumps({'applicationSha256': sha(app), 'coreSha256': sha(core), 'testSources': before}, indent=2) + '\n')
    status = {'passed': False, 'actualQtArchives': len(manifest['archives']), 'vpnAuthenticationClaimed': False,
              'pushedPolicyDataPlaneClaimed': False, 'hostTun': False, 'hostProxy': False, 'hostPolkitTested': False}
    env = os.environ.copy()
    for key in ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY']: env.pop(key, None)
    env['_THRONIUM_LEGACY_VPN_FIXTURES'] = str(copied)
    cmd = [sys.executable, str(DESKTOP / 'scripts/test_native.py'), '--application', str(app),
           '--legacy-vpn-bindings-only', '--private-tray-bus', '--artifacts', str(out)]
    (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    started = time.monotonic()
    try:
        with (out / 'native.log').open('w') as log:
            result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        status['nativeExitCode'] = result.returncode
        result.check_returncode()
        status['checks'] = json.loads((out / 'results.json').read_text())['count']
        status['passed'] = True
    finally:
        status.update(seconds=round(time.monotonic() - started, 3), applicationSha256=sha(app), coreSha256=sha(core),
            pinnedInputsUnchanged=sha(app) == args.application_sha256 and sha(core) == args.core_sha256,
            testSourcesUnchanged=before == {str(path.relative_to(DESKTOP)): sha(path) for path in files},
            fixtureCopiesUnchanged=all(sha(copied / name) == entry['sha256'] for name, entry in manifest['archives'].items()))
        if not all(status[key] for key in ['pinnedInputsUnchanged', 'testSourcesUnchanged', 'fixtureCopiesUnchanged']): status['passed'] = False
        (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
        assert all(status[key] for key in ['pinnedInputsUnchanged', 'testSourcesUnchanged', 'fixtureCopiesUnchanged'])
    print('PASS', status['checks'])

if __name__ == '__main__': main()
