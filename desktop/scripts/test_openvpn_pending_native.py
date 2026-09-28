#!/usr/bin/env python3
"""The window against an actual OpenVPN 2.7 server that parks the client in
`client-pending-auth`: a text challenge, a notice, a link, a deadline that
lapses, and the dynamic CRV1 challenge of a refusal. Loopback only."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--suite', choices=('pending', 'restart'), default='pending')
    args = parser.parse_args()
    desktop = Path(__file__).resolve().parents[1]
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert shutil.which('openvpn'), 'this stand needs an OpenVPN server'
    status = {'passed': False,
              'applicationSha256': hashlib.sha256(args.application.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='thronium-openvpn-pending-') as folder:
        root = Path(folder)
        root.chmod(0o700)
        fixture = subprocess.Popen(
            [sys.executable, str(desktop / 'tests/openvpn_pending_fixture.py'), str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            stderr=(out / 'fixture-stderr.log').open('w'))
        try:
            assert select.select([fixture.stdout], [], [], 30)[0], 'fixture_ready_timeout'
            line = fixture.stdout.readline()
            assert line, 'fixture_start_failed'
            ready = json.loads(line)
            ready_file = out / 'fixture-ready.json'
            ready_file.write_text(json.dumps(ready, indent=2) + '\n')
            status['openvpnVersion'] = ready['openvpnVersion']
            command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--',
                       'dbus-run-session', '--', 'python3', str(args.accessibility_runner),
                       str(out / 'accessibility'), 'python3', str(desktop / 'scripts/test_native.py'),
                       '--openvpn-pending-only' if args.suite == 'pending' else '--vpn-restart-only',
                       '--application', str(args.application),
                       '--artifacts', str(out / 'native')]
            env = {**os.environ, '_THRONIUM_OPENVPN_PENDING_READY': str(ready_file),
                   'GSETTINGS_BACKEND': 'memory', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon'}
            with (out / 'runtime.log').open('w') as log:
                result = subprocess.run(command, env=env, cwd=desktop.parent, stdout=log,
                                        stderr=subprocess.STDOUT, timeout=900)
            status['exitCode'] = result.returncode
        finally:
            fixture.stdin.close()
            try:
                status['fixtureExitCode'] = fixture.wait(timeout=20)
            except subprocess.TimeoutExpired:
                fixture.terminate()
                status['fixtureExitCode'] = fixture.wait(timeout=10)
            for name in ('openvpn.log', 'observations.json', 'server.conf'):
                if (root / name).exists():
                    shutil.copy2(root / name, out / ('fixture-' + name))
        status['passed'] = status.get('exitCode') == 0 and status['fixtureExitCode'] == 0
    (out / 'summary.json').write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps(status), flush=True)
    assert status['passed'], status
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
