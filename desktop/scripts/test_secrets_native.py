#!/usr/bin/env python3
"""The library at rest, against a real Secret Service. A private keyring of this
run holds the key: the desktop's own store is never opened or written."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--keyring-child', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    desktop = Path(__file__).resolve().parents[1]
    if args.keyring_child:
        # Inside the private bus: bring up the key store, then run the suite.
        passphrase = 'secrets-stand-passphrase'
        keyring = subprocess.run(['gnome-keyring-daemon', '--unlock', '--components=secrets'],
                                 input=passphrase, text=True, capture_output=True, timeout=30)
        (out / 'keyring.log').write_text(keyring.stdout + keyring.stderr)
        names = subprocess.run(['busctl', '--user', 'list', '--no-pager'], text=True,
                               capture_output=True, timeout=30).stdout
        assert 'org.freedesktop.secrets' in names, 'no Secret Service on the private bus'
        command = ['python3', str(args.accessibility_runner), str(out / 'accessibility'),
                   'python3', str(desktop / 'scripts/test_native.py'), '--secrets-only',
                   '--application', str(args.application), '--artifacts', str(out / 'native')]
        return subprocess.run(command, cwd=desktop.parent).returncode
    out.mkdir(parents=True, exist_ok=False)
    assert shutil.which('gnome-keyring-daemon'), 'this stand needs a Secret Service implementation'
    with tempfile.TemporaryDirectory(prefix='thronium-secrets-') as folder:
        root = Path(folder)
        (root / 'data').mkdir()
        (root / 'run').mkdir(mode=0o700)
        env = {**os.environ, 'XDG_DATA_HOME': str(root / 'data'), 'XDG_RUNTIME_DIR': str(root / 'run'),
               'GSETTINGS_BACKEND': 'memory', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon'}
        command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--',
                   'dbus-run-session', '--', 'python3', str(Path(__file__).resolve()), '--keyring-child']
        for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner'):
            command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
        with (out / 'runtime.log').open('w') as log:
            result = subprocess.run(command, env=env, cwd=desktop.parent, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=420)
        stored = sorted(p.name for p in (root / 'data' / 'keyrings').glob('*')) \
            if (root / 'data' / 'keyrings').is_dir() else []
        summary = {'exitCode': result.returncode, 'privateKeyringFiles': stored,
                   'applicationSha256': hashlib.sha256(args.application.read_bytes()).hexdigest()}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    assert summary['exitCode'] == 0 and summary['privateKeyringFiles'], summary
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
