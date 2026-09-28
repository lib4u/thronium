#!/usr/bin/env python3
"""Actual openresolv/TUN recovery, using private root, PID and network namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'core', 'upstream', 'artifacts'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--legacy-core', type=Path)
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    if args.namespace_child:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
        from openresolv_fixture import install_private
        install_private(args.upstream)
        return subprocess.run([str(out / 'bin/Thronium')], timeout=150).returncode
    out.mkdir(parents=True, exist_ok=False)
    (out / 'bin').mkdir(mode=0o700)
    shutil.copy2(args.application, out / 'bin/Thronium')
    shutil.copy2(args.core, out / 'bin/ThroniumCore')
    if args.legacy_core:
        (out / 'bin/legacy').mkdir(mode=0o700)
        shutil.copy2(args.application, out / 'bin/legacy/Thronium')
        shutil.copy2(args.legacy_core, out / 'bin/legacy/ThroniumCore')
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    before = sha('/etc/resolv.conf')
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'),
           'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'),
           'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus',
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc',
               'python3', str(Path(__file__).resolve()), '--namespace-child']
    for name in ('application', 'core', 'upstream', 'artifacts'):
        command += ['--' + name, str(getattr(args, name).resolve())]
    with (out / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=170)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    checks = [line[5:] for line in (out / 'runtime.log').read_text().splitlines() if line.startswith('PASS ')]
    record = {'exitCode': code, 'checks': checks, 'hostResolvConfUnchanged': sha('/etc/resolv.conf') == before,
              'privatePIDNamespaceExited': process.poll() is not None,
              'applicationSha256': sha(args.application), 'coreSha256': sha(args.core)}
    (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)
    assert code == 0 and len(checks) >= 9 and record['hostResolvConfUnchanged']


if __name__ == '__main__':
    raise SystemExit(main())
