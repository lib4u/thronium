#!/usr/bin/env python3
"""Actual openresolv TUN/DNS window in a private root and network namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner', 'upstream'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    parser.add_argument('--local-dns', action='store_true')
    parser.add_argument('--xray-local-dns', action='store_true')
    parser.add_argument('--network-dns', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    desktop = Path(__file__).resolve().parents[1]
    if args.namespace_child:
        sys.path.insert(0, str(desktop / 'tests'))
        from openresolv_fixture import install_private
        install_private(args.upstream)
        Path('/run/thronium-test').mkdir(mode=0o700)
        env = {**os.environ, 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/dbus/system_bus_socket', '_THRONIUM_TUN_SYSTEM_DNS': '1', '_THRONIUM_TUN_DNS_BACKEND': 'resolvconf', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'XDG_RUNTIME_DIR': '/run/thronium-test', 'XDG_CONFIG_HOME': '/run/thronium-config', 'XDG_DATA_HOME': '/run/thronium-data'}
        if args.local_dns or args.xray_local_dns or args.network_dns:
            env['_THRONIUM_TUN_LOCAL_DNS_PROBE'] = '1'
        if args.network_dns:
            env['_THRONIUM_TUN_NETWORK_DNS_PROBE'] = '1'
        if args.xray_local_dns:
            env['_THRONIUM_TUN_XRAY_LOCAL_DNS'] = '1'
        command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--', 'dbus-run-session', '--', 'python3', str(args.accessibility_runner), str(out / 'accessibility'), 'python3', str(desktop / 'scripts/test_native.py'), '--tun-reconnect-only', '--application', str(args.application), '--artifacts', str(out / 'native')]
        result = subprocess.run(command, env=env, cwd=desktop.parent, timeout=150)
        record = {'exitCode': result.returncode, 'privateNetns': os.readlink('/proc/self/ns/net'), 'pidNamespace': True, 'privateRoot': True}
        (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        return result.returncode
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    before = sha('/etc/resolv.conf')
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'), 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc', 'python3', str(Path(__file__).resolve()), '--namespace-child']
    for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner', 'upstream'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
    if args.local_dns:
        command.append('--local-dns')
    if args.xray_local_dns:
        command.append('--xray-local-dns')
    if args.network_dns:
        command.append('--network-dns')
    with (out / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try: code = process.wait(timeout=180)
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
    record = {'exitCode': code, 'hostResolvConfUnchanged': sha('/etc/resolv.conf') == before, 'privatePIDNamespaceExited': process.poll() is not None, 'applicationSha256': sha(args.application), 'coreSha256': sha(args.application.with_name('ThroniumCore'))}
    (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)
    assert code == 0 and record['hostResolvConfUnchanged']
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
