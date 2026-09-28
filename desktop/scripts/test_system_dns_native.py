#!/usr/bin/env python3
"""Actual TUN/DNS window, with its own display, resolved and network namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args()
    out = args.artifacts.resolve()
    desktop = Path(__file__).resolve().parents[1]
    if args.namespace_child:
        assert os.getpid() == 1 and os.geteuid() == 0
        for kind in ('net', 'mnt'):
            assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS']
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
        Path('/run/systemd').mkdir(mode=0o755)
        Path('/run/dbus').mkdir(mode=0o755)
        Path('/run/thronium-test').mkdir(mode=0o700)
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        config = Path('/run/dbus/fixture.conf')
        config.write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
        env = {**os.environ, 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/dbus/system_bus_socket', 'SYSTEMD_LOG_LEVEL': 'warning', 'SYSTEMD_LOG_TARGET': 'console', '_THRONIUM_TUN_SYSTEM_DNS': '1', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'XDG_RUNTIME_DIR': '/run/thronium-test', 'XDG_CONFIG_HOME': '/run/thronium-config', 'XDG_DATA_HOME': '/run/thronium-data'}
        processes = []
        record = {'privateNetns': os.readlink('/proc/self/ns/net'), 'pidNamespace': True}
        try:
            bus = subprocess.Popen(['dbus-daemon', '--nofork', '--nopidfile', '--config-file=' + str(config)], env=env)
            processes.append(bus)
            for _ in range(100):
                if Path('/run/dbus/system_bus_socket').exists(): break
                assert bus.poll() is None
                time.sleep(.02)
            resolved = subprocess.Popen(['/usr/lib/systemd/systemd-resolved'], env=env)
            processes.append(resolved)
            for _ in range(100):
                if subprocess.run(['resolvectl', 'status'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
                assert resolved.poll() is None
                time.sleep(.05)
            else: raise AssertionError('private resolved did not start')
            command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--', 'dbus-run-session', '--', 'python3', str(args.accessibility_runner), str(out / 'accessibility'), 'python3', str(desktop / 'scripts/test_native.py'), '--tun-reconnect-only', '--application', str(args.application), '--artifacts', str(out / 'native')]
            result = subprocess.run(command, env=env, cwd=desktop.parent)
            record['exitCode'] = result.returncode
        finally:
            for process in reversed(processes):
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            record['ownedDNSProcessesReaped'] = all(p.poll() is not None for p in processes)
            (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        return result.returncode
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    before = sha('/etc/resolv.conf')
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'), 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc', 'python3', str(Path(__file__).resolve()), '--namespace-child']
    for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
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
