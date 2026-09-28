#!/usr/bin/env python3
"""Run managed system DNS against real resolved in disposable Linux namespaces."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def namespace_child(application):
    for kind in ('net', 'mnt'):
        assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS'], 'host namespace forbidden'
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
    Path('/run/systemd').mkdir(mode=0o755)
    Path('/run/dbus').mkdir(mode=0o755)
    config = Path('/run/dbus/fixture.conf')
    config.write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    env = {**os.environ, 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/dbus/system_bus_socket', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-session-bus', 'SYSTEMD_LOG_LEVEL': 'warning', 'SYSTEMD_LOG_TARGET': 'console'}
    bus = subprocess.Popen(['dbus-daemon', '--nofork', '--nopidfile', '--config-file=' + str(config)], env=env)
    try:
        for _ in range(100):
            if Path('/run/dbus/system_bus_socket').exists():
                break
            assert bus.poll() is None
            time.sleep(.02)
        return subprocess.run([str(application)], env=env, timeout=120).returncode
    finally:
        bus.terminate()
        try:
            bus.wait(timeout=3)
        except subprocess.TimeoutExpired:
            bus.kill()
            bus.wait()


def main():
    desktop = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', type=Path, default=desktop / 'engine/target/debug/system-dns-smoke')
    parser.add_argument('--core', type=Path, default=desktop / 'src-tauri/binaries/ThroniumCore-x86_64-unknown-linux-gnu')
    parser.add_argument('--artifacts', type=Path, default=desktop / 'test-results/system-dns-core')
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args()
    if args.namespace_child:
        return namespace_child(args.application)
    for tool in ('unshare', 'newuidmap', 'newgidmap', 'mount', 'ip', 'dbus-daemon', 'resolvectl', 'pgrep'):
        assert shutil.which(tool), tool + ' is required'
    assert Path('/usr/lib/systemd/systemd-resolved').is_file()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    before = sha('/etc/resolv.conf')
    # Reap descendants even if the test deliberately kills their immediate parent.
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    with tempfile.TemporaryDirectory(prefix='thronium-system-dns-') as folder:
        root = Path(folder)
        shutil.copy2(args.application, root / 'Thronium')
        shutil.copy2(args.core, root / 'ThroniumCore')
        legacy = os.environ.get('THRONIUM_TEST_LEGACY_CORE')
        if legacy:
            (root / 'legacy').mkdir()
            shutil.copy2(args.application, root / 'legacy/Thronium')
            shutil.copy2(legacy, root / 'legacy/ThroniumCore')
        env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'), 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=' + folder + '/no-host-system', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + folder + '/no-host-session'}
        with (artifacts / 'runtime.log').open('w') as log:
            process = subprocess.Popen(['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', 'python3', str(Path(__file__).resolve()), '--namespace-child', '--application', str(root / 'Thronium')], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=140)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                for _ in range(100):
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid == 0:
                        time.sleep(.03)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            reaped = True
        else:
            reaped = False
        output = (artifacts / 'runtime.log').read_text()
        checks = [line[5:] for line in output.splitlines() if line.startswith('PASS ')]
        result = {'exitCode': code, 'checks': checks, 'hostResolvConfUnchanged': sha('/etc/resolv.conf') == before, 'ownedProcessesReaped': reaped, 'coreSha256': sha(args.core), 'applicationSha256': sha(args.application)}
        (artifacts / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        assert code == 0 and len(checks) >= 8 and reaped and result['hostResolvConfUnchanged'], output[-8000:]
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
