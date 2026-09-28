#!/usr/bin/env python3
"""Legacy WARP import UI and independent userspace peer in private namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner', 'peer-binary'):
        parser.add_argument('--' + name, type=Path, required=True)
    # Writes archives as Qt-Throne does, without Qt; another writer may be named.
    parser.add_argument('--golden-writer', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'tests/thrbackup_writer.py')
    parser.add_argument('--namespace-child', action='store_true')
    args = parser.parse_args(); out = args.artifacts.resolve()
    desktop = Path(__file__).resolve().parents[1]
    if args.namespace_child:
        assert os.getpid() == 1 and os.geteuid() == 0
        for kind in ('net', 'mnt'):
            assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS']
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
        root = Path('/run/thronium-legacy-warp74'); root.mkdir(mode=0o700)
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        hosts = root / 'hosts'; hosts.write_text('127.0.0.1 localhost api.cloudflareclient.com\n::1 localhost\n')
        subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
        sys.path.insert(0, str(desktop / 'tests'))
        from warp_registration_fixture import Fixture
        fixture = Fixture(root / 'https')
        env = {**os.environ, 'SSL_CERT_FILE': str(fixture.cert), 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'GSETTINGS_BACKEND': 'memory', 'XDG_RUNTIME_DIR': str(root), 'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data')}
        for key in list(env):
            if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'): env.pop(key)
        record = {'privateNetns': os.readlink('/proc/self/ns/net'), 'privatePidNamespace': True, 'noExternalRoutes': not subprocess.check_output(['ip', 'route', 'show', 'default'], text=True).strip()}
        peer_log = (out / 'peer.log').open('w')
        peer = subprocess.Popen([str(args.peer_binary), str(root / 'peer'), '127.0.0.1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=peer_log, text=True)
        try:
            assert select.select([peer.stdout], [], [], 10)[0], 'Owned peer readiness timed out'
            ready = peer.stdout.readline().strip(); assert ready
            from legacy_warp_live_archive74 import prepare
            prepare(ready, args.golden_writer)
            info = json.loads(Path(ready).read_text()); info['registrationAdmin'] = json.loads(fixture.path.read_text())['admin']
            Path(ready).write_text(json.dumps(info, indent=2) + '\n'); env['_THRONIUM_LEGACY_WARP_READY'] = ready
            (out / 'peer-ready-private.json').write_text(json.dumps(info, indent=2) + '\n'); (out / 'peer-ready-private.json').chmod(0o600)
            command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--', 'dbus-run-session', '--', 'python3', str(args.accessibility_runner), str(out / 'accessibility'), 'python3', str(desktop / 'scripts/test_native.py'), '--legacy-warp-only', '--application', str(args.application), '--artifacts', str(out / 'native')]
            result = subprocess.run(command, env=env, cwd=desktop.parent); record['exitCode'] = result.returncode
        finally:
            peer.stdin.close()
            try: peer_exit = peer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                peer.kill(); peer_exit = peer.wait(timeout=5)
            peer_log.close()
            record.update(peerExitCode=peer_exit, peerReaped=peer.poll() is not None)
            record['fixture'] = fixture.close(); (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['peerExitCode'] == 0 and record['peerReaped']
        assert record['noExternalRoutes'] and record['fixture']['serviceThreadsReaped'] and record['fixture']['serverSocketsClosed'] and record['fixture']['socketCount'] == 0 and record['fixture']['active'] == 0
        return result.returncode
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    before = {name: sha(name) for name in ('/etc/hosts', '/etc/resolv.conf')}
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'), 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc', 'python3', str(Path(__file__).resolve()), '--namespace-child']
    for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner', 'peer_binary', 'golden_writer'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
    with (out / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try: code = process.wait(timeout=360)
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
    record = {'exitCode': code, 'hostNetworkFilesUnchanged': all(sha(name) == digest for name, digest in before.items()), 'privatePIDNamespaceExited': process.poll() is not None, 'applicationSha256': sha(args.application), 'coreSha256': sha(args.application.with_name('ThroniumCore'))}
    (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n'); print(json.dumps(record), flush=True)
    assert code == 0 and record['hostNetworkFilesUnchanged']
    return 0


if __name__ == '__main__': raise SystemExit(main())
