#!/usr/bin/env python3
"""IP/speed through an owned OpenVPN peer; no external or host network changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import tempfile
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('application', 'artifacts', 'display-runner', 'accessibility-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--namespace-child', action='store_true')
    parser.add_argument('--peer-root', type=Path)
    args = parser.parse_args(); out = args.artifacts.resolve()
    desktop = Path(__file__).resolve().parents[1]
    if args.namespace_child:
        assert os.getpid() == 1 and os.geteuid() == 0
        for kind in ('net', 'mnt'):
            assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS']
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
        root = Path('/run/thronium-vpn72'); root.mkdir(mode=0o700)
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        hosts = root / 'hosts'; hosts.write_text('127.0.0.1 localhost\n10.79.36.1 api.ip2location.io www.speedtest.net speed.peer.test\n::1 localhost\n')
        subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
        subprocess.run(['ip','link','add','uplink','type','dummy'],check=True)
        subprocess.run(['ip','addr','add','192.0.2.2/24','dev','uplink'],check=True)
        subprocess.run(['ip','link','set','uplink','up'],check=True)
        subprocess.run(['ip','route','add','default','via','192.0.2.1','dev','uplink'],check=True)
        sys.path.insert(0, str(desktop / 'tests'))
        from vpn_diagnostics_fixture72 import Fixture
        fixture = Fixture(root / 'https', args.peer_root)
        env = {**os.environ, 'SSL_CERT_FILE': str(fixture.cert), '_THRONIUM_VPN_DIAGNOSTICS_FIXTURE': str(fixture.path), 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'GSETTINGS_BACKEND': 'memory', 'XDG_RUNTIME_DIR': str(root), 'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data')}
        for key in list(env):
            if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'appimage', 'appdir'): env.pop(key)
        record = {'privateNetns': os.readlink('/proc/self/ns/net'), 'privatePidNamespace': True, 'onlyOwnedInterfaces': {row['ifname'] for row in json.loads(subprocess.check_output(['ip','-j','link'],text=True))} == {'lo','uplink'}}
        try:
            command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--', 'dbus-run-session', '--', 'python3', str(args.accessibility_runner), str(out / 'accessibility'), 'python3', str(desktop / 'scripts/test_native.py'), '--vpn-diagnostics-only', '--application', str(args.application), '--artifacts', str(out / 'native')]
            result = subprocess.run(command, env=env, cwd=desktop.parent); record['exitCode'] = result.returncode
        finally:
            record['fixture'] = fixture.close(); (out / 'namespace.json').write_text(json.dumps(record, indent=2) + '\n')
        assert record['onlyOwnedInterfaces'] and record['fixture']['serviceThreadsReaped'] and record['fixture']['serverSocketsClosed'] and record['fixture']['socketCount'] == 0 and record['fixture']['active'] == 0 and all(record['fixture'][key] for key in ('peerReaped','authThreadReaped','authSocketClosed'))
        return result.returncode
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    before = {name: sha(name) for name in ('/etc/hosts', '/etc/resolv.conf')}
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'), 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    peer = tempfile.TemporaryDirectory(prefix='thronium-vpn72-peer-')
    peer_root = Path(peer.name)
    shutil.copy2(Path(sys.executable).resolve(), peer_root / 'Thronium')
    shutil.copy2(args.application.with_name('ThroniumCore'), peer_root / 'ThroniumCore')
    assert sha(peer_root / 'ThroniumCore') == sha(args.application.with_name('ThroniumCore'))
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc', str(peer_root / 'Thronium'), str(Path(__file__).resolve()), '--namespace-child', '--peer-root', str(peer_root)]
    for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
    with (out / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try: code = process.wait(timeout=600)
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
    peer.cleanup()
    record = {'peerDirectoryRemoved': not peer_root.exists(), 'exitCode': code, 'hostNetworkFilesUnchanged': all(sha(name) == digest for name, digest in before.items()), 'privatePIDNamespaceExited': process.poll() is not None, 'applicationSha256': sha(args.application), 'coreSha256': sha(args.application.with_name('ThroniumCore'))}
    (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n'); print(json.dumps(record), flush=True)
    assert code == 0 and record['hostNetworkFilesUnchanged']
    return 0


if __name__ == '__main__': raise SystemExit(main())
