#!/usr/bin/env python3
"""Pinned VPN probe acceptance with owned userspace VPN/HTTP and private GNOME."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

DESKTOP = Path(__file__).resolve().parents[1]

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


class FixtureControl:
    """Private test-only Unix relay to the exact fixture's stdin/stdout."""
    def __init__(self, root, fixture):
        self.path = root / 'fixture-control.sock'
        self.fixture = fixture
        self.stop = threading.Event()
        self.errors = []
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(self.path)); self.path.chmod(0o600)
        self.socket.listen(2); self.socket.settimeout(.2)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: client, _ = self.socket.accept()
            except socket.timeout: continue
            except OSError: return
            with client:
                client.settimeout(3)
                try:
                    data = b''
                    while b'\n' not in data:
                        part = client.recv(1024)
                        assert part and len(data) + len(part) <= 1024
                        data += part
                    value = json.loads(data)
                    assert value in ({'op': 'release-holds'}, {'op': 'reset-holds'})
                    self.fixture.stdin.write(json.dumps(value) + '\n'); self.fixture.stdin.flush()
                    assert select.select([self.fixture.stdout], [], [], 3)[0], 'fixture_control_timeout'
                    result = json.loads(self.fixture.stdout.readline())
                    assert result == {'done': True}
                    client.sendall(b'{"done":true}\n')
                except BaseException as error:
                    # Commands contain no credentials and only finite operations.
                    self.errors.append(type(error).__name__)
                    with contextlib.suppress(OSError): client.sendall(b'{"error":"fixture_control_failed"}\n')

    def close(self):
        self.stop.set(); self.socket.close(); self.thread.join(timeout=4)
        self.path.unlink(missing_ok=True)
        assert not self.thread.is_alive() and not self.errors, 'fixture_control_cleanup_failed'


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
    files = [Path(__file__).resolve(), *[DESKTOP / name for name in [
        'tests/vpn_probe_fixture36.py', 'tests/vpn_auth_fixture.py', 'tests/vpn_otp_fixture.py', 'tests/vpn_credentials_fixture.py',
        'tests/vpn_probes_ui.py', 'scripts/test_native.py', 'tests/native_smoke.py', 'tests/native_transport.py',
        'tests/native_screenshot.py', 'tests/native_menu.py', 'tests/native_processes.py', 'tests/tray_ui.py', 'tests/window_ui.py']]]
    before = {str(path.relative_to(DESKTOP)): sha(path) for path in files}
    sources = out / 'test-sources'; sources.mkdir()
    for path in files: shutil.copy2(path, sources / path.name)
    (out / 'before-run.json').write_text(json.dumps({'applicationSha256':sha(app),'coreSha256':sha(core),'testSources':before},indent=2)+'\n')
    env = os.environ.copy()
    for key in ['http_proxy','https_proxy','all_proxy','no_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY']:
        env.pop(key,None)
    status = {'passed':False,'hostTun':False,'hostProxy':False,'hostTrustChanged':False,'hostPolkitTested':False,
              'tlsTrustScope':'Private disposable App and its children; public Engine after-main-spawn trust is separate.',
              'openconnectCstpConnectedClaimed':False,'vpnPolicyRouteGateClaimed':False}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='vpn-probe36-') as temporary:
            root = Path(temporary); root.chmod(0o700)
            shutil.copy2(Path(sys.executable).resolve(),root/'Thronium');shutil.copy2(core,root/'ThroniumCore')
            with (out/'fixture-stderr.log').open('w') as log:
                fixture = subprocess.Popen([str(root/'Thronium'),str(sources/'vpn_probe_fixture36.py'),str(root)],
                    env={**env,'PYTHONHOME':sys.prefix},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True)
                control = None
                try:
                    assert select.select([fixture.stdout],[],[],20)[0], 'vpn_fixture_ready_timeout'
                    ready = json.loads(fixture.stdout.readline())
                    assert ready['systemTun'] is False
                    control = FixtureControl(root,fixture)
                    ready_file = root/'ready.json';ready_file.write_text(json.dumps(ready));ready_file.chmod(0o600)
                    trust = root/'empty-trust';trust.mkdir(mode=0o700)
                    native_env = {**env,'_THRONIUM_VPN_PROBES_READY':str(ready_file),'_THRONIUM_VPN_PROBES_CONTROL':str(control.path),
                                  'SSL_CERT_FILE':ready['httpsCertificate'],'SSL_CERT_DIR':str(trust)}
                    cmd = [sys.executable,str(DESKTOP/'scripts/test_native.py'),'--application',str(app),'--vpn-probes-only',
                           '--private-tray-bus','--artifacts',str(out)]
                    (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
                    with (out/'native.log').open('w') as log: result = subprocess.run(cmd,env=native_env,stdout=log,stderr=subprocess.STDOUT)
                    status['nativeExitCode']=result.returncode;result.check_returncode()
                    status['checks']=json.loads((out/'results.json').read_text())['count']
                finally:
                    control_error = None
                    try:
                        if control: control.close()
                    except BaseException as error:
                        control_error = error
                    fixture.stdin.close()
                    try:status['fixtureExitCode']=fixture.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        fixture.terminate();status['fixtureExitCode']=fixture.wait(timeout=5)
                    for source,target in [('http-events.jsonl','fixture-http-events.jsonl'),('auth-events.jsonl','fixture-auth-events.jsonl')]:
                        if (root/source).exists():shutil.copy2(root/source,out/target)
                    assert sha(root/'ThroniumCore')==args.core_sha256
                    if control_error: raise control_error
                assert status['fixtureExitCode']==0
                status['passed']=True
    finally:
        status.update(seconds=round(time.monotonic()-started,3),applicationSha256=sha(app),coreSha256=sha(core),
            pinnedInputsUnchanged=sha(app)==args.application_sha256 and sha(core)==args.core_sha256,
            testSourcesUnchanged=before=={str(path.relative_to(DESKTOP)):sha(path) for path in files})
        if not status['pinnedInputsUnchanged'] or not status['testSourcesUnchanged']:status['passed']=False
        (out/('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status,indent=2)+'\n')
        assert status['pinnedInputsUnchanged'] and status['testSourcesUnchanged']
    print('PASS',status['checks'])

if __name__ == '__main__':
    main()
