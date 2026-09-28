#!/usr/bin/env python3
"""Exercise the real TUN in an isolated, unprivileged Linux network namespace."""
import pathlib
import os
import platform
import signal
import hashlib
import json
import shutil
import subprocess
import tempfile

desktop = pathlib.Path(__file__).resolve().parents[1]
if platform.system() != 'Linux':
    raise SystemExit('Linux TUN test requires Linux')
for tool in ('unshare', 'ip', 'pgrep', 'mount', 'newuidmap', 'newgidmap'):
    if not shutil.which(tool):
        raise SystemExit(f'{tool} is required')
host = next(line[6:] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines() if line.startswith('host: '))
core = desktop / 'src-tauri/binaries' / f'ThroniumCore-{host}'
subprocess.run(['cargo', 'build', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--bin', 'tun-smoke', '--bin', 'l3-smoke', '-j', '2'], check=True)
with tempfile.TemporaryDirectory(prefix='thronium-tun-test-', dir='/tmp') as folder:
    root = pathlib.Path(folder)
    root.chmod(0o755)
    subprocess.run(['go', 'test', '-p', '2', '-c', '-o', str(root / 'session-tests'), './internal/tunsession'], cwd=desktop.parent / 'core/server', check=True)
    shutil.copy2(core, root / 'ThroniumCore')
    shutil.copy2(desktop / 'engine/target/debug/tun-smoke', root / 'Thronium')
    # Disable access to the host D-Bus services even inside the network namespace.
    env = {**os.environ, 'TMPDIR': '/tmp', 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'),
           'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'),
           'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=' + str(root / 'no-system-bus'),
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(root / 'no-session-bus')}
    env['THRONIUM_TEST_CORE'] = str(root / 'ThroniumCore')
    dns_before = hashlib.sha256(pathlib.Path('/etc/resolv.conf').read_bytes()).digest()
    artifacts = desktop / 'test-results/tun-core'
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / 'results.json').unlink(missing_ok=True)
    security = subprocess.run(['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', 'sh', '-c',
        'mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && exec "$@"', 'sh', str(root / 'session-tests'), '-test.v'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=40)
    (artifacts / 'supervisor.log').write_text(security.stdout)
    print(security.stdout, end='')
    security.check_returncode()
    log = (artifacts / 'core.log').open('w+')
    process = subprocess.Popen(['unshare', '--user', '--map-root-user', '--net', '--mount', 'sh', '-c', 'mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && exec "$@"', 'sh', str(root / 'Thronium')], env=env, start_new_session=True, stdout=log, stderr=subprocess.STDOUT, text=True)
    try:
        process.wait(timeout=120)
        log.flush()
        output = (artifacts / 'core.log').read_text()
        print(output, end='')
        if process.returncode:
            raise SystemExit(process.returncode)
        assert hashlib.sha256(pathlib.Path('/etc/resolv.conf').read_bytes()).digest() == dns_before, 'Host resolv.conf changed'
        shutil.copy2(desktop / 'engine/target/debug/l3-smoke', root / 'Thronium')
        l3 = subprocess.run(['unshare','--user','--map-root-user','--net','--mount','sh','-c','mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && exec "$@"','sh',os.environ.get('PYTHON','python3'),str(desktop / 'tests/l3_fixture.py'),str(root / 'Thronium')],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
        (artifacts / 'l3.log').write_text(l3.stdout);print(l3.stdout,end='');l3.check_returncode()
        output += l3.stdout
        (artifacts / 'results.json').write_text(json.dumps({
            'checks': [line[5:] for line in output.splitlines() if line.startswith('PASS ')],
            'supervisorChecks': [line.split()[2] for line in security.stdout.splitlines() if line.startswith('--- PASS:')],
            'coreSha256': hashlib.sha256(core.read_bytes()).hexdigest(),
            'hostResolvConfUnchanged': True,
        }, indent=2) + '\n')
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        log.close()
