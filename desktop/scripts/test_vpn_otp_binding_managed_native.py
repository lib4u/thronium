#!/usr/bin/env python3
"""Pinned managed automatic OTP window inside disposable user/net/mount namespaces.

Namespace root is not host root. No host polkit authorization is requested or
counted as tested. This runs only the bounded managed OTP subset, never the local full-JSON cases.
The namespace bootstrap is preserved from the accepted auth28 wrapper.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

DESKTOP = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--application', type=Path, required=True)
p.add_argument('--application-sha256', required=True)
p.add_argument('--core-sha256', required=True)
p.add_argument('--artifacts', type=Path, required=True)
p.add_argument('--long-tmpdir', action='store_true', help='Exercise both IPC sockets beyond the Linux sockaddr_un path limit')
p.set_defaults(prepare_only=False)
p.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
a = p.parse_args()
app, out = a.application.resolve(), a.artifacts.resolve()
core = app.with_name('ThroniumCore')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(app) == a.application_sha256 and sha(core) == a.core_sha256


def ip(*args):
    return json.loads(subprocess.check_output(['ip', '-j', *args], text=True))


def network():
    return {'links': ip('link'), 'rules4': ip('-4', 'rule'), 'rules6': ip('-6', 'rule'),
            'routes4': ip('-4', 'route', 'show', 'table', 'all'),
            'routes6': ip('-6', 'route', 'show', 'table', 'all')}


def state_without_counters(value):
    # ip link state/counters are outside cleanup ownership; compare identities.
    return {'links': [(row['ifindex'], row['ifname']) for row in value['links']],
            **{key: value[key] for key in ['rules4', 'rules6', 'routes4', 'routes6']}}


if not a.inside:
    assert sys.platform == 'linux', 'Linux namespace fixture required'
    for tool in ['unshare', 'mount', 'ip', 'dbus-run-session']:
        assert shutil.which(tool), tool + ' required'
    out.mkdir(parents=True, exist_ok=False)
    source_dir = out / 'namespace-sources'
    source_dir.mkdir()
    tracked = [Path(__file__), DESKTOP / 'scripts/test_vpn_otp_binding_native.py', DESKTOP / 'tests/vpn_auth_fixture.py', DESKTOP / 'tests/vpn_otp_fixture.py', DESKTOP / 'tests/native_screenshot.py']
    if not a.prepare_only:
        tracked.append(DESKTOP / 'tests/vpn_otp_binding_managed_ui.py')
    sources = {str(path.relative_to(DESKTOP)): sha(path) for path in tracked}
    for path in tracked:
        shutil.copy2(path, source_dir / path.name)
    baseline = network()
    dns = sha(Path('/etc/resolv.conf'))
    host_ns = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ['net', 'mnt', 'user']}
    result = None
    status = {'passed': False, 'prepareOnly': a.prepare_only, 'hostPolkitTested': False,
              'hostNamespaces': host_ns, 'applicationSha256': sha(app), 'coreSha256': sha(core), 'sources': sources}
    try:
        with tempfile.TemporaryDirectory(prefix='thronium-managed-auth-ns-') as directory:
            root = Path(directory)
            root.chmod(0o700)
            env = {**os.environ, 'XDG_RUNTIME_DIR': '/run/thronium-test', 'GIO_USE_VFS': 'local',
                   'NO_AT_BRIDGE': '1', 'XDG_DATA_HOME': str(root / 'data'), 'XDG_CONFIG_HOME': str(root / 'config'),
                   'GSETTINGS_BACKEND': 'memory', 'XDG_CURRENT_DESKTOP': 'GNOME', 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/host-system-bus-unavailable',
                   'THRONIUM_TEST_ORIGINAL_NETNS': host_ns['net'],
                   'THRONIUM_TEST_ORIGINAL_MNTNS': host_ns['mnt'],
                   'THRONIUM_TEST_ORIGINAL_USERNS': host_ns['user']}
            env.pop('DBUS_SESSION_BUS_ADDRESS', None)
            env.pop('AT_SPI_BUS_ADDRESS', None)
            if os.environ.get('XAUTHORITY'):
                authority = root / 'xauthority'
                shutil.copyfile(os.environ['XAUTHORITY'], authority)
                authority.chmod(0o600)
                env['XAUTHORITY'] = str(authority)
            inside = [sys.executable, str(Path(__file__).resolve()), '--inside',
                      '--application', str(app), '--application-sha256', a.application_sha256,
                      '--core-sha256', a.core_sha256, '--artifacts', str(out)]
            if a.prepare_only:
                inside.append('--prepare-only')
            if a.long_tmpdir:
                inside.append('--long-tmpdir')
            cmd = ['unshare', '--user', '--map-root-user', '--net', '--mount', 'sh', '-c',
                   'mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && mkdir -m 700 /run/thronium-test && ip link set lo up && exec "$@"',
                   'sh', 'dbus-run-session', '--', *inside]
            (out / 'namespace-command.json').write_text(json.dumps(cmd, indent=2) + '\n')
            with (out / 'namespace.log').open('w') as log:
                process = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    result = process.wait(timeout=480)
                finally:
                    # Only the session created above; never search by process name.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
            status['namespaceExitCode'] = result
            assert result == 0, 'Private namespace acceptance failed; see namespace.log'
            status['passed'] = True
    finally:
        status['hostNetworkUnchanged'] = state_without_counters(network()) == state_without_counters(baseline)
        status['hostResolvConfUnchanged'] = sha(Path('/etc/resolv.conf')) == dns
        status['pinnedInputsUnchanged'] = sha(app) == a.application_sha256 and sha(core) == a.core_sha256
        status['sourcesUnchanged'] = sources == {str(path.relative_to(DESKTOP)): sha(path) for path in tracked}
        (out / ('summary.json' if status['passed'] else 'attempt-status.json')).write_text(json.dumps(status, indent=2) + '\n')
        assert all(status[key] for key in ['hostNetworkUnchanged', 'hostResolvConfUnchanged', 'pinnedInputsUnchanged', 'sourcesUnchanged'])
    print('PASS namespace', 'preparation' if a.prepare_only else 'managed authorization')
    raise SystemExit(0)

assert os.geteuid() == 0
ns = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ['net', 'mnt', 'user']}
for kind in ns:
    assert ns[kind] != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS']
assert os.environ['DBUS_SYSTEM_BUS_ADDRESS'] == 'unix:path=/run/host-system-bus-unavailable'
assert not Path('/run/dbus/system_bus_socket').exists()
for cmd in [['link', 'add', 'uplink', 'type', 'dummy'], ['addr', 'add', '192.0.2.2/24', 'dev', 'uplink'],
            ['link', 'set', 'uplink', 'up'], ['route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'uplink']]:
    subprocess.run(['ip', *cmd], check=True)
baseline = network()
fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
try:
    fcntl.ioctl(fd, 0x400454CA, struct.pack('16sH', b'auth-ns-probe', 0x0001 | 0x1000))
    assert socket.if_nametoindex('auth-ns-probe') > 0
finally:
    os.close(fd)
try:
    socket.if_nametoindex('auth-ns-probe')
    raise AssertionError('Disposable TUN remained after closing descriptor')
except OSError:
    pass
assert state_without_counters(network()) == state_without_counters(baseline)
# Test the same private D-Bus accessibility bootstrap used by the native runner;
# this does not open a window or call host D-Bus services.
from gi.repository import Gio, GLib
# Session service activation invokes dbus-launch-helper, whose privilege path
# is unavailable in this user namespace. Start our own launcher directly.
access_log = (out / 'private-accessibility.log').open('w')
accessibility = subprocess.Popen(['/usr/libexec/at-spi-bus-launcher', '--launch-immediately'],
                                 stdout=access_log, stderr=subprocess.STDOUT)
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
for _ in range(50):
    names = bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus',
                          'ListNames', None, None, Gio.DBusCallFlags.NONE, 1000, None).unpack()[0]
    if 'org.a11y.Bus' in names:
        break
    assert accessibility.poll() is None, 'Private accessibility launcher exited'
    time.sleep(.05)
else:
    raise AssertionError('Private accessibility launcher did not register')
address = bus.call_sync('org.a11y.Bus', '/org/a11y/bus', 'org.a11y.Bus', 'GetAddress',
                       None, None, Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
assert address.startswith('unix:')
os.environ['AT_SPI_BUS_ADDRESS'] = address
os.environ['_THRONIUM_TEST_BUS'] = os.environ['DBUS_SESSION_BUS_ADDRESS']
for key in ('IsEnabled', 'ScreenReaderEnabled'):
    bus.call_sync('org.a11y.Bus', '/org/a11y/bus', 'org.freedesktop.DBus.Properties',
                  'Set', GLib.Variant('(ssv)', ('org.a11y.Status', key, GLib.Variant('b', True))),
                  None, Gio.DBusCallFlags.NONE, 2000, None)

if os.environ.get('DISPLAY'):
    sys.path.insert(0, str(DESKTOP / 'tests'))
    from native_screenshot import connect
    display = connect()
    display.sync()
    display.close()
(out / 'namespace-probe.json').write_text(json.dumps({'namespaces': ns, 'euid': os.geteuid(),
    'tunCreatedAndRemoved': True, 'namespaceBaselineRestored': True,
    'privateAccessibilityBusAvailable': True, 'xDisplayAvailable': bool(os.environ.get('DISPLAY')),
    'hostSystemBusUnavailable': True, 'managedAuthForwardingTested': False}, indent=2) + '\n')
cmd = [sys.executable, str(DESKTOP / 'scripts/test_vpn_otp_binding_native.py'), '--application', str(app),
       '--application-sha256', a.application_sha256, '--core-sha256', a.core_sha256,
       '--artifacts', str(out / 'fixture-native')]
cmd.append('--prepare-only' if a.prepare_only else '--managed')
if a.long_tmpdir:
    # Bootstrap X11/D-Bus using the normal short temp directory. Only our app,
    # Core and fixture data inherit the long path under test.
    with tempfile.TemporaryDirectory(prefix='long-' + 'x' * 100 + '-', dir=out) as temporary:
        (out / 'long-tmpdir.json').write_text(json.dumps({'pathBytes': len(os.fsencode(temporary)), 'private': True}) + '\n')
        subprocess.run(cmd, check=True, env={**os.environ, '_THRONIUM_TEST_APP_TMPDIR': temporary})
else:
    subprocess.run(cmd, check=True)
assert state_without_counters(network()) == state_without_counters(baseline), 'Namespace routes/rules/interface not cleaned'
accessibility.terminate()
accessibility.wait(timeout=5)
access_log.close()
(out / 'namespace-cleanup.json').write_text(json.dumps({'baselineRestored': True, 'namespaces': ns}, indent=2) + '\n')
