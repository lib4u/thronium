#!/usr/bin/env python3
"""Run the actual TUN window in disposable user, network and mount namespaces."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import shutil
import tempfile

desktop = Path(__file__).resolve().parents[1]
temporary = tempfile.TemporaryDirectory(prefix='thronium-tun-native-')
authority = Path(temporary.name) / 'xauthority'
shutil.copyfile(os.environ['XAUTHORITY'], authority)
authority.chmod(0o600)
env = {**os.environ, 'XAUTHORITY': str(authority), 'XDG_RUNTIME_DIR': '/run/thronium-test', 'GIO_USE_VFS': 'local', 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'),
       'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'),
       'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/thronium-no-system-bus', 'NO_AT_BRIDGE': '1'}
process = subprocess.Popen(['unshare', '--user', '--map-root-user', '--net', '--mount', 'sh', '-c',
    'mount --make-rprivate / && mount -t tmpfs -o mode=755 tmpfs /run && mkdir -m 700 /run/thronium-test && ip link set lo up && exec "$@"', 'sh',
    'dbus-run-session', '--', sys.executable, str(desktop / 'scripts/test_native.py'),
    '--tun-reconnect-only', '--artifacts', str(desktop / 'test-results/tun-reconnect-ui')], env=env, start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=180))
finally:
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait()
    temporary.cleanup()
