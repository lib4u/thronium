"""Shared launcher for native stands that run the real app inside private user, network, mount and PID namespaces.

The outer process copies nothing into the host network: it records host network files, starts the namespace
child through `unshare`, and writes the summary. The child sets up loopback, an optional /etc/hosts view and a
dummy uplink with a default route (the core needs a default interface to bind endpoints to), then runs the
owned display and accessibility runners around `scripts/test_native.py`.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

DESKTOP = Path(__file__).resolve().parents[1]
UPLINK = ('192.0.2.2/24', '192.0.2.1')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare_child(run_dir, hosts_lines=('127.0.0.1 localhost', '::1 localhost')):
    """Private mounts, loopback, /etc/hosts view and the dummy uplink; returns the writable run directory."""
    assert os.getpid() == 1 and os.geteuid() == 0
    for kind in ('net', 'mnt'):
        assert os.readlink('/proc/self/ns/' + kind) != os.environ['THRONIUM_TEST_ORIGINAL_' + kind.upper() + 'NS']
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True)
    root = Path('/run') / run_dir
    root.mkdir(mode=0o700)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    hosts = root / 'hosts'
    hosts.write_text('\n'.join(hosts_lines) + '\n')
    subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
    subprocess.run(['ip', 'link', 'add', 'uplink', 'type', 'dummy'], check=True)
    subprocess.run(['ip', 'addr', 'add', UPLINK[0], 'dev', 'uplink'], check=True)
    subprocess.run(['ip', 'link', 'set', 'uplink', 'up'], check=True)
    subprocess.run(['ip', 'route', 'add', 'default', 'via', UPLINK[1], 'dev', 'uplink'], check=True)
    return root


def child_env(root, extra):
    env = {**os.environ, **extra, 'ATSPI_DBUS_IMPLEMENTATION': 'dbus-daemon', 'GSETTINGS_BACKEND': 'memory',
           'XDG_RUNTIME_DIR': str(root), 'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_DATA_HOME': str(root / 'data')}
    for key in list(env):
        if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'appimage', 'appdir'):
            env.pop(key)
    return env


def interfaces():
    return {row['ifname'] for row in json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))}


def run_suite(args, out, env, suite_flag):
    """Runs test_native.py for one suite inside the owned display and accessibility runners; returns the exit code."""
    command = ['python3', str(args.display_runner), '--artifacts', str(out / 'display'), '--', 'dbus-run-session', '--',
               'python3', str(args.accessibility_runner), str(out / 'accessibility'), 'python3', str(DESKTOP / 'scripts/test_native.py'),
               suite_flag, '--application', str(args.application), '--artifacts', str(out / 'native')]
    return subprocess.run(command, env=env, cwd=DESKTOP.parent).returncode


def run_outer(args, out, script, child_args, tracked, record_extra=None, timeout=900, executable=None):
    """Starts the namespace child for `script` (optionally under an owned interpreter copy, e.g. one named
    Thronium so a fixture Core accepts it as parent), waits, and writes summary.json; returns 0 on success."""
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    before = {name: sha(name) for name in ('/etc/hosts', '/etc/resolv.conf')}
    digests = {str(p.relative_to(DESKTOP.parent)): sha(p) for p in tracked}
    env = {**os.environ, 'THRONIUM_TEST_ORIGINAL_NETNS': os.readlink('/proc/self/ns/net'), 'THRONIUM_TEST_ORIGINAL_MNTNS': os.readlink('/proc/self/ns/mnt'),
           'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/no-host-system-bus', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/no-host-session-bus'}
    command = ['unshare', '--user', '--map-root-user', '--map-auto', '--net', '--mount', '--pid', '--fork', '--kill-child=SIGKILL', '--mount-proc',
               str(executable or sys.executable), str(Path(script).resolve()), '--namespace-child', *child_args]
    for name in ('application', 'artifacts', 'display_runner', 'accessibility_runner'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
    with (out / 'runtime.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    changes = [name for name, digest in digests.items() if sha(DESKTOP.parent / name) != digest]
    record = {'exitCode': code, 'sourceChanges': changes,
              'hostNetworkFilesUnchanged': all(sha(name) == digest for name, digest in before.items()),
              'privatePIDNamespaceExited': process.poll() is not None,
              'applicationSha256': sha(args.application), 'coreSha256': sha(args.application.with_name('ThroniumCore')),
              **(record_extra or {})}
    record['passed'] = code == 0 and record['hostNetworkFilesUnchanged'] and not changes
    (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)
    return 0 if record['passed'] else 1
