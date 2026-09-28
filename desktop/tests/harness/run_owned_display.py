#!/usr/bin/env python3
"""Run a command on a private Xvfb display owned by this process.

Part of the native test harness (see scripts/native.py).

Contract checked by desktop/tests/native_screenshot.py and
owned_accessibility.py: Xvfb is this process's child, started with
`-auth <XAUTHORITY>`, the authority file is 0600 inside a
/tmp/thronium-private-x11-* directory, and the artifacts directory is new.
"""
import argparse, os, secrets, shutil, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path

DESKTOP = Path(__file__).resolve().parents[2]
# Xvfb and openbox of Fedora, unpacked without root on first use.
TOOLS = DESKTOP / '.tools/native-display'
ROOT = TOOLS / 'root'
PACKAGES = ['xorg-x11-server-Xvfb.x86_64', 'openbox.x86_64', 'openbox-libs.x86_64', 'imlib2.x86_64']


def display_tools():
    if (ROOT / 'usr/bin/Xvfb').exists() and (ROOT / 'usr/bin/openbox').exists():
        return
    rpms = TOOLS / 'rpms'
    rpms.mkdir(parents=True, exist_ok=True)
    ROOT.mkdir(parents=True, exist_ok=True)
    subprocess.run(['dnf', 'download', '--assumeyes', '--quiet', *PACKAGES], cwd=rpms, check=True)
    for package in sorted(rpms.glob('*.rpm')):
        extract = subprocess.Popen(['rpm2cpio', str(package)], stdout=subprocess.PIPE)
        subprocess.run(['cpio', '-idmu', '--quiet'], stdin=extract.stdout, cwd=ROOT, check=True)
        extract.wait()


def authority(path, number, cookie):
    def field(data):
        return struct.pack('>H', len(data)) + data
    entry = lambda family, address: (struct.pack('>H', family) + field(address) + field(number.encode())
                                     + field(b'MIT-MAGIC-COOKIE-1') + field(cookie))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(entry(256, socket.gethostname().encode()) + entry(65535, b''))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        sys.exit('no command')
    display_tools()
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    number = next(str(n) for n in range(90, 200)
                  if not Path(f'/tmp/.X{n}-lock').exists() and not Path(f'/tmp/.X11-unix/X{n}').exists())
    private = Path(tempfile.mkdtemp(prefix='thronium-private-x11-', dir='/tmp'))
    xauth = private / 'Xauthority'
    authority(xauth, number, secrets.token_bytes(16))
    env = {**os.environ, 'DISPLAY': f':{number}', 'XAUTHORITY': str(xauth),
           'XDG_DATA_DIRS': f"{ROOT / 'usr/share'}:{os.environ.get('XDG_DATA_DIRS', '/usr/local/share:/usr/share')}"}
    libs = {**env, 'XDG_CONFIG_DIRS': f"{ROOT / 'etc/xdg'}:{os.environ.get('XDG_CONFIG_DIRS', '/etc/xdg')}",
            'LD_LIBRARY_PATH': ':'.join(filter(None, [str(ROOT / 'usr/lib64'), os.environ.get('LD_LIBRARY_PATH')]))}
    processes = []
    code = 1
    try:
        with (out / 'xvfb.log').open('w') as log:
            xvfb = subprocess.Popen([str(ROOT / 'usr/bin/Xvfb'), f':{number}', '-auth', str(xauth),
                                     '-screen', '0', '1440x960x24', '-nolisten', 'tcp'],
                                    env=libs, stdout=log, stderr=subprocess.STDOUT)
        processes.append(xvfb)
        for _ in range(200):
            if Path(f'/tmp/.X11-unix/X{number}').exists() and Path(f'/tmp/.X{number}-lock').exists():
                break
            if xvfb.poll() is not None:
                sys.exit('Xvfb exited; see xvfb.log')
            time.sleep(0.05)
        else:
            sys.exit('Xvfb did not start')
        with (out / 'openbox.log').open('w') as log:
            processes.append(subprocess.Popen([str(ROOT / 'usr/bin/openbox')], env=libs,
                                              stdout=log, stderr=subprocess.STDOUT))
        time.sleep(0.5)
        (out / 'display.json').write_text(f'{{"display": ":{number}", "xvfbPid": {xvfb.pid}}}\n')
        code = subprocess.run(command, env=env).returncode
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(private, ignore_errors=True)
    (out / 'exit-code').write_text(f'{code}\n')
    sys.exit(code)


if __name__ == '__main__':
    main()
