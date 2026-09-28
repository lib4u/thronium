#!/usr/bin/env python3
"""Compile the application for Windows from Linux, without Windows.

This proves the sources still build for the target; it runs nothing. The MinGW
toolchain is kept in `desktop/.tools/mingw-windows` so it survives a reboot, and
is fetched with `dnf download` when missing.

    scripts/windows_cross.py [--crate engine|host|all] [--arch x86_64|aarch64] [--jobs N]

x86_64 uses Fedora's MinGW (x86_64-pc-windows-gnu). ARM64 uses llvm-mingw
(aarch64-pc-windows-gnullvm), a pinned release unpacked into
`desktop/.tools/llvm-mingw`.
"""
import hashlib
import tarfile
import urllib.request
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

DESKTOP = pathlib.Path(__file__).resolve().parents[1]
TOOLS = DESKTOP / '.tools/mingw-windows'
COMPILER = TOOLS / 'root/usr/bin/x86_64-w64-mingw32-gcc'
TARGET = 'x86_64-pc-windows-gnu'
# Without the shared winpthreads package aws-lc-sys fails on pthread_time.h;
# without the CRT nothing links, so test binaries for Wine cannot be built.
PACKAGES = [
    'mingw64-binutils', 'mingw64-cpp', 'mingw64-crt', 'mingw64-gcc', 'mingw64-gcc-c++',
    'mingw64-headers', 'mingw64-winpthreads', 'mingw64-winpthreads-static',
]
# Present only once the CRT is unpacked; an older checkout lacks it.
RUNTIME = TOOLS / 'root/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libkernel32.a'
CRATES = {'engine': DESKTOP / 'engine/Cargo.toml', 'host': DESKTOP / 'src-tauri/Cargo.toml'}


# makensis for Linux with the Windows stubs and plugins, for the installer.
NSIS_TOOLS = DESKTOP / '.tools/nsis'
MAKENSIS = NSIS_TOOLS / 'root/usr/bin/makensis'
NSIS_DATA = NSIS_TOOLS / 'root/usr/share/nsis'
NSIS_PACKAGES = ['mingw-nsis-base', 'mingw32-nsis']


def fetch(tools, packages, wanted):
    """Unpack Fedora packages into tools/root unless wanted already exists."""
    if wanted.exists():
        return
    for tool in ('dnf', 'rpm2cpio', 'cpio'):
        if not shutil.which(tool):
            raise SystemExit(f'{tool} is required to fetch {", ".join(packages)}')
    rpms = tools / 'rpms'
    root = tools / 'root'
    rpms.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=True)
    print('+ fetching', ', '.join(packages), 'into', tools, flush=True)
    subprocess.run(['dnf', 'download', '--assumeyes', '--quiet', *packages],
                   cwd=rpms, check=True)
    for package in sorted(rpms.glob('*.rpm')):
        extract = subprocess.Popen(['rpm2cpio', str(package)], stdout=subprocess.PIPE)
        subprocess.run(['cpio', '-idmu', '--quiet'], stdin=extract.stdout, cwd=root, check=True)
        extract.wait()
    if not wanted.exists():
        raise SystemExit(f'{wanted} is still missing after extraction')


def toolchain():
    """The cross compiler, downloaded into .tools on first use."""
    if not RUNTIME.exists():
        fetch(TOOLS, PACKAGES, RUNTIME)
    fetch(TOOLS, PACKAGES, COMPILER)


# makensis and Tauri read NSIS's stubs and plugins only from /usr/share/nsis.
# Without a system NSIS the packaging runs in a user namespace (no root) where
# an overlay of /usr/share gains an nsis folder bound to the unpacked copy.
NAMESPACE = """up=$1; work=$2; data=$3; shift 3
mount -t overlay overlay -o "lowerdir=/usr/share,upperdir=$up,workdir=$work" /usr/share &&
  mkdir -p /usr/share/nsis && mount --bind "$data" /usr/share/nsis && exec "$@"
"""


def remove_overlay():
    """Remove the NSIS overlay; overlayfs leaves work/work without permissions."""
    overlay = NSIS_TOOLS / 'overlay'
    for folder in [overlay, *overlay.rglob('*')] if overlay.exists() else []:
        if folder.is_dir() and not folder.is_symlink():
            folder.chmod(0o700)
    shutil.rmtree(overlay, ignore_errors=True)


def nsis(command, environ):
    """command made able to find NSIS; environ gains makensis on PATH."""
    if shutil.which('makensis') and pathlib.Path('/usr/share/nsis/Stubs').is_dir():
        return command
    fetch(NSIS_TOOLS, NSIS_PACKAGES, MAKENSIS)
    environ['PATH'] = f"{MAKENSIS.parent}{os.pathsep}{environ['PATH']}"
    overlay = NSIS_TOOLS / 'overlay'
    remove_overlay()
    (overlay / 'upper').mkdir(parents=True)
    (overlay / 'work').mkdir()
    return ['unshare', '--user', '--map-root-user', '--mount', 'sh', '-c', NAMESPACE, 'nsis',
            str(overlay / 'upper'), str(overlay / 'work'), str(NSIS_DATA), *command]


LLVM_MINGW_RELEASE = '20260922'
LLVM_MINGW_NAME = f'llvm-mingw-{LLVM_MINGW_RELEASE}-ucrt-ubuntu-22.04-x86_64'
LLVM_MINGW_SHA256 = 'bb7bb7654b33d5aa8712acb837c963b2e0c56352560c76105270a3268c665c21'
LLVM_MINGW = DESKTOP / '.tools/llvm-mingw' / LLVM_MINGW_NAME / 'bin'
TARGETS = {'x86_64': TARGET, 'aarch64': 'aarch64-pc-windows-gnullvm'}


def llvm_mingw():
    """The ARM64 cross toolchain, downloaded and checked on first use."""
    if (LLVM_MINGW / 'aarch64-w64-mingw32-clang').exists():
        return
    url = ('https://github.com/mstorsjo/llvm-mingw/releases/download/'
           f'{LLVM_MINGW_RELEASE}/{LLVM_MINGW_NAME}.tar.xz')
    folder = LLVM_MINGW.parents[1]
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / (LLVM_MINGW_NAME + '.tar.xz')
    print('+ fetching', url, flush=True)
    urllib.request.urlretrieve(url, archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != LLVM_MINGW_SHA256:
        archive.unlink()
        raise SystemExit('llvm-mingw archive does not match its pinned SHA-256')
    with tarfile.open(archive) as tar:
        tar.extractall(folder, filter='tar')
    archive.unlink()


def environment(arch):
    """The Rust triple for arch and the variables that cross-compile to it."""
    triple = TARGETS[arch]
    key = triple.replace('-', '_')
    if arch == 'aarch64':
        llvm_mingw()
        compiler = str(LLVM_MINGW / 'aarch64-w64-mingw32-clang')
        extra = {'PATH': f"{LLVM_MINGW}{os.pathsep}{os.environ['PATH']}",
                 f'CC_{key}': compiler, f'CXX_{key}': compiler + '++',
                 f'AR_{key}': str(LLVM_MINGW / 'llvm-ar'),
                 f'CARGO_TARGET_{key.upper()}_LINKER': compiler}
    else:
        toolchain()
        compiler = str(COMPILER)
        extra = {'PATH': f"{COMPILER.parent}{os.pathsep}{os.environ['PATH']}",
                 f'CC_{key}': compiler, f'CXX_{key}': compiler.replace('gcc', 'g++'),
                 f'CARGO_TARGET_{key.upper()}_LINKER': compiler}
    return triple, extra


def check(manifest, jobs, arch='x86_64'):
    triple, extra = environment(arch)
    command = ['cargo', 'check', '--locked', '--manifest-path', str(manifest),
               '--lib', '--target', triple, '-j', str(jobs)]
    print('+', ' '.join(command), flush=True)
    return subprocess.run(command, env={**os.environ, **extra}).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--crate', choices=[*CRATES, 'all'], default='all')
    parser.add_argument('--arch', choices=list(TARGETS), default='x86_64')
    parser.add_argument('--jobs', type=int, default=4)
    arguments = parser.parse_args()
    triple = TARGETS[arguments.arch]
    if subprocess.run(['rustup', 'target', 'list', '--installed'],
                      capture_output=True, text=True).stdout.find(triple) < 0:
        raise SystemExit(f'rustup target add {triple}')
    names = list(CRATES) if arguments.crate == 'all' else [arguments.crate]
    failed = [name for name in names if check(CRATES[name], arguments.jobs, arguments.arch) != 0]
    if failed:
        raise SystemExit(f"Windows check failed: {', '.join(failed)}")
    print(f"Windows check passed for {', '.join(names)}")


if __name__ == '__main__':
    sys.exit(main())
