#!/usr/bin/env python3
"""Build the full upstream core as the Tauri sidecar on native Linux/macOS.

Tool downloads are pinned and kept in desktop/.tools; go.mod/go.sum retain
Throne's exact protocol forks. Windows DLL packaging still needs its own port.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shlex
import shutil
import subprocess
import sys
import venv
from core_overlay import prepare as prepare_overlay

DESKTOP = pathlib.Path(__file__).resolve().parents[1]
CORE = DESKTOP.parent / 'core/server'
CACHE = DESKTOP / '.tools'
TAGS = 'with_clash_api,with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp,with_tailscale,with_openvpn,with_openconnect,with_naive_outbound,badlinkname,tfogo_checklinkname0'


def output(*args, cwd=CORE, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def source_commit():
    """The commit the core is built from; None outside git or before the first commit."""
    try:
        return subprocess.check_output(['git', 'rev-parse', '--verify', '-q', 'HEAD'], cwd=CORE,
                                       text=True, stderr=subprocess.DEVNULL).strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def run(args, cwd=CORE, env=None):
    print('+', shlex.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if platform.system() not in ('Linux', 'Darwin', 'Windows'):
        raise RuntimeError('Unsupported builder host')
    if args.jobs < 1:
        raise RuntimeError('--jobs must be positive')
    # A Windows core for another machine: THRONIUM_CORE_TARGET names its Rust
    # triple (x86_64 or aarch64); THRONIUM_WINDOWS_CROSS=1 is the x86_64 GNU one.
    cross_target = os.environ.get('THRONIUM_CORE_TARGET') or (
        'x86_64-pc-windows-gnu' if os.environ.get('THRONIUM_WINDOWS_CROSS') == '1' else '')
    cross_windows = bool(cross_target)
    if cross_windows and ('-windows-' not in cross_target
                          or cross_target.split('-')[0] not in ('x86_64', 'aarch64')):
        raise RuntimeError(f'Unsupported core target: {cross_target}')
    # The Windows core needs no C compiler (Cronet through purego); elsewhere clang.
    compilers = () if platform.system() == 'Windows' or cross_windows else ('clang',)
    for tool in ('go', 'rustc'):
        if not shutil.which(tool):
            raise RuntimeError(f'{tool} is required; see README.md')
    if compilers and not any(shutil.which(tool) for tool in compilers):
        raise RuntimeError(f"{' or '.join(compilers)} is required; see README.md")
    host = next(line.removeprefix('host: ') for line in output('rustc', '-vV').splitlines() if line.startswith('host: '))
    goos = {'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system(), 'linux')
    goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(host.split('-')[0])
    target_host = host
    if cross_windows:
        goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[cross_target.split('-')[0]]
        goos, target_host = 'windows', cross_target
    elif not goarch or {'linux': 'linux', 'darwin': 'apple-darwin', 'windows': 'windows'}[goos] not in host:
        raise RuntimeError(f'Unsupported native Rust target: {host}')
    env = {**os.environ, 'GOOS': goos, 'GOARCH': goarch, 'CGO_ENABLED': '0' if goos == 'windows' else '1',
           'GOMAXPROCS': str(args.jobs)}
    if goos == 'windows':
        # Without cgo: Naive loads Cronet at run time from libcronet.dll, which
        # comes from the module go.mod pins and ships beside the core.
        build_tags = TAGS + ',with_purego'
    else:
        env['CC'] = shutil.which('clang')
        build_tags = TAGS
    CACHE.mkdir(exist_ok=True)
    # A Windows venv keeps its interpreter in Scripts, and Go tools end in .exe.
    windows_host = os.name == 'nt'
    proto_python = CACHE / ('protobuf/Scripts/python.exe' if windows_host else 'protobuf/bin/python')
    tool = lambda name: name + ('.exe' if windows_host else '')
    if not proto_python.exists():
        venv.create(CACHE / 'protobuf', with_pip=True)
    if subprocess.run([proto_python, '-c', 'import grpc_tools.protoc'], capture_output=True).returncode:
        run([proto_python, '-m', 'pip', 'install', 'grpcio-tools==1.83.1'])
    plugin_dir = CACHE / 'bin'
    plugin_dir.mkdir(exist_ok=True)
    # Match upstream's protobuf module; codegen remains host-native.
    tools_env = {**os.environ, 'GOBIN': str(plugin_dir)}
    tools_env.pop('GOOS', None)
    tools_env.pop('GOARCH', None)
    for name, package, version in (
        ('protoc-gen-go', 'google.golang.org/protobuf/cmd/protoc-gen-go', 'v1.36.12'),
        ('protoc-gen-go-grpc', 'google.golang.org/grpc/cmd/protoc-gen-go-grpc', 'v1.5.1'),
    ):
        if not (plugin_dir / tool(name)).exists():
            run(['go', 'install', f'{package}@{version}'], env=tools_env)
    gen = CORE / 'gen'
    run([proto_python, '-m', 'grpc_tools.protoc', '-I', gen,
         f'--plugin=protoc-gen-go={plugin_dir / tool("protoc-gen-go")}',
         f'--plugin=protoc-gen-go-grpc={plugin_dir / tool("protoc-gen-go-grpc")}',
         f'--go_out={gen}', f'--go-grpc_out={gen}', gen / 'libcore.proto'])

    version = output('go', 'list', '-m', '-f', '{{.Version}}', 'github.com/sagernet/sing-box', env=env)
    # The one Thronium version (scripts/version.mjs); the core carries it too.
    app_version = json.loads((DESKTOP / 'package.json').read_text())['version']
    flags = ['-w', '-s', '-X', 'ThroneCore/parentcheck.expectedParentName=Thronium', '-X', f'main.appVersion={app_version}',
             '-X', f'github.com/sagernet/sing-box/constant.Version={version}',
             '-X', 'internal/godebug.defaultGODEBUG=multipathtcp=0', '-checklinkname=0']
    if goos == 'linux':
        linker = shutil.which('ld.lld')
        if not linker:
            root = pathlib.Path(output('rustc', '--print', 'sysroot'))
            candidates = [root / 'lib/rustlib' / host / 'bin/gcc-ld/ld.lld']
            linker = next((str(p) for p in candidates if p.is_file()), None)
        if not linker:
            raise RuntimeError('LLVM ld.lld is required for the Cronet archive (Naive); install lld or use the Rust toolchain that bundles it.')
        flags += ['-extld=clang', f'-extldflags=-fuse-ld={linker}']
    elif goos == 'darwin':
        env['CGO_LDFLAGS'] = (env.get('CGO_LDFLAGS', '') + ' -weak_framework UniformTypeIdentifiers').strip()
    # The overlays patch private copies of pinned modules, so a fresh module
    # cache needs them before the build downloads the rest.
    overlay_modules = ['github.com/sagernet/sing-box', 'github.com/sagernet/sing-tun',
                       'github.com/sagernet/sing-openconnect', 'github.com/sagernet/sing-openvpn',
                       'github.com/sagernet/wireguard-go', 'github.com/Mahdi-zarei/speedtest-go']
    if goos == 'windows':
        overlay_modules.append(f'github.com/sagernet/cronet-go/lib/windows_{goarch}')
    run(['go', 'mod', 'download', *overlay_modules], env=env)
    overlay,overlay_hash = prepare_overlay(CORE,CACHE,env)
    # Tauri resolves a sidecar as <name>-<triple> plus the platform suffix.
    binary = DESKTOP / 'src-tauri/binaries' / f'ThroniumCore-{target_host}{".exe" if goos == "windows" else ""}'
    binary.parent.mkdir(parents=True, exist_ok=True)
    # Build to a temporary filename so a failed build preserves the last binary.
    temporary = binary.with_name(binary.name + '.building')
    try:
        run(['go', 'build', '-modfile', overlay, '-p', args.jobs, '-o', temporary, '-trimpath',
             '-ldflags', shlex.join(flags), '-tags', build_tags, '.'], env=env)
        temporary.replace(binary)
    finally:
        temporary.unlink(missing_ok=True)
    extra = {}
    if goos == 'windows':
        # Cronet from the exact module version go.mod pins, never a download.
        module = f'github.com/sagernet/cronet-go/lib/windows_{goarch}'
        source = pathlib.Path(output('go', 'list', '-modfile', overlay, '-m', '-f', '{{.Dir}}', module, env=env))
        library = binary.parent / 'libcronet.dll'
        shutil.copyfile(source / 'libcronet.dll', library)
        extra['libcronetSha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
    manifest = {'target': target_host, 'appVersion': app_version, 'go': output('go', 'version'), 'tags': build_tags.split(','),
                'sourceCommit': source_commit(),
                'goModSha256': hashlib.sha256((CORE / 'go.mod').read_bytes()).hexdigest(),
                'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'parentName': 'Thronium', 'tunOverlaySha256': overlay_hash, **extra}
    binary.with_suffix('.build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Built {binary}', flush=True)


if __name__ == '__main__':
    if platform.system() == 'Windows' and not sys.flags.utf8_mode:
        # The overlays read and write UTF-8 sources; Windows defaults to its ANSI code page.
        sys.exit(subprocess.run([sys.executable, '-X', 'utf8', *sys.argv]).returncode)
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
