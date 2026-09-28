#!/usr/bin/env python3
"""Real system-proxy recovery in a private GNOME keyfile, never user GSettings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

desktop = Path(__file__).resolve().parents[1]
root = desktop.parent
parser = argparse.ArgumentParser()
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--build-inputs', type=Path, required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
core, output = args.core.resolve(), args.artifacts.resolve()
assert sha(core) == args.core_sha256
output.mkdir(parents=True, exist_ok=False)
pin = json.loads(args.build_inputs.read_text())
inputs = {name: digest for name, digest in pin.items() if name.startswith('desktop/engine/') or name in {'desktop/contracts/settings.catalog.json', 'core/server/gen/libcore.proto'}}
assert all(sha(root / name) == digest for name, digest in inputs.items()), 'Engine/compiler inputs differ from the supplied frozen manifest'
inputs.update({str(p.relative_to(root)): sha(p) for p in [Path(__file__), desktop / 'engine/tests/system_proxy_recovery_review.rs']})
for name in inputs:
    target = output / 'sources' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / name, target)
(output / 'input-hashes.json').write_text(json.dumps({'sourceHashes': inputs, 'core': str(core), 'coreSha256': sha(core), 'buildInputs': str(args.build_inputs.resolve())}, indent=2) + '\n')
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--test', 'system_proxy_recovery_review', '--no-run', '--message-format=json']
compiled = subprocess.run(build, capture_output=True, text=True, timeout=300)
(output / 'build.log').write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
messages = [json.loads(line) for line in compiled.stdout.splitlines() if line.startswith('{')]
test = next(Path(m['executable']) for m in messages if m.get('reason') == 'compiler-artifact' and m.get('target', {}).get('name') == 'system_proxy_recovery_review' and m.get('executable'))
with tempfile.TemporaryDirectory(prefix='thronium-system-proxy-review-') as tmp:
    tmp = Path(tmp)
    shutil.copy2(test, tmp / 'Thronium')
    shutil.copy2(core, tmp / 'ThroniumCore')
    env = dict(os.environ)
    for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']:
        path = tmp / name.lower()
        path.mkdir(mode=0o700)
        env[name] = str(path)
    env.update({'GSETTINGS_BACKEND': 'keyfile', 'XDG_CURRENT_DESKTOP': 'GNOME'})
    for name in ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']:
        env.pop(name, None)
        env.pop(name.upper(), None)
    command = [str(tmp / 'Thronium'), '--ignored', '--nocapture', '--test-threads=1']
    binaries = {name: sha(tmp / name) for name in ['Thronium', 'ThroniumCore']}
    private_env = {name: env[name] for name in ['XDG_CONFIG_HOME', 'GSETTINGS_BACKEND', 'XDG_CURRENT_DESKTOP']}
    (output / 'commands.json').write_text(json.dumps({'build': build, 'run': command, 'binaries': binaries, 'privateEnvironment': private_env}, indent=2) + '\n')
    route_before = Path('/proc/net/route').read_bytes()
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    route_after = Path('/proc/net/route').read_bytes()
    (output / 'core.log').write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end='', flush=True)
    for name in ['glib-2.0/settings/keyfile', 'thronium-system-proxy/recovery.json']:
        source = Path(env['XDG_CONFIG_HOME']) / name
        if source.exists():
            target = output / 'final-private-config' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
marker = 'SYSTEM_PROXY_RECOVERY_REVIEW_JSON '
observations = [json.loads(line.split(marker, 1)[1]) for line in result.stdout.splitlines() if marker in line]
changes = {name: {'before': digest, 'after': sha(root / name)} for name, digest in inputs.items() if sha(root / name) != digest}
summary = {'passed': result.returncode == 0 and len(observations) == 7 and not changes and route_before == route_after, 'exitCode': result.returncode, 'rustTests': 1, 'completedScenarios': len(observations), 'observations': observations, 'binaries': binaries, 'sourceChanges': changes, 'hostRoutesUnchanged': route_before == route_after, 'sourceHashes': inputs, 'boundaries': ['Linux GNOME private keyfile only, not user GSettings and not Windows/macOS/KDE acceptance', 'Actual core and owned loopback HTTP, no provider URLs or machine identifiers', 'Journal bytes/inode/mtime and lock prove retention; internal backend.write call counts remain separate unit evidence', 'Late external write after retained precheck is controlled by stopping the new verified child during its real IPC handshake, with no production test override']}
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
result.check_returncode()
assert summary['passed'], summary
print(f'System proxy recovery public report: {output / "summary.json"}')
