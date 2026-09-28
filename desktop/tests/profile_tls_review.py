#!/usr/bin/env python3
"""Public Engine TLS acceptance with a pinned core and owned TLS/HTTP fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile

desktop = Path(__file__).resolve().parents[1]
repository = desktop.parent
parser = argparse.ArgumentParser()
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--build-inputs', type=Path, required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
core, output = args.core.resolve(), args.artifacts.resolve()
assert sha(core) == args.core_sha256
output.mkdir(parents=True, exist_ok=False)
pin = json.loads(args.build_inputs.read_text())
inputs = {name: digest for name, digest in pin.items() if name.startswith('desktop/engine/') or name in {
    'core/server/gen/libcore.proto', 'desktop/contracts/settings.catalog.json',
    'desktop/src/profiles/import.ts', 'desktop/src/profiles/share.ts', 'desktop/src/profiles/schema.ts',
}}
drift = {name: {'pinned': digest, 'actual': sha(repository / name)} for name, digest in inputs.items() if sha(repository / name) != digest}
assert not drift, drift
owned = [Path(__file__), desktop / 'tests/profile-tls-fixtures.mjs', desktop / 'engine/tests/profile_tls_review.rs', desktop / 'engine/tests/fixtures/profile-tls/server.go']
before = {name: sha(repository / name) for name in inputs}
before.update({str(source.relative_to(repository)): sha(source) for source in owned})
for name in before:
    target = output / 'sources' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(repository / name, target)
(output / 'input-hashes.json').write_text(json.dumps({'coreSha256': sha(core), 'applicationBuildInputs': str(args.build_inputs.resolve()), 'sources': before}, indent=2) + '\n')
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--test', 'profile_tls_review', '--no-run', '--message-format=json']
compiled = subprocess.run(build, capture_output=True, text=True, timeout=300)
(output / 'rust-build.log').write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
messages = [json.loads(line) for line in compiled.stdout.splitlines() if line.startswith('{')]
test = next(Path(message['executable']) for message in messages if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == 'profile_tls_review' and message.get('executable'))
fixture_binary = output / 'tls-fixture'
go_build = ['go', 'build', '-o', str(fixture_binary), str(desktop / 'engine/tests/fixtures/profile-tls/server.go')]
compiled_go = subprocess.run(go_build, capture_output=True, text=True, timeout=120)
(output / 'go-build.log').write_text(compiled_go.stdout + compiled_go.stderr)
compiled_go.check_returncode()
route_before = Path('/proc/net/route').read_text()
fixture_errors = (output / 'fixture-stderr.log').open('w')
fixture = subprocess.Popen([str(fixture_binary), str(output / 'fixture')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=fixture_errors, text=True)
try:
    assert select.select([fixture.stdout], [], [], 10)[0], 'owned TLS fixture ready timeout'
    ready = json.loads(fixture.stdout.readline())
    ready_path = output / 'fixture-ready.json'
    ready_path.write_text(json.dumps(ready, indent=2) + '\n')
    uri_path = output / 'uri-fixtures.json'
    node = ['node', '--experimental-strip-types', str(desktop / 'tests/profile-tls-fixtures.mjs'), str(ready_path), str(uri_path)]
    generated = subprocess.run(node, capture_output=True, text=True, timeout=30)
    (output / 'frontend-fixture.log').write_text(generated.stdout + generated.stderr)
    generated.check_returncode()
    with tempfile.TemporaryDirectory(prefix='thronium-public-tls-') as directory:
        directory = Path(directory)
        shutil.copy2(core, directory / 'ThroniumCore')
        shutil.copy2(test, directory / 'Thronium')
        binaries = {name: sha(directory / name) for name in ['Thronium', 'ThroniumCore']}
        command = [str(directory / 'Thronium'), '--ignored', '--nocapture', '--test-threads=1']
        (output / 'commands.json').write_text(json.dumps({'build': build, 'goBuild': go_build, 'uriFixtures': node, 'run': command, 'binaries': binaries}, indent=2) + '\n')
        environment = dict(os.environ)
        for name in ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']:
            environment.pop(name, None)
        for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']:
            folder = directory / name.lower()
            folder.mkdir(mode=0o700)
            environment[name] = str(folder)
        environment.update(SSL_CERT_FILE=ready['ca'], THRONIUM_TLS_FIXTURE=str(ready_path), THRONIUM_TLS_URI_FIXTURES=str(uri_path))
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=180)
        (output / 'core.log').write_text(result.stdout + result.stderr)
        print(result.stdout, end='', flush=True)
        print(result.stderr, end='', flush=True)
finally:
    fixture.stdin.close()
    fixture_exit = fixture.wait(timeout=10)
    fixture_errors.close()
marker = 'PROFILE_TLS_REVIEW_JSON '
observations = [json.loads(line.split(marker, 1)[1]) for line in result.stdout.splitlines() if marker in line]
events = [json.loads(line) for line in Path(ready['events']).read_text().splitlines()]
source_changes = {name: {'before': digest, 'after': sha(repository / name)} for name, digest in before.items() if sha(repository / name) != digest}
summary = {
    'passed': result.returncode == 0 and len(observations) == 14 and not source_changes and fixture_exit == 0,
    'exitCode': result.returncode, 'rustTests': 3, 'completedScenarios': len(observations),
    'coreSha256': sha(core), 'binaries': binaries, 'fixtureExitCode': fixture_exit,
    'tlsHandshakes': sum(row['event'] == 'handshake' for row in events),
    'httpRequests': sum(row['event'] == 'http' for row in events),
    'observations': observations, 'sourceChangesDuringRun': source_changes, 'sourceHashes': before,
    'hostRoutesUnchanged': route_before == Path('/proc/net/route').read_text(),
    'boundaries': ['Linux actual pinned sing-box TLS HTTP only; no Windows/macOS TLS engine acceptance',
        'Private generated CA passed only through child SSL_CERT_FILE; no host trust changes',
        'TLS spoof enabled only receives Check, never Start or privileged raw packet activity',
        'Public save/settings/check/connect/disconnect/export APIs; source profiles retained exactly',
        'Full sing-box JSON verified with actual HTTP; full Xray JSON source retention verified through Check only',
        'Built-in fragment true/false successful handshake; no claim of fragmentation packet layout or TFO precedence parity'],
}
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
result.check_returncode()
assert summary['passed'] and summary['hostRoutesUnchanged'], summary
assert summary['tlsHandshakes'] == 13 and summary['httpRequests'] == 13, summary
print(f'Public TLS report: {output / "summary.json"}')
