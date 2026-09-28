#!/usr/bin/env python3
"""Pinned real-core public auth acceptance; private userspace VPN/HTTPS only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
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
inputs = {name: digest for name, digest in pin.items() if name.startswith('desktop/engine/') or name == 'core/server/gen/libcore.proto'}
drift = {name: {'pinned': digest, 'actual': sha(repository / name)} for name, digest in inputs.items() if sha(repository / name) != digest}
assert not drift, drift
owned = [Path(__file__), desktop / 'engine/tests/vpn_auth_public.rs', desktop / 'tests/vpn_auth_fixture.py']
before = {name: sha(repository / name) for name in inputs}
before.update({str(source.relative_to(repository)): sha(source) for source in owned})
for name in before:
    target = output / 'sources' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(repository / name, target)
(output / 'input-hashes.json').write_text(json.dumps({'coreSha256': sha(core), 'applicationBuildInputs': str(args.build_inputs.resolve()), 'sources': before}, indent=2) + '\n')
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--test', 'vpn_auth_public', '--no-run', '--message-format=json']
compiled = subprocess.run(build, capture_output=True, text=True, timeout=420)
(output / 'rust-build.log').write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
messages = [json.loads(line) for line in compiled.stdout.splitlines() if line.startswith('{')]
test = next(Path(message['executable']) for message in messages if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == 'vpn_auth_public' and message.get('executable'))
spec = importlib.util.spec_from_file_location('public_auth_fixture', desktop / 'tests/vpn_auth_fixture.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
route_before = Path('/proc/net/route').read_text()
interfaces_before = sorted(path.name for path in Path('/sys/class/net').iterdir())
# Unix RPC sockets must fit sockaddr_un; the evidence path is deliberately long.
# Keep execution in a short private directory and copy only safe observations.
fixture_directory = tempfile.TemporaryDirectory(prefix='thronium-auth-server-')
fixture_root = Path(fixture_directory.name)
shutil.copy2(Path(sys.executable).resolve(), fixture_root / 'Thronium')
shutil.copy2(core, fixture_root / 'ThroniumCore')
environment = dict(os.environ)
for name in ['http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']:
    environment.pop(name, None)
for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR']:
    folder = fixture_root / name.lower()
    folder.mkdir(mode=0o700)
    environment[name] = str(folder)
fixture_command = [str(fixture_root / 'Thronium'), str(desktop / 'tests/vpn_auth_fixture.py'), str(fixture_root)]
fixture_errors = (output / 'fixture-stderr.log').open('w')
fixture = subprocess.Popen(fixture_command, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=fixture_errors, text=True)
try:
    assert select.select([fixture.stdout], [], [], 15)[0], 'owned fixture ready timeout'
    line = fixture.stdout.readline()
    assert line, 'owned fixture exited before ready; inspect fixture-stderr.log'
    ready = json.loads(line)
    (output / 'fixture-ready.json').write_text(json.dumps(ready, indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='thronium-public-auth-') as directory:
        directory = Path(directory)
        shutil.copy2(core, directory / 'ThroniumCore')
        shutil.copy2(test, directory / 'Thronium')
        ready['answers'] = {name: getattr(module, name) for name in ['USER', 'PASSWORD', 'ANSWER', 'FORM_USER', 'FORM_PASSWORD', 'FORM_ANSWER']}
        context = directory / 'synthetic-answers.json'
        context.write_text(json.dumps(ready))
        context.chmod(0o600)
        environment['THRONIUM_AUTH_FIXTURE'] = str(context)
        binaries = {name: sha(directory / name) for name in ['Thronium', 'ThroniumCore']}
        command = [str(directory / 'Thronium'), '--ignored', '--nocapture', '--test-threads=1']
        (output / 'commands.json').write_text(json.dumps({'build': build, 'fixture': fixture_command, 'run': command, 'binaries': binaries}, indent=2) + '\n')
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=180)
        (output / 'core.log').write_text(result.stdout + result.stderr)
        print(result.stdout, end='', flush=True)
        print(result.stderr, end='', flush=True)
finally:
    fixture.stdin.close()
    fixture_exit = fixture.wait(timeout=15)
    fixture_errors.close()
    for name in ['events.jsonl', 'server-core.log']:
        if (fixture_root / name).exists():
            shutil.copy2(fixture_root / name, output / ('fixture-' + name))
    fixture_directory.cleanup()
marker = 'VPN_AUTH_PUBLIC_JSON '
observations = [json.loads(line.split(marker, 1)[1]) for line in result.stdout.splitlines() if marker in line]
events = [json.loads(line) for line in (output / 'fixture-events.jsonl').read_text().splitlines()]
source_changes = {name: {'before': digest, 'after': sha(repository / name)} for name, digest in before.items() if sha(repository / name) != digest}
summary = {
    'passed': result.returncode == 0 and len(observations) == 3 and not source_changes and fixture_exit == 0,
    'exitCode': result.returncode, 'rustTests': 3, 'completedScenarios': len(observations),
    'coreSha256': sha(core), 'binaries': binaries, 'fixtureExitCode': fixture_exit,
    'openconnectHttpsRequests': len(events), 'exactInitialFormSubmissions': sum(row['formExact'] for row in events),
    'exactOtpSubmissions': sum(row['otpExact'] for row in events),
    'observations': observations, 'sourceChangesDuringRun': source_changes, 'sourceHashes': before,
    'hostRoutesUnchanged': route_before == Path('/proc/net/route').read_text(),
    'hostInterfacesUnchanged': interfaces_before == sorted(path.name for path in Path('/sys/class/net').iterdir()),
    'boundaries': ['Linux local userspace OpenVPN and OpenConnect only; system:false and no privileged TUN',
        'Private own certificate configured only in owned profiles; no host trust changes',
        'Real OpenVPN credentials/static-answer TLS session connected; no claim of Internet tunnel traffic',
        'Real OpenConnect HTTPS form and OTP verified; fixture intentionally does not establish an AnyConnect data tunnel',
        'Real OpenConnect process replacement repeats its numeric ID; OpenVPN random-ID collision not forced',
        'Full JSON held HTTP CONNECT stays live during auth actions, not during process death',
        'Actual stale session and unsupported URL actions; expiry/browser SSO are covered only by separate model/unit checks',
        'No private Engine/Store mutation, transport fake or runtime test hooks'],
}
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
result.check_returncode()
assert summary['passed'] and summary['hostRoutesUnchanged'] and summary['hostInterfacesUnchanged'], summary
assert len(events) == 9 and summary['exactInitialFormSubmissions'] == 2 and summary['exactOtpSubmissions'] == 1, summary
print(f'Public auth report: {output / "summary.json"}')
