#!/usr/bin/env python3
"""Compile and run independent public recovery tests with an explicitly pinned core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
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
engine_inputs = {name: digest for name, digest in pin.items() if name.startswith('desktop/engine/') or name in {'core/server/gen/libcore.proto', 'desktop/contracts/settings.catalog.json'}}
drift = {name: {'pinned': digest, 'actual': sha(repository / name)} for name, digest in engine_inputs.items() if sha(repository / name) != digest}
# This cfg(test) fixture was corrected after the application was pinned: the
# public save_profile guard was valid, the old unit expectation was not.
allowed_test_only = {'desktop/engine/src/recovery/tests.rs'}
assert not (set(drift) - allowed_test_only), drift
sources = [Path(__file__), desktop / 'engine/tests/local_recovery_review.rs']
for name in engine_inputs:
    source = repository / name
    target = output / 'sources' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
for source in sources:
    target = output / 'sources' / source.relative_to(repository)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
before = {name: sha(repository / name) for name in engine_inputs}
before.update({str(source.relative_to(repository)): sha(source) for source in sources})
(output / 'input-hashes.json').write_text(json.dumps({'pinnedCore': str(core), 'coreSha256': sha(core), 'applicationBuildInputs': str(args.build_inputs.resolve()), 'differencesFromApplicationPin': drift, 'sources': before}, indent=2) + '\n')
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'), '--test', 'local_recovery_review', '--no-run', '--message-format=json']
compiled = subprocess.run(build, capture_output=True, text=True, timeout=300)
(output / 'rust-build.log').write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
messages = [json.loads(line) for line in compiled.stdout.splitlines() if line.startswith('{')]
test = next(Path(message['executable']) for message in messages if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == 'local_recovery_review' and message.get('executable'))
with tempfile.TemporaryDirectory(prefix='thronium-public-recovery-') as directory:
    directory = Path(directory)
    shutil.copy2(core, directory / 'ThroniumCore')
    shutil.copy2(test, directory / 'Thronium')
    binaries = {name: sha(directory / name) for name in ['Thronium', 'ThroniumCore']}
    command = [str(directory / 'Thronium'), '--ignored', '--nocapture', '--test-threads=1']
    (output / 'commands.json').write_text(json.dumps({'build': build, 'run': command, 'binaries': binaries}, indent=2) + '\n')
    environment = dict(os.environ)
    for name in ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME']:
        folder = directory / name.lower()
        folder.mkdir(mode=0o700)
        environment[name] = str(folder)
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=120)
    (output / 'core.log').write_text(result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
marker = 'LOCAL_RECOVERY_REVIEW_JSON '
observations = [json.loads(line.split(marker, 1)[1]) for line in result.stdout.splitlines() if marker in line]
after = {name: sha(repository / name) for name in before}
source_changes = {name: {'before': digest, 'after': after[name]} for name, digest in before.items() if after[name] != digest}
summary = {'passed': result.returncode == 0 and len(observations) == 6 and not source_changes, 'exitCode': result.returncode, 'completedScenarios': len(observations), 'binaries': binaries, 'coreSha256': sha(core), 'differencesFromApplicationPin': drift, 'sourceChangesDuringRun': source_changes, 'observations': observations, 'sourceHashes': before, 'boundaries': ['Actual Linux local internal core only; no managed TUN/system proxy/external worker/Windows/macOS acceptance', 'No private Engine state or timer manipulation; public snapshot/poll/check/connect/disconnect/recovery_tick APIs', 'Only authenticated owned PID/starttime/parent/executable targeted through pidfd SIGKILL or SIGSTOP/SIGCONT', 'HTTP fixture endpoints and marker servers are loopback only; no user/provider URLs']}
(output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
result.check_returncode()
assert summary['passed'], summary
print(f'Public recovery report: {output / "summary.json"}')
