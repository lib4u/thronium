#!/usr/bin/env python3
"""Run independent HTTP/DNS rule-set oracles against one pinned release core."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

desktop = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--core-sha256', required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
core, output = args.core.resolve(), args.artifacts.resolve()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(core) == args.core_sha256, 'Pinned core SHA mismatch'
output.mkdir(parents=True, exist_ok=False)
build = ['cargo', 'test', '--offline', '--locked', '--manifest-path', str(desktop / 'engine/Cargo.toml'),
         '--test', 'inline_ruleset_oracle', '--no-run', '--message-format=json']
result = subprocess.run(build, capture_output=True, text=True, timeout=300)
(output / 'build.log').write_text(result.stdout + result.stderr)
result.check_returncode()
artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
test = next(Path(item['executable']) for item in artifacts if item.get('reason') == 'compiler-artifact'
            and item.get('target', {}).get('name') == 'inline_ruleset_oracle' and item.get('executable'))
with tempfile.TemporaryDirectory(prefix='thronium-inline-ruleset-oracle-') as directory:
    directory = Path(directory)
    shutil.copy2(core, directory / 'ThroniumCore')
    shutil.copy2(test, directory / 'Thronium')
    binaries = {name: sha(directory / name) for name in ['Thronium', 'ThroniumCore']}
    command = [str(directory / 'Thronium'), 'pinned_core_inline_', '--ignored', '--nocapture', '--test-threads=1']
    (output / 'commands.json').write_text(json.dumps(dict(build=build, run=command, binaries=binaries), indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (output / 'core.log').write_text(result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
    result.check_returncode()
observations = {}
for kind in ['HTTP', 'DNS']:
    marker = f'INLINE_{kind}_ORACLE_JSON '
    values = [json.loads(line[len(marker):]) for line in result.stdout.splitlines() if line.startswith(marker)]
    assert len(values) == 1
    observations[kind.lower()] = values[0]
assert observations['http']['httpResponses'] == 54 and observations['dns']['responses'] == 14
module = desktop / '.tools/core-overlay/sing-box@v1.11.16-0.20260909122315-b801a09c9742'
sources = [Path(__file__), desktop / 'engine/tests/inline_ruleset_oracle.rs', desktop / 'engine/src/transport.rs',
           *sorted((desktop / 'engine/tests/fixtures/inline-ruleset').glob('*')),
           *[module / name for name in ['option/rule_set.go', 'option/types.go', 'route/rule/rule_headless.go',
             'route/rule/rule_item_rule_set.go', 'route/rule/rule_abstract.go', 'route/rule/rule_set_local.go']]]
hashes = {str(path.relative_to(desktop)): sha(path) for path in sources}
for source in sources:
    destination = output / 'sources' / source.relative_to(desktop)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
(output / 'summary.json').write_text(json.dumps(dict(passed=True, exitCode=result.returncode,
    sourceSHA256=hashes, binaries=binaries, observation=observations,
    independentOf='Raw JSON sent to core RPC. No current/future UI model or Engine routing compiler. Actual HTTP and UDP DNS packets to owned loopback responders.'), indent=2) + '\n')
print(f'Inline rule-set oracle report: {output / "summary.json"}')
